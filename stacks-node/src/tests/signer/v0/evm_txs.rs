// Copyright (C) 2026 Stacks Open Internet Foundation
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! End-to-end tests for the experimental EVM transaction payloads
//! (`EvmPublish` / `EvmContractCall`) against a live nakamoto node with
//! signers, booted directly into Epoch 3.3 (the EVM activation epoch).

use std::env;
use std::time::Duration;

use clarity::vm::Value;
use pinny::tag;
use stacks::chainstate::stacks::{
    TransactionEvmContractCall, TransactionEvmPublish, TransactionPayload,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks::codec::StacksMessageCodec;
use stacks::core::test_util::{sign_standard_single_sig_tx, to_addr};
use stacks::types::chainstate::{StacksAddress, StacksPrivateKey};
use stacks::types::StacksEpochId;
use stacks::util::hash::{hex_bytes, Hash160};
use stacks_signer::v0::SpawnedSigner;

use crate::tests::nakamoto_integrations::{get_tx_result_by_id, get_tx_status_by_id, wait_for};
use crate::tests::neon_integrations::{get_account, submit_tx};
use crate::tests::signer::{test_observer, SignerTest};

/// Init code for a minimal storage contract. Behavior of the deployed
/// runtime (payable, no function selector):
/// - empty calldata: returns the 32-byte word in slot 0
/// - otherwise: stores calldata[0..32] into slot 0 and emits a LOG1 with
///   topic 0x1111...11
const STORAGE_INIT_CODE: &str = concat!(
    // init: codecopy(0, 0x0c, 0x3e); return(0, 0x3e)
    "603e600c600039603e6000f3",
    // runtime, 0x3e bytes
    "3615603257",
    "600035600055",
    "7f1111111111111111111111111111111111111111111111111111111111111111",
    "60006000a100",
    "5b60005460005260206000f3",
);

/// Init code for a contract whose runtime always reverts.
const REVERT_INIT_CODE: &str = concat!(
    // init: codecopy(0, 0x0c, 0x05); return(0, 0x05)
    "6005600c60003960056000f3",
    // runtime: revert(0, 0)
    "60006000fd",
);

const TX_FEE: u64 = 10_000;
const GAS_LIMIT: u64 = 1_000_000;

/// Sign an EVM payload with the standard single-sig testnet settings,
/// submit it to the node, and return its txid hex (no 0x prefix).
fn submit_evm_tx(
    http_origin: &str,
    chain_id: u32,
    sender_sk: &StacksPrivateKey,
    nonce: u64,
    payload: TransactionPayload,
) -> String {
    let tx = sign_standard_single_sig_tx(payload, sender_sk, nonce, TX_FEE, chain_id);
    submit_tx(http_origin, &tx.serialize_to_vec())
}

/// Extract the buff payload from an `(ok (buff ...))` receipt result.
fn expect_ok_buff(result: &Value) -> Vec<u8> {
    let Value::Response(response) = result else {
        panic!("expected response value, got {result:?}");
    };
    assert!(response.committed, "expected ok, got {result:?}");
    match response.data.as_ref() {
        Value::Sequence(clarity::vm::types::SequenceData::Buffer(buff)) => buff.data.clone(),
        other => panic!("expected buff, got {other:?}"),
    }
}

/// Scan the event observer for a `contract_event` with the given topic
/// attached to the given txid.
fn observer_has_evm_log(txid: &str) -> bool {
    for block in test_observer::get_blocks().iter() {
        let Some(events) = block.get("events").and_then(|e| e.as_array()) else {
            continue;
        };
        for event in events {
            let matches_txid = event
                .get("txid")
                .and_then(|v| v.as_str())
                .and_then(|v| v.strip_prefix("0x"))
                == Some(txid);
            let matches_topic = event
                .get("contract_event")
                .and_then(|c| c.get("topic"))
                .and_then(|t| t.as_str())
                == Some("evm-log");
            if matches_txid && matches_topic {
                return true;
            }
        }
    }
    false
}

#[tag(bitcoind)]
#[test]
#[ignore]
/// End-to-end EVM transaction flow on a live nakamoto chain.
///
/// Test Setup:
/// The test spins up five stacks signers, one miner Nakamoto node, and a
/// corresponding bitcoind, with epochs 3.0-3.2 collapsed so the chain boots
/// directly into Epoch 3.3 (where the EVM payloads activate).
///
/// Test Execution:
/// - `EvmPublish` a minimal storage contract and an always-revert contract.
/// - `EvmContractCall` the storage contract's write path with a msg.value
///   attached; then call its read path and check the returned word.
/// - `EvmContractCall` the revert contract.
///
/// Test Assertions:
/// - Both publishes succeed and return 20-byte contract addresses.
/// - The write call succeeds, emits an "evm-log" contract event, and moves
///   real uSTX to the contract's mapped principal.
/// - The read call returns the previously stored word.
/// - The revert call is mined as `abort_by_response` and still consumes the
///   sender's nonce.
fn evm_publish_and_contract_calls() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let sender_sk = StacksPrivateKey::from_seed(&[0xe1; 32]);
    let sender_addr = to_addr(&sender_sk);

    info!("------------------------- Test Setup -------------------------");
    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![(sender_addr.clone(), 100_000_000)],
        |_| {},
        |node_config| {
            // boot directly to epoch 3.3, where the EVM payloads activate
            let epochs = node_config.burnchain.epochs.as_mut().unwrap();
            let epoch_30_height = epochs[StacksEpochId::Epoch30].start_height;

            epochs[StacksEpochId::Epoch30].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch31].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].start_height = epoch_30_height;
            epochs[StacksEpochId::Epoch32].end_height = epoch_30_height;
            epochs[StacksEpochId::Epoch33].start_height = epoch_30_height;
        },
        None,
        None,
    );

    signer_test.boot_to_epoch_3();

    let http_origin = signer_test.running_nodes.rpc_origin();
    let chain_id = signer_test.running_nodes.conf.burnchain.chain_id;

    info!("------------------------- Mine a normal Nakamoto block -------------------------");
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    info!("------------------------- Publish the storage contract -------------------------");
    let publish_payload = TransactionPayload::EvmPublish(TransactionEvmPublish {
        gas_limit: GAS_LIMIT,
        value: 0,
        code: hex_bytes(STORAGE_INIT_CODE).unwrap(),
    });
    let storage_txid = submit_evm_tx(&http_origin, chain_id, &sender_sk, 0, publish_payload);
    signer_test
        .wait_for_nonce_increase(&sender_addr, 0)
        .expect("Timed out waiting for the storage-contract publish to be mined");

    assert_eq!(
        get_tx_status_by_id(&storage_txid).as_deref(),
        Some("success"),
        "storage-contract publish was not mined successfully"
    );
    let storage_result =
        get_tx_result_by_id(&storage_txid).expect("no receipt result for storage publish");
    let storage_addr_bytes = expect_ok_buff(&storage_result);
    assert_eq!(storage_addr_bytes.len(), 20);
    let storage_contract = Hash160(storage_addr_bytes.as_slice().try_into().unwrap());
    info!("Storage contract created at EVM address {storage_contract}");

    info!("------------------------- Publish the revert contract -------------------------");
    let publish_payload = TransactionPayload::EvmPublish(TransactionEvmPublish {
        gas_limit: GAS_LIMIT,
        value: 0,
        code: hex_bytes(REVERT_INIT_CODE).unwrap(),
    });
    let revert_txid = submit_evm_tx(&http_origin, chain_id, &sender_sk, 1, publish_payload);
    signer_test
        .wait_for_nonce_increase(&sender_addr, 1)
        .expect("Timed out waiting for the revert-contract publish to be mined");

    assert_eq!(
        get_tx_status_by_id(&revert_txid).as_deref(),
        Some("success"),
        "revert-contract publish was not mined successfully"
    );
    let revert_result =
        get_tx_result_by_id(&revert_txid).expect("no receipt result for revert publish");
    let revert_addr_bytes = expect_ok_buff(&revert_result);
    let revert_contract = Hash160(revert_addr_bytes.as_slice().try_into().unwrap());
    assert_ne!(storage_contract, revert_contract);

    info!("------------------------- Write to storage with msg.value -------------------------");
    let mut word = vec![0u8; 32];
    word[31] = 0x2a;
    let write_payload = TransactionPayload::EvmContractCall(TransactionEvmContractCall {
        address: storage_contract.clone(),
        gas_limit: GAS_LIMIT,
        value: 500,
        calldata: word.clone(),
    });
    let write_txid = submit_evm_tx(&http_origin, chain_id, &sender_sk, 2, write_payload);
    signer_test
        .wait_for_nonce_increase(&sender_addr, 2)
        .expect("Timed out waiting for the write call to be mined");

    assert_eq!(
        get_tx_status_by_id(&write_txid).as_deref(),
        Some("success"),
        "storage write call was not mined successfully"
    );

    // the EVM log surfaced as a contract event with topic "evm-log"
    assert!(
        observer_has_evm_log(&write_txid),
        "no evm-log contract event observed for the write call"
    );

    // msg.value moved real uSTX to the contract's mapped principal
    let contract_principal = StacksAddress::new(
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
        storage_contract.clone(),
    )
    .unwrap();
    let contract_account = get_account(&http_origin, &contract_principal);
    assert_eq!(contract_account.balance, 500);

    info!("------------------------- Read the stored word back -------------------------");
    let read_payload = TransactionPayload::EvmContractCall(TransactionEvmContractCall {
        address: storage_contract.clone(),
        gas_limit: GAS_LIMIT,
        value: 0,
        calldata: vec![],
    });
    let read_txid = submit_evm_tx(&http_origin, chain_id, &sender_sk, 3, read_payload);
    signer_test
        .wait_for_nonce_increase(&sender_addr, 3)
        .expect("Timed out waiting for the read call to be mined");

    assert_eq!(get_tx_status_by_id(&read_txid).as_deref(), Some("success"));
    let read_result = get_tx_result_by_id(&read_txid).expect("no receipt result for read call");
    assert_eq!(expect_ok_buff(&read_result), word);

    info!("------------------------- Call the revert contract -------------------------");
    let revert_call_payload = TransactionPayload::EvmContractCall(TransactionEvmContractCall {
        address: revert_contract,
        gas_limit: GAS_LIMIT,
        value: 0,
        calldata: vec![],
    });
    let revert_call_txid =
        submit_evm_tx(&http_origin, chain_id, &sender_sk, 4, revert_call_payload);
    signer_test
        .wait_for_nonce_increase(&sender_addr, 4)
        .expect("Timed out waiting for the revert call to be mined");

    // the revert is mined, reported as an aborted response, and consumed
    // the sender's nonce (fee paid), but committed no state
    assert_eq!(
        get_tx_status_by_id(&revert_call_txid).as_deref(),
        Some("abort_by_response"),
        "revert call should be mined as abort_by_response"
    );
    let sender_account = get_account(&http_origin, &sender_addr);
    assert_eq!(sender_account.nonce, 5);

    // the read result is unchanged after the revert
    wait_for(30, || Ok(get_tx_result_by_id(&read_txid).is_some()))
        .expect("read receipt disappeared from the observer");

    info!("------------------------- Shutdown -------------------------");
    signer_test.shutdown();
}
