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

use std::io::{self, Write};
use std::time::Duration;
use std::{env, thread};

use clarity::vm::Value;
use pinny::tag;
use stacks::chainstate::stacks::db::evm::abi::encode_call_input;
use stacks::chainstate::stacks::db::evm::CLARITY_READ_PRECOMPILE;
use stacks::chainstate::stacks::{
    TransactionEvmContractCall, TransactionEvmPublish, TransactionPayload,
    C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks::codec::StacksMessageCodec;
use stacks::core::test_util::{sign_standard_single_sig_tx, to_addr};
use stacks::types::chainstate::{StacksAddress, StacksPrivateKey};
use stacks::types::StacksEpochId;
use stacks::util::hash::{hex_bytes, to_hex, Hash160};
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

// ===========================================================================
// Narrated end-to-end demo (`evm_demo`)
//
// Same real stack as the test above (bitcoind + signers + miner, Epoch 3.3),
// but presented as a guided, boxed-panel walkthrough for live demos. It adds
// the `clarity-read` precompile bridge: an EVM contract reading a value out
// of a Clarity contract.
//
// In a test build the node/signer logger writes to *stdout*, so the demo
// writes its panels to *stderr* instead. Capturing stdout then gives a clean
// walkthrough with full logs preserved:  `... 1>node.log`.
//
// The EVM bytecode is minimal, hand-assembled bytecode (the same fixtures the
// unit tests use); the "equivalent Solidity" shown in panels describes what
// that bytecode does, it is not compiled from it.
// ===========================================================================

mod demo_ui {
    use std::io::{self, Write};

    pub const RESET: &str = "\x1b[0m";
    pub const BOLD: &str = "\x1b[1m";
    pub const DIM: &str = "\x1b[2m";
    pub const CYAN: &str = "\x1b[36m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const MAGENTA: &str = "\x1b[35m";
    pub const BLUE: &str = "\x1b[34m";

    const WIDTH: usize = 72;

    fn visible_len(s: &str) -> usize {
        let mut len = 0;
        let mut esc = false;
        for ch in s.chars() {
            if esc {
                if ch == 'm' {
                    esc = false;
                }
            } else if ch == '\x1b' {
                esc = true;
            } else {
                len += 1;
            }
        }
        len
    }

    fn pad(s: &str) -> String {
        let v = visible_len(s);
        if v >= WIDTH {
            s.to_string()
        } else {
            format!("{s}{}", " ".repeat(WIDTH - v))
        }
    }

    pub fn banner() {
        eprint!("\x1b[2J\x1b[H");
        let _ = io::stderr().flush();
        let bar = "=".repeat(WIDTH + 2);
        eprintln!("{CYAN}{BOLD}+{bar}+{RESET}");
        for line in [
            "",
            "        E V M   o n   S T A C K S   -   live e2e demo",
            "",
            "   Real bitcoind + signers + miner, booted to Epoch 3.3.",
            "   Solidity-style contracts as native Stacks transactions,",
            "   sharing the MARF, the STX ledger, and one gas meter.",
            "",
        ] {
            eprintln!("{CYAN}{BOLD}|{RESET} {} {CYAN}{BOLD}|{RESET}", pad(line));
        }
        eprintln!("{CYAN}{BOLD}+{bar}+{RESET}");
        eprintln!();
    }

    pub struct Panel {
        rows: Vec<String>,
    }

    pub fn step(n: u32, title: &str) -> Panel {
        eprintln!("{MAGENTA}{BOLD}+- STEP {n}: {title}{RESET}");
        Panel { rows: vec![] }
    }

    impl Panel {
        pub fn line(&mut self, s: impl AsRef<str>) -> &mut Self {
            self.rows.push(s.as_ref().to_string());
            self
        }
        pub fn kv(&mut self, key: &str, value: impl AsRef<str>) -> &mut Self {
            self.rows.push(format!(
                "{DIM}{key:<14}{RESET}{}",
                value.as_ref(),
                key = key
            ));
            self
        }
        pub fn divider(&mut self) -> &mut Self {
            self.rows.push(format!("{DIM}{}{RESET}", "-".repeat(WIDTH)));
            self
        }
        pub fn code(&mut self, code: &str, color: &str) -> &mut Self {
            for l in code.lines() {
                self.rows
                    .push(format!("{color}{DIM}|{RESET} {color}{l}{RESET}"));
            }
            self
        }
        pub fn render(&mut self) {
            let bar = "-".repeat(WIDTH + 2);
            eprintln!("{MAGENTA}+{bar}{RESET}");
            for row in self.rows.drain(..) {
                eprintln!("{MAGENTA}|{RESET} {} {MAGENTA}|{RESET}", pad(&row));
            }
            eprintln!("{MAGENTA}+{bar}+{RESET}");
        }
    }

    pub fn ok(msg: &str) {
        eprintln!("  {GREEN}{BOLD}[ok]{RESET} {msg}");
    }
    pub fn info(msg: &str) {
        eprintln!("  {BLUE}>{RESET} {msg}");
    }

    /// Pause between steps. Under `podman run -it` this waits for Enter; with
    /// no TTY it reads EOF and continues (autoplay).
    pub fn wait(prompt: &str) {
        eprintln!();
        eprint!("  {YELLOW}> {prompt}{RESET}");
        let _ = io::stderr().flush();
        let mut buf = String::new();
        let _ = io::stdin().read_line(&mut buf);
        eprintln!();
    }
}

/// A 32-byte big-endian ABI word holding `value` in its low 16 bytes.
fn demo_word_u128(value: u128) -> Vec<u8> {
    let mut word = vec![0u8; 32];
    word[16..32].copy_from_slice(&value.to_be_bytes());
    word
}

/// Decode a 32-byte ABI word's low 16 bytes as a u128.
fn demo_word_to_u128(word: &[u8]) -> u128 {
    if word.len() < 32 {
        return 0;
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&word[16..32]);
    u128::from_be_bytes(buf)
}

/// Init code for a forwarder EVM contract whose runtime copies all calldata,
/// `CALL`s `target` with it, and bubbles up the returned/reverted data. Used
/// to prove an EVM *contract* (not just a top-level tx) can reach the Clarity
/// precompile.
fn demo_forwarder_init_code(target: &[u8; 20]) -> Vec<u8> {
    let mut runtime = vec![0x36, 0x60, 0x00, 0x60, 0x00, 0x37];
    runtime.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x36, 0x60, 0x00, 0x60, 0x00]);
    runtime.push(0x73);
    runtime.extend_from_slice(target);
    runtime.extend_from_slice(&[0x5a, 0xf1]);
    runtime.extend_from_slice(&[0x3d, 0x60, 0x00, 0x60, 0x00, 0x3e]);
    let ok_dest = u8::try_from(runtime.len() + 7).unwrap();
    runtime.extend_from_slice(&[0x60, ok_dest, 0x57]);
    runtime.extend_from_slice(&[0x3d, 0x60, 0x00, 0xfd]);
    runtime.extend_from_slice(&[0x5b, 0x3d, 0x60, 0x00, 0xf3]);
    let len = u8::try_from(runtime.len()).unwrap();
    let mut init = vec![
        0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3,
    ];
    init.extend_from_slice(&runtime);
    init
}

const DEMO_VAULT_SOLIDITY: &str = "contract Vault {                      // payable
  uint256 stored;
  fallback() external payable {
    if (msg.data.length == 0) return abi.encode(stored);
    stored = abi.decode(msg.data,(uint256));
    emit Stored();                    // -> Stacks event
  } }";

const DEMO_ORACLE_CODE: &str = "(define-read-only (get-answer) u42)";

#[tag(bitcoind)]
#[test]
#[ignore]
/// Narrated end-to-end demo. Run via the `contrib/evm-demo` container, or:
///   BITCOIND_TEST=1 cargo test -p stacks-node evm_demo -- --ignored --nocapture
fn evm_demo() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    use demo_ui::*;

    let sender_sk = StacksPrivateKey::from_seed(&[0xd3; 32]);
    let sender_addr = to_addr(&sender_sk);

    banner();
    wait("press Enter to boot bitcoind + 5 signers + miner to Epoch 3.3");

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        5,
        vec![(sender_addr.clone(), 100_000_000)],
        |_| {},
        |node_config| {
            let epochs = node_config.burnchain.epochs.as_mut().unwrap();
            let h = epochs[StacksEpochId::Epoch30].start_height;
            epochs[StacksEpochId::Epoch30].end_height = h;
            epochs[StacksEpochId::Epoch31].start_height = h;
            epochs[StacksEpochId::Epoch31].end_height = h;
            epochs[StacksEpochId::Epoch32].start_height = h;
            epochs[StacksEpochId::Epoch32].end_height = h;
            epochs[StacksEpochId::Epoch33].start_height = h;
        },
        None,
        None,
    );
    signer_test.boot_to_epoch_3();
    let http = signer_test.running_nodes.rpc_origin();
    let chain_id = signer_test.running_nodes.conf.burnchain.chain_id;
    signer_test.mine_nakamoto_block(Duration::from_secs(30), true);

    let mut nonce: u64 = 0;
    // Submit an EVM/Clarity payload and block until the miner includes it.
    // A local macro (rather than a closure) so it doesn't hold a long-lived
    // mutable borrow of `nonce`, which the panels below also read.
    macro_rules! submit {
        ($payload:expr) => {{
            let txid = submit_evm_tx(&http, chain_id, &sender_sk, nonce, $payload);
            signer_test
                .wait_for_nonce_increase(&sender_addr, nonce)
                .expect("timed out waiting for the tx to be mined");
            nonce += 1;
            txid
        }};
    }

    let mut p = step(0, "Chain booted");
    p.kv("epoch", format!("{GREEN}3.3{RESET}  (EVM payloads active)"));
    p.kv("network", "regtest nakamoto (bitcoind + 5 signers)");
    p.kv("sender", sender_addr.to_string());
    p.kv(
        "balance",
        format!("{} uSTX", get_account(&http, &sender_addr).balance),
    );
    p.render();
    ok("A single Stacks key controls both the Stacks and EVM address.");
    wait("press Enter to deploy an EVM contract");

    // --- step 1: deploy vault -------------------------------------------
    let txid = submit!(TransactionPayload::EvmPublish(TransactionEvmPublish {
        gas_limit: GAS_LIMIT,
        value: 0,
        code: hex_bytes(STORAGE_INIT_CODE).unwrap(),
    }));
    let vault = Hash160(
        expect_ok_buff(&get_tx_result_by_id(&txid).unwrap())
            .as_slice()
            .try_into()
            .unwrap(),
    );
    let mut p = step(1, "EvmPublish - deploy a payable Vault contract");
    p.line(format!("{DIM}equivalent Solidity:{RESET}"));
    p.code(DEMO_VAULT_SOLIDITY, CYAN);
    p.divider();
    p.kv("status", format!("{GREEN}success{RESET}"));
    p.kv(
        "created addr",
        format!("{GREEN}0x{}{RESET}", to_hex(&vault.0)),
    );
    p.render();
    ok("Deployed in a real signer-approved Nakamoto block; code lives in the MARF.");
    wait("press Enter to call it with 5 STX attached");

    // --- step 2: write + value transfer ---------------------------------
    let vault_addr =
        StacksAddress::new(C32_ADDRESS_VERSION_TESTNET_SINGLESIG, vault.clone()).unwrap();
    let caller_before = get_account(&http, &sender_addr).balance;
    let txid = submit!(TransactionPayload::EvmContractCall(
        TransactionEvmContractCall {
            address: vault.clone(),
            gas_limit: GAS_LIMIT,
            value: 5_000_000,
            calldata: demo_word_u128(42),
        }
    ));
    let caller_after = get_account(&http, &sender_addr).balance;
    let vault_bal = get_account(&http, &vault_addr).balance;
    let logged = observer_has_evm_log(&txid);
    let mut p = step(2, "EvmContractCall - store 42, send 5 STX (msg.value)");
    p.kv("status", format!("{GREEN}success{RESET}"));
    p.kv(
        "evm log",
        if logged {
            format!("{GREEN}Stored event on the Stacks event feed{RESET}")
        } else {
            "none".to_string()
        },
    );
    p.divider();
    p.line(format!(
        "{DIM}STX ledger (uSTX)         before        after{RESET}"
    ));
    p.line(format!(
        "  caller              {caller_before:>10}   {caller_after:>10}"
    ));
    p.line(format!(
        "  vault contract               0   {GREEN}{vault_bal:>10}{RESET}"
    ));
    p.render();
    ok("msg.value moved real STX to the contract's own Stacks principal:");
    info(&vault_addr.to_string());
    wait("press Enter to read the stored value back");

    // --- step 3: read path ----------------------------------------------
    let txid = submit!(TransactionPayload::EvmContractCall(
        TransactionEvmContractCall {
            address: vault.clone(),
            gas_limit: GAS_LIMIT,
            value: 0,
            calldata: vec![],
        }
    ));
    let ret = expect_ok_buff(&get_tx_result_by_id(&txid).unwrap());
    let mut p = step(3, "EvmContractCall - read slot 0 (a separate tx)");
    p.kv("returned", format!("0x{}", to_hex(&ret)));
    p.kv(
        "decoded",
        format!("{GREEN}{}{RESET}", demo_word_to_u128(&ret)),
    );
    p.render();
    ok("EVM contract storage persisted across transactions, in the MARF.");
    wait("press Enter to deploy a Clarity contract");

    // --- step 4: deploy Clarity oracle ----------------------------------
    let txid =
        submit!(TransactionPayload::new_smart_contract("oracle", DEMO_ORACLE_CODE, None).unwrap());
    let oracle_id = format!("{sender_addr}.oracle");
    assert_eq!(get_tx_status_by_id(&txid).as_deref(), Some("success"));
    let mut p = step(4, "SmartContract - deploy a normal Clarity contract");
    p.line(format!("{DIM}Clarity:{RESET}"));
    p.code(DEMO_ORACLE_CODE, YELLOW);
    p.divider();
    p.kv("contract", format!("{GREEN}{oracle_id}{RESET}"));
    p.render();
    ok("A plain Clarity contract, deployed the normal way.");
    wait("press Enter for the headline: an EVM contract reading Clarity");

    // --- step 5: clarity-read bridge ------------------------------------
    let txid = submit!(TransactionPayload::EvmPublish(TransactionEvmPublish {
        gas_limit: GAS_LIMIT,
        value: 0,
        code: demo_forwarder_init_code(&CLARITY_READ_PRECOMPILE.0 .0),
    }));
    let forwarder = Hash160(
        expect_ok_buff(&get_tx_result_by_id(&txid).unwrap())
            .as_slice()
            .try_into()
            .unwrap(),
    );
    let calldata = encode_call_input(&oracle_id, "get-answer", &[]);
    let txid = submit!(TransactionPayload::EvmContractCall(
        TransactionEvmContractCall {
            address: forwarder,
            gas_limit: 2_000_000,
            value: 0,
            calldata,
        }
    ));
    let ret = expect_ok_buff(&get_tx_result_by_id(&txid).unwrap());
    let mut p = step(5, "EVM -> Clarity  (clarity-read precompile)");
    p.line(format!(
        "{DIM}the forwarder EVM contract runs, in effect:{RESET}"
    ));
    p.code(
        "// precompile at 0x00..c1a90001\n\
         (ok, ret) = CLARITY_READ.staticcall(\n\
         \x20   abi.encode(\"SP..oracle\", \"get-answer\", \"\"));\n\
         uint answer = abi.decode(ret, (uint));",
        CYAN,
    );
    p.divider();
    p.kv(
        "precompile",
        format!("0x{}", to_hex(&CLARITY_READ_PRECOMPILE.0 .0)),
    );
    p.kv("clarity fn", format!("{oracle_id} :: get-answer"));
    p.kv(
        "decoded",
        format!(
            "{GREEN}{BOLD}{}{RESET}  (Clarity's u42, read by the EVM)",
            demo_word_to_u128(&ret)
        ),
    );
    p.render();
    ok("An EVM contract just read live Clarity state through the precompile,");
    info("with the Clarity execution cost charged against the EVM gas limit.");
    wait("press Enter to see a revert");

    // --- step 6: revert semantics ---------------------------------------
    let txid = submit!(TransactionPayload::EvmPublish(TransactionEvmPublish {
        gas_limit: GAS_LIMIT,
        value: 0,
        code: hex_bytes(REVERT_INIT_CODE).unwrap(),
    }));
    let guard = Hash160(
        expect_ok_buff(&get_tx_result_by_id(&txid).unwrap())
            .as_slice()
            .try_into()
            .unwrap(),
    );
    let nonce_before = nonce;
    let txid = submit!(TransactionPayload::EvmContractCall(
        TransactionEvmContractCall {
            address: guard,
            gas_limit: GAS_LIMIT,
            value: 1_000_000,
            calldata: vec![],
        }
    ));
    let mut p = step(6, "Revert - mined, fee paid, nothing moved");
    p.kv(
        "status",
        format!(
            "{YELLOW}{}{RESET}",
            get_tx_status_by_id(&txid).unwrap_or_default()
        ),
    );
    p.kv("value attempted", "1000000 uSTX  (rolled back)");
    p.kv("nonce", format!("{nonce_before} -> {nonce}  (consumed)"));
    p.render();
    ok("A revert is a mined transaction: nonce advances, no state changes.");
    wait("press Enter to finish");

    let bar = "=".repeat(74);
    eprintln!("{GREEN}{BOLD}+{bar}+{RESET}");
    for line in [
        "  EVM-on-Stacks: Solidity-style contracts, Bitcoin-anchored settlement.",
        "",
        "  * EVM state lives in the MARF  (fork-aware, block-committed)",
        "  * EVM balances ARE the STX ledger  (1 wei = 1 uSTX)",
        "  * EVM gas maps into Clarity block cost  (one meter)",
        "  * EVM contracts can read Clarity via the clarity-read precompile",
    ] {
        eprintln!("{GREEN}{BOLD}|{RESET} {line:<72} {GREEN}{BOLD}|{RESET}");
    }
    eprintln!("{GREEN}{BOLD}+{bar}+{RESET}");

    // brief pause so the closing panel isn't clobbered by shutdown logs
    thread::sleep(Duration::from_millis(500));
    let _ = io::stderr().flush();
    signer_test.shutdown();
}
