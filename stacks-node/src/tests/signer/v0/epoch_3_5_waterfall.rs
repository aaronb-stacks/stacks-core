// Copyright (C) 2020-2026 Stacks Open Internet Foundation
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

//! Integration tests covering the Epoch 3.5 transition to PoX-5 / sBTC
//! "waterfall" leader block commits.
//!
//! These tests use shim overrides in `stacks::chainstate::nakamoto::signer_set`
//! to stand in for the (not-yet-implemented) PoX-5 and sBTC contracts:
//!
//! * `TEST_FORCE_POX_5_ACTIVE` makes the PoX-5 dispatch arm reachable as soon
//!   as `epoch >= Epoch35`. (Without it `PoxConstants::active_pox_contract`
//!   never returns `pox-5`.)
//! * `TEST_WATERFALL_SIGNER_SET_OVERRIDE` short-circuits the read against the
//!   (placeholder) PoX-5 contract body and supplies a hardcoded signer set.
//! * `TEST_WATERFALL_SBTC_ADDRESS_OVERRIDE` supplies the sBTC recipient the
//!   miner should commit to.

use std::collections::HashMap;
use std::env;
use std::time::Duration;

use pinny::tag;
use stacks::address::AddressHashMode;
use stacks::burnchains::Txid;
use stacks::chainstate::nakamoto::signer_set::{
    TEST_FORCE_POX_5_ACTIVE, TEST_WATERFALL_SBTC_ADDRESS_OVERRIDE,
    TEST_WATERFALL_SIGNER_SET_OVERRIDE,
};
use stacks::chainstate::stacks::address::PoxAddress;
use stacks::types::chainstate::{StacksAddress, StacksPrivateKey};
use stacks::util::hash::Hash160;
use stacks::util::secp256k1::Secp256k1PublicKey;
use stacks_common::deps_common::bitcoin::blockdata::transaction::Transaction as BitcoinTransaction;
use stacks_signer::v0::SpawnedSigner;

use super::SignerTest;
use crate::tests::nakamoto_integrations::wait_for;
use crate::tests::neon_integrations::{get_chain_info, next_block_and_wait};
use crate::BitcoinRegtestController;

/// Build a `PoxAddress` to stand in for the per-cycle sBTC recipient.
fn make_sbtc_recipient_fixture() -> PoxAddress {
    PoxAddress::Standard(
        StacksAddress::new(
            AddressHashMode::SerializeP2PKH.to_version_testnet(),
            Hash160::from_data(b"epoch-3-5-waterfall-sbtc-recipient"),
        )
        .expect("constant testnet address version is valid"),
        Some(AddressHashMode::SerializeP2PKH),
    )
}

/// Derive `(signer_key, amount_ustx)` pairs from the test's signer private keys
/// for use as a hardcoded waterfall signer-set fixture. Equal stake per signer
/// so `pox_5_make_signer_set` produces equal weights summing to `reward_slots`.
fn signer_pairs_from_keys(keys: &[StacksPrivateKey]) -> Vec<([u8; 33], u128)> {
    keys.iter()
        .map(|sk| {
            let signer_key: [u8; 33] = Secp256k1PublicKey::from_private(sk)
                .to_bytes_compressed()
                .try_into()
                .expect("compressed secp256k1 pubkey is 33 bytes");
            (signer_key, 100_000_000_000_u128)
        })
        .collect()
}

/// Populate the override map for a wide span of reward cycles, so the test
/// does not need to time the override to a specific cycle number.
fn override_map_all_cycles(pairs: Vec<([u8; 33], u128)>) -> HashMap<u64, Vec<([u8; 33], u128)>> {
    let mut map = HashMap::new();
    for cycle in 0..1_000 {
        map.insert(cycle, pairs.clone());
    }
    map
}

/// Pre-generate signer keys deterministically so the override can be derived
/// before `SignerTest` is constructed.
fn pre_generate_signer_keys(num_signers: usize, seed_tag: &str) -> Vec<StacksPrivateKey> {
    (0..num_signers)
        .map(|i| StacksPrivateKey::from_seed(format!("signer_{i}_{seed_tag}").as_bytes()))
        .collect()
}

/// Get the most recent unconfirmed block-commit bitcoin transaction, if one
/// is in the mempool.
fn get_unconfirmed_commit_tx(
    btc_controller: &BitcoinRegtestController,
    miner_pk: &Secp256k1PublicKey,
) -> Option<BitcoinTransaction> {
    let unconfirmed_utxo = btc_controller
        .get_all_utxos(miner_pk)
        .into_iter()
        .find(|utxo| utxo.confirmations == 0)?;
    let unconfirmed_txid = Txid::from_bitcoin_tx_hash(&unconfirmed_utxo.txid);
    Some(btc_controller.get_raw_transaction(&unconfirmed_txid))
}

/// Returns the miner's bitcoin pubkey for the test node.
fn get_miner_pubkey<Z: super::SpawnedSignerTrait>(
    signer_test: &SignerTest<Z>,
) -> Secp256k1PublicKey {
    signer_test
        .running_nodes
        .btc_regtest_controller
        .get_mining_pubkey()
        .as_deref()
        .map(Secp256k1PublicKey::from_hex)
        .expect("mining pubkey configured")
        .expect("mining pubkey decodes")
}

/// After the Epoch 3.5 boundary, miners produce leader block commits
/// with a single PoX output paying to the configured sBTC recipient, and
/// blocks continue to assemble.
#[tag(slow, bitcoind)]
#[test]
#[ignore]
fn epoch_3_5_block_commit_uses_single_sbtc_output() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;
    let signer_keys = pre_generate_signer_keys(num_signers, "epoch_3_5_basic");
    let sbtc_recipient = make_sbtc_recipient_fixture();
    let signer_pairs = signer_pairs_from_keys(&signer_keys);

    // Install overrides BEFORE constructing the test harness so that any
    // burnchain activity that triggers the PoX-5 path picks them up.
    TEST_WATERFALL_SBTC_ADDRESS_OVERRIDE.set(sbtc_recipient.clone());
    TEST_WATERFALL_SIGNER_SET_OVERRIDE.set(override_map_all_cycles(signer_pairs));
    TEST_FORCE_POX_5_ACTIVE.set(true);

    let signer_test: SignerTest<SpawnedSigner> = SignerTest::new_with_config_modifications(
        num_signers,
        vec![],
        |_| {},
        |node_config| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
        },
        None,
        Some(signer_keys),
    );

    let conf = signer_test.running_nodes.conf.clone();
    let miner_pk = get_miner_pubkey(&signer_test);
    let sbtc_script_pubkey = sbtc_recipient.clone().to_bitcoin_tx_out(0).script_pubkey;

    signer_test.boot_to_epoch_3();
    info!("------------------------- Reached Epoch 3.0 -------------------------");

    // Mine until we observe a block-commit whose first PoX output equals the
    // configured sBTC recipient. Pre-3.5 prepare-phase commits also produce
    // single-output txs (paying to the burn address — see relayer.rs's
    // `is_in_prepare_phase` branch), so length alone is not a reliable signal.
    // Positive identification on the recipient script is.
    //
    // Default integration epochs put Epoch 3.5 start at burn height 254 with
    // reward_cycle_length=20, so waterfall begins around burn height 260 — a
    // few dozen tenures past `boot_to_epoch_3`'s landing point near 220.
    let max_tenures = 60;
    let mut waterfall_observed = false;
    for i in 0..max_tenures {
        let burn_height = get_chain_info(&conf).burn_block_height;
        info!("Mining tenure {} (burn_height={burn_height})", i + 1);
        signer_test.mine_nakamoto_block(Duration::from_secs(60), true);
        signer_test.check_signer_states_normal();
        let Some(tx) =
            get_unconfirmed_commit_tx(&signer_test.running_nodes.btc_regtest_controller, &miner_pk)
        else {
            continue;
        };
        if tx.output.len() >= 2 && tx.output[1].script_pubkey == sbtc_script_pubkey {
            assert_eq!(
                tx.output.len(),
                3,
                "waterfall commit must have exactly 3 outputs (op_return + sbtc + change), got {}",
                tx.output.len()
            );
            waterfall_observed = true;
            info!(
                "------------------------- Observed waterfall block commit at burn_height={burn_height} -------------------------"
            );
            break;
        }
    }

    assert!(
        waterfall_observed,
        "no waterfall block commit (paying to the configured sBTC recipient) observed in \
         {max_tenures} tenures"
    );

    // Mine more bitcoin blocks and confirm the chain keeps producing waterfall
    // block commits to the sBTC recipient. Use the lower-level
    // `next_block_and_wait` here rather than `mine_nakamoto_block` because the
    // strict path panics on a missed sortition, and the burn block immediately
    // following the first cycle-13 sortition can race with the miner's commit
    // submission. The waterfall-format invariant is what we care about for
    // steady state.
    let blocks_processed = signer_test.running_nodes.counters.blocks_processed.clone();
    let target_steady_state_waterfalls = 3;
    let mut steady_state_waterfalls = 0;
    let mut last_stacks_tip = get_chain_info(&conf).stacks_tip_height;
    for i in 0..(target_steady_state_waterfalls * 4) {
        if steady_state_waterfalls >= target_steady_state_waterfalls {
            break;
        }
        info!(
            "Steady-state bitcoin block {} (waterfalls observed {}/{})",
            i + 1,
            steady_state_waterfalls,
            target_steady_state_waterfalls
        );
        next_block_and_wait(
            &signer_test.running_nodes.btc_regtest_controller,
            &blocks_processed,
        );
        // Best-effort wait for a Stacks block in the (possibly new) tenure;
        // tolerate timeouts caused by missed sortitions.
        let _ = wait_for(30, || {
            Ok(get_chain_info(&conf).stacks_tip_height > last_stacks_tip)
        });
        last_stacks_tip = get_chain_info(&conf).stacks_tip_height;
        let Some(tx) =
            get_unconfirmed_commit_tx(&signer_test.running_nodes.btc_regtest_controller, &miner_pk)
        else {
            continue;
        };
        if tx.output.len() >= 2 && tx.output[1].script_pubkey == sbtc_script_pubkey {
            steady_state_waterfalls += 1;
            info!(
                "Steady-state waterfall block commit #{steady_state_waterfalls} observed at burn_height={}",
                get_chain_info(&conf).burn_block_height
            );
        }
    }

    assert!(
        steady_state_waterfalls >= target_steady_state_waterfalls,
        "expected {target_steady_state_waterfalls} steady-state waterfall block commits, only \
         observed {steady_state_waterfalls}"
    );

    signer_test.shutdown();
}
