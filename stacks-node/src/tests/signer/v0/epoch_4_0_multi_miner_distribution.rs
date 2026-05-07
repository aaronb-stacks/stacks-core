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

//! Two-miner integration test for the burn-distribution / commit-windowing
//! path across the Epoch 4.0 boundary.
//!
//! With a single miner, dropped commits in the burn distribution don't
//! manifest as observable failures (the lone miner wins every sortition
//! regardless of effective burn). Two miners with deterministic asymmetric
//! fees give the math something to actually decide between, so a windowing
//! bug at the boundary surfaces as a failure mode the test can catch.
//!
//! Three deterministic assertions, all per-tenure:
//!
//! * **Per-tenure burn distribution** — `LATEST_BURN_DISTRIBUTION` (test
//!   hook in `make_min_median_distribution`) exposes the actual
//!   `Vec<BurnSamplePoint>` the chain computed for each sortition. We
//!   assert two samples (one chain per miner) and that the sorted `burns`
//!   values match `[MINER_1_FEE, MINER_2_FEE]`. Catches chaining failures
//!   that drop enough entries to shift the median for either miner, or
//!   that fail to construct one of the two chains entirely.
//! * **Per-block commit count** — every post-boundary burn block that has
//!   any commits has exactly two `pox_transactions` entries. Catches a
//!   parse-side regression that silently drops one miner's commit.
//! * **Total commit fee invariant** — sum of `reward_recipients` amounts
//!   equals the configured fee total per block. Catches dropped commits or
//!   a classification flip between burn-output and PoX-recipient paths.

use std::collections::HashMap;
use std::env;
use std::time::Duration;

use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::ContractName;
use pinny::tag;
use stacks::chainstate::burn::distribution::LATEST_BURN_DISTRIBUTION;
use stacks::chainstate::nakamoto::signer_set::{
    TEST_FORCE_POX_5_ACTIVE, TEST_WATERFALL_SIGNER_SET_OVERRIDE,
};
use stacks::chainstate::stacks::events::BurnBlockEvent;
use stacks::core::{StacksEpochId, STACKS_EPOCH_MAX};
use stacks::types::chainstate::StacksPrivateKey;
use stacks::util::secp256k1::Secp256k1PublicKey;

use super::MultipleMinerTest;
use crate::tests::neon_integrations::{get_chain_info, test_observer};
use crate::tests::to_addr;

/// Per-miner deterministic burn fee (satoshis). Asymmetric so the burn
/// distribution actually has something to decide between.
const MINER_1_FEE: u64 = 5_000;
const MINER_2_FEE: u64 = 10_000;

/// Number of post-Epoch-4.0 tenures to mine.
const POST_BOUNDARY_TENURES: u64 = 15;

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

fn override_map_all_cycles(pairs: Vec<([u8; 33], u128)>) -> HashMap<u64, Vec<([u8; 33], u128)>> {
    let mut map = HashMap::new();
    for cycle in 0..1_000 {
        map.insert(cycle, pairs.clone());
    }
    map
}

/// Filter burn-block events to those at or after the Epoch 4.0 start height.
fn post_boundary_burn_blocks(epoch_40_start: u64) -> Vec<BurnBlockEvent> {
    test_observer::get_burn_blocks()
        .into_iter()
        .filter(|ev| ev.burn_block_height >= epoch_40_start)
        .collect()
}

/// Two miners with asymmetric burn fees mine across the Epoch 4.0 boundary.
/// After the boundary, the burn distribution computed for each sortition
/// must contain both miners' chains with their configured fees as the
/// effective burn, and every burn block (with commits) must contain both
/// miners' commits with the fee sum invariant intact.
#[tag(slow, bitcoind)]
#[test]
#[ignore]
fn epoch_4_0_burn_distribution_chains_across_boundary() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let num_signers = 5;

    let agg_pubkey: [u8; 33] = Secp256k1PublicKey::from_private(&StacksPrivateKey::from_seed(
        b"epoch-4-0-multi-miner-agg",
    ))
    .to_bytes_compressed()
    .try_into()
    .expect("compressed secp256k1 pubkey is 33 bytes");

    // Deterministic publisher key so we can derive the contract id ahead of
    // SignerTest construction (needed to set `node.pox_5_aggregate_pubkey_contract`
    // via the modifier closure).
    let publisher_sk = StacksPrivateKey::from_seed(b"epoch-4-0-multi-miner-publisher");
    let publisher_addr = to_addr(&publisher_sk);
    let contract_name = "agg-pubkey-stub";
    let contract_id = QualifiedContractIdentifier::new(
        publisher_addr.clone().into(),
        ContractName::try_from(contract_name.to_string()).expect("valid contract name"),
    );

    // PoX-5 routing fault-injection. Safe to set before construction: it's
    // gated on `current_epoch >= Epoch40`, so it has no effect until cycle
    // 9's prepare phase.
    TEST_FORCE_POX_5_ACTIVE.set(true);

    let publisher_addr_str = publisher_addr.to_string();
    let contract_id_modifier = contract_id.clone();

    // IMPORTANT: only the node 1 modifier sets shared state — the publisher's
    // initial balance and the aggregate-pubkey contract id. Node 2's conf is
    // *cloned* from node 1's after node 1's modifier runs (see
    // `MultipleMinerTest::new_with_signer_dist`), so the clone already
    // carries both. Re-adding the balance from node 2's modifier duplicates
    // it → divergent genesis state root → node 2 rejects node 1's blocks.
    // Re-setting the contract id is just redundant (and invites the false
    // impression that the two values could differ; they must always match
    // for both miners to derive the same sBTC recipient).
    let mut miners = MultipleMinerTest::new_with_config_modifications(
        num_signers,
        0,
        |_| {},
        move |node_config| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
            node_config.burnchain.burn_fee_cap = MINER_1_FEE;
            node_config.node.pox_5_aggregate_pubkey_contract = Some(contract_id_modifier.clone());
            node_config.add_initial_balance(publisher_addr_str.clone(), 1_000_000);
        },
        |node_config| {
            node_config.miner.block_commit_delay = Duration::from_secs(1);
            node_config.burnchain.burn_fee_cap = MINER_2_FEE;
        },
    );

    // Build the PoX-5 signer-set override from the *actual* signer keys
    // SignerTest auto-generated, not from a separately-seeded set. Otherwise
    // the cycle-9 reward set (computed from the override) lists pubkeys
    // nobody is using; the running signers see themselves missing from the
    // set and report `registered_for_current: false`; block #1 of cycle 9
    // never gets signed and the chain stalls at the cycle boundary.
    //
    // Safe to set after construction since `pox_5_compute_and_update_signers`
    // doesn't run until Epoch 4.0 starts (cycle 9's prepare phase, well
    // after this point).
    let signer_pairs = signer_pairs_from_keys(miners.signer_stacks_private_keys());
    TEST_WATERFALL_SIGNER_SET_OVERRIDE.set(override_map_all_cycles(signer_pairs));

    let conf_1 = miners.get_node_configs().0;

    let epoch_40_start = conf_1
        .burnchain
        .epochs
        .as_ref()
        .and_then(|e| e.get(StacksEpochId::Epoch40))
        .map(|epoch| epoch.start_height)
        .filter(|h| *h < STACKS_EPOCH_MAX)
        .expect("test requires Epoch 4.0 configured");

    miners.boot_to_epoch_4(&publisher_sk, 0, contract_name, &agg_pubkey);
    info!("------------------------- Reached Epoch 4.0 (multi-miner) -------------------------");

    // Mine N tenures past the boundary. Before each BTC block, wait for
    // both nodes to have settled on the current tenure and for both miners
    // to have committed pointing at the current tip — that way the next
    // sortition has both samples in the burn distribution and no miner is
    // mid-flight on a stale tenure.
    //
    // After each sortition is processed, read the captured
    // `LATEST_BURN_DISTRIBUTION` and assert per-tenure invariants on the
    // computed `Vec<BurnSamplePoint>`. This is the tight integration check
    // for the windowing/chaining math: the burns value reflects the
    // post-median effective burn for each miner's chain. With both miners
    // committing every block at constant per-miner fees, the median over
    // any window equals the miner's fee — unless the linker dropped enough
    // entries to shift it.
    let sortdb = conf_1
        .get_burnchain()
        .open_sortition_db(true)
        .expect("open sortition db");
    let expected_burns = {
        let mut v = vec![MINER_1_FEE as u128, MINER_2_FEE as u128];
        v.sort();
        v
    };
    for i in 0..POST_BOUNDARY_TENURES {
        miners
            .wait_for_both_miners_committed_to_current_tenure(&sortdb, 60)
            .unwrap_or_else(|e| panic!("settle before post-boundary tenure {i} failed: {e}"));
        miners
            .mine_bitcoin_blocks_and_confirm(&sortdb, 1, 60)
            .unwrap_or_else(|e| panic!("post-boundary tenure {i} failed: {e}"));

        let dist = LATEST_BURN_DISTRIBUTION
            .get_opt()
            .unwrap_or_else(|| panic!("tenure {i}: no burn distribution captured"));

        // Two miners both committing every block ⇒ exactly two chains in
        // the distribution.
        assert_eq!(
            dist.len(),
            2,
            "tenure {i}: expected 2 BurnSamplePoints (one per miner chain), got {} \
             — a chain may have failed to construct",
            dist.len(),
        );

        // With constant per-miner fees and an intact chain, each chain's
        // post-median effective burn equals the miner's configured fee.
        // (For windowed reward-phase tenures the median is over 6 entries
        // of the same fee; for prepare-phase tenures the window collapses
        // to 1 and the single entry is the fee. Either way, fully-linked
        // chains produce burns == fee.)
        let mut burns: Vec<u128> = dist.iter().map(|s| s.burns).collect();
        burns.sort();
        assert_eq!(
            burns, expected_burns,
            "tenure {i}: per-chain burns mismatch (got {:?}, expected {:?}). The \
             windowing/chaining math may have dropped entries from one or both \
             miners' chains across the Epoch 4.0 boundary.",
            burns, expected_burns,
        );
    }

    // Per-block commit count + fee-sum invariant on burn events. Same parse-
    // side coverage as before; complementary to the per-tenure distribution
    // check above (which covers the chaining/windowing side).
    let expected_fee_sum = MINER_1_FEE + MINER_2_FEE;
    let post_boundary = post_boundary_burn_blocks(epoch_40_start);
    let mut blocks_with_commits = 0usize;
    for ev in post_boundary.iter() {
        let commit_count = ev.pox_transactions.len();
        if commit_count == 0 {
            continue;
        }
        blocks_with_commits += 1;

        assert_eq!(
            commit_count, 2,
            "burn_block_height={} had {} commits (expected 2 — one from each miner). \
             Likely a parse-side regression at the Epoch 4.0 boundary silently dropped a commit.",
            ev.burn_block_height, commit_count,
        );

        let recipient_sum: u64 = ev.reward_recipients.iter().map(|r| r.amt).sum();
        assert_eq!(
            recipient_sum, expected_fee_sum,
            "burn_block_height={} reward_recipients summed to {recipient_sum} (expected \
             {expected_fee_sum} = MINER_1_FEE + MINER_2_FEE). Either a commit was dropped, or \
             fees were miscategorized between burn-output and PoX-recipient paths.",
            ev.burn_block_height,
        );
    }
    assert!(
        blocks_with_commits >= POST_BOUNDARY_TENURES as usize / 2,
        "fewer than half of post-boundary blocks had any commits at all ({blocks_with_commits} of \
         {} examined); test is likely flaky on this run, not a real regression",
        post_boundary.len(),
    );

    let final_info = get_chain_info(&conf_1);
    info!(
        "Multi-miner waterfall test passed";
        "stacks_tip_height" => final_info.stacks_tip_height,
        "burn_block_height" => final_info.burn_block_height,
        "blocks_with_commits" => blocks_with_commits,
    );

    miners.shutdown();
}
