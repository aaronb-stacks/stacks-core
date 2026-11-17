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

//! sBTC P2TR (taproot) deposit-address derivation for the PoX-5 sBTC recipient.
//!
//! The per-cycle sBTC recipient is a witness-v1 P2TR output committing to a
//! 2-leaf script tree (`deposit`, `reclaim`). Two deposit formats exist; the
//! epoch of the block that computes the reward set selects between them
//! (`StacksEpochId::sbtc_deposit_format`):
//!
//! - v1 (Epoch 4.0): the deposit leaf is locked by the registry's WSTS/FROST
//!   aggregate key, under the BIP-0341 NUMS internal key.
//! - v2 (Epoch 4.1+; stacks-sbtc/sbtc#2138): the deposit leaf is a hash-lock
//!   on the deposit data followed by the signers' `multi_a` Taproot
//!   script-path multisig, under the sBTC v2 NUMS internal key. Each signer's
//!   key is the BIP-32 `/0/0` child of its registry key.
//!
//! PoX-5 uses `lock_time = u16::MAX` and `[OP_RETURN]` as the reclaim leaf's
//! user script, which disables the reclaim path.
//!
//! The scripts, signer-key derivation and taproot tree all come from the
//! upstream `sbtc` crate, pinned to an exact git revision in
//! `stackslib/Cargo.toml`. This module only converts node types to `sbtc`
//! types and maps upstream errors to `ChainstateError::Expects`. In Epoch
//! 4.1+ the caller turns any such error into a fallback to the burn address
//! for the cycle; in Epoch 4.0 the caller propagates it. Upstream signer-key
//! derivation panics instead of erroring on a BIP-32 child tweak that is not a
//! valid scalar or yields the point at infinity; for registry keys this has
//! negligible probability (about 2^-128 per key).
//!
//! The output is consensus-critical: block-commits are validated against it.
//! It depends on the `sbtc` revision and on the `bitcoin` and `secp256k1`
//! versions in `Cargo.lock` (they build the scripts, leaf hashes and taproot
//! tweak), so bumping the `sbtc` pin or updating those crates can change
//! consensus. The frozen reference vectors in this module's tests detect that,
//! and must not be regenerated to make an update pass. An intentional upstream
//! format change has to be adopted at an epoch boundary, with the previous
//! derivation kept for earlier epochs.
//!
//! # Dependency design
//!
//! `sbtc` depends on stacks-core's `clarity`, `clarity-types` and
//! `stacks-common` at a pinned git revision, so the node is built with a
//! second copy of those crates, and `sbtc`'s `PrincipalData` is a different
//! type from the node's. The recipient crosses over through its consensus
//! encoding (`to_sbtc_principal`), which is exactly what the deposit data
//! commits to, and the conversion is rejected unless it re-encodes to the
//! same bytes.
//!
//! Building `sbtc` against this workspace's crates with a `[patch]` was
//! considered and rejected. Cargo ignores `[patch]` in dependencies, so every
//! crate that depends on `stackslib` from outside this workspace would need
//! the same patch or fail to compile. That includes `sbtc`'s own workspace,
//! which depends on `stackslib`, so the two repositories would be locked
//! together in a dependency cycle.
//!
//! Consequences of the second copy:
//! - `cargo -p clarity`, `-p clarity-types` and `-p stacks-common` become
//!   ambiguous when the same command also selects a package that depends on
//!   `stackslib` (for example `-p clarity -p stackslib`). The `clippy-stacks`
//!   alias therefore selects workspace members with `--workspace`/`--exclude`.
//! - The `sbtc-clarity` revision in `stackslib/Cargo.toml` must track the
//!   stacks-core revision that the pinned `sbtc` uses.
//!
//! The intended end state is an upstream `sbtc` API that does not take
//! stacks-core types (for example, the recipient as consensus-encoded bytes,
//! or the script code in a crate that depends only on `bitcoin`). That would
//! remove the second copy, and this conversion with it.

use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::secp256k1::{PublicKey, XOnlyPublicKey};
use bitcoin::ScriptBuf;
use clarity::vm::types::PrincipalData;
use sbtc::deposits::{
    to_taproot, to_v2_taproot, DepositScriptInputs, DepositScriptInputsV2, ReclaimScriptInputs,
};
use sbtc::SignerKeySet;
use stacks_common::codec::StacksMessageCodec;

use crate::chainstate::stacks::Error as ChainstateError;

/// `PrincipalData` from the stacks-core revision that `sbtc` is built
/// against, which is a different type from the node's own `PrincipalData`.
type SbtcPrincipalData = sbtc_clarity::vm::types::PrincipalData;

/// A validated sBTC v2 signer key set: the distinct, sorted x-only signing
/// keys derived from the registry keys, and the number of signatures required
/// to spend. Input order and duplicate keys do not affect the set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SbtcSignerKeySet(SignerKeySet);

impl SbtcSignerKeySet {
    /// Build the key set that the sBTC signers derive from the registry's
    /// `current-signer-set` (33-byte compressed keys) and
    /// `current-signature-threshold`.
    ///
    /// Rejects any key that is not a valid compressed secp256k1 point, a
    /// threshold that does not fit in `u16`, and any key count or threshold
    /// that `sbtc::SignerKeySet` rejects (no keys, more than
    /// `sbtc::MAX_SIGNERS` distinct keys, a zero threshold, or a threshold
    /// above the distinct key count).
    pub fn from_registry(
        signer_keys: &[[u8; 33]],
        signature_threshold: u128,
    ) -> Result<Self, ChainstateError> {
        let signatures_required = u16::try_from(signature_threshold).map_err(|_| {
            ChainstateError::Expects(format!(
                "sBTC registry signature threshold {signature_threshold} does not fit in u16"
            ))
        })?;
        let public_keys = signer_keys
            .iter()
            .map(|key| {
                PublicKey::from_slice(key)
                    .map_err(|_| ChainstateError::Expects("sBTC signer pubkey not on curve".into()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        SignerKeySet::derive(public_keys, signatures_required)
            .map(Self)
            .map_err(|e| ChainstateError::Expects(format!("invalid sBTC v2 signer key set: {e}")))
    }
}

/// The 32-byte P2TR output key of the PoX-5 v1 sBTC deposit for `recipient`,
/// locked by the registry's aggregate key in its 33-byte compressed form (what
/// `get-current-aggregate-pubkey` returns).
///
/// Only the x coordinate is committed to, so the parity byte is ignored.
pub fn sbtc_pox5_deposit_taproot_output_key(
    aggregate_pubkey_compressed: &[u8; 33],
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> Result<[u8; 32], ChainstateError> {
    let signers_public_key = XOnlyPublicKey::from_slice(&aggregate_pubkey_compressed[1..])
        .map_err(|_| ChainstateError::Expects("aggregate pubkey not on curve".into()))?;
    let deposit_script = DepositScriptInputs {
        signers_public_key,
        recipient: to_sbtc_principal(recipient)?,
        max_fee: max_fee_sats,
    }
    .deposit_script();
    Ok(to_taproot(deposit_script, pox_5_reclaim_script()?)
        .output_key()
        .serialize())
}

/// The 32-byte P2TR output key of the PoX-5 v2 sBTC deposit for `recipient`,
/// locked by the signers' Taproot script-path multisig `key_set`.
pub fn sbtc_pox5_v2_deposit_taproot_output_key(
    key_set: &SbtcSignerKeySet,
    recipient: &PrincipalData,
    max_fee_sats: u64,
) -> Result<[u8; 32], ChainstateError> {
    let deposit_script = DepositScriptInputsV2 {
        signer_key_set: key_set.0.clone(),
        recipient: to_sbtc_principal(recipient)?,
        max_fee: max_fee_sats,
    }
    .deposit_script();
    Ok(to_v2_taproot(deposit_script, pox_5_reclaim_script()?)
        .output_key()
        .serialize())
}

/// The PoX-5 reclaim leaf: `<u16::MAX> OP_CSV OP_RETURN`.
fn pox_5_reclaim_script() -> Result<ScriptBuf, ChainstateError> {
    let user_script = ScriptBuf::builder().push_opcode(OP_RETURN).into_script();
    ReclaimScriptInputs::try_new(u32::from(u16::MAX), user_script)
        .map(|inputs| inputs.reclaim_script())
        .map_err(|e| ChainstateError::Expects(format!("invalid PoX-5 sBTC reclaim script: {e}")))
}

/// Convert a principal to the type `sbtc` takes, through its consensus
/// encoding. The deposit data commits to exactly these bytes, so the
/// conversion is rejected unless the converted principal re-encodes to them.
fn to_sbtc_principal(principal: &PrincipalData) -> Result<SbtcPrincipalData, ChainstateError> {
    use sbtc_clarity::codec::StacksMessageCodec as SbtcStacksMessageCodec;

    let bytes = principal.serialize_to_vec();
    let converted =
        <SbtcPrincipalData as SbtcStacksMessageCodec>::consensus_deserialize(&mut &bytes[..])
            .map_err(|e| {
                ChainstateError::Expects(format!("sBTC recipient principal rejected: {e}"))
            })?;
    if SbtcStacksMessageCodec::serialize_to_vec(&converted) != bytes {
        return Err(ChainstateError::Expects(
            "sBTC recipient principal does not re-encode to the same bytes in sbtc's clarity"
                .into(),
        ));
    }
    Ok(converted)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bitcoin::taproot::{LeafVersion, TapLeafHash};
    use clarity::vm::representations::CONTRACT_MAX_NAME_LENGTH;
    use clarity::vm::types::{QualifiedContractIdentifier, StandardPrincipalData};
    use clarity::vm::ContractName;
    use pinny::tag;
    use proptest::prelude::*;
    use secp256k1::Secp256k1;
    use serde::Deserialize;
    use stacks_common::util::hash::{hex_bytes, to_hex};

    use super::*;

    // ---- Frozen reference vectors ----
    //
    // Every vector below was produced by a fixed sBTC revision (or, for the
    // PoX-5 v1 vectors, by the node's previous independent implementation,
    // which matched sBTC byte-for-byte). They are frozen: a mismatch after an
    // `sbtc` pin bump means the bump changes the consensus-critical recipient
    // and must not be resolved by regenerating them. The upstream intermediate
    // values (scripts, leaf hashes, merkle root) are checked as well so that a
    // drift points at the step that changed.

    fn hex_array<const N: usize>(hex_str: &str) -> [u8; N] {
        hex_bytes(hex_str)
            .expect("fixture value is valid hex")
            .try_into()
            .unwrap_or_else(|_| panic!("fixture value is {N} bytes"))
    }

    fn leaf_hash_hex(script: &ScriptBuf) -> String {
        TapLeafHash::from_script(script, LeafVersion::TapScript).to_string()
    }

    const FIXTURES_JSON: &str = r#"{
  "fixtures": [
    {
      "description": "Standard mainnet stacks address recipient (burn address); small lock_time that uses OP_PUSHNUM; empty user-supplied reclaim script.",
      "expected": {
        "script_pubkey_hex": "51203a900085e4603715fd25abda9299a4989a9f94a490f0d6f1892bc8a1c6babf1a"
      },
      "inputs": {
        "lock_time": 6,
        "max_fee": 15000,
        "recipient_principal": "SP000000000000000000002Q6VF78",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000000003a9805160000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "62ff1e284841c8b5655ffe1e1e5815eac12cb498d38b6f3b2d638a1c15648158",
        "merkle_root_hex": "f242112a4a0a232d5a77a6b100ca75054b76b2c8745ce5ee6ca0bf8ed33d9c88",
        "reclaim_script_hex": "56b2",
        "reclaim_tapleaf_hash_hex": "4b49f80fd3b1a30785b34bc7f0aa362a5a22aa4cc1ef0570489efec975526d28",
        "taproot_output_key_xonly_hex": "3a900085e4603715fd25abda9299a4989a9f94a490f0d6f1892bc8a1c6babf1a"
      },
      "name": "standard_mainnet_recipient_simple_reclaim"
    },
    {
      "description": "Standard testnet stacks address recipient (burn address); small lock_time; empty user-supplied reclaim script.",
      "expected": {
        "script_pubkey_hex": "51206601c757b0f7d2e5cfb45a938be833c17afbea7f6d5f8b293b454d3563008ba0"
      },
      "inputs": {
        "lock_time": 144,
        "max_fee": 100000000,
        "recipient_principal": "ST000000000000000000002AMW42H",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000005f5e100051a00000000000000000000000000000000000000007520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
        "deposit_tapleaf_hash_hex": "1110862072f1eb0877efaf240d5f2e8e3a524c6e53561d8baccb61fa674d2852",
        "merkle_root_hex": "d2d9a9b96c0881bc199a686662a49ffc71d9eed5a71716f1023297dc791f0dcf",
        "reclaim_script_hex": "029000b2",
        "reclaim_tapleaf_hash_hex": "454bd4c344b99a80a157d5e97bd0526d1fb12d26411f3fab1c49747e0bf1ed4b",
        "taproot_output_key_xonly_hex": "6601c757b0f7d2e5cfb45a938be833c17afbea7f6d5f8b293b454d3563008ba0"
      },
      "name": "standard_testnet_recipient_simple_reclaim"
    },
    {
      "description": "Contract principal recipient with a short contract-name; medium lock_time; reclaim user script is a single OP_DROP.",
      "expected": {
        "script_pubkey_hex": "5120b2e483a39cc83c83ed0e0ae613ae2443b5d4bfa554c6d3752301ffeb2669fd9b"
      },
      "inputs": {
        "lock_time": 1024,
        "max_fee": 0,
        "recipient_principal": "ST000000000000000000002AMW42H.my-contract",
        "reclaim_user_script_hex": "75",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "2a0000000000000000061a00000000000000000000000000000000000000000b6d792d636f6e7472616374752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "a943750ad40e7cf2c822c4589ad5da847bcc52083bb78488b945ae23a93b713d",
        "merkle_root_hex": "50e71558eb44d8c6cece84a81fe8abf70d0bcdd2482b2a6d166ed14d1d37d02a",
        "reclaim_script_hex": "020004b275",
        "reclaim_tapleaf_hash_hex": "6e72448b2a47baf78970c0d5a3b57f414f0d7498572da1cc4bbd56de44335822",
        "taproot_output_key_xonly_hex": "b2e483a39cc83c83ed0e0ae613ae2443b5d4bfa554c6d3752301ffeb2669fd9b"
      },
      "name": "contract_recipient_short_name"
    },
    {
      "description": "Contract principal recipient with a longer contract-name (40 bytes). The deposit OP_DROP data exceeds 75 bytes, forcing OP_PUSHDATA1 in the deposit script. Larger lock_time; non-trivial reclaim user script.",
      "expected": {
        "script_pubkey_hex": "51207796ada72f5f892234230446bef7c897b638bead6479b1adbdb6c3542a2326ed"
      },
      "inputs": {
        "lock_time": 65535,
        "max_fee": 1234567,
        "recipient_principal": "ST000000000000000000002AMW42H.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reclaim_user_script_hex": "20000000000000000000000000000000000000000000000000000000000000000075",
        "signers_public_key_xonly_hex": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      },
      "intermediate": {
        "deposit_script_hex": "47000000000012d687061a000000000000000000000000000000000000000028616161616161616161616161616161616161616161616161616161616161616161616161616161617520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
        "deposit_tapleaf_hash_hex": "05b21b1cf20c3bff18c61e667a35bdf320d84a68a7c93f2174518923e3b00ce8",
        "merkle_root_hex": "bce95b41e7caa60ee8beb29d1cd1eee251e4cbe595af2d4afc729c6f02d4b779",
        "reclaim_script_hex": "03ffff00b220000000000000000000000000000000000000000000000000000000000000000075",
        "reclaim_tapleaf_hash_hex": "c92bbca25a0644acce8f214e24a837544e5ef29d8304184858a915de30cc8f2c",
        "taproot_output_key_xonly_hex": "7796ada72f5f892234230446bef7c897b638bead6479b1adbdb6c3542a2326ed"
      },
      "name": "contract_recipient_long_name_pushdata1"
    },
    {
      "description": "Lock_time large enough to need a 3-byte push in the script, while staying block-based. BIP-68 reserves bit 22 (0x400000) as the type flag: setting it switches the lock-time to time-based, which the validator rejects (UnsupportedLockTimeUnits). 0x3f_ff_ff is the largest 3-byte-encoded value with bit 22 clear. User reclaim script combines a push with OP_EQUAL.",
      "expected": {
        "script_pubkey_hex": "5120fd5e38a5c16f1e3df25ec70051b8eb1de1da880956c4e6181b64f1b30234fd22"
      },
      "inputs": {
        "lock_time": 4194303,
        "max_fee": 42,
        "recipient_principal": "SP000000000000000000002Q6VF78",
        "reclaim_user_script_hex": "02abcd87",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "1e000000000000002a05160000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "257bdae7d9e24d8abcaec346878f63b0418c7ae6dda627cff38dea37bb341100",
        "merkle_root_hex": "de9b211ae7e18e1879140418a2d94d8fe62ed568d451f54fcb8d18a7afa96ab9",
        "reclaim_script_hex": "03ffff00b202abcd87",
        "reclaim_tapleaf_hash_hex": "b748b56a4e5a77c7ed2e39068620bc5872d2840e0f0182d215061a9d50e71967",
        "taproot_output_key_xonly_hex": "fd5e38a5c16f1e3df25ec70051b8eb1de1da880956c4e6181b64f1b30234fd22"
      },
      "name": "high_lock_time_with_user_script"
    },
    {
      "description": "max_fee = 0 (8 leading zero bytes in the deposit data prefix). Standard testnet recipient, empty reclaim user-script. Smallest legal lock_time of 1.",
      "expected": {
        "script_pubkey_hex": "512015df47f9f35347183eadea820aecb745c144e3e4cf20c58f40cb12ca02e0ed2f"
      },
      "inputs": {
        "lock_time": 1,
        "max_fee": 0,
        "recipient_principal": "ST000000000000000000002AMW42H",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000000000000051a00000000000000000000000000000000000000007520f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac",
        "deposit_tapleaf_hash_hex": "56ccfebe0f3b7966524bb2c4df69d0549a97ed89c9266c68f6a309bb5d7a2db3",
        "merkle_root_hex": "0b10bc3e783b461c3794c2a93c5e1db111045c9287502031ad28b038c2153ea0",
        "reclaim_script_hex": "51b2",
        "reclaim_tapleaf_hash_hex": "d5d02fadcf3cff8d20c521cb244b23f8029a11f1625978884026f5d4125063f6",
        "taproot_output_key_xonly_hex": "15df47f9f35347183eadea820aecb745c144e3e4cf20c58f40cb12ca02e0ed2f"
      },
      "name": "max_fee_zero_minimal"
    },
    {
      "description": "max_fee = u64::MAX. The 8-byte big-endian prefix is all 0xff. Useful for catching off-by-one or signedness bugs in the prefix encoder.",
      "expected": {
        "script_pubkey_hex": "51202b404aeae41af5ddc55eed518df8ff82d4e7b302428d0a4dddad72b551664f54"
      },
      "inputs": {
        "lock_time": 100,
        "max_fee": 18446744073709551615,
        "recipient_principal": "SP000000000000000000002Q6VF78",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "1effffffffffffffff05160000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "3044c7b1a313589014414cedebd3d54419fe93839b1522e181811fb57f5d43ca",
        "merkle_root_hex": "840a316154aedf83cac24e89558bf4488720eab5372d9b467f5bf355c6e3e341",
        "reclaim_script_hex": "0164b2",
        "reclaim_tapleaf_hash_hex": "2e4fa0084100dc5355b5d1d0bc2e6e0e67513ace2282812e0eaa930158051f32",
        "taproot_output_key_xonly_hex": "2b404aeae41af5ddc55eed518df8ff82d4e7b302428d0a4dddad72b551664f54"
      },
      "name": "max_fee_u64_max"
    },
    {
      "description": "Contract-name length is 44 bytes. Total deposit data length is 8 + 1 + 1 + 20 + 1 + 44 = 75 bytes, the largest size for which the bitcoin script builder still emits OP_PUSHBYTES_75 rather than OP_PUSHDATA1. Pair this with the next case to cover both sides of that boundary.",
      "expected": {
        "script_pubkey_hex": "5120fd756efcda9d7ff3c9e69f87eb52a9cc43beb70900ec313426fae9f2901ac273"
      },
      "inputs": {
        "lock_time": 50,
        "max_fee": 7,
        "recipient_principal": "ST000000000000000000002AMW42H.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "4b0000000000000007061a00000000000000000000000000000000000000002c6161616161616161616161616161616161616161616161616161616161616161616161616161616161616161752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "4cfd8a35fb20658d8d9d3cae47fd453695eca7a530668b55cfa443dfbdc45d53",
        "merkle_root_hex": "76538274b025b82022140c923a632d58aee3caa51a39e95828029089b5fd064b",
        "reclaim_script_hex": "0132b2",
        "reclaim_tapleaf_hash_hex": "d08e126224478587e0426d7d534affde56d0b0f940612babf36b919a4f140d36",
        "taproot_output_key_xonly_hex": "fd756efcda9d7ff3c9e69f87eb52a9cc43beb70900ec313426fae9f2901ac273"
      },
      "name": "contract_name_44_pushbytes_boundary"
    },
    {
      "description": "Contract-name length is 45 bytes. Total deposit data length is 76 bytes, the smallest size that triggers OP_PUSHDATA1 in the deposit-script encoding. Otherwise identical to the 44-byte case.",
      "expected": {
        "script_pubkey_hex": "51202762a90adc00f30c7d718f60be6970a5336906f7ebf4473719164fa025333960"
      },
      "inputs": {
        "lock_time": 50,
        "max_fee": 7,
        "recipient_principal": "ST000000000000000000002AMW42H.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "4c4c0000000000000007061a00000000000000000000000000000000000000002d616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "8f62366217618e7086a3f8da75e727d8ec22967efcc296f0f6f334d6f4cceb7e",
        "merkle_root_hex": "6041c4dd9d6ca8bea17133c7aa7974d5c65eaac54ee56da10e8a0c9e90d8d130",
        "reclaim_script_hex": "0132b2",
        "reclaim_tapleaf_hash_hex": "d08e126224478587e0426d7d534affde56d0b0f940612babf36b919a4f140d36",
        "taproot_output_key_xonly_hex": "2762a90adc00f30c7d718f60be6970a5336906f7ebf4473719164fa025333960"
      },
      "name": "contract_name_45_pushdata1_boundary"
    },
    {
      "description": "lock_time = 0. In bitcoin script this encodes as OP_0 (a single 0x00 byte, which is a push of the empty byte-string) rather than a 1-byte push of 0x00. Exercises the empty-push branch of the script-num encoder.",
      "expected": {
        "script_pubkey_hex": "51201a9cfb07c82a6bf5147adc968816e1759a795a07bfb9e47364e59ec3496aaed4"
      },
      "inputs": {
        "lock_time": 0,
        "max_fee": 1,
        "recipient_principal": "SP000000000000000000002Q6VF78",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000000000001051600000000000000000000000000000000000000007520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
        "deposit_tapleaf_hash_hex": "2fbc2300e180827c419953a6c3bae55f3dfcca06cd12bd5caf5f2669370dae13",
        "merkle_root_hex": "02e2defd794263bb543dd39e2a4c571f29da6fbf87ad3d9a77b2c666ec37e039",
        "reclaim_script_hex": "00b2",
        "reclaim_tapleaf_hash_hex": "b45bd313fdb88c774cedf0e8435fc15678f0edd8a43c2791008f7db0d2f89b6e",
        "taproot_output_key_xonly_hex": "1a9cfb07c82a6bf5147adc968816e1759a795a07bfb9e47364e59ec3496aaed4"
      },
      "name": "lock_time_zero"
    },
    {
      "description": "lock_time = 0x100 (256). Smallest value that needs a 2-byte little-endian push in the script-num encoding (1-byte values cover up to 0xff; 0x100 is the first to require a second byte).",
      "expected": {
        "script_pubkey_hex": "51202e0980724fb67bfb978bb44b209f8e8bbff654fd06cb8cc0ff9c987e04dcc6e6"
      },
      "inputs": {
        "lock_time": 256,
        "max_fee": 9999,
        "recipient_principal": "ST000000000000000000002AMW42H",
        "reclaim_user_script_hex": "",
        "signers_public_key_xonly_hex": "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
      },
      "intermediate": {
        "deposit_script_hex": "1e000000000000270f051a00000000000000000000000000000000000000007520f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9ac",
        "deposit_tapleaf_hash_hex": "ab051c6ded9411d42008b56926cadee6048e2e220908e8b7eb0c70c55da02e38",
        "merkle_root_hex": "433073c68e3c5c96a5c8de249c756c7566597a219f3bfdd7cf29824c501bb03d",
        "reclaim_script_hex": "020001b2",
        "reclaim_tapleaf_hash_hex": "4107d1688b77534bd3dfe3c8a8c0a0e9fb1159befeb61cca57cefdb336fd53bc",
        "taproot_output_key_xonly_hex": "2e0980724fb67bfb978bb44b209f8e8bbff654fd06cb8cc0ff9c987e04dcc6e6"
      },
      "name": "lock_time_two_byte_push"
    },
    {
      "description": "Standard principal on mainnet (version byte 22) with hash160 = 0x11..11. Together with the burn-address cases this means the SIP-005 version byte and the 20 hash bytes both vary across the fixture set.",
      "expected": {
        "script_pubkey_hex": "512044e23abf259d1109b0ce4c63664cf15d2779d7412d9e53327636da93c7bba3b6"
      },
      "inputs": {
        "lock_time": 200,
        "max_fee": 555,
        "recipient_principal": "SP8H248H248H248H248H248H248H248H24ARTQ82",
        "reclaim_user_script_hex": "75",
        "signers_public_key_xonly_hex": "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
      },
      "intermediate": {
        "deposit_script_hex": "1e000000000000022b051611111111111111111111111111111111111111117520c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ac",
        "deposit_tapleaf_hash_hex": "dd24bea2b39e7e4fc8d7e7bc70502a292409072bfe837afa6dd0475941097e96",
        "merkle_root_hex": "a829fc5de1048cd04c007def7876bf72588256310cfd2cac3f3de7ee1c6df14b",
        "reclaim_script_hex": "02c800b275",
        "reclaim_tapleaf_hash_hex": "cc0aa182176facbf8c1768a42c6b70adb180cca5adec16e381e88f040fb20bf9",
        "taproot_output_key_xonly_hex": "44e23abf259d1109b0ce4c63664cf15d2779d7412d9e53327636da93c7bba3b6"
      },
      "name": "nonzero_hash_mainnet_principal"
    },
    {
      "description": "User reclaim script is exactly 2048 bytes (sbtc::MAX_RECLAIM_SCRIPT_LENGTH), the upper bound the validator accepts. Filled with OP_DROP (0x75), which is neither an OP_SUCCESSx nor a push opcode — passes validation and produces a deterministic byte pattern. Exercises tapleaf hashing over a large script.",
      "expected": {
        "script_pubkey_hex": "51200900b1b63da96ca9a8bdd794a54d53e0ee4f5c5372b676e824b7b02845b6e533"
      },
      "inputs": {
        "lock_time": 10,
        "max_fee": 100,
        "recipient_principal": "ST000000000000000000002AMW42H",
        "reclaim_user_script_hex": "7575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575",
        "signers_public_key_xonly_hex": "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
      },
      "intermediate": {
        "deposit_script_hex": "1e0000000000000064051a0000000000000000000000000000000000000000752079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798ac",
        "deposit_tapleaf_hash_hex": "17a2d34646cd2c607b8a005cade01384bfba07a516c3cf7e47bec36ec5855bf1",
        "merkle_root_hex": "0afbfd14892580cd2bac43800bb36317723611e708162a364c7561f46f0851d2",
        "reclaim_script_hex": "5ab27575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575",
        "reclaim_tapleaf_hash_hex": "1ec1ec76d3a3ced9a7822d25c46ea6a4756edf63a901b31278f039a71dc27e8f",
        "taproot_output_key_xonly_hex": "0900b1b63da96ca9a8bdd794a54d53e0ee4f5c5372b676e824b7b02845b6e533"
      },
      "name": "max_reclaim_user_script_length"
    }
  ],
  "nums_x_coordinate_hex": "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0",
  "source": "https://github.com/stacks-sbtc/sbtc",
  "source_commit": "b0c9da395403438b2811b7c0945de88b6a5911f4",
  "source_function": "sbtc::deposits::to_script_pubkey (in sbtc/src/deposits.rs)"
}"#;

    #[derive(Deserialize)]
    struct FixturesFile {
        fixtures: Vec<Fixture>,
        nums_x_coordinate_hex: String,
    }

    #[derive(Deserialize)]
    struct Fixture {
        name: String,
        inputs: Inputs,
        intermediate: Intermediate,
    }

    #[derive(Deserialize)]
    struct Inputs {
        /// `u32` because some fixtures were generated from oversized values
        /// that the generator truncated to `u16`; the same truncation is
        /// applied here.
        lock_time: u32,
        max_fee: u64,
        recipient_principal: String,
        reclaim_user_script_hex: String,
        signers_public_key_xonly_hex: String,
    }

    #[derive(Deserialize)]
    struct Intermediate {
        deposit_script_hex: String,
        deposit_tapleaf_hash_hex: String,
        merkle_root_hex: String,
        reclaim_script_hex: String,
        reclaim_tapleaf_hash_hex: String,
        taproot_output_key_xonly_hex: String,
    }

    /// The v1 deposit tree built by the pinned `sbtc` matches the frozen
    /// vectors, across recipient shapes, lock-time encodings and reclaim
    /// scripts that PoX-5 itself does not use.
    #[test]
    fn matches_sbtc_reference_fixtures() {
        let parsed: FixturesFile =
            serde_json::from_str(FIXTURES_JSON).expect("embedded fixtures parse");
        assert_eq!(
            to_hex(&sbtc::NUMS_X_COORDINATE),
            parsed.nums_x_coordinate_hex
        );
        assert!(!parsed.fixtures.is_empty());

        for fixture in &parsed.fixtures {
            let name = &fixture.name;
            let recipient = PrincipalData::parse(&fixture.inputs.recipient_principal)
                .unwrap_or_else(|e| panic!("{name}: bad recipient principal: {e:?}"));
            let deposit = DepositScriptInputs {
                signers_public_key: XOnlyPublicKey::from_slice(&hex_array::<32>(
                    &fixture.inputs.signers_public_key_xonly_hex,
                ))
                .expect("fixture key on curve"),
                recipient: to_sbtc_principal(&recipient).expect("principal converts"),
                max_fee: fixture.inputs.max_fee,
            }
            .deposit_script();
            let reclaim = ReclaimScriptInputs::try_new(
                // The generator truncated lock times to u16.
                u32::from(fixture.inputs.lock_time as u16),
                ScriptBuf::from_bytes(
                    hex_bytes(&fixture.inputs.reclaim_user_script_hex).expect("valid hex"),
                ),
            )
            .unwrap_or_else(|e| panic!("{name}: reclaim inputs rejected: {e:?}"))
            .reclaim_script();
            let expected = &fixture.intermediate;

            assert_eq!(
                to_hex(deposit.as_bytes()),
                expected.deposit_script_hex,
                "{name}"
            );
            assert_eq!(
                to_hex(reclaim.as_bytes()),
                expected.reclaim_script_hex,
                "{name}"
            );
            assert_eq!(
                leaf_hash_hex(&deposit),
                expected.deposit_tapleaf_hash_hex,
                "{name}"
            );
            assert_eq!(
                leaf_hash_hex(&reclaim),
                expected.reclaim_tapleaf_hash_hex,
                "{name}"
            );
            let taproot = to_taproot(deposit, reclaim);
            assert_eq!(
                taproot.merkle_root().expect("two-leaf tree").to_string(),
                expected.merkle_root_hex,
                "{name}"
            );
            assert_eq!(
                to_hex(&taproot.output_key().serialize()),
                expected.taproot_output_key_xonly_hex,
                "{name}"
            );
        }
    }

    /// Frozen PoX-5 v1 recipients: `(name, aggregate pubkey, recipient,
    /// max fee, scriptPubKey)`. Recorded from the node's previous independent
    /// implementation and confirmed equal to sBTC at the original pin.
    const POX5_V1_VECTORS: [(&str, &str, &str, u64, &str); 5] = [
        (
            "pox5_mainnet_devenv_key",
            "035249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46",
            "SP000000000000000000002Q6VF78.pox-5",
            80_000,
            "5120067c970b35c36ac31433c8976d793038cb0d16b90659f3d6d02f6236bf2186e1",
        ),
        (
            "pox5_testnet_devenv_key",
            "035249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46",
            "ST000000000000000000002AMW42H.pox-5",
            80_000,
            "5120bccb1a0cd85da86c4e4b73fd278f62d722557027247716ce4e45f9302174c991",
        ),
        (
            "pox5_mainnet_even_prefix_same_x",
            "025249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46",
            "SP000000000000000000002Q6VF78.pox-5",
            80_000,
            "5120067c970b35c36ac31433c8976d793038cb0d16b90659f3d6d02f6236bf2186e1",
        ),
        (
            "pox5_testnet_testnet_signer_key",
            "03fc6197a1396680f7acc4241ac3935ba4af560deac0224abec45c47c5e73ea638",
            "ST000000000000000000002AMW42H.pox-5",
            80_000,
            "51204b4a3a047893da6fd2b5943289ec93e27ba6ddd1f0b7a5bc749f0e2413227d4c",
        ),
        (
            "pox5_mainnet_random_key_zero_fee",
            "027212421e4a9c34e251a7cd523146c4434451e42c230d576b07fe8874f97a694d",
            "SP000000000000000000002Q6VF78.pox-5",
            0,
            "5120133e70255d5ebea718604f4ad12847a850ee8226b7dc1cff9e3ac8a254727507",
        ),
    ];

    /// The PoX-5 v1 entry point reproduces the frozen recipients.
    #[test]
    fn pox5_v1_matches_frozen_vectors() {
        for (name, pubkey, recipient, max_fee, script_pubkey) in POX5_V1_VECTORS {
            let recipient = PrincipalData::parse(recipient).expect("valid principal");
            let output_key =
                sbtc_pox5_deposit_taproot_output_key(&hex_array(pubkey), &recipient, max_fee)
                    .unwrap_or_else(|e| panic!("{name}: derivation failed: {e:?}"));
            assert_eq!(
                format!("5120{}", to_hex(&output_key)),
                script_pubkey,
                "{name}"
            );
        }
    }

    /// Frozen v2 vectors, generated from sBTC at revision
    /// `6ec5dbeecb606fc2e921661ec9b43a6ad3545e6e` (the file records the
    /// revision and the upstream functions used).
    const V2_FIXTURES_JSON: &str = include_str!("fixtures/sbtc-v2.json");

    #[derive(Deserialize)]
    struct V2FixturesFile {
        fixtures: Vec<V2Fixture>,
        v2_nums_x_coordinate_hex: String,
    }

    #[derive(Deserialize)]
    struct V2Fixture {
        name: String,
        inputs: V2Inputs,
        intermediate: V2Intermediate,
        expected: V2Expected,
    }

    #[derive(Deserialize)]
    struct V2Inputs {
        signer_keys_compressed_hex: Vec<String>,
        signatures_required: u16,
        recipient_principal: String,
        max_fee: u64,
        lock_time: u32,
        reclaim_user_script_hex: String,
    }

    #[derive(Deserialize)]
    struct V2Intermediate {
        derived_xonly_keys_sorted_hex: Vec<String>,
        signing_script_hex: String,
        key_set_script_pubkey_hex: String,
        deposit_script_hex: String,
        reclaim_script_hex: String,
        deposit_tapleaf_hash_hex: String,
        reclaim_tapleaf_hash_hex: String,
        merkle_root_hex: String,
        taproot_output_key_xonly_hex: String,
    }

    #[derive(Deserialize)]
    struct V2Expected {
        script_pubkey_hex: String,
    }

    /// The v2 key set and deposit tree built by the pinned `sbtc` match the
    /// frozen vectors, and every vector in the PoX-5 shape is reproduced by
    /// the PoX-5 v2 entry point.
    #[test]
    fn matches_sbtc_v2_reference_fixtures() {
        let parsed: V2FixturesFile =
            serde_json::from_str(V2_FIXTURES_JSON).expect("embedded fixtures parse");
        assert_eq!(
            to_hex(&sbtc::V2_NUMS_X_COORDINATE),
            parsed.v2_nums_x_coordinate_hex
        );

        let mut pox5_shaped = 0;
        for fixture in &parsed.fixtures {
            let name = &fixture.name;
            let expected = &fixture.intermediate;
            let signer_keys: Vec<[u8; 33]> = fixture
                .inputs
                .signer_keys_compressed_hex
                .iter()
                .map(|key| hex_array(key))
                .collect();
            let key_set = SbtcSignerKeySet::from_registry(
                &signer_keys,
                u128::from(fixture.inputs.signatures_required),
            )
            .unwrap_or_else(|e| panic!("{name}: key set rejected: {e:?}"));

            let derived_keys: Vec<String> = key_set
                .0
                .public_keys()
                .iter()
                .map(|k| k.to_string())
                .collect();
            assert_eq!(
                derived_keys, expected.derived_xonly_keys_sorted_hex,
                "{name}"
            );
            assert_eq!(
                to_hex(key_set.0.signing_script().as_bytes()),
                expected.signing_script_hex,
                "{name}"
            );
            assert_eq!(
                to_hex(key_set.0.script_pubkey().as_bytes()),
                expected.key_set_script_pubkey_hex,
                "{name}"
            );

            let recipient = PrincipalData::parse(&fixture.inputs.recipient_principal)
                .unwrap_or_else(|e| panic!("{name}: bad recipient principal: {e:?}"));
            let user_script = hex_bytes(&fixture.inputs.reclaim_user_script_hex).expect("hex");
            let deposit = DepositScriptInputsV2 {
                signer_key_set: key_set.0.clone(),
                recipient: to_sbtc_principal(&recipient).expect("principal converts"),
                max_fee: fixture.inputs.max_fee,
            }
            .deposit_script();
            let reclaim = ReclaimScriptInputs::try_new(
                fixture.inputs.lock_time,
                ScriptBuf::from_bytes(user_script.clone()),
            )
            .unwrap_or_else(|e| panic!("{name}: reclaim inputs rejected: {e:?}"))
            .reclaim_script();

            assert_eq!(
                to_hex(deposit.as_bytes()),
                expected.deposit_script_hex,
                "{name}"
            );
            assert_eq!(
                to_hex(reclaim.as_bytes()),
                expected.reclaim_script_hex,
                "{name}"
            );
            assert_eq!(
                leaf_hash_hex(&deposit),
                expected.deposit_tapleaf_hash_hex,
                "{name}"
            );
            assert_eq!(
                leaf_hash_hex(&reclaim),
                expected.reclaim_tapleaf_hash_hex,
                "{name}"
            );
            let taproot = to_v2_taproot(deposit, reclaim);
            assert_eq!(
                taproot.merkle_root().expect("two-leaf tree").to_string(),
                expected.merkle_root_hex,
                "{name}"
            );
            let output_key = taproot.output_key().serialize();
            assert_eq!(
                to_hex(&output_key),
                expected.taproot_output_key_xonly_hex,
                "{name}"
            );
            assert_eq!(
                format!("5120{}", to_hex(&output_key)),
                fixture.expected.script_pubkey_hex,
                "{name}"
            );

            if fixture.inputs.lock_time == u32::from(u16::MAX) && user_script == [OP_RETURN.to_u8()]
            {
                pox5_shaped += 1;
                let pox5_output_key = sbtc_pox5_v2_deposit_taproot_output_key(
                    &key_set,
                    &recipient,
                    fixture.inputs.max_fee,
                )
                .unwrap_or_else(|e| panic!("{name}: PoX-5 derivation failed: {e:?}"));
                assert_eq!(pox5_output_key, output_key, "{name}: PoX-5 entry point");
            }
        }
        assert!(
            pox5_shaped > 0,
            "no fixture exercises the PoX-5 entry point"
        );
    }

    // ---- Key-set validation ----

    /// The sBTC devenv signer set (compressed registry keys).
    const SBTC_DEVENV_SIGNER_KEYS: [&str; 3] = [
        "035249137286c077ccee65ecc43e724b9b9e5a588e3d7f51e3b62f9624c2a49e46",
        "031a4d9f4903da97498945a4e01a5023a1d53bc96ad670bfe03adf8a06c52e6380",
        "02007311430123d4cad97f4f7e86e023b28143130a18099ecf094d36fef0f6135c",
    ];

    fn devenv_keys() -> Vec<[u8; 33]> {
        SBTC_DEVENV_SIGNER_KEYS
            .iter()
            .map(|key| hex_array(key))
            .collect()
    }

    /// Compressed keys with secret scalars `1..=count`.
    fn compressed_keys_from_small_scalars(count: u8) -> Vec<[u8; 33]> {
        SECP_CTX.with(|secp| {
            (1..=count)
                .map(|scalar| {
                    let mut secret = [0u8; 32];
                    secret[31] = scalar;
                    let sk = secp256k1::SecretKey::from_slice(&secret).expect("small scalar");
                    secp256k1::PublicKey::from_secret_key(secp, &sk).serialize()
                })
                .collect()
        })
    }

    /// Input order and duplicates do not affect the key set.
    #[test]
    fn key_set_is_order_and_duplicate_independent() {
        let canonical = SbtcSignerKeySet::from_registry(&devenv_keys(), 2).unwrap();
        let mut shuffled = devenv_keys();
        shuffled.reverse();
        shuffled.push(shuffled[0]);
        assert_eq!(
            canonical,
            SbtcSignerKeySet::from_registry(&shuffled, 2).unwrap()
        );
        assert_eq!(canonical.0.public_keys().len(), 3);
    }

    /// `1 <= distinct keys <= 16` and `1 <= threshold <= distinct keys`, with
    /// duplicates collapsed before the bounds apply.
    #[test]
    fn key_set_bounds() {
        let seventeen = compressed_keys_from_small_scalars(17);
        let ok = |keys: &[[u8; 33]], threshold: u128| {
            SbtcSignerKeySet::from_registry(keys, threshold).is_ok()
        };

        assert!(!ok(&[], 1), "empty set");
        assert!(!ok(&seventeen[..1], 0), "zero threshold");
        assert!(!ok(&seventeen[..1], 2), "threshold > n");
        assert!(ok(&seventeen[..1], 1), "1-of-1");
        assert!(ok(&seventeen[..16], 16), "16-of-16");
        assert!(!ok(&seventeen[..16], 17), "17-of-16");
        assert!(!ok(&seventeen, 1), "17 keys");
        assert!(
            !ok(&devenv_keys(), u128::from(u16::MAX) + 1),
            "threshold overflows u16"
        );

        let mut sixteen_plus_dup = seventeen[..16].to_vec();
        sixteen_plus_dup.push(seventeen[0]);
        let key_set = SbtcSignerKeySet::from_registry(&sixteen_plus_dup, 16).unwrap();
        assert_eq!(key_set.0.public_keys().len(), sbtc::MAX_SIGNERS);
    }

    #[test]
    fn from_registry_rejects_malformed_keys() {
        let mut off_curve = [0xff; 33];
        off_curve[0] = 0x02;
        assert!(SbtcSignerKeySet::from_registry(&[off_curve], 1).is_err());
        // A v2-rotated registry stores `0xFF || block-hash` in the aggregate
        // pubkey field; that value is never a valid signer key either.
        assert!(SbtcSignerKeySet::from_registry(&[[0xff; 33]], 1).is_err());
        let mut keys = devenv_keys();
        keys[1] = off_curve;
        assert!(
            SbtcSignerKeySet::from_registry(&keys, 1).is_err(),
            "one bad key rejects the set"
        );
    }

    // ---- Property tests ----

    thread_local! {
        /// Shared `Secp256k1` context; building one precomputes tables.
        static SECP_CTX: Secp256k1<secp256k1::All> = Secp256k1::new();
    }

    /// 33-byte compressed secp256k1 pubkey, as the registry returns.
    fn arb_valid_compressed_pubkey_33() -> impl Strategy<Value = [u8; 33]> {
        any::<[u8; 32]>().prop_filter_map("scalar not in [1, n)", |sk_bytes| {
            let sk = secp256k1::SecretKey::from_slice(&sk_bytes).ok()?;
            Some(SECP_CTX.with(|secp| secp256k1::PublicKey::from_secret_key(secp, &sk).serialize()))
        })
    }

    /// Standard principal (version < 32, arbitrary 20-byte hash).
    fn arb_standard_principal() -> impl Strategy<Value = StandardPrincipalData> {
        (0u8..32u8, any::<[u8; 20]>()).prop_map(|(version, bytes)| {
            StandardPrincipalData::new(version, bytes).expect("version < 32 by construction")
        })
    }

    /// Valid Clarity contract name of length `1..=CONTRACT_MAX_NAME_LENGTH`.
    fn arb_contract_name() -> impl Strategy<Value = ContractName> {
        let lead = prop_oneof![b'a'..=b'z', b'A'..=b'Z'];
        let body = prop::collection::vec(
            prop_oneof![
                b'a'..=b'z',
                b'A'..=b'Z',
                b'0'..=b'9',
                Just(b'-'),
                Just(b'_')
            ],
            0..CONTRACT_MAX_NAME_LENGTH,
        );
        (lead, body).prop_map(|(lead, body)| {
            let name: String = std::iter::once(lead).chain(body).map(char::from).collect();
            ContractName::try_from(name).expect("structurally valid contract name")
        })
    }

    /// Standard- or contract-principal, uniformly weighted.
    fn arb_principal_data() -> impl Strategy<Value = PrincipalData> {
        prop_oneof![
            arb_standard_principal().prop_map(PrincipalData::Standard),
            (arb_standard_principal(), arb_contract_name()).prop_map(|(issuer, name)| {
                PrincipalData::Contract(QualifiedContractIdentifier::new(issuer, name))
            }),
        ]
    }

    /// A registry signer set: 1..=16 keys and a threshold in `1..=distinct`.
    fn arb_v2_registry_signer_set() -> impl Strategy<Value = (Vec<[u8; 33]>, u16)> {
        prop::collection::vec(arb_valid_compressed_pubkey_33(), 1..=sbtc::MAX_SIGNERS)
            .prop_flat_map(|keys| {
                let distinct = keys.iter().collect::<BTreeSet<_>>().len() as u16;
                (Just(keys), 1..=distinct)
            })
    }

    fn v1_key(pubkey: &[u8; 33], recipient: &PrincipalData, max_fee: u64) -> [u8; 32] {
        sbtc_pox5_deposit_taproot_output_key(pubkey, recipient, max_fee).expect("derives")
    }

    fn v2_key(
        keys: &[[u8; 33]],
        threshold: u16,
        recipient: &PrincipalData,
        max_fee: u64,
    ) -> [u8; 32] {
        let key_set = SbtcSignerKeySet::from_registry(keys, u128::from(threshold))
            .expect("valid registry signer set");
        sbtc_pox5_v2_deposit_taproot_output_key(&key_set, recipient, max_fee).expect("derives")
    }

    proptest! {
        /// Every principal crosses to `sbtc`'s `clarity` with identical
        /// consensus bytes, which is what the deposit data commits to.
        #[tag(t_prop)]
        #[test]
        fn prop_principal_conversion_preserves_bytes(recipient in arb_principal_data()) {
            let converted = to_sbtc_principal(&recipient).expect("converts");
            prop_assert_eq!(
                sbtc_clarity::codec::StacksMessageCodec::serialize_to_vec(&converted),
                recipient.serialize_to_vec()
            );
        }

        /// The v1 recipient is a pure function of its inputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v1_key_deterministic(
            pubkey in arb_valid_compressed_pubkey_33(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assert_eq!(
                v1_key(&pubkey, &recipient, max_fee),
                v1_key(&pubkey, &recipient, max_fee)
            );
        }

        /// Different recipients lock different v1 outputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v1_key_distinct_by_recipient(
            pubkey in arb_valid_compressed_pubkey_33(),
            recipient_a in arb_principal_data(),
            recipient_b in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assume!(recipient_a != recipient_b);
            prop_assert_ne!(
                v1_key(&pubkey, &recipient_a, max_fee),
                v1_key(&pubkey, &recipient_b, max_fee)
            );
        }

        /// Different max fees lock different v1 outputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v1_key_distinct_by_max_fee(
            pubkey in arb_valid_compressed_pubkey_33(),
            recipient in arb_principal_data(),
            max_fee_a in any::<u64>(),
            max_fee_b in any::<u64>(),
        ) {
            prop_assume!(max_fee_a != max_fee_b);
            prop_assert_ne!(
                v1_key(&pubkey, &recipient, max_fee_a),
                v1_key(&pubkey, &recipient, max_fee_b)
            );
        }

        /// Different aggregate keys (by x coordinate) lock different v1
        /// outputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v1_key_distinct_by_pubkey(
            pubkey_a in arb_valid_compressed_pubkey_33(),
            pubkey_b in arb_valid_compressed_pubkey_33(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assume!(pubkey_a[1..] != pubkey_b[1..]);
            prop_assert_ne!(
                v1_key(&pubkey_a, &recipient, max_fee),
                v1_key(&pubkey_b, &recipient, max_fee)
            );
        }

        /// An aggregate key whose x coordinate is off the curve is rejected
        /// (and the caller falls back to the burn address).
        #[tag(t_prop)]
        #[test]
        fn prop_v1_off_curve_pubkey_rejected(
            pubkey in any::<[u8; 33]>().prop_filter(
                "off-curve x only",
                |b| XOnlyPublicKey::from_slice(&b[1..]).is_err(),
            ),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assert!(sbtc_pox5_deposit_taproot_output_key(&pubkey, &recipient, max_fee).is_err());
        }

        /// Registry key order does not affect the v2 recipient.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_independent_of_registry_order(
            (keys, shuffled, threshold) in arb_v2_registry_signer_set().prop_flat_map(
                |(keys, threshold)| (Just(keys.clone()), Just(keys).prop_shuffle(), Just(threshold))
            ),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assert_eq!(
                v2_key(&keys, threshold, &recipient, max_fee),
                v2_key(&shuffled, threshold, &recipient, max_fee),
            );
        }

        /// The v2 recipient is a pure function of its inputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_deterministic(
            (keys, threshold) in arb_v2_registry_signer_set(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assert_eq!(
                v2_key(&keys, threshold, &recipient, max_fee),
                v2_key(&keys, threshold, &recipient, max_fee),
            );
        }

        /// Different thresholds over the same keys lock different outputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_distinct_by_threshold(
            (keys, threshold_a) in arb_v2_registry_signer_set(),
            threshold_b in 1..=sbtc::MAX_SIGNERS as u16,
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            let distinct = keys.iter().collect::<BTreeSet<_>>().len() as u16;
            prop_assume!(threshold_b <= distinct && threshold_a != threshold_b);
            prop_assert_ne!(
                v2_key(&keys, threshold_a, &recipient, max_fee),
                v2_key(&keys, threshold_b, &recipient, max_fee),
            );
        }

        /// Different recipients lock different v2 outputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_distinct_by_recipient(
            (keys, threshold) in arb_v2_registry_signer_set(),
            recipient_a in arb_principal_data(),
            recipient_b in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assume!(recipient_a != recipient_b);
            prop_assert_ne!(
                v2_key(&keys, threshold, &recipient_a, max_fee),
                v2_key(&keys, threshold, &recipient_b, max_fee),
            );
        }

        /// Different max fees lock different v2 outputs.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_distinct_by_max_fee(
            (keys, threshold) in arb_v2_registry_signer_set(),
            recipient in arb_principal_data(),
            max_fee_a in any::<u64>(),
            max_fee_b in any::<u64>(),
        ) {
            prop_assume!(max_fee_a != max_fee_b);
            prop_assert_ne!(
                v2_key(&keys, threshold, &recipient, max_fee_a),
                v2_key(&keys, threshold, &recipient, max_fee_b),
            );
        }

        /// A key set with one extra signer locks a different output.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_distinct_by_signer_set(
            (keys, threshold) in arb_v2_registry_signer_set(),
            extra in arb_valid_compressed_pubkey_33(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assume!(keys.len() < sbtc::MAX_SIGNERS && !keys.contains(&extra));
            let mut extended = keys.clone();
            extended.push(extra);
            prop_assert_ne!(
                v2_key(&keys, threshold, &recipient, max_fee),
                v2_key(&extended, threshold, &recipient, max_fee),
            );
        }

        /// A single-signer v2 deposit never collides with the v1 deposit for
        /// the same key, recipient and fee, so the epoch switch always moves
        /// the recipient.
        #[tag(t_prop)]
        #[test]
        fn prop_v2_key_differs_from_v1(
            key in arb_valid_compressed_pubkey_33(),
            recipient in arb_principal_data(),
            max_fee in any::<u64>(),
        ) {
            prop_assert_ne!(
                v1_key(&key, &recipient, max_fee),
                v2_key(&[key], 1, &recipient, max_fee)
            );
        }
    }
}
