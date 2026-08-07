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

//! Host implementation of the Clarity `evm-call?` native function.
//!
//! The Clarity VM declares the [`EvmCallHandler`] hook but has no EVM of its
//! own (it cannot depend on `revm`); this module supplies the implementation
//! and the MARF-backed stores install it, mirroring how `pox-locking`
//! injects PoX behavior through `SpecialCaseHandler`.
//!
//! Value semantics: the EVM caller is the *calling Clarity contract* (its
//! derived EVM address), never `tx-sender`. Attached `value` is moved from
//! the contract's real principal to that derived principal before execution,
//! so the EVM sees a funded `msg.sender`; the whole call runs in a savepoint
//! that is rolled back if the EVM fails, undoing the pre-funding.
//!
//! Funds a contract *receives* in EVM-land accumulate under its derived
//! principal. Sweeping them back to the contract's real principal is not
//! implemented yet, so this direction is effectively send-only for value.

use clarity::vm::database::{ClarityDatabase, EvmCallOutcome, EvmCallRequest};
use clarity::vm::errors::{VmExecutionError, VmInternalError};

use super::{
    evm_address_to_principal, principal_to_evm_address, run_evm_from_clarity, EVM_TX_GAS_CAP,
};

/// The `evm-call?` implementation installed by the MARF-backed stores.
pub fn handle_evm_call(
    db: &mut ClarityDatabase,
    request: &EvmCallRequest,
) -> Result<EvmCallOutcome, VmExecutionError> {
    if !request.epoch.supports_evm() {
        return Err(VmInternalError::Expect(format!(
            "evm-call? is not supported in epoch {}",
            request.epoch
        ))
        .into());
    }
    if request.gas_limit > EVM_TX_GAS_CAP {
        return Err(VmInternalError::Expect(format!(
            "evm-call? gas limit {} exceeds cap {EVM_TX_GAS_CAP}",
            request.gas_limit
        ))
        .into());
    }

    // Everything below happens in a savepoint: on any EVM failure it is
    // rolled back, which also undoes the value pre-funding.
    db.begin();
    let result = run_call(db, request);
    match &result {
        Ok(outcome) if outcome.committed => {
            db.commit()?;
        }
        _ => {
            db.roll_back()?;
        }
    }
    result
}

/// Inner call: pre-fund the caller's derived EVM principal, run the EVM, and
/// map the outcome.
fn run_call(
    db: &mut ClarityDatabase,
    request: &EvmCallRequest,
) -> Result<EvmCallOutcome, VmExecutionError> {
    // Move the attached value from the calling contract's real principal to
    // the derived principal that holds its EVM-side balance, so the
    // interpreter sees a funded msg.sender. A shortfall here is an EVM-level
    // failure (reported as a revert), not a Clarity error.
    if request.value > 0 {
        let caller_evm = principal_to_evm_address(request.caller);
        let derived = evm_address_to_principal(&caller_evm, request.mainnet);
        let mut snapshot = db.get_stx_balance_snapshot(request.caller)?;
        if !snapshot.can_transfer(request.value)? {
            debug!("evm-call? caller cannot cover attached value";
                   "caller" => %request.caller,
                   "value" => request.value);
            return Ok(EvmCallOutcome {
                committed: false,
                data: vec![],
                gas_used: 0,
                events: vec![],
            });
        }
        snapshot.transfer_to(&derived, request.value)?;
    }

    let outcome = run_evm_from_clarity(
        db,
        request.mainnet,
        request.chain_id,
        request.epoch,
        request.caller,
        request.address,
        request.gas_limit,
        request.value,
        request.calldata.to_vec(),
    )
    .map_err(|e| VmInternalError::Expect(format!("EVM execution failed: {e}")))?;

    let data = match &outcome.result {
        clarity::vm::Value::Response(response) => match response.data.as_ref() {
            clarity::vm::Value::Sequence(clarity::vm::types::SequenceData::Buffer(buff)) => {
                buff.data.clone()
            }
            _ => vec![],
        },
        _ => vec![],
    };

    Ok(EvmCallOutcome {
        committed: outcome.succeeded,
        data,
        gas_used: outcome.gas_used,
        events: outcome.events,
    })
}
