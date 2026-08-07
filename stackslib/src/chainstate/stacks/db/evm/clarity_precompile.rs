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

//! The `clarity-read` precompile: lets EVM contracts invoke Clarity
//! functions in a read-only fashion.
//!
//! Solidity calls `CLARITY_READ_PRECOMPILE` with
//! `abi.encode(string contractId, string functionName, bytes args)` (see
//! `abi.rs` for the argument mapping). The precompile executes the target
//! Clarity function against current chain state under a write-forbidding
//! cost budget (write limits are zero, so any attempted write exhausts the
//! budget -- the same trick the read-only RPC endpoint uses), and always
//! rolls back its database savepoint afterwards.
//!
//! Result mapping:
//! - plain value / `(ok v)`  -> precompile succeeds, returns ABI-encoded `v`
//! - `(err e)`               -> precompile reverts with ABI-encoded `e`
//! - decode / lookup failure -> precompile reverts with `Error(string)`
//! - cost budget exhausted   -> precompile halts out-of-gas
//!
//! Consumed Clarity execution cost is converted back into EVM gas via
//! `EVM_GAS_TO_RUNTIME`, so the caller's gas limit bounds Clarity work.

use std::cell::RefCell;
use std::rc::Rc;

use clarity::vm::analysis::RuntimeCheckErrorKind;
use clarity::vm::contexts::{ContractContext, OwnedEnvironment};
use clarity::vm::costs::{ExecutionCost, LimitedCostTracker};
use clarity::vm::database::ClarityDatabase;
use clarity::vm::errors::VmExecutionError;
use clarity::vm::types::QualifiedContractIdentifier;
use clarity::vm::{ClarityVersion, SymbolicExpression, Value};
use revm::context_interface::{Cfg, ContextTr};
use revm::handler::{precompile_output_to_interpreter_result, EthPrecompiles, PrecompileProvider};
use revm::interpreter::{CallInputs, InterpreterResult};
use revm::precompile::{PrecompileHalt, PrecompileOutput, PrecompileStatus};
use revm::primitives::hardfork::SpecId;
use revm::primitives::{address, Address, AddressSet, Bytes};
use stacks_common::types::StacksEpochId;

use super::{abi, evm_address_to_principal, EVM_GAS_TO_RUNTIME};

/// Address of the read-only Clarity precompile ("C1A9" ~ CLAR).
pub const CLARITY_READ_PRECOMPILE: Address = address!("00000000000000000000000000000000c1a90001");

/// Flat gas charged by a Clarity precompile call before any Clarity
/// execution cost.
pub const CLARITY_PRECOMPILE_BASE_GAS: u64 = 10_000;

/// Crude gas-equivalent price of one Clarity read operation, used to derive
/// the read budget from available gas (cold-SLOAD-flavored).
const GAS_PER_READ: u64 = 500;

/// Crude number of Clarity read-length bytes afforded per unit of gas.
const READ_LENGTH_PER_GAS: u64 = 10;

/// Outcome of a Clarity read execution, before mapping to an interpreter
/// result.
enum ReadOutcome {
    /// Function returned a plain value or `(ok v)`.
    Ok(Vec<u8>),
    /// Function returned `(err e)` -- surfaced as a revert.
    Err(Vec<u8>),
    /// Clarity cost budget exhausted -- surfaced as out-of-gas.
    OutOfGas,
    /// Anything else (decode failure, no such contract/function, attempted
    /// write, unsupported type) -- surfaced as a revert with `Error(string)`.
    Failed(String),
}

/// `PrecompileProvider` that adds the Clarity precompiles on top of the
/// standard Ethereum set.
pub struct ClarityPrecompiles<'a> {
    eth: EthPrecompiles,
    warm: AddressSet,
    db_cell: Rc<RefCell<Option<ClarityDatabase<'a>>>>,
    mainnet: bool,
    chain_id: u32,
    epoch: StacksEpochId,
}

impl<'a> ClarityPrecompiles<'a> {
    pub fn new(
        db_cell: Rc<RefCell<Option<ClarityDatabase<'a>>>>,
        mainnet: bool,
        chain_id: u32,
        epoch: StacksEpochId,
        spec: SpecId,
    ) -> Self {
        let eth = EthPrecompiles::new(spec);
        let warm = Self::warm_set(&eth);
        ClarityPrecompiles {
            eth,
            warm,
            db_cell,
            mainnet,
            chain_id,
            epoch,
        }
    }

    fn warm_set(eth: &EthPrecompiles) -> AddressSet {
        let mut set = eth.warm_addresses().clone();
        set.insert(CLARITY_READ_PRECOMPILE);
        set
    }

    /// Derive the Clarity cost budget affordable with `gas_limit` gas.
    /// Write limits are zero: any attempted write exhausts the budget and is
    /// reported as `NotReadOnly`.
    fn read_budget(gas_limit: u64) -> ExecutionCost {
        ExecutionCost {
            write_length: 0,
            write_count: 0,
            read_length: gas_limit.saturating_mul(READ_LENGTH_PER_GAS),
            read_count: gas_limit / GAS_PER_READ,
            runtime: gas_limit.saturating_mul(EVM_GAS_TO_RUNTIME),
        }
    }

    /// Convert consumed Clarity cost back into EVM gas.
    fn gas_from_cost(consumed: &ExecutionCost) -> u64 {
        let runtime_gas = consumed.runtime / EVM_GAS_TO_RUNTIME;
        let read_gas = consumed.read_count.saturating_mul(GAS_PER_READ);
        let read_length_gas = consumed.read_length / READ_LENGTH_PER_GAS;
        CLARITY_PRECOMPILE_BASE_GAS.saturating_add(runtime_gas.max(read_gas).max(read_length_gas))
    }

    /// Execute the read-only Clarity call described by `input`. Consumes the
    /// database from the shared cell for the duration of the call and always
    /// puts it back; all database changes are rolled back.
    fn run_clarity_read(
        &mut self,
        caller: &Address,
        input: &[u8],
        gas_limit: u64,
    ) -> PrecompileOutput {
        if gas_limit < CLARITY_PRECOMPILE_BASE_GAS {
            return PrecompileOutput {
                status: PrecompileStatus::Halt(PrecompileHalt::OutOfGas),
                gas_used: gas_limit,
                gas_refunded: 0,
                state_gas_used: 0,
                state_gas_spilled: 0,
                reservoir: 0,
                bytes: Bytes::new(),
            };
        }

        let (outcome, clarity_cost) = self.execute_read(caller, input, gas_limit);
        let gas_used = Self::gas_from_cost(&clarity_cost).min(gas_limit);

        let (status, bytes) = match outcome {
            ReadOutcome::Ok(bytes) => (PrecompileStatus::Success, Bytes::from(bytes)),
            ReadOutcome::Err(bytes) => (PrecompileStatus::Revert, Bytes::from(bytes)),
            ReadOutcome::OutOfGas => (
                PrecompileStatus::Halt(PrecompileHalt::OutOfGas),
                Bytes::new(),
            ),
            ReadOutcome::Failed(msg) => {
                debug!("clarity-read precompile failed: {msg}");
                (
                    PrecompileStatus::Revert,
                    Bytes::from(abi::encode_error_string(&msg)),
                )
            }
        };

        PrecompileOutput {
            status,
            gas_used,
            gas_refunded: 0,
            state_gas_used: 0,
            state_gas_spilled: 0,
            reservoir: 0,
            bytes,
        }
    }

    fn execute_read(
        &mut self,
        caller: &Address,
        input: &[u8],
        gas_limit: u64,
    ) -> (ReadOutcome, ExecutionCost) {
        let no_cost = ExecutionCost::ZERO;

        let (contract_id, function, args_bytes) = match abi::decode_call_input(input) {
            Ok(decoded) => decoded,
            Err(msg) => return (ReadOutcome::Failed(msg), no_cost),
        };
        let contract_id = match QualifiedContractIdentifier::parse(&contract_id) {
            Ok(id) => id,
            Err(_) => {
                return (
                    ReadOutcome::Failed(format!("invalid Clarity contract id: {contract_id}")),
                    no_cost,
                )
            }
        };

        let Some(mut db) = self.db_cell.borrow_mut().take() else {
            return (
                ReadOutcome::Failed("EVM database cell is empty".into()),
                no_cost,
            );
        };

        // everything in this savepoint is rolled back below
        db.begin();
        let (mut db, outcome, cost) =
            self.execute_read_with_db(db, &contract_id, &function, &args_bytes, caller, gas_limit);
        db.roll_back()
            .expect("FATAL: failed to roll back clarity-read savepoint");
        self.db_cell.borrow_mut().replace(db);

        (outcome, cost)
    }

    /// Inner execution: owns the database for the duration and always
    /// returns it, along with the outcome and the consumed Clarity cost.
    fn execute_read_with_db<'db>(
        &self,
        mut db: ClarityDatabase<'db>,
        contract_id: &QualifiedContractIdentifier,
        function: &str,
        args_bytes: &[u8],
        caller: &Address,
        gas_limit: u64,
    ) -> (ClarityDatabase<'db>, ReadOutcome, ExecutionCost) {
        let no_cost = ExecutionCost::ZERO;

        // look up the target function's Clarity argument types
        let contract = match db.get_contract(contract_id) {
            Ok(contract) => contract,
            Err(_) => {
                return (
                    db,
                    ReadOutcome::Failed(format!("no such Clarity contract: {contract_id}")),
                    no_cost,
                )
            }
        };
        let Some(target_function) = contract.lookup_function(function) else {
            return (
                db,
                ReadOutcome::Failed(format!("no such Clarity function: {function}")),
                no_cost,
            );
        };

        let args = match abi::decode_clarity_args(
            target_function.get_arg_types(),
            args_bytes,
            self.mainnet,
        ) {
            Ok(args) => args,
            Err(msg) => return (db, ReadOutcome::Failed(msg), no_cost),
        };
        let args: Vec<_> = args
            .into_iter()
            .map(SymbolicExpression::atom_value)
            .collect();

        let cost_track = match LimitedCostTracker::new_mid_block(
            self.mainnet,
            self.chain_id,
            Self::read_budget(gas_limit),
            &mut db,
            self.epoch,
        ) {
            Ok(tracker) => tracker,
            Err(e) => {
                return (
                    db,
                    ReadOutcome::Failed(format!("failed to build Clarity cost tracker: {e}")),
                    no_cost,
                )
            }
        };

        let sender = evm_address_to_principal(caller, self.mainnet);
        let clarity_version = ClarityVersion::default_for_epoch(self.epoch);
        let initial_context =
            ContractContext::new(QualifiedContractIdentifier::transient(), clarity_version);

        let mut vm_env = OwnedEnvironment::new_cost_limited(
            self.mainnet,
            self.chain_id,
            db,
            cost_track,
            self.epoch,
        );
        let result: Result<(Value, _, _), VmExecutionError> = vm_env.execute_in_env(
            sender,
            None,
            Some(initial_context),
            |exec_state, invoke_ctx| {
                // execute with read_only = false so that read-only functions
                // reached via contract-call? also work; actual writes are
                // prevented by the zero write budget
                exec_state.execute_contract(invoke_ctx, contract_id, function, &args, false)
            },
        );

        #[allow(clippy::expect_used)]
        let (db, cost_track) = vm_env
            .destruct()
            .expect("Failed to recover database reference after executing clarity-read");
        let consumed = cost_track.get_total();

        let outcome = match result {
            Ok((value, ..)) => match value {
                Value::Response(response) => {
                    let encoded = match abi::encode_clarity_value(&response.data) {
                        Ok(encoded) => encoded,
                        Err(msg) => return (db, ReadOutcome::Failed(msg), consumed),
                    };
                    if response.committed {
                        ReadOutcome::Ok(encoded)
                    } else {
                        ReadOutcome::Err(encoded)
                    }
                }
                plain => match abi::encode_clarity_value(&plain) {
                    Ok(encoded) => ReadOutcome::Ok(encoded),
                    Err(msg) => ReadOutcome::Failed(msg),
                },
            },
            Err(VmExecutionError::RuntimeCheck(RuntimeCheckErrorKind::CostBalanceExceeded(
                actual,
                _,
            ))) => {
                if actual.write_count > 0 || actual.write_length > 0 {
                    ReadOutcome::Failed(format!("Clarity function {function} is not read-only"))
                } else {
                    ReadOutcome::OutOfGas
                }
            }
            Err(e) => ReadOutcome::Failed(format!("Clarity execution error: {e}")),
        };

        (db, outcome, consumed)
    }
}

impl<'a, CTX: ContextTr> PrecompileProvider<CTX> for ClarityPrecompiles<'a> {
    type Output = InterpreterResult;

    fn set_spec(&mut self, spec: <CTX::Cfg as Cfg>::Spec) -> bool {
        let changed = <EthPrecompiles as PrecompileProvider<CTX>>::set_spec(&mut self.eth, spec);
        if changed {
            self.warm = Self::warm_set(&self.eth);
        }
        changed
    }

    fn run(
        &mut self,
        context: &mut CTX,
        inputs: &CallInputs,
    ) -> Result<Option<InterpreterResult>, String> {
        if inputs.bytecode_address != CLARITY_READ_PRECOMPILE {
            return self.eth.run(context, inputs);
        }
        let input = inputs.input.as_bytes(context);
        let output = self.run_clarity_read(&inputs.caller, input.as_ref(), inputs.gas_limit);
        Ok(Some(precompile_output_to_interpreter_result(
            output,
            inputs.gas_limit,
        )))
    }

    fn warm_addresses(&self) -> &AddressSet {
        &self.warm
    }

    fn contains(&self, address: &Address) -> bool {
        *address == CLARITY_READ_PRECOMPILE || self.eth.contains(address)
    }
}
