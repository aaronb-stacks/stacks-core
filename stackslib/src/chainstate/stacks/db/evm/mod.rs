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

//! Experimental EVM execution support (`EvmPublish` / `EvmContractCall`
//! transaction payloads).
//!
//! This module drops the `revm` interpreter on top of the existing
//! MARF-backed Clarity key-value store. EVM account state (nonces, code,
//! storage slots) is persisted under an `evm::`-prefixed key namespace via
//! `ClarityDatabase::put_data`/`get_data`, so it inherits the same
//! fork-awareness, per-transaction savepoint rollback, and per-block commit
//! behavior as Clarity contract state.
//!
//! EVM balances ARE the STX ledger: a 20-byte EVM address is the Hash160 of
//! a standard Stacks principal (with the canonical single-sig version byte),
//! and 1 wei == 1 uSTX. Balance reads come from the Clarity account ledger;
//! balance changes computed by the EVM are applied back to it after a
//! successful execution. Contract principals map to a derived address (the
//! Hash160 of the qualified contract id), never their deployer's. Two
//! standard principals that share a Hash160 but differ in version byte alias
//! to the same EVM account; this is an accepted limitation of this
//! experimental feature.
//!
//! State layout (all values are strings; `<addr>` is lowercase hex of the
//! 20-byte EVM address):
//! - `evm::acct::<addr>::nonce`   -> EVM nonce as a decimal string
//! - `evm::acct::<addr>::code`    -> deployed runtime bytecode as hex
//! - `evm::storage::<addr>::<slot>` -> 32-byte storage word as hex
//!
//! Execution never writes through the interpreter: `revm` buffers all state
//! changes and returns them as a diff, which is applied here only when the
//! execution succeeds. Reverts and halts leave no EVM state behind (the
//! transaction is still mined and its fee still paid).

pub mod abi;
pub mod clarity_call;
pub mod clarity_precompile;

use std::cell::RefCell;
use std::rc::Rc;

use clarity::vm::clarity::ClarityError;
use clarity::vm::database::ClarityDatabase;
use clarity::vm::errors::{VmExecutionError, VmInternalError};
use clarity::vm::events::{SmartContractEventData, StacksTransactionEvent};
use clarity::vm::types::{
    PrincipalData, QualifiedContractIdentifier, StandardPrincipalData, Value,
};
use clarity::vm::ContractName;
use revm::context::result::{EVMError, ExecutionResult, Output};
use revm::context::{BlockEnv, CfgEnv, TxEnv};
use revm::database_interface::DBErrorMarker;
use revm::primitives::hardfork::SpecId;
use revm::primitives::{keccak256, Address, Bytes, Log, TxKind, B256, KECCAK_EMPTY, U256};
use revm::state::{AccountInfo, Bytecode, EvmState};
use revm::{Context, Database, ExecuteEvm, MainBuilder, MainContext};
use stacks_common::address::{
    C32_ADDRESS_VERSION_MAINNET_SINGLESIG, C32_ADDRESS_VERSION_TESTNET_SINGLESIG,
};
use stacks_common::types::StacksEpochId;
use stacks_common::util::hash::{hex_bytes, to_hex, Hash160};

pub use crate::chainstate::stacks::db::evm::clarity_precompile::{
    ClarityPrecompiles, CLARITY_READ_PRECOMPILE,
};
use crate::chainstate::stacks::{TransactionEvmContractCall, TransactionEvmPublish};

/// Hard cap on the EVM gas limit a single transaction may request.
pub const EVM_TX_GAS_CAP: u64 = 30_000_000;

/// Fixed conversion ratio from consumed EVM gas to Clarity `ExecutionCost`
/// runtime units, so EVM work counts against the block's runtime budget.
pub const EVM_GAS_TO_RUNTIME: u64 = 100;

/// Maximum number of bytes of EVM return / revert data carried into the
/// transaction receipt's Clarity `(ok ...)` / `(err ...)` buff.
pub const EVM_MAX_RESULT_LEN: usize = 1024;

/// Maximum number of bytes of a single EVM log payload carried into a
/// receipt event; longer payloads are truncated.
pub const EVM_MAX_LOG_LEN: usize = 102400;

/// The EVM hardfork revision the interpreter runs at.
const EVM_SPEC: SpecId = SpecId::CANCUN;

/// Outcome of executing an EVM payload. Always represents a mined
/// transaction: `succeeded == false` means the EVM reverted or halted, in
/// which case no EVM state was written but the fee is still owed.
pub struct EvmOutcome {
    /// Receipt result: `(ok (buff ...))` on success, `(err (buff ...))` on
    /// revert or halt. For `EvmPublish`, the ok-value is the 20-byte address
    /// of the created contract.
    pub result: Value,
    /// EVM logs, wrapped as `SmartContractEvent`s (topic "evm-log").
    pub events: Vec<StacksTransactionEvent>,
    /// EVM gas consumed.
    pub gas_used: u64,
    /// Address of the contract created by an `EvmPublish`.
    pub created_address: Option<Hash160>,
    /// Whether execution succeeded (state was committed).
    pub succeeded: bool,
}

/// Error type surfaced from the `revm::Database` shim. Wraps the underlying
/// Clarity VM error as a string, since `revm` requires its database error to
/// be `Send + Sync + 'static` while `VmExecutionError` is not.
#[derive(Debug)]
pub struct EvmDbError(pub String);

impl std::fmt::Display for EvmDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "EVM database error: {}", self.0)
    }
}

impl std::error::Error for EvmDbError {}
impl DBErrorMarker for EvmDbError {}

impl From<VmExecutionError> for EvmDbError {
    fn from(e: VmExecutionError) -> Self {
        EvmDbError(e.to_string())
    }
}

fn evm_error(msg: String) -> ClarityError {
    ClarityError::Interpreter(VmExecutionError::Internal(VmInternalError::Expect(msg)))
}

/// Map a Stacks principal to its EVM address.
///
/// Standard principals map to their Hash160 directly. Contract principals
/// map to a *derived* address -- the Hash160 of the fully-qualified contract
/// identifier bytes -- so that a contract never aliases (and can never spend
/// the EVM-side funds of) its deployer.
pub fn principal_to_evm_address(principal: &PrincipalData) -> Address {
    match principal {
        PrincipalData::Standard(standard) => Address::from(standard.1),
        PrincipalData::Contract(contract_id) => {
            let mut preimage = Vec::with_capacity(22 + contract_id.name.len() as usize);
            preimage.push(contract_id.issuer.version());
            preimage.extend_from_slice(&contract_id.issuer.1);
            preimage.push(b'.');
            preimage.extend_from_slice(contract_id.name.as_str().as_bytes());
            Address::from(Hash160::from_data(&preimage).0)
        }
    }
}

/// Map a 20-byte EVM address to the standard Stacks principal whose Hash160
/// is that address, using the canonical single-sig version byte.
pub fn evm_address_to_principal(address: &Address, mainnet: bool) -> PrincipalData {
    let version = if mainnet {
        C32_ADDRESS_VERSION_MAINNET_SINGLESIG
    } else {
        C32_ADDRESS_VERSION_TESTNET_SINGLESIG
    };
    PrincipalData::Standard(
        StandardPrincipalData::new(version, address.0 .0)
            .expect("BUG: canonical singlesig version byte is invalid"),
    )
}

fn evm_nonce_key(address: &Address) -> String {
    format!("evm::acct::{}::nonce", to_hex(address.as_slice()))
}

fn evm_code_key(address: &Address) -> String {
    format!("evm::acct::{}::code", to_hex(address.as_slice()))
}

fn evm_storage_key(address: &Address, slot: &U256) -> String {
    format!(
        "evm::storage::{}::{:064x}",
        to_hex(address.as_slice()),
        slot
    )
}

/// The shared handle to the Clarity database during an EVM execution. The
/// database is owned by the cell so that both the `revm::Database` shim and
/// the Clarity precompiles can access it (revm is single-threaded, and the
/// precompiles temporarily `take` the database out to build a Clarity VM
/// environment, which requires ownership).
pub type SharedClarityDb<'a> = Rc<RefCell<Option<ClarityDatabase<'a>>>>;

/// How an EVM execution accesses the Clarity database.
///
/// - `Shared`: the database is owned by a cell shared with the Clarity
///   precompiles (the top-level EVM transaction path). The `clarity-read`
///   precompile is functional.
/// - `Borrowed`: the database is mutably borrowed from an enclosing Clarity
///   VM execution (the `evm-call?` path). The Clarity precompiles get an
///   empty cell, so nested cross-VM re-entry cleanly reverts.
pub enum DbHandle<'a, 'db> {
    Shared(SharedClarityDb<'a>),
    Borrowed(&'db mut ClarityDatabase<'a>),
}

impl<'a> DbHandle<'a, '_> {
    fn with_db<R>(
        &mut self,
        f: impl FnOnce(&mut ClarityDatabase) -> Result<R, EvmDbError>,
    ) -> Result<R, EvmDbError> {
        match self {
            DbHandle::Shared(cell) => {
                let mut guard = cell.borrow_mut();
                let db = guard
                    .as_mut()
                    .ok_or_else(|| EvmDbError("EVM database cell is empty".into()))?;
                f(db)
            }
            DbHandle::Borrowed(db) => f(db),
        }
    }
}

fn read_nonce(db: &mut ClarityDatabase, address: &Address) -> Result<u64, EvmDbError> {
    let nonce_str: Option<String> = db.get_data(&evm_nonce_key(address))?;
    let Some(nonce_str) = nonce_str else {
        return Ok(0);
    };
    nonce_str
        .parse::<u64>()
        .map_err(|_| EvmDbError(format!("corrupt EVM nonce for {address}")))
}

fn read_code(db: &mut ClarityDatabase, address: &Address) -> Result<Option<Bytecode>, EvmDbError> {
    let code_hex: Option<String> = db.get_data(&evm_code_key(address))?;
    let Some(code_hex) = code_hex else {
        return Ok(None);
    };
    if code_hex.is_empty() {
        // self-destructed contract
        return Ok(None);
    }
    let code_bytes =
        hex_bytes(&code_hex).map_err(|_| EvmDbError(format!("corrupt EVM code for {address}")))?;
    Ok(Some(Bytecode::new_raw(Bytes::from(code_bytes))))
}

fn read_available_balance(
    db: &mut ClarityDatabase,
    address: &Address,
    mainnet: bool,
) -> Result<u128, EvmDbError> {
    let principal = evm_address_to_principal(address, mainnet);
    let mut snapshot = db.get_stx_balance_snapshot(&principal)?;
    Ok(snapshot.get_available_balance()?)
}

/// `revm::Database` implementation over the MARF-backed Clarity KV store.
///
/// Reads are served live from `evm::` keys plus the STX account ledger.
/// Balances first reported to the interpreter are remembered so that the
/// post-execution balance deltas can be applied to the STX ledger.
pub struct StacksEvmDb<'a, 'db> {
    handle: DbHandle<'a, 'db>,
    mainnet: bool,
    /// code fetched via `basic()`, so `code_by_hash` can answer from cache
    code_cache: std::collections::HashMap<B256, Bytecode>,
    /// available uSTX balance as first reported to the interpreter
    loaded_balances: std::collections::HashMap<Address, u128>,
}

impl<'a, 'db> StacksEvmDb<'a, 'db> {
    pub fn new(handle: DbHandle<'a, 'db>, mainnet: bool) -> Self {
        StacksEvmDb {
            handle,
            mainnet,
            code_cache: std::collections::HashMap::new(),
            loaded_balances: std::collections::HashMap::new(),
        }
    }

    /// Read the available (spendable) uSTX balance of the principal mapped
    /// to `address`, memoizing the first read for delta computation later.
    fn load_balance(&mut self, address: &Address) -> Result<u128, EvmDbError> {
        if let Some(balance) = self.loaded_balances.get(address) {
            return Ok(*balance);
        }
        let mainnet = self.mainnet;
        let balance = self
            .handle
            .with_db(|db| read_available_balance(db, address, mainnet))?;
        self.loaded_balances.insert(*address, balance);
        Ok(balance)
    }

    /// Apply the interpreter's post-execution state diff to the underlying
    /// store. Only called after a successful execution.
    fn commit_state(&mut self, state: &EvmState) -> Result<(), EvmDbError> {
        let Self {
            handle,
            mainnet,
            loaded_balances,
            ..
        } = self;
        let mainnet = *mainnet;
        handle.with_db(|db| {
            for (address, account) in state.iter() {
                if !account.is_touched() {
                    continue;
                }

                // nonce
                let stored_nonce = read_nonce(db, address)?;
                if account.info.nonce != stored_nonce {
                    db.put_data(&evm_nonce_key(address), &account.info.nonce.to_string())?;
                }

                // code: written once at creation; cleared on self-destruct
                if account.is_selfdestructed() {
                    db.put_data(&evm_code_key(address), &String::new())?;
                } else if account.is_created() {
                    if let Some(code) = account.info.code.as_ref() {
                        if !code.is_empty() && account.info.code_hash != KECCAK_EMPTY {
                            let code_hex = to_hex(code.original_byte_slice());
                            db.put_data(&evm_code_key(address), &code_hex)?;
                        }
                    }
                }

                // changed storage slots
                for (slot, slot_value) in account.changed_storage_slots() {
                    let value_hex = format!("{:064x}", slot_value.present_value);
                    db.put_data(&evm_storage_key(address, slot), &value_hex)?;
                }

                // balance delta relative to what the interpreter was told;
                // the delta (rather than the absolute balance) is applied so
                // that concurrent STX movements outside the EVM's view
                // compose
                let old_balance = match loaded_balances.get(address) {
                    Some(balance) => *balance,
                    None => read_available_balance(db, address, mainnet)?,
                };
                let new_balance: u128 =
                    account.info.balance.try_into().map_err(|_| {
                        EvmDbError(format!("EVM balance of {address} overflows u128"))
                    })?;
                let principal = evm_address_to_principal(address, mainnet);
                if new_balance > old_balance {
                    let mut snapshot = db.get_stx_balance_snapshot(&principal)?;
                    snapshot.credit(new_balance - old_balance)?;
                    snapshot.save()?;
                } else if new_balance < old_balance {
                    let mut snapshot = db.get_stx_balance_snapshot(&principal)?;
                    snapshot.debit(old_balance - new_balance)?;
                    snapshot.save()?;
                }
                loaded_balances.insert(*address, new_balance);
            }
            Ok(())
        })
    }
}

impl Database for StacksEvmDb<'_, '_> {
    type Error = EvmDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        let balance = self.load_balance(&address)?;
        let (nonce, code) = self
            .handle
            .with_db(|db| Ok((read_nonce(db, &address)?, read_code(db, &address)?)))?;

        if balance == 0 && nonce == 0 && code.is_none() {
            return Ok(None);
        }

        let (code_hash, code) = match code {
            Some(code) => {
                let code_hash = keccak256(code.original_byte_slice());
                self.code_cache.insert(code_hash, code.clone());
                (code_hash, Some(code))
            }
            None => (KECCAK_EMPTY, Some(Bytecode::default())),
        };

        Ok(Some(AccountInfo {
            balance: U256::from(balance),
            nonce,
            code_hash,
            account_id: None,
            code,
        }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if code_hash == KECCAK_EMPTY {
            return Ok(Bytecode::default());
        }
        self.code_cache
            .get(&code_hash)
            .cloned()
            .ok_or_else(|| EvmDbError(format!("unknown EVM code hash {code_hash}")))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let value_hex: Option<String> = self
            .handle
            .with_db(|db| Ok(db.get_data(&evm_storage_key(&address, &index))?))?;
        let Some(value_hex) = value_hex else {
            return Ok(U256::ZERO);
        };
        U256::from_str_radix(&value_hex, 16)
            .map_err(|_| EvmDbError(format!("corrupt EVM storage for {address} slot {index}")))
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        // BLOCKHASH is not supported; every historical block hash reads as zero
        Ok(B256::ZERO)
    }
}

/// Convert EVM logs to receipt events. Each log becomes a
/// `SmartContractEvent` against the pseudo contract `<addr-principal>.evm`
/// with topic "evm-log" and a buff value encoded as:
/// `[n_topics: u8] [topic: 32 bytes]*n [data]`.
fn logs_to_events(logs: &[Log], mainnet: bool) -> Vec<StacksTransactionEvent> {
    logs.iter()
        .map(|log| {
            let mut payload = Vec::with_capacity(1 + 32 * log.data.topics().len());
            payload.push(log.data.topics().len() as u8);
            for topic in log.data.topics() {
                payload.extend_from_slice(topic.as_slice());
            }
            let data = log.data.data.as_ref();
            let take = data.len().min(EVM_MAX_LOG_LEN);
            payload.extend_from_slice(data.get(..take).unwrap_or(data));

            let issuer = match evm_address_to_principal(&log.address, mainnet) {
                PrincipalData::Standard(standard) => standard,
                PrincipalData::Contract(..) => unreachable!("mapped principal is standard"),
            };
            let contract_id = QualifiedContractIdentifier::new(
                issuer,
                ContractName::try_from("evm").expect("BUG: invalid static contract name"),
            );
            StacksTransactionEvent::SmartContractEvent(SmartContractEventData {
                key: (contract_id, "evm-log".to_string()),
                value: Value::buff_from(payload)
                    .expect("BUG: EVM log payload exceeds Clarity buff limit"),
            })
        })
        .collect()
}

/// Build the receipt result buff from return / revert data, truncated to
/// `EVM_MAX_RESULT_LEN`.
fn result_buff(data: &[u8]) -> Value {
    let take = data.len().min(EVM_MAX_RESULT_LEN);
    Value::buff_from(data.get(..take).unwrap_or(data).to_vec())
        .expect("BUG: bounded EVM result exceeds buff limit")
}

/// Execute an `EvmPublish` payload. The contract is created at the standard
/// EVM CREATE address (keccak256(rlp(sender, evm_nonce))[12..]).
pub fn run_evm_publish<'db>(
    db: ClarityDatabase<'db>,
    mainnet: bool,
    chain_id: u32,
    epoch: StacksEpochId,
    origin: &PrincipalData,
    payload: &TransactionEvmPublish,
) -> (ClarityDatabase<'db>, Result<EvmOutcome, ClarityError>) {
    run_evm(
        db,
        mainnet,
        chain_id,
        epoch,
        origin,
        TxKind::Create,
        payload.gas_limit,
        payload.value,
        payload.code.clone(),
    )
}

/// Execute an `EvmContractCall` payload.
pub fn run_evm_call<'db>(
    db: ClarityDatabase<'db>,
    mainnet: bool,
    chain_id: u32,
    epoch: StacksEpochId,
    origin: &PrincipalData,
    payload: &TransactionEvmContractCall,
) -> (ClarityDatabase<'db>, Result<EvmOutcome, ClarityError>) {
    run_evm(
        db,
        mainnet,
        chain_id,
        epoch,
        origin,
        TxKind::Call(Address::from(payload.address.0)),
        payload.gas_limit,
        payload.value,
        payload.calldata.clone(),
    )
}

/// Take the database back out of the shared cell after execution.
fn reclaim_db<'db>(cell: &SharedClarityDb<'db>) -> ClarityDatabase<'db> {
    cell.borrow_mut()
        .take()
        .expect("BUG: EVM database cell is empty after execution")
}

#[allow(clippy::too_many_arguments)]
fn run_evm<'db>(
    mut db: ClarityDatabase<'db>,
    mainnet: bool,
    chain_id: u32,
    epoch: StacksEpochId,
    origin: &PrincipalData,
    kind: TxKind,
    gas_limit: u64,
    value: u64,
    data: Vec<u8>,
) -> (ClarityDatabase<'db>, Result<EvmOutcome, ClarityError>) {
    let caller = principal_to_evm_address(origin);
    let caller_nonce = match read_nonce(&mut db, &caller) {
        Ok(nonce) => nonce,
        Err(e) => return (db, Err(evm_error(e.to_string()))),
    };

    // the database is shared between the revm Database shim and the Clarity
    // precompiles for the duration of the execution
    let cell: SharedClarityDb<'db> = Rc::new(RefCell::new(Some(db)));
    let precompiles = ClarityPrecompiles::new(cell.clone(), mainnet, chain_id, epoch, EVM_SPEC);
    let mut shim = StacksEvmDb::new(DbHandle::Shared(cell.clone()), mainnet);

    let outcome = run_evm_core(
        &mut shim,
        precompiles,
        mainnet,
        chain_id,
        caller,
        caller_nonce,
        kind,
        gas_limit,
        u128::from(value),
        data,
    );
    drop(shim);
    (reclaim_db(&cell), outcome)
}

/// Execute an EVM call initiated from inside a Clarity VM execution (the
/// `evm-call?` native function). The database is mutably borrowed from the
/// enclosing Clarity environment, so the Clarity precompiles are disabled
/// for the nested run (re-entering Clarity from here cleanly reverts).
///
/// All writes land in the database's current savepoint; the caller is
/// responsible for savepoint management (including rolling back any value
/// pre-funding when the call fails).
pub fn run_evm_from_clarity(
    db: &mut ClarityDatabase,
    mainnet: bool,
    chain_id: u32,
    epoch: StacksEpochId,
    caller: &PrincipalData,
    address: [u8; 20],
    gas_limit: u64,
    value: u128,
    calldata: Vec<u8>,
) -> Result<EvmOutcome, ClarityError> {
    let caller_evm = principal_to_evm_address(caller);
    let caller_nonce = read_nonce(db, &caller_evm).map_err(|e| evm_error(e.to_string()))?;

    // an empty cell: the clarity-read precompile finds no database and
    // reverts, which is exactly the wanted nested-re-entry behavior
    let empty_cell: SharedClarityDb = Rc::new(RefCell::new(None));
    let precompiles = ClarityPrecompiles::new(empty_cell, mainnet, chain_id, epoch, EVM_SPEC);
    let mut shim = StacksEvmDb::new(DbHandle::Borrowed(db), mainnet);

    run_evm_core(
        &mut shim,
        precompiles,
        mainnet,
        chain_id,
        caller_evm,
        caller_nonce,
        TxKind::Call(Address::from(address)),
        gas_limit,
        value,
        calldata,
    )
}

/// Shared EVM execution core: builds the environment, transacts, and maps
/// the result to an `EvmOutcome` (committing the state diff on success).
#[allow(clippy::too_many_arguments)]
fn run_evm_core(
    shim: &mut StacksEvmDb,
    precompiles: ClarityPrecompiles,
    mainnet: bool,
    chain_id: u32,
    caller: Address,
    caller_nonce: u64,
    kind: TxKind,
    gas_limit: u64,
    value: u128,
    data: Vec<u8>,
) -> Result<EvmOutcome, ClarityError> {
    let (block_height, timestamp) = shim
        .handle
        .with_db(|db| {
            let block_height = db.get_current_block_height();
            // the current block's header is not written yet while its
            // transactions are being processed, so read the parent block's
            // timestamp
            let timestamp = if block_height > 0 {
                db.get_block_time(block_height.saturating_sub(1))
                    .unwrap_or(0)
            } else {
                0
            };
            Ok((block_height, timestamp))
        })
        .map_err(|e| evm_error(e.to_string()))?;

    let mut cfg_env = CfgEnv::new_with_spec(EVM_SPEC);
    cfg_env.chain_id = u64::from(chain_id);
    cfg_env.tx_chain_id_check = false;

    let block_env = BlockEnv {
        number: U256::from(block_height),
        timestamp: U256::from(timestamp),
        gas_limit: EVM_TX_GAS_CAP,
        prevrandao: Some(B256::ZERO),
        ..BlockEnv::default()
    };

    let tx_env = TxEnv {
        caller,
        gas_limit,
        gas_price: 0,
        kind,
        value: U256::from(value),
        data: Bytes::from(data),
        nonce: caller_nonce,
        chain_id: None,
        ..TxEnv::default()
    };

    let mut evm = Context::mainnet()
        .with_db(&mut *shim)
        .with_cfg(cfg_env)
        .with_block(block_env)
        .build_mainnet()
        .with_precompiles(precompiles);

    let transact_result = evm.transact(tx_env);
    drop(evm);

    let result_and_state = match transact_result {
        Ok(result_and_state) => result_and_state,
        Err(EVMError::Database(db_err)) => {
            // a real storage failure aborts transaction processing
            return Err(evm_error(db_err.to_string()));
        }
        Err(other) => {
            // statically invalid EVM transaction (e.g. balance below value,
            // init code too large): mined as a failed transaction
            debug!("EVM transaction invalid: {other}");
            return Ok(EvmOutcome {
                result: Value::error(result_buff(&[]))
                    .expect("BUG: failed to construct error value"),
                events: vec![],
                gas_used: 0,
                created_address: None,
                succeeded: false,
            });
        }
    };

    process_execution_result(shim, mainnet, result_and_state)
}

/// Map a completed EVM execution to an `EvmOutcome`, committing the state
/// diff on success.
fn process_execution_result(
    shim: &mut StacksEvmDb,
    mainnet: bool,
    result_and_state: revm::context::result::ExecResultAndState<ExecutionResult, EvmState>,
) -> Result<EvmOutcome, ClarityError> {
    match result_and_state.result {
        ExecutionResult::Success {
            gas, logs, output, ..
        } => {
            shim.commit_state(&result_and_state.state)
                .map_err(|e| evm_error(e.to_string()))?;

            let (result_value, created_address) = match &output {
                Output::Create(_, Some(created)) => (
                    Value::okay(result_buff(created.as_slice()))
                        .expect("BUG: failed to construct ok value"),
                    Some(Hash160(created.0 .0)),
                ),
                Output::Create(_, None) => (
                    Value::okay(result_buff(&[])).expect("BUG: failed to construct ok value"),
                    None,
                ),
                Output::Call(bytes) => (
                    Value::okay(result_buff(bytes.as_ref()))
                        .expect("BUG: failed to construct ok value"),
                    None,
                ),
            };

            Ok(EvmOutcome {
                result: result_value,
                events: logs_to_events(&logs, mainnet),
                gas_used: gas.tx_gas_used(),
                created_address,
                succeeded: true,
            })
        }
        ExecutionResult::Revert { gas, output, .. } => Ok(EvmOutcome {
            result: Value::error(result_buff(output.as_ref()))
                .expect("BUG: failed to construct error value"),
            events: vec![],
            gas_used: gas.tx_gas_used(),
            created_address: None,
            succeeded: false,
        }),
        ExecutionResult::Halt { reason, gas, .. } => {
            debug!("EVM transaction halted: {reason:?}");
            Ok(EvmOutcome {
                result: Value::error(result_buff(&[]))
                    .expect("BUG: failed to construct error value"),
                events: vec![],
                gas_used: gas.tx_gas_used(),
                created_address: None,
                succeeded: false,
            })
        }
    }
}

#[cfg(test)]
mod test {
    use clarity::util::secp256k1::Secp256k1PrivateKey;
    use stacks_common::codec::StacksMessageCodec;
    use stacks_common::types::chainstate::{BlockHeaderHash, ConsensusHash, StacksPrivateKey};
    use stacks_common::types::StacksEpochId;
    use stacks_common::util::hash::hex_bytes;

    use super::*;
    use crate::chainstate::stacks::db::testing::TestChainstateBuilder;
    use crate::chainstate::stacks::db::transactions::test::{
        TestBurnStateDB_32, TestBurnStateDB_33,
    };
    use crate::chainstate::stacks::db::StacksChainState;
    use crate::chainstate::stacks::events::StacksTransactionReceipt;
    use crate::chainstate::stacks::{
        Error, FungibleConditionCode, PostConditionPrincipal, StacksBlock, StacksTransaction,
        StacksTransactionSigner, TransactionAuth, TransactionPayload, TransactionPostCondition,
        TransactionPostConditionMode, TransactionVersion, MAX_EVM_CODE_LEN,
    };
    use crate::core::{FIRST_BURNCHAIN_CONSENSUS_HASH, FIRST_STACKS_BLOCK_HASH};

    /// Init code for a minimal storage contract. Behavior of the deployed
    /// runtime (payable, no function selector):
    /// - empty calldata: returns the 32-byte word in slot 0
    /// - otherwise: stores calldata[0..32] into slot 0 and emits a LOG1 with
    ///   topic 0x1111...11
    const STORAGE_INIT_CODE: &str = concat!(
        // init: codecopy(0, 0x0c, 0x42); return(0, 0x42)
        "6042600c60003960426000f3",
        // runtime, 0x42 bytes.
        // if calldatasize == 0, jump to the read path at 0x36
        "3615603657",
        // word = calldataload(0); sstore(0, word); mstore(0, word)
        "60003580600055600052",
        // log1(offset=0, size=32, topic=0x1111..) -- the data is the stored word
        "7f1111111111111111111111111111111111111111111111111111111111111111",
        "60206000a100",
        // read path: return the 32-byte word in slot 0
        "5b60005460005260206000f3",
    );

    /// Init code for a contract whose runtime always reverts.
    const REVERT_INIT_CODE: &str = concat!(
        // init: codecopy(0, 0x0c, 0x05); return(0, 0x05)
        "6005600c60003960056000f3",
        // runtime: revert(0, 0)
        "60006000fd",
    );

    const LOG_TOPIC: [u8; 32] = [0x11; 32];

    fn make_evm_tx(
        privk: &StacksPrivateKey,
        nonce: u64,
        payload: TransactionPayload,
    ) -> StacksTransaction {
        let auth = TransactionAuth::from_p2pkh(privk).unwrap();
        let mut tx = StacksTransaction::new(TransactionVersion::Testnet, auth, payload);
        tx.chain_id = 0x80000000;
        tx.post_condition_mode = TransactionPostConditionMode::Allow;
        tx.set_tx_fee(0);
        tx.set_origin_nonce(nonce);

        let mut signer = StacksTransactionSigner::new(&tx);
        signer.sign_origin(privk).unwrap();
        signer.get_tx().unwrap()
    }

    fn publish_payload(gas_limit: u64, value: u64, code_hex: &str) -> TransactionPayload {
        TransactionPayload::EvmPublish(TransactionEvmPublish {
            gas_limit,
            value,
            code: hex_bytes(code_hex).unwrap(),
        })
    }

    fn call_payload(
        address: &Hash160,
        gas_limit: u64,
        value: u64,
        calldata: Vec<u8>,
    ) -> TransactionPayload {
        TransactionPayload::EvmContractCall(TransactionEvmContractCall {
            address: address.clone(),
            gas_limit,
            value,
            calldata,
        })
    }

    fn expect_ok_buff(receipt: &StacksTransactionReceipt) -> Vec<u8> {
        let response = match &receipt.result {
            Value::Response(response) => response,
            other => panic!("expected response value, got {other:?}"),
        };
        assert!(response.committed, "expected ok, got {:?}", receipt.result);
        match response.data.as_ref() {
            Value::Sequence(clarity::vm::types::SequenceData::Buffer(buff)) => buff.data.clone(),
            other => panic!("expected buff, got {other:?}"),
        }
    }

    fn expect_err(receipt: &StacksTransactionReceipt) {
        let response = match &receipt.result {
            Value::Response(response) => response,
            other => panic!("expected response value, got {other:?}"),
        };
        assert!(
            !response.committed,
            "expected err, got {:?}",
            receipt.result
        );
    }

    /// Extract the buff payload from an `(err (buff ...))` receipt result.
    fn expect_err_buff(receipt: &StacksTransactionReceipt) -> Vec<u8> {
        let response = match &receipt.result {
            Value::Response(response) => response,
            other => panic!("expected response value, got {other:?}"),
        };
        assert!(
            !response.committed,
            "expected err, got {:?}",
            receipt.result
        );
        match response.data.as_ref() {
            Value::Sequence(clarity::vm::types::SequenceData::Buffer(buff)) => buff.data.clone(),
            other => panic!("expected buff, got {other:?}"),
        }
    }

    /// A 32-byte ABI word holding a u128 in its low bytes.
    fn word_u128(value: u128) -> Vec<u8> {
        let mut word = vec![0u8; 32];
        word[16..32].copy_from_slice(&value.to_be_bytes());
        word
    }

    /// ABI encoding of a single dynamic `bytes` argument.
    fn abi_bytes_arg(data: &[u8]) -> Vec<u8> {
        let mut out = word_u128(32);
        out.extend_from_slice(&word_u128(data.len() as u128));
        out.extend_from_slice(data);
        out.resize(64 + data.len().div_ceil(32) * 32, 0);
        out
    }

    /// EVM init code for a contract that forwards its calldata to `target`
    /// via CALL and bubbles up the result (return or revert).
    fn forwarder_init_code(target: &Address) -> Vec<u8> {
        // calldatacopy(0, 0, calldatasize)
        let mut runtime = vec![0x36, 0x60, 0x00, 0x60, 0x00, 0x37];
        // call(gas, target, 0, 0, calldatasize, 0, 0)
        runtime.extend_from_slice(&[0x60, 0x00, 0x60, 0x00, 0x36, 0x60, 0x00, 0x60, 0x00]);
        runtime.push(0x73); // PUSH20
        runtime.extend_from_slice(target.as_slice());
        runtime.extend_from_slice(&[0x5a, 0xf1]); // GAS CALL
                                                  // returndatacopy(0, 0, returndatasize)
        runtime.extend_from_slice(&[0x3d, 0x60, 0x00, 0x60, 0x00, 0x3e]);
        // bubble: jump to ok on success, else revert(0, returndatasize)
        let ok_dest = u8::try_from(runtime.len() + 7).unwrap();
        runtime.extend_from_slice(&[0x60, ok_dest, 0x57]); // PUSH1 ok JUMPI
        runtime.extend_from_slice(&[0x3d, 0x60, 0x00, 0xfd]); // REVERT
        runtime.extend_from_slice(&[0x5b, 0x3d, 0x60, 0x00, 0xf3]); // JUMPDEST RETURN
                                                                    // init: codecopy(0, 0x0c, len); return(0, len)
        let len = u8::try_from(runtime.len()).unwrap();
        let mut init = vec![
            0x60, len, 0x60, 0x0c, 0x60, 0x00, 0x39, 0x60, len, 0x60, 0x00, 0xf3,
        ];
        init.extend_from_slice(&runtime);
        init
    }

    /// The Clarity contract targeted by the precompile tests.
    const CLARITY_TARGET_NAME: &str = "evm-target";
    const CLARITY_TARGET_CODE: &str = r#"
(define-read-only (add-forty (x uint)) (+ x u40))
(define-read-only (echo-buff (b (buff 40))) b)
(define-read-only (echo-principal (p principal)) p)
(define-read-only (checked (flag bool)) (if flag (ok u7) (err u99)))
(define-data-var counter uint u0)
(define-public (bump)
  (ok (var-set counter (+ (var-get counter) u1))))
"#;

    /// Build a precompile call payload targeting the Clarity fixture.
    fn clarity_read_payload(contract_id: &str, function: &str, args: &[u8]) -> TransactionPayload {
        call_payload(
            &Hash160(CLARITY_READ_PRECOMPILE.0 .0),
            1_000_000,
            0,
            abi::encode_call_input(contract_id, function, args),
        )
    }

    #[test]
    fn evm_payload_codec_roundtrip() {
        let publish = publish_payload(1_000_000, 42, STORAGE_INIT_CODE);
        let call = call_payload(&Hash160([0xaa; 20]), 500_000, 7, vec![1, 2, 3]);

        for payload in [publish, call] {
            let bytes = payload.serialize_to_vec();
            let parsed = TransactionPayload::consensus_deserialize(&mut &bytes[..]).unwrap();
            assert_eq!(parsed, payload);
        }

        // deserialization must reject oversized code
        let oversized = TransactionPayload::EvmPublish(TransactionEvmPublish {
            gas_limit: 1,
            value: 0,
            code: vec![0u8; (MAX_EVM_CODE_LEN + 1) as usize],
        });
        let bytes = oversized.serialize_to_vec();
        assert!(TransactionPayload::consensus_deserialize(&mut &bytes[..]).is_err());
    }

    #[test]
    fn evm_publish_call_and_read() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let origin = PrincipalData::from(addr.clone());

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([1u8; 20]),
            &BlockHeaderHash([1u8; 32]),
        );

        // 1: publish the storage contract
        let publish_tx = make_evm_tx(&privk, 0, publish_payload(1_000_000, 0, STORAGE_INIT_CODE));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &publish_tx, false, None).unwrap();

        let created_bytes = expect_ok_buff(&receipt);
        assert_eq!(created_bytes.len(), 20);
        assert!(receipt.vm_error.is_none());

        // the create address is the standard EVM CREATE address for
        // (sender, evm_nonce = 0)
        let caller_evm = principal_to_evm_address(&origin);
        let expected = caller_evm.create(0);
        assert_eq!(&created_bytes[..], expected.as_slice());
        let contract = Hash160(expected.0 .0);

        // gas was charged as runtime cost (at least the intrinsic 21k gas)
        assert!(receipt.execution_cost.runtime >= 21_000 * EVM_GAS_TO_RUNTIME);

        // the sender's EVM nonce advanced, and the contract's code was stored
        conn.connection().as_transaction(|tx_conn| {
            tx_conn
                .with_clarity_db(|db| {
                    let nonce: Option<String> = db.get_data(&evm_nonce_key(&caller_evm))?;
                    assert_eq!(nonce.as_deref(), Some("1"));
                    let code: Option<String> = db.get_data(&evm_code_key(&expected))?;
                    let code = code.expect("contract code must be stored");
                    assert!(code.ends_with("60206000f3"));
                    Ok(())
                })
                .unwrap()
        });

        // 2: write 0x..2a into slot 0, expect the log event
        let mut word = vec![0u8; 32];
        word[31] = 0x2a;
        let write_tx = make_evm_tx(
            &privk,
            1,
            call_payload(&contract, 1_000_000, 0, word.clone()),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &write_tx, false, None).unwrap();
        expect_ok_buff(&receipt);
        assert_eq!(receipt.events.len(), 1);
        match &receipt.events[0] {
            StacksTransactionEvent::SmartContractEvent(event) => {
                assert_eq!(event.key.1, "evm-log");
                let payload = match &event.value {
                    Value::Sequence(clarity::vm::types::SequenceData::Buffer(buff)) => &buff.data,
                    other => panic!("expected buff event payload, got {other:?}"),
                };
                // one topic (our constant), and the stored word as the data
                assert_eq!(payload[0], 1);
                assert_eq!(&payload[1..33], &LOG_TOPIC);
                assert_eq!(&payload[33..], word.as_slice());
                assert_eq!(payload.len(), 65);
            }
            other => panic!("expected smart contract event, got {other:?}"),
        }

        // 3: read slot 0 back in a separate transaction
        let read_tx = make_evm_tx(&privk, 2, call_payload(&contract, 1_000_000, 0, vec![]));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &read_tx, false, None).unwrap();
        let returned = expect_ok_buff(&receipt);
        assert_eq!(returned, word);

        conn.commit_block();
    }

    #[test]
    fn evm_value_transfer_moves_stx() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let origin = PrincipalData::from(addr.clone());

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([2u8; 20]),
            &BlockHeaderHash([2u8; 32]),
        );

        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &origin, 10_000);
        });

        // publish with a 1000 uSTX endowment
        let publish_tx = make_evm_tx(
            &privk,
            0,
            publish_payload(1_000_000, 1_000, STORAGE_INIT_CODE),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &publish_tx, false, None).unwrap();
        let created_bytes = expect_ok_buff(&receipt);
        let contract = Hash160(created_bytes.as_slice().try_into().unwrap());
        let contract_principal =
            evm_address_to_principal(&Address::from(contract.0.clone()), false);

        let sender_account = StacksChainState::get_account(&mut conn, &origin);
        assert_eq!(sender_account.stx_balance.amount_unlocked(), 9_000);
        let contract_account = StacksChainState::get_account(&mut conn, &contract_principal);
        assert_eq!(contract_account.stx_balance.amount_unlocked(), 1_000);

        // call with msg.value = 500 (the contract is payable)
        let call_tx = make_evm_tx(&privk, 1, call_payload(&contract, 1_000_000, 500, vec![]));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &call_tx, false, None).unwrap();
        expect_ok_buff(&receipt);

        let sender_account = StacksChainState::get_account(&mut conn, &origin);
        assert_eq!(sender_account.stx_balance.amount_unlocked(), 8_500);
        let contract_account = StacksChainState::get_account(&mut conn, &contract_principal);
        assert_eq!(contract_account.stx_balance.amount_unlocked(), 1_500);

        // a transfer of more than the sender's balance must fail and move
        // nothing
        let overdraw_tx = make_evm_tx(
            &privk,
            2,
            call_payload(&contract, 1_000_000, 50_000, vec![]),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &overdraw_tx, false, None).unwrap();
        expect_err(&receipt);

        let sender_account = StacksChainState::get_account(&mut conn, &origin);
        assert_eq!(sender_account.stx_balance.amount_unlocked(), 8_500);
        assert_eq!(sender_account.nonce, 3);

        conn.commit_block();
    }

    #[test]
    fn evm_revert_and_out_of_gas() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let origin = PrincipalData::from(addr.clone());

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([3u8; 20]),
            &BlockHeaderHash([3u8; 32]),
        );

        // publish the always-revert contract
        let publish_tx = make_evm_tx(&privk, 0, publish_payload(1_000_000, 0, REVERT_INIT_CODE));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &publish_tx, false, None).unwrap();
        let created_bytes = expect_ok_buff(&receipt);
        let revert_contract = Hash160(created_bytes.as_slice().try_into().unwrap());

        // calling it reverts: mined, nonce advanced, err result
        let call_tx = make_evm_tx(
            &privk,
            1,
            call_payload(&revert_contract, 1_000_000, 0, vec![]),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &call_tx, false, None).unwrap();
        expect_err(&receipt);
        assert!(receipt.vm_error.is_some());
        let account = StacksChainState::get_account(&mut conn, &origin);
        assert_eq!(account.nonce, 2);

        // out of gas: publish the storage contract, then call the write path
        // with too little gas for the cold SSTORE
        let publish_tx = make_evm_tx(&privk, 2, publish_payload(1_000_000, 0, STORAGE_INIT_CODE));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &publish_tx, false, None).unwrap();
        let created_bytes = expect_ok_buff(&receipt);
        let storage_contract = Hash160(created_bytes.as_slice().try_into().unwrap());

        let mut word = vec![0u8; 32];
        word[31] = 0x2a;
        let oog_tx = make_evm_tx(&privk, 3, call_payload(&storage_contract, 22_000, 0, word));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &oog_tx, false, None).unwrap();
        expect_err(&receipt);

        // the storage write must not have landed
        let read_tx = make_evm_tx(
            &privk,
            4,
            call_payload(&storage_contract, 1_000_000, 0, vec![]),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &read_tx, false, None).unwrap();
        let returned = expect_ok_buff(&receipt);
        assert_eq!(returned, vec![0u8; 32]);

        conn.commit_block();
    }

    #[test]
    fn evm_epoch_gate() {
        // static epoch validation
        let privk = Secp256k1PrivateKey::random();
        let tx = make_evm_tx(&privk, 0, publish_payload(1_000_000, 0, STORAGE_INIT_CODE));
        assert!(!StacksBlock::validate_transaction_static_epoch(
            &tx,
            StacksEpochId::Epoch32
        ));
        assert!(StacksBlock::validate_transaction_static_epoch(
            &tx,
            StacksEpochId::Epoch33
        ));

        // over-cap gas limit is rejected even when the epoch supports EVM
        let over_cap = make_evm_tx(
            &privk,
            0,
            publish_payload(EVM_TX_GAS_CAP + 1, 0, STORAGE_INIT_CODE),
        );
        assert!(!StacksBlock::validate_transaction_static_epoch(
            &over_cap,
            StacksEpochId::Epoch33
        ));

        // the processing-time defensive check also rejects pre-3.3 epochs
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_32,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([4u8; 20]),
            &BlockHeaderHash([4u8; 32]),
        );
        let res = StacksChainState::process_transaction(&mut conn, &tx, false, None);
        assert!(matches!(res, Err(Error::InvalidStacksTransaction(..))));
        conn.commit_block();
    }

    #[test]
    fn evm_post_conditions_rejected() {
        let privk = Secp256k1PrivateKey::random();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let mut tx = StacksTransaction::new(
            TransactionVersion::Testnet,
            auth,
            publish_payload(1_000_000, 0, STORAGE_INIT_CODE),
        );
        tx.chain_id = 0x80000000;
        tx.post_condition_mode = TransactionPostConditionMode::Allow;
        tx.post_conditions.push(TransactionPostCondition::STX(
            PostConditionPrincipal::Origin,
            FungibleConditionCode::SentLe,
            1,
        ));
        tx.set_tx_fee(0);
        let mut signer = StacksTransactionSigner::new(&tx);
        signer.sign_origin(&privk).unwrap();
        let signed_tx = signer.get_tx().unwrap();

        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();
        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([5u8; 20]),
            &BlockHeaderHash([5u8; 32]),
        );
        let res = StacksChainState::process_transaction(&mut conn, &signed_tx, false, None);
        assert!(matches!(res, Err(Error::InvalidStacksTransaction(..))));
        conn.commit_block();
    }

    #[test]
    fn evm_clarity_read_precompile_direct() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let contract_id = format!("{addr}.{CLARITY_TARGET_NAME}");

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([6u8; 20]),
            &BlockHeaderHash([6u8; 32]),
        );

        // deploy the Clarity fixture contract with a normal contract-publish
        let deploy_tx = make_evm_tx(
            &privk,
            0,
            TransactionPayload::new_smart_contract(CLARITY_TARGET_NAME, CLARITY_TARGET_CODE, None)
                .unwrap(),
        );
        StacksChainState::process_transaction(&mut conn, &deploy_tx, false, None).unwrap();

        // uint round trip: add-forty(2) == u42
        let tx = make_evm_tx(
            &privk,
            1,
            clarity_read_payload(&contract_id, "add-forty", &word_u128(2)),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        assert_eq!(expect_ok_buff(&receipt), word_u128(42));

        // response unwrapping: checked(true) -> (ok u7) -> returndata u7
        let mut flag_true = vec![0u8; 32];
        flag_true[31] = 1;
        let tx = make_evm_tx(
            &privk,
            2,
            clarity_read_payload(&contract_id, "checked", &flag_true),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        assert_eq!(expect_ok_buff(&receipt), word_u128(7));

        // response unwrapping: checked(false) -> (err u99) -> revert with u99
        let tx = make_evm_tx(
            &privk,
            3,
            clarity_read_payload(&contract_id, "checked", &vec![0u8; 32]),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        assert_eq!(expect_err_buff(&receipt), word_u128(99));

        // principal <-> address round trip
        let caller_evm = principal_to_evm_address(&PrincipalData::from(addr.clone()));
        let mut principal_arg = vec![0u8; 32];
        principal_arg[12..32].copy_from_slice(caller_evm.as_slice());
        let tx = make_evm_tx(
            &privk,
            4,
            clarity_read_payload(&contract_id, "echo-principal", &principal_arg),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        assert_eq!(expect_ok_buff(&receipt), principal_arg);

        // buff round trip (dynamic argument and dynamic return)
        let buff_data = vec![0xab; 33];
        let args = abi_bytes_arg(&buff_data);
        let tx = make_evm_tx(
            &privk,
            5,
            clarity_read_payload(&contract_id, "echo-buff", &args),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        assert_eq!(expect_ok_buff(&receipt), args);

        // a write-attempting public function is rejected as not read-only,
        // surfaced as a revert with an Error(string) payload
        let tx = make_evm_tx(&privk, 6, clarity_read_payload(&contract_id, "bump", &[]));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        let revert_data = expect_err_buff(&receipt);
        assert_eq!(&revert_data[..4], &[0x08, 0xc3, 0x79, 0xa0]);

        // unknown contract is a clean failure, not a panic
        let tx = make_evm_tx(
            &privk,
            7,
            clarity_read_payload(&format!("{addr}.nonexistent"), "add-forty", &word_u128(2)),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        let revert_data = expect_err_buff(&receipt);
        assert_eq!(&revert_data[..4], &[0x08, 0xc3, 0x79, 0xa0]);

        // the counter variable must not have been bumped
        conn.connection().as_transaction(|tx_conn| {
            tx_conn
                .with_clarity_db(|db| {
                    let contract =
                        QualifiedContractIdentifier::parse(&contract_id).expect("valid id");
                    let epoch = db.get_clarity_epoch_version()?;
                    let counter =
                        db.lookup_variable_unknown_descriptor(&contract, "counter", &epoch)?;
                    assert_eq!(counter, Value::UInt(0));
                    Ok(())
                })
                .unwrap()
        });

        conn.commit_block();
    }

    #[test]
    fn evm_clarity_read_precompile_via_contract() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let contract_id = format!("{addr}.{CLARITY_TARGET_NAME}");

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([7u8; 20]),
            &BlockHeaderHash([7u8; 32]),
        );

        // deploy the Clarity fixture and the EVM forwarder contract
        let deploy_tx = make_evm_tx(
            &privk,
            0,
            TransactionPayload::new_smart_contract(CLARITY_TARGET_NAME, CLARITY_TARGET_CODE, None)
                .unwrap(),
        );
        StacksChainState::process_transaction(&mut conn, &deploy_tx, false, None).unwrap();

        let init_code = forwarder_init_code(&CLARITY_READ_PRECOMPILE);
        let publish_tx = make_evm_tx(
            &privk,
            1,
            TransactionPayload::EvmPublish(TransactionEvmPublish {
                gas_limit: 1_000_000,
                value: 0,
                code: init_code,
            }),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &publish_tx, false, None).unwrap();
        let forwarder = Hash160(expect_ok_buff(&receipt).as_slice().try_into().unwrap());

        // an EVM contract calling into Clarity: forwarder -> precompile ->
        // add-forty(2) == u42
        let calldata = abi::encode_call_input(&contract_id, "add-forty", &word_u128(2));
        let tx = make_evm_tx(&privk, 2, call_payload(&forwarder, 1_000_000, 0, calldata));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        assert_eq!(expect_ok_buff(&receipt), word_u128(42));

        // the (err ...) path bubbles through the intermediate contract too
        let calldata = abi::encode_call_input(&contract_id, "checked", &vec![0u8; 32]);
        let tx = make_evm_tx(&privk, 3, call_payload(&forwarder, 1_000_000, 0, calldata));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        assert_eq!(expect_err_buff(&receipt), word_u128(99));

        conn.commit_block();
    }

    /// Clarity contract that drives the EVM through `evm-call?`.
    const CLARITY_CALLER_NAME: &str = "evm-caller";
    const CLARITY_CALLER_CODE: &str = r#"
(define-data-var marker uint u0)
(define-public (call-evm (addr (buff 20)) (calldata (buff 1024)) (value uint))
  (evm-call? addr calldata value u1000000))
(define-public (call-evm-swallow (addr (buff 20)) (calldata (buff 1024)) (value uint))
  (begin
    (var-set marker u1)
    (match (evm-call? addr calldata value u1000000)
      ok-data (ok u0)
      err-data (ok u1))))
(define-public (call-evm-propagate (addr (buff 20)) (calldata (buff 1024)) (value uint))
  (begin
    (var-set marker u2)
    (unwrap! (evm-call? addr calldata value u1000000) (err u500))
    (ok u0)))
;; the shape the demo uses: print the EVM's response, then pass it through
(define-public (call-evm-print (addr (buff 20)) (calldata (buff 1024)) (value uint))
  (match (evm-call? addr calldata value u1000000)
    returned (begin (print { evm-returned: returned }) (ok returned))
    reverted (begin (print { evm-reverted: reverted }) (err reverted))))
"#;

    /// Build a contract-call payload invoking the Clarity caller contract.
    fn caller_payload(
        caller_id: &str,
        function: &str,
        target: &Hash160,
        calldata: Vec<u8>,
        value: u128,
    ) -> TransactionPayload {
        let contract_id = QualifiedContractIdentifier::parse(caller_id).unwrap();
        TransactionPayload::ContractCall(crate::chainstate::stacks::TransactionContractCall {
            address: stacks_common::types::chainstate::StacksAddress::new(
                contract_id.issuer.version(),
                Hash160(contract_id.issuer.1),
            )
            .unwrap(),
            contract_name: contract_id.name.clone(),
            function_name: clarity::vm::ClarityName::try_from(function).unwrap(),
            function_args: vec![
                Value::buff_from(target.0.to_vec()).unwrap(),
                Value::buff_from(calldata).unwrap(),
                Value::UInt(value),
            ],
        })
    }

    /// Read a `uint` data-var out of a deployed contract.
    fn read_uint_var(
        conn: &mut crate::chainstate::stacks::db::ClarityTx,
        contract_id: &str,
        var: &str,
    ) -> Value {
        let contract = QualifiedContractIdentifier::parse(contract_id).unwrap();
        conn.connection().as_transaction(|tx_conn| {
            tx_conn
                .with_clarity_db(|db| {
                    let epoch = db.get_clarity_epoch_version()?;
                    Ok(db.lookup_variable_unknown_descriptor(&contract, var, &epoch)?)
                })
                .unwrap()
        })
    }

    #[test]
    fn clarity_calls_evm_write_and_value() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let origin = PrincipalData::from(addr.clone());

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([8u8; 20]),
            &BlockHeaderHash([8u8; 32]),
        );

        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &origin, 10_000);
        });

        // deploy the Clarity caller and the EVM vault
        let deploy_tx = make_evm_tx(
            &privk,
            0,
            TransactionPayload::new_smart_contract(CLARITY_CALLER_NAME, CLARITY_CALLER_CODE, None)
                .unwrap(),
        );
        StacksChainState::process_transaction(&mut conn, &deploy_tx, false, None).unwrap();
        let publish_tx = make_evm_tx(&privk, 1, publish_payload(1_000_000, 0, STORAGE_INIT_CODE));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &publish_tx, false, None).unwrap();
        let vault = Hash160(expect_ok_buff(&receipt).as_slice().try_into().unwrap());

        let caller_id = format!("{addr}.{CLARITY_CALLER_NAME}");
        let caller_principal =
            PrincipalData::Contract(QualifiedContractIdentifier::parse(&caller_id).unwrap());

        // fund the calling contract so it can attach value
        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &caller_principal, 5_000);
        });

        // the calling contract's derived EVM principal must NOT be its
        // deployer's principal (the contract-aliasing fix)
        let caller_evm = principal_to_evm_address(&caller_principal);
        assert_ne!(evm_address_to_principal(&caller_evm, false), origin);

        // Clarity -> EVM: store 42 in the vault, attaching 500 uSTX
        let mut word = vec![0u8; 32];
        word[31] = 0x2a;
        let tx = make_evm_tx(
            &privk,
            2,
            caller_payload(&caller_id, "call-evm", &vault, word.clone(), 500),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        let response = match &receipt.result {
            Value::Response(response) => response,
            other => panic!("expected response, got {other:?}"),
        };
        assert!(response.committed, "evm-call? failed: {:?}", receipt.result);

        // the EVM log surfaced as a Clarity transaction event
        assert!(
            receipt.events.iter().any(|e| matches!(
                e,
                StacksTransactionEvent::SmartContractEvent(data) if data.key.1 == "evm-log"
            )),
            "expected an evm-log event"
        );

        // value moved out of the calling contract into the vault's principal
        let vault_principal = evm_address_to_principal(&Address::from(vault.0), false);
        assert_eq!(
            StacksChainState::get_account(&mut conn, &vault_principal)
                .stx_balance
                .amount_unlocked(),
            500
        );
        assert_eq!(
            StacksChainState::get_account(&mut conn, &caller_principal)
                .stx_balance
                .amount_unlocked(),
            4_500
        );

        // the EVM write landed: read slot 0 back with a direct EVM tx
        let read_tx = make_evm_tx(&privk, 3, call_payload(&vault, 1_000_000, 0, vec![]));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &read_tx, false, None).unwrap();
        assert_eq!(expect_ok_buff(&receipt), word);

        // the demo's shape: the Clarity contract `print`s the EVM's response
        // alongside the EVM's own log, so both events reach the event feed
        let mut word2 = vec![0u8; 32];
        word2[31] = 0x63;
        let tx = make_evm_tx(
            &privk,
            4,
            caller_payload(&caller_id, "call-evm-print", &vault, word2.clone(), 0),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        let response = match &receipt.result {
            Value::Response(response) => response,
            other => panic!("expected response, got {other:?}"),
        };
        assert!(
            response.committed,
            "call-evm-print failed: {:?}",
            receipt.result
        );

        let topics: Vec<_> = receipt
            .events
            .iter()
            .filter_map(|e| match e {
                StacksTransactionEvent::SmartContractEvent(data) => Some(data.key.1.as_str()),
                _ => None,
            })
            .collect();
        assert!(
            topics.contains(&"evm-log"),
            "expected the EVM's own log, got {topics:?}"
        );
        assert!(
            topics.contains(&"print"),
            "expected the Clarity print of the EVM response, got {topics:?}"
        );

        conn.commit_block();
    }

    #[test]
    fn clarity_calls_evm_revert_semantics() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let origin = PrincipalData::from(addr.clone());

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([9u8; 20]),
            &BlockHeaderHash([9u8; 32]),
        );

        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &origin, 10_000);
        });

        let deploy_tx = make_evm_tx(
            &privk,
            0,
            TransactionPayload::new_smart_contract(CLARITY_CALLER_NAME, CLARITY_CALLER_CODE, None)
                .unwrap(),
        );
        StacksChainState::process_transaction(&mut conn, &deploy_tx, false, None).unwrap();
        let publish_tx = make_evm_tx(&privk, 1, publish_payload(1_000_000, 0, REVERT_INIT_CODE));
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &publish_tx, false, None).unwrap();
        let guard = Hash160(expect_ok_buff(&receipt).as_slice().try_into().unwrap());

        let caller_id = format!("{addr}.{CLARITY_CALLER_NAME}");
        let caller_principal =
            PrincipalData::Contract(QualifiedContractIdentifier::parse(&caller_id).unwrap());
        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &caller_principal, 5_000);
        });

        // swallowing the err keeps the Clarity transaction alive, and the
        // attempted value transfer is rolled back
        let tx = make_evm_tx(
            &privk,
            2,
            caller_payload(&caller_id, "call-evm-swallow", &guard, vec![], 700),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        assert_eq!(receipt.result, Value::okay(Value::UInt(1)).unwrap());
        assert_eq!(
            StacksChainState::get_account(&mut conn, &caller_principal)
                .stx_balance
                .amount_unlocked(),
            5_000,
            "value transfer must be rolled back"
        );

        // the swallowing branch's own write did commit, proving only the EVM
        // sub-call was rolled back
        assert_eq!(
            read_uint_var(&mut conn, &caller_id, "marker"),
            Value::UInt(1)
        );

        // propagating the err aborts the Clarity function: its marker write
        // is rolled back too
        let tx = make_evm_tx(
            &privk,
            3,
            caller_payload(&caller_id, "call-evm-propagate", &guard, vec![], 700),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        let response = match &receipt.result {
            Value::Response(response) => response,
            other => panic!("expected response, got {other:?}"),
        };
        assert!(!response.committed);
        assert_eq!(
            read_uint_var(&mut conn, &caller_id, "marker"),
            Value::UInt(1),
            "propagated err must roll back the whole Clarity call"
        );
        assert_eq!(
            StacksChainState::get_account(&mut conn, &caller_principal)
                .stx_balance
                .amount_unlocked(),
            5_000
        );

        conn.commit_block();
    }

    #[test]
    fn clarity_calls_evm_nested_bridge_blocked() {
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();
        let auth = TransactionAuth::from_p2pkh(&privk).unwrap();
        let addr = auth.origin().address_testnet();
        let origin = PrincipalData::from(addr.clone());

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([10u8; 20]),
            &BlockHeaderHash([10u8; 32]),
        );

        conn.connection().as_transaction(|tx| {
            StacksChainState::account_credit(tx, &origin, 10_000);
        });

        let deploy_tx = make_evm_tx(
            &privk,
            0,
            TransactionPayload::new_smart_contract(CLARITY_CALLER_NAME, CLARITY_CALLER_CODE, None)
                .unwrap(),
        );
        StacksChainState::process_transaction(&mut conn, &deploy_tx, false, None).unwrap();
        let deploy_tx = make_evm_tx(
            &privk,
            1,
            TransactionPayload::new_smart_contract(CLARITY_TARGET_NAME, CLARITY_TARGET_CODE, None)
                .unwrap(),
        );
        StacksChainState::process_transaction(&mut conn, &deploy_tx, false, None).unwrap();

        let publish_tx = make_evm_tx(
            &privk,
            2,
            TransactionPayload::EvmPublish(TransactionEvmPublish {
                gas_limit: 1_000_000,
                value: 0,
                code: forwarder_init_code(&CLARITY_READ_PRECOMPILE),
            }),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &publish_tx, false, None).unwrap();
        let forwarder = Hash160(expect_ok_buff(&receipt).as_slice().try_into().unwrap());

        // Clarity -> EVM -> (clarity-read) must revert cleanly rather than
        // recursing back into the Clarity VM
        let caller_id = format!("{addr}.{CLARITY_CALLER_NAME}");
        let target_id = format!("{addr}.{CLARITY_TARGET_NAME}");
        let calldata = abi::encode_call_input(&target_id, "add-forty", &word_u128(2));
        let tx = make_evm_tx(
            &privk,
            3,
            caller_payload(&caller_id, "call-evm", &forwarder, calldata, 0),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &tx, false, None).unwrap();
        let response = match &receipt.result {
            Value::Response(response) => response,
            other => panic!("expected response, got {other:?}"),
        };
        assert!(
            !response.committed,
            "nested clarity-read must revert, got {:?}",
            receipt.result
        );

        conn.commit_block();
    }

    #[test]
    fn clarity_evm_call_version_gated() {
        // `evm-call?` is a Clarity 4 keyword: a Clarity 3 contract using it
        // must fail analysis
        let mut chainstate = TestChainstateBuilder::new_testnet(function_name!()).build();

        let privk = StacksPrivateKey::from_hex(
            "6d430bb91222408e7706c9001cfaeb91b08c2be6d5ac95779ab52c6b431950e001",
        )
        .unwrap();

        let mut conn = chainstate.block_begin(
            &TestBurnStateDB_33,
            &FIRST_BURNCHAIN_CONSENSUS_HASH,
            &FIRST_STACKS_BLOCK_HASH,
            &ConsensusHash([11u8; 20]),
            &BlockHeaderHash([11u8; 32]),
        );

        let deploy_tx = make_evm_tx(
            &privk,
            0,
            TransactionPayload::new_smart_contract(
                CLARITY_CALLER_NAME,
                CLARITY_CALLER_CODE,
                Some(clarity::vm::ClarityVersion::Clarity3),
            )
            .unwrap(),
        );
        let (_, receipt) =
            StacksChainState::process_transaction(&mut conn, &deploy_tx, false, None).unwrap();
        assert!(
            receipt.vm_error.is_some(),
            "evm-call? must not analyze under Clarity 3: {:?}",
            receipt.result
        );

        conn.commit_block();
    }
}
