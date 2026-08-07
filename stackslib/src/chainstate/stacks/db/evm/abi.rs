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

//! Minimal Solidity-ABI codec for the Clarity precompiles.
//!
//! The calling convention between Solidity and Clarity:
//! - The precompile input is `abi.encode(string contractId, string
//!   functionName, bytes args)`, where `args` is itself the ABI encoding of
//!   the function's arguments per the mapping below.
//! - Clarity argument types are looked up from the target function's
//!   definition, and each ABI argument is decoded against them:
//!
//!   | Clarity           | Solidity  |
//!   |-------------------|-----------|
//!   | `uint`            | `uint128` |
//!   | `int`             | `int128`  |
//!   | `bool`            | `bool`    |
//!   | `principal`       | `address` |
//!   | `(buff N)`        | `bytes`   |
//!   | `(string-ascii N)`| `string`  |
//!
//! - Return values are encoded with the same mapping, plus
//!   `(optional T)` -> `(bool, T)` for word-sized `T`. Response values are
//!   unwrapped by the caller before encoding (ok -> return data,
//!   err -> revert data).
//!
//! Only this subset is supported; tuples, lists, and nested sequences are
//! rejected. This is a hackathon-grade convention, not a general bridge.

use clarity::vm::types::{
    OptionalData, PrincipalData, SequenceData, SequenceSubtype, StringSubtype, TypeSignature,
};
use clarity::vm::Value;
use revm::primitives::Address;

use super::evm_address_to_principal;

/// 4-byte selector of Solidity's `Error(string)`, used to encode failure
/// messages so `require`-style tooling can decode them.
const ERROR_STRING_SELECTOR: [u8; 4] = [0x08, 0xc3, 0x79, 0xa0];

/// Cap on any single dynamic element we will decode, to bound allocation.
const MAX_DYNAMIC_LEN: usize = 1024 * 1024;

fn read_word(data: &[u8], offset: usize) -> Result<[u8; 32], String> {
    let slice = data
        .get(offset..offset + 32)
        .ok_or_else(|| format!("ABI input truncated at offset {offset}"))?;
    let mut word = [0u8; 32];
    word.copy_from_slice(slice);
    Ok(word)
}

/// Read a word that encodes an offset or length; must fit in usize and be
/// bounded by the input size to prevent huge allocations.
fn read_usize(data: &[u8], offset: usize) -> Result<usize, String> {
    let word = read_word(data, offset)?;
    if word[..24].iter().any(|b| *b != 0) {
        return Err("ABI offset/length word out of range".into());
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&word[24..32]);
    let value = u64::from_be_bytes(buf) as usize;
    if value > MAX_DYNAMIC_LEN.max(data.len()) {
        return Err("ABI offset/length exceeds input size".into());
    }
    Ok(value)
}

/// Read a dynamic element (`bytes` / `string`) whose tail starts at `offset`.
fn read_dynamic(data: &[u8], offset: usize) -> Result<Vec<u8>, String> {
    let len = read_usize(data, offset)?;
    if len > MAX_DYNAMIC_LEN {
        return Err("ABI dynamic element too large".into());
    }
    data.get(offset + 32..offset + 32 + len)
        .map(|slice| slice.to_vec())
        .ok_or_else(|| "ABI dynamic element truncated".into())
}

fn pad32_len(len: usize) -> usize {
    len.div_ceil(32) * 32
}

fn push_padded(out: &mut Vec<u8>, data: &[u8]) {
    out.extend_from_slice(data);
    out.resize(out.len() + (pad32_len(data.len()) - data.len()), 0);
}

fn push_usize_word(out: &mut Vec<u8>, value: usize) {
    let mut word = [0u8; 32];
    word[24..32].copy_from_slice(&(value as u64).to_be_bytes());
    out.extend_from_slice(&word);
}

/// Decode the precompile call input: `abi.encode(string contractId, string
/// functionName, bytes args)`.
pub fn decode_call_input(input: &[u8]) -> Result<(String, String, Vec<u8>), String> {
    let contract_offset = read_usize(input, 0)?;
    let function_offset = read_usize(input, 32)?;
    let args_offset = read_usize(input, 64)?;

    let contract_id = String::from_utf8(read_dynamic(input, contract_offset)?)
        .map_err(|_| "contract id is not valid UTF-8".to_string())?;
    let function = String::from_utf8(read_dynamic(input, function_offset)?)
        .map_err(|_| "function name is not valid UTF-8".to_string())?;
    let args = read_dynamic(input, args_offset)?;
    Ok((contract_id, function, args))
}

/// Encode a precompile call input (used by tests and client tooling).
pub fn encode_call_input(contract_id: &str, function: &str, args: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let contract_offset = 96;
    let function_offset = contract_offset + 32 + pad32_len(contract_id.len());
    let args_offset = function_offset + 32 + pad32_len(function.len());
    push_usize_word(&mut out, contract_offset);
    push_usize_word(&mut out, function_offset);
    push_usize_word(&mut out, args_offset);
    push_usize_word(&mut out, contract_id.len());
    push_padded(&mut out, contract_id.as_bytes());
    push_usize_word(&mut out, function.len());
    push_padded(&mut out, function.as_bytes());
    push_usize_word(&mut out, args.len());
    push_padded(&mut out, args);
    out
}

/// Whether a Clarity type maps to a single static ABI word.
fn is_word_type(ty: &TypeSignature) -> bool {
    matches!(
        ty,
        TypeSignature::UIntType
            | TypeSignature::IntType
            | TypeSignature::BoolType
            | TypeSignature::PrincipalType
    )
}

fn decode_word_value(ty: &TypeSignature, word: &[u8; 32], mainnet: bool) -> Result<Value, String> {
    match ty {
        TypeSignature::UIntType => {
            if word[..16].iter().any(|b| *b != 0) {
                return Err("uint argument exceeds 128 bits".into());
            }
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&word[16..32]);
            Ok(Value::UInt(u128::from_be_bytes(buf)))
        }
        TypeSignature::IntType => {
            let negative = word[16] & 0x80 != 0;
            let expected_fill = if negative { 0xff } else { 0x00 };
            if word[..16].iter().any(|b| *b != expected_fill) {
                return Err("int argument exceeds 128 bits".into());
            }
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&word[16..32]);
            Ok(Value::Int(i128::from_be_bytes(buf)))
        }
        TypeSignature::BoolType => {
            if word[..31].iter().any(|b| *b != 0) || word[31] > 1 {
                return Err("bool argument is not 0 or 1".into());
            }
            Ok(Value::Bool(word[31] == 1))
        }
        TypeSignature::PrincipalType => {
            if word[..12].iter().any(|b| *b != 0) {
                return Err("address argument has nonzero padding".into());
            }
            let mut bytes = [0u8; 20];
            bytes.copy_from_slice(&word[12..32]);
            Ok(Value::Principal(evm_address_to_principal(
                &Address::from(bytes),
                mainnet,
            )))
        }
        _ => Err(format!("Clarity type {ty} is not word-sized")),
    }
}

/// Decode an ABI-encoded argument blob against the target function's
/// declared Clarity argument types.
pub fn decode_clarity_args(
    arg_types: &[TypeSignature],
    data: &[u8],
    mainnet: bool,
) -> Result<Vec<Value>, String> {
    let mut values = Vec::with_capacity(arg_types.len());
    for (i, ty) in arg_types.iter().enumerate() {
        let head = 32 * i;
        if is_word_type(ty) {
            values.push(decode_word_value(ty, &read_word(data, head)?, mainnet)?);
            continue;
        }
        match ty {
            TypeSignature::SequenceType(SequenceSubtype::BufferType(max_len)) => {
                let offset = read_usize(data, head)?;
                let bytes = read_dynamic(data, offset)?;
                if bytes.len() > u32::from(max_len) as usize {
                    return Err(format!("buff argument {i} exceeds declared max length"));
                }
                values.push(Value::buff_from(bytes).map_err(|e| e.to_string())?);
            }
            TypeSignature::SequenceType(SequenceSubtype::StringType(StringSubtype::ASCII(
                max_len,
            ))) => {
                let offset = read_usize(data, head)?;
                let bytes = read_dynamic(data, offset)?;
                if bytes.len() > u32::from(max_len) as usize {
                    return Err(format!("string argument {i} exceeds declared max length"));
                }
                values.push(Value::string_ascii_from_bytes(bytes).map_err(|e| e.to_string())?);
            }
            other => {
                return Err(format!(
                    "Clarity argument type {other} is not supported by the EVM calling convention"
                ));
            }
        }
    }
    Ok(values)
}

fn encode_word_value(value: &Value) -> Result<[u8; 32], String> {
    let mut word = [0u8; 32];
    match value {
        Value::UInt(u) => word[16..32].copy_from_slice(&u.to_be_bytes()),
        Value::Int(i) => {
            if *i < 0 {
                word[..16].fill(0xff);
            }
            word[16..32].copy_from_slice(&i.to_be_bytes());
        }
        Value::Bool(b) => word[31] = u8::from(*b),
        Value::Principal(PrincipalData::Standard(standard)) => {
            word[12..32].copy_from_slice(&standard.1);
        }
        Value::Principal(PrincipalData::Contract(..)) => {
            return Err("contract principals cannot be represented as EVM addresses".to_string());
        }
        other => return Err(format!("Clarity value {other} is not word-sized")),
    }
    Ok(word)
}

/// Encode a Clarity return value to ABI bytes. Response values must be
/// unwrapped by the caller first.
pub fn encode_clarity_value(value: &Value) -> Result<Vec<u8>, String> {
    match value {
        Value::UInt(..) | Value::Int(..) | Value::Bool(..) | Value::Principal(..) => {
            Ok(encode_word_value(value)?.to_vec())
        }
        Value::Sequence(SequenceData::Buffer(buff)) => {
            let mut out = Vec::new();
            push_usize_word(&mut out, 32);
            push_usize_word(&mut out, buff.data.len());
            push_padded(&mut out, &buff.data);
            Ok(out)
        }
        Value::Sequence(SequenceData::String(clarity::vm::types::CharType::ASCII(ascii))) => {
            let mut out = Vec::new();
            push_usize_word(&mut out, 32);
            push_usize_word(&mut out, ascii.data.len());
            push_padded(&mut out, &ascii.data);
            Ok(out)
        }
        Value::Optional(OptionalData { data }) => {
            // encoded as Solidity `(bool present, T value)` for word-sized T
            let mut out = Vec::new();
            match data {
                Some(inner) => {
                    let word = encode_word_value(inner)
                        .map_err(|_| "only word-sized optional values are supported".to_string())?;
                    push_usize_word(&mut out, 1);
                    out.extend_from_slice(&word);
                }
                None => {
                    push_usize_word(&mut out, 0);
                    out.extend_from_slice(&[0u8; 32]);
                }
            }
            Ok(out)
        }
        other => Err(format!(
            "Clarity return type of {other} is not supported by the EVM calling convention"
        )),
    }
}

/// Encode a message as Solidity's canonical `Error(string)` revert payload.
pub fn encode_error_string(msg: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 64 + pad32_len(msg.len()));
    out.extend_from_slice(&ERROR_STRING_SELECTOR);
    push_usize_word(&mut out, 32);
    push_usize_word(&mut out, msg.len());
    push_padded(&mut out, msg.as_bytes());
    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn call_input_roundtrip() {
        let args = vec![0xaa; 33];
        let encoded = encode_call_input("SP123.contract", "my-fn", &args);
        let (contract, function, decoded_args) = decode_call_input(&encoded).unwrap();
        assert_eq!(contract, "SP123.contract");
        assert_eq!(function, "my-fn");
        assert_eq!(decoded_args, args);
    }

    #[test]
    fn word_values_roundtrip() {
        for (ty, value) in [
            (TypeSignature::UIntType, Value::UInt(42)),
            (TypeSignature::IntType, Value::Int(-42)),
            (TypeSignature::IntType, Value::Int(42)),
            (TypeSignature::BoolType, Value::Bool(true)),
        ] {
            let word = encode_word_value(&value).unwrap();
            let decoded = decode_word_value(&ty, &word, false).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn rejects_oversized_uint() {
        let mut word = [0u8; 32];
        word[15] = 1;
        assert!(decode_word_value(&TypeSignature::UIntType, &word, false).is_err());
    }

    #[test]
    fn error_string_shape() {
        let encoded = encode_error_string("boom");
        assert_eq!(&encoded[..4], &ERROR_STRING_SELECTOR);
        assert_eq!(encoded.len(), 4 + 32 + 32 + 32);
    }
}
