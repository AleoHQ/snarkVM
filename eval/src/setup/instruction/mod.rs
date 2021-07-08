// Copyright (C) 2019-2021 Aleo Systems Inc.
// This file is part of the snarkVM library.

// The snarkVM library is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The snarkVM library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with the snarkVM library. If not, see <https://www.gnu.org/licenses/>.

use std::{borrow::Cow, convert::TryInto};

use im::HashMap;
use snarkvm_fields::PrimeField;
use snarkvm_gadgets::{
    integers::{UInt16, UInt32, UInt8},
    Boolean,
    CondSelectGadget,
    EqGadget,
    EvaluateEqGadget,
    Integer as IntegerTrait,
};
use snarkvm_ir::{
    ArrayInitRepeatData,
    CallCoreData,
    CallData,
    Instruction,
    Integer as IrInteger,
    LogData,
    LogLevel,
    PredicateData,
    QueryData,
    Value,
    VarData,
};
use snarkvm_r1cs::ConstraintSystem;

use crate::{
    errors::{ArrayError, ValueError},
    operations,
    ConstrainedValue,
    GroupType,
    Integer,
};

use anyhow::*;

use super::EvaluatorState;

mod array_index_get;
mod array_index_store;
mod array_slice_get;
mod array_slice_store;
mod core;

impl<'a, F: PrimeField, G: GroupType<F>, CS: ConstraintSystem<F>> EvaluatorState<'a, F, G, CS> {
    fn resolve_binary(&mut self, data: &QueryData<2>) -> Result<(ConstrainedValue<F, G>, ConstrainedValue<F, G>)> {
        let left = self.resolve(data.values.get(0).unwrap())?.into_owned();
        let right = self.resolve(data.values.get(1).unwrap())?.into_owned();
        Ok((left, right))
    }

    /// Evaluates a single instruction in the local [`EvaluatorState`] context. Panics if `instruction` is a control instruction.
    pub(super) fn evaluate_instruction(&mut self, instruction: &Instruction) -> Result<Option<ConstrainedValue<F, G>>> {
        match instruction {
            Instruction::Add(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::enforce_add(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Sub(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::enforce_sub(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Mul(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::enforce_mul(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Div(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::enforce_div(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Pow(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::enforce_pow(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Or(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::enforce_or(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::And(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::enforce_and(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Eq(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::evaluate_eq(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Ne(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::evaluate_not(operations::evaluate_eq(&mut self.cs(), left, right)?)?;
                self.store(data.destination, out);
            }
            Instruction::Ge(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::evaluate_ge(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Gt(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::evaluate_gt(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Le(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::evaluate_le(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::Lt(data) => {
                let (left, right) = self.resolve_binary(data)?;
                let out = operations::evaluate_lt(&mut self.cs(), left, right)?;
                self.store(data.destination, out);
            }
            Instruction::BitOr(_) => return Err(anyhow!("BitOr unimplemented")),
            Instruction::BitAnd(_) => return Err(anyhow!("BitAnd unimplemented")),
            Instruction::BitXor(_) => return Err(anyhow!("BitXor unimplemented")),
            Instruction::Shr(_) => return Err(anyhow!("Shr unimplemented")),
            Instruction::ShrSigned(_) => return Err(anyhow!("ShrSigned unimplemented")),
            Instruction::Shl(_) => return Err(anyhow!("Shl unimplemented")),
            Instruction::Mod(_) => return Err(anyhow!("Mod unimplemented")),
            Instruction::Not(QueryData { destination, values }) => {
                let inner = self.resolve(values.get(0).unwrap())?.into_owned();
                let out = operations::evaluate_not(inner)?;
                self.store(*destination, out);
            }
            Instruction::Negate(QueryData { destination, values }) => {
                let inner = self.resolve(values.get(0).unwrap())?.into_owned();
                let out = operations::enforce_negate(&mut self.cs(), inner)?;
                self.store(*destination, out);
            }
            Instruction::BitNot(_) => return Err(anyhow!("BitNot unimplemented")),
            Instruction::ArrayInitRepeat(ArrayInitRepeatData {
                destination,
                length,
                value,
            }) => {
                let inner = self.resolve(value)?.into_owned();
                // todo: max array length (DOS vector)
                let array = ConstrainedValue::Array(vec![inner; *length as usize]);
                self.store(*destination, array);
            }
            Instruction::ArrayInit(VarData { destination, values }) => {
                let mut inner = Vec::with_capacity(values.len());
                for value in values {
                    let value = self.resolve(value)?.into_owned();
                    match value {
                        ConstrainedValue::Array(values) => {
                            for value in values {
                                inner.push(value);
                            }
                        }
                        value => {
                            inner.push(value);
                        }
                    }
                }
                //todo: optionally assert same type
                let array = ConstrainedValue::Array(inner);
                self.store(*destination, array);
            }
            instruction @ Instruction::ArrayIndexGet(_) => {
                self.evaluate_array_index_get(instruction)?;
            }
            instruction @ Instruction::ArraySliceGet(_) => {
                self.evaluate_array_slice_get(instruction)?;
            }
            instruction @ Instruction::ArrayIndexStore(_) => {
                self.evaluate_array_index_store(instruction)?;
            }
            instruction @ Instruction::ArraySliceStore(_) => {
                self.evaluate_array_slice_store(instruction)?;
            }
            Instruction::TupleInit(VarData { destination, values }) => {
                let mut inner = Vec::with_capacity(values.len());
                for value in values {
                    inner.push(self.resolve(value)?.into_owned());
                }
                let array = ConstrainedValue::Tuple(inner);
                self.store(*destination, array);
            }
            Instruction::TupleIndexGet(QueryData { destination, values }) => {
                let index = self
                    .resolve(values.get(1).unwrap())?
                    .extract_integer()
                    .map_err(|value| anyhow!("invalid index type for tuple index: {}", value))?
                    .to_usize()
                    .ok_or_else(|| anyhow!("illegal variable input for tuple index"))?;

                let tuple = self.resolve(values.get(0).unwrap())?;
                let tuple = tuple
                    .extract_tuple()
                    .map_err(|value| anyhow!("invalid tuple type for tuple index: {}", value))?;

                let out = tuple
                    .get(index)
                    .ok_or_else(|| {
                        anyhow!(
                            "illegal index {} into tuple of length {} for tuple index",
                            index,
                            tuple.len()
                        )
                    })?
                    .clone();

                self.store(*destination, out);
            }
            Instruction::TupleIndexStore(QueryData { destination, values }) => {
                let index = self
                    .resolve(values.get(0).unwrap())?
                    .extract_integer()
                    .map_err(|value| anyhow!("invalid index type for tuple store: {}", value))?
                    .to_usize()
                    .ok_or_else(|| anyhow!("illegal variable input for tuple store"))?;

                let tuple = self.resolve(&Value::Ref(*destination))?.into_owned();
                let mut tuple = tuple
                    .extract_tuple()
                    .map_err(|value| anyhow!("invalid tuple type for tuple store: {}", value))?
                    .clone();

                let tuple_len = tuple.len();
                let out = tuple.get_mut(index).ok_or_else(|| {
                    anyhow!(
                        "illegal index {} into tuple of length {} for tuple store",
                        index,
                        tuple_len
                    )
                })?;
                *out = self.resolve(values.get(1).unwrap())?.into_owned();

                self.store(*destination, ConstrainedValue::Tuple(tuple));
            }
            Instruction::Pick(QueryData { destination, values }) => {
                let condition = self.resolve(values.get(0).unwrap())?.into_owned();
                let condition = condition
                    .extract_bool()
                    .map_err(|value| anyhow!("invalid value for pick condition: {}", value))?;
                let left = self.resolve(values.get(1).unwrap())?.into_owned();
                let right = self.resolve(values.get(2).unwrap())?.into_owned();
                let picked = ConstrainedValue::conditionally_select(&mut self.cs(), &condition, &left, &right)?;
                self.store(*destination, picked);
            }
            Instruction::Mask(_) => {
                panic!("cannot eval mask instructions directly");
            }
            Instruction::Repeat(_) => {
                panic!("cannot eval repeat instructions directly");
            }
            Instruction::Store(QueryData { destination, values }) => {
                let value = self.resolve(values.get(0).unwrap())?.into_owned();
                self.store(*destination, value);
            }
            Instruction::Call(CallData {
                destination,
                index,
                arguments,
            }) => {
                let arguments = arguments
                    .iter()
                    .map(|x| self.resolve(x).map(|x| x.into_owned()))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut inner_state = HashMap::new();
                let output = self.child(
                    "function call",
                    |state| state.evaluate_function(*index as usize, &arguments[..]),
                    &mut inner_state,
                )?;
                // drop inner_state as we do not care about inner function state

                self.store(*destination, output);
            }
            Instruction::Return(PredicateData { values }) => {
                let value = values.get(0).unwrap();
                let value = self.resolve(value)?.into_owned();
                return Ok(Some(value));
            }
            Instruction::Assert(PredicateData { values }) => {
                let value = values.get(0).unwrap();
                let value = self.resolve(value)?.into_owned();
                match value {
                    ConstrainedValue::Boolean(b) => {
                        if b.is_allocated() {
                            tracing::warn!("input based assertion");
                        }
                        if !b
                            .get_value()
                            .ok_or_else(|| anyhow!("cannot have input-based assertion with no known value"))?
                        {
                            return Err(anyhow!("assertion failed"));
                        }
                    }
                    _ => return Err(anyhow!("invalid type for assertion, expected boolean")),
                }
            }
            Instruction::Log(LogData { log_level, parts }) => {
                let mut out = String::new();
                for part in parts {
                    match part {
                        Value::Str(s) => out += &**s,
                        x => out += &*x.to_string(),
                    }
                }
                match log_level {
                    LogLevel::Error => tracing::error!("{}", out),
                    LogLevel::Info => tracing::info!("{}", out),
                    LogLevel::Debug => tracing::debug!("{}", out),
                }
            }
            Instruction::CallCore(CallCoreData {
                destination,
                identifier,
                arguments,
            }) => {
                let arguments = arguments
                    .iter()
                    .map(|x| self.resolve(x).map(Cow::into_owned))
                    .collect::<Result<Vec<_>>>()?;

                let out = self.call_core(&**identifier, &arguments[..])?;
                self.store(*destination, out);
            }
        }
        Ok(None)
    }
}
