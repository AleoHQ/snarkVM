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

use crate::{errors::AddressError, ConstrainedValue, GroupType};

use snarkvm_dpc::{account::AccountAddress, testnet1::instantiated::Components};
use snarkvm_fields::PrimeField;
use snarkvm_gadgets::{
    boolean::Boolean,
    integers::uint::UInt8,
    traits::{
        alloc::AllocGadget,
        eq::{ConditionalEqGadget, EqGadget, EvaluateEqGadget},
        select::CondSelectGadget,
    },
    Integer,
};
use snarkvm_ir::Value;
use snarkvm_r1cs::{Assignment, ConstraintSystem, SynthesisError};
use snarkvm_utilities::{FromBytes, ToBytes};
use std::{borrow::Borrow, str::FromStr};

/// A public address
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Address {
    pub address: AccountAddress<Components>,
    pub bytes: Vec<UInt8>,
}

impl Address {
    pub(crate) fn constant(address_bytes: &[u8]) -> Result<Self, AddressError> {
        let mut address_bytes_reader = address_bytes;
        let address = AccountAddress::read(&mut address_bytes_reader)
            .map_err(|error| AddressError::account_error(error.into()))?;

        let bytes = UInt8::constant_vec(address_bytes);

        Ok(Address { address, bytes })
    }

    pub(crate) fn is_constant(&self) -> bool {
        self.bytes.iter().all(|byte| byte.is_constant())
    }

    pub(crate) fn from_input<F: PrimeField, G: GroupType<F>, CS: ConstraintSystem<F>>(
        cs: &mut CS,
        name: &str,
        value: Value,
    ) -> Result<ConstrainedValue<F, G>, AddressError> {
        // Check that the input value is the correct type
        let value = if let Value::Address(value) = value {
            value
        } else {
            return Err(AddressError::invalid_address(name));
        };

        let account =
            AccountAddress::read(&mut &value[..]).map_err(|error| AddressError::account_error(error.into()))?;
        let bytes = UInt8::alloc_vec(cs, &value[..])?;

        let address = Address {
            address: account,
            bytes,
        };

        Ok(ConstrainedValue::Address(address))
    }

    pub(crate) fn alloc_helper<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<String>>(
        value_gen: Fn,
    ) -> Result<AccountAddress<Components>, SynthesisError> {
        let address_string = match value_gen() {
            Ok(value) => {
                let string_value = value.borrow().clone();
                Ok(string_value)
            }
            _ => Err(SynthesisError::AssignmentMissing),
        }?;

        AccountAddress::from_str(&address_string).map_err(|_| SynthesisError::AssignmentMissing)
    }
}

impl<F: PrimeField> AllocGadget<String, F> for Address {
    fn alloc<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<String>, CS: ConstraintSystem<F>>(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let address = Self::alloc_helper(value_gen)?;
        let mut address_bytes = vec![];
        address
            .write(&mut address_bytes)
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        let bytes = UInt8::alloc_vec(cs, &address_bytes[..])?;

        Ok(Address { address, bytes })
    }

    fn alloc_input<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<String>, CS: ConstraintSystem<F>>(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let address = Self::alloc_helper(value_gen)?;
        let mut address_bytes = vec![];
        address
            .write(&mut address_bytes)
            .map_err(|_| SynthesisError::AssignmentMissing)?;

        let bytes = UInt8::alloc_input_vec_le(cs, &address_bytes[..])?;

        Ok(Address { address, bytes })
    }
}

impl<F: PrimeField> EvaluateEqGadget<F> for Address {
    fn evaluate_equal<CS: ConstraintSystem<F>>(&self, mut cs: CS, other: &Self) -> Result<Boolean, SynthesisError> {
        if self.bytes.len() != other.bytes.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        if self.is_constant() && other.is_constant() {
            Ok(Boolean::Constant(self.eq(other)))
        } else {
            let mut result = Boolean::constant(true);

            for (i, (a, b)) in self.bytes.iter().zip(&other.bytes).enumerate() {
                let equal =
                    a.evaluate_equal(&mut cs.ns(|| format!("address evaluate equality for {}-th byte", i)), b)?;

                result = Boolean::and(
                    &mut cs.ns(|| format!("address and result for {}-th byte", i)),
                    &equal,
                    &result,
                )?;
            }

            Ok(result)
        }
    }
}

fn cond_equal_helper(first: &Address, second: &Address, cond: bool) -> Result<(), SynthesisError> {
    if cond {
        if first.eq(second) {
            Ok(())
        } else {
            Err(SynthesisError::Unsatisfiable)
        }
    } else {
        Ok(())
    }
}

impl<F: PrimeField> ConditionalEqGadget<F> for Address {
    fn conditional_enforce_equal<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        other: &Self,
        condition: &Boolean,
    ) -> Result<(), SynthesisError> {
        if let Boolean::Constant(cond) = *condition {
            cond_equal_helper(self, other, cond)
        } else {
            if self.bytes.len() != other.bytes.len() {
                return Err(SynthesisError::Unsatisfiable);
            }

            for (i, (a, b)) in self.bytes.iter().zip(&other.bytes).enumerate() {
                a.conditional_enforce_equal(
                    &mut cs.ns(|| format!("address equality check for {}-th byte", i)),
                    b,
                    condition,
                )?;
            }
            Ok(())
        }
    }

    fn cost() -> usize {
        <UInt8 as ConditionalEqGadget<F>>::cost() * 32 // address 32 bytes
    }
}

fn cond_select_helper(first: &Address, second: &Address, cond: bool) -> Address {
    if cond { first.clone() } else { second.clone() }
}

impl<F: PrimeField> CondSelectGadget<F> for Address {
    fn conditionally_select<CS: ConstraintSystem<F>>(
        mut cs: CS,
        cond: &Boolean,
        first: &Self,
        second: &Self,
    ) -> Result<Self, SynthesisError> {
        if let Boolean::Constant(cond) = *cond {
            Ok(cond_select_helper(first, second, cond))
        } else {
            let result_val = cond.get_value().and_then(|c| {
                if c {
                    Some(first.address.clone())
                } else {
                    Some(second.address.clone())
                }
            });

            let result = Self::alloc(cs.ns(|| "cond_select_result"), || {
                result_val.get().map(|v| v.to_string())
            })?;

            if first.bytes.len() != second.bytes.len() {
                return Err(SynthesisError::Unsatisfiable);
            }

            let expected_bytes = first
                .bytes
                .iter()
                .zip(&second.bytes)
                .enumerate()
                .map(|(i, (a, b))| {
                    UInt8::conditionally_select(&mut cs.ns(|| format!("address_cond_select_{}", i)), cond, a, b)
                        .unwrap()
                })
                .collect::<Vec<UInt8>>();

            for (i, (actual, expected)) in result.bytes.iter().zip(expected_bytes.iter()).enumerate() {
                actual.enforce_equal(&mut cs.ns(|| format!("selected_result_byte_{}", i)), expected)?;
            }

            Ok(result)
        }
    }

    fn cost() -> usize {
        <UInt8 as CondSelectGadget<F>>::cost() * 32
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}
