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

use crate::{
    errors::SignedIntegerError,
    utilities::{
        alloc::AllocGadget,
        arithmetic::{Add, Neg, Sub},
        int::*,
        Integer,
    },
};
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::ConstraintSystem;

macro_rules! sub_int_impl {
    ($($gadget: ident)*) => ($(
        impl<F: PrimeField> Sub<F> for $gadget {
            type ErrorType = SignedIntegerError;

            fn sub<CS: ConstraintSystem<F>>(&self, mut cs: CS, other: &Self) -> Result<Self, Self::ErrorType> {
                // use an alternative subtraction algorithm when the other operand can't be negated without overflowing
                if other.value == Some(<Self as Integer>::IntegerType::MIN) {
                    // if both values are IntegerType::MIN, neither can be negated without an overflow, but the result is just zero
                    if self.value == Some(<Self as Integer>::IntegerType::MIN) {
                        if self.is_constant() {
                            return Ok(Self::zero());
                        } else {
                            return <$gadget>::alloc(cs.ns(|| "zero"), || Ok(0)).map_err(|e| e.into());
                        }
                    }

                    // negate self
                    let self_neg = self.neg(cs.ns(|| format!("negate")))?;

                    // negated self + other
                    let added = self_neg.add(cs.ns(|| format!("add_complement")), &other)?;

                    // negate the result
                    added.neg(cs.ns(|| format!("negate result")))
                } else {
                    // Negate other
                    let other_neg = other.neg(cs.ns(|| format!("negate")))?;

                    // self + negated other
                    self.add(cs.ns(|| format!("add_complement")), &other_neg)
                }
            }
        }
    )*)
}

sub_int_impl!(Int8 Int16 Int32 Int64 Int128);
