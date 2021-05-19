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

use crate::errors::UnsignedIntegerError;

use crate::utilities::{
    alloc::AllocGadget,
    arithmetic::{Mul, Pow},
    boolean::Boolean,
    integer::Integer,
    select::CondSelectGadget,
    uint::*,
};
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::ConstraintSystem;

macro_rules! pow_int_impl {
    ($($gadget:ident),*) => ($(
        impl<F: PrimeField> Pow<F> for $gadget {
            type ErrorType = UnsignedIntegerError;

            /// Bitwise exponentiation of two unsized integers.
            /// Reference: /snarkVM/models/src/curves/field.rs
            fn pow<CS: ConstraintSystem<F>>(
                &self,
                mut cs: CS,
                other: &Self,
            ) -> Result<Self, Self::ErrorType> {
                // let mut res = Self::one();
                //
                // for i in BitIteratorBE::new(exp) {
                //     res.square_in_place();
                //
                //     if i {
                //         res *= self;
                //     }
                // }
                // res

                let is_constant = Boolean::constant(Self::result_is_constant(&self, &other));
                let constant_result = Self::constant(1 as <$gadget as Integer>::IntegerType);
                let allocated_result = Self::alloc(
                    &mut cs.ns(|| format!("allocated_1u{}", <$gadget as Integer>::SIZE)),
                    || Ok(1 as <$gadget as Integer>::IntegerType),
                )?;
                let mut result = Self::conditionally_select(
                    &mut cs.ns(|| "constant_or_allocated"),
                    &is_constant,
                    &constant_result,
                    &allocated_result,
                )?;

                for (i, bit) in other.bits.iter().rev().enumerate() {
                    result = result.mul(cs.ns(|| format!("square_{}", i)), &result).unwrap();

                    let mul_by_self = result
                        .mul(cs.ns(|| format!("multiply_by_self_{}", i)), &self)
                        .unwrap();

                    result = Self::conditionally_select(
                        &mut cs.ns(|| format!("mul_by_self_or_result_{}", i)),
                        &bit,
                        &mul_by_self,
                        &result,
                    )?;
                }

                Ok(result)
            }
        }
    )*)
}

pow_int_impl!(UInt8, UInt16, UInt32, UInt64);
