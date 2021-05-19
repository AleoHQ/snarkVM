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
    uint_impl_common,
    utilities::{
        alloc::AllocGadget,
        arithmetic::{Mul, Pow},
        boolean::{AllocatedBit, Boolean},
        eq::{ConditionalEqGadget, EqGadget},
        integer::Integer,
        select::CondSelectGadget,
        uint::unsigned_integer::{UInt, UInt8},
        ToBytesGadget,
    },
    UnsignedIntegerError,
};
use snarkvm_fields::{Field, FieldParameters, PrimeField};
use snarkvm_r1cs::{errors::SynthesisError, Assignment, ConstraintSystem, LinearCombination};

use snarkvm_utilities::{
    biginteger::{BigInteger, BigInteger256},
    bytes::ToBytes,
};

uint_impl_common!(UInt128, u128, 128);

impl UInt for UInt128 {
    uint_trait_common!(self);

    /// Perform modular addition of several `UInt128` objects.
    fn addmany<F: PrimeField, CS: ConstraintSystem<F>>(mut cs: CS, operands: &[Self]) -> Result<Self, SynthesisError> {
        // Make some arbitrary bounds for ourselves to avoid overflows
        // in the scalar field
        assert!(F::Parameters::MODULUS_BITS <= 253);
        assert!(operands.len() >= 2); // Weird trivial cases that should never happen

        // Compute the maximum value of the sum so we allocate enough bits for
        // the result
        let mut max_value = BigInteger256::from_u128(u128::max_value());
        max_value.muln(operands.len() as u32);

        // Keep track of the resulting value
        let mut big_result_value = Some(BigInteger256::default());

        // This is a linear combination that we will enforce to be "zero"
        let mut lc = LinearCombination::zero();

        let mut all_constants = true;

        // Iterate over the operands
        for op in operands {
            // Accumulate the value
            match op.value {
                Some(val) => {
                    // Subtract or add operand
                    if op.negated {
                        // Perform subtraction
                        big_result_value
                            .as_mut()
                            .map(|v| v.sub_noborrow(&BigInteger256::from_u128(val)));
                    } else {
                        // Perform addition
                        big_result_value
                            .as_mut()
                            .map(|v| v.add_nocarry(&BigInteger256::from_u128(val)));
                    }
                }
                None => {
                    // If any of our operands have unknown value, we won't
                    // know the value of the result
                    big_result_value = None;
                }
            }

            // Iterate over each bit_gadget of the operand and add the operand to
            // the linear combination
            let mut coeff = F::one();
            for bit in &op.bits {
                match *bit {
                    Boolean::Is(ref bit) => {
                        all_constants = false;

                        if op.negated {
                            // Subtract coeff * bit gadget
                            lc = lc - (coeff, bit.get_variable());
                        } else {
                            // Add coeff * bit_gadget
                            lc += (coeff, bit.get_variable());
                        }
                    }
                    Boolean::Not(ref bit) => {
                        all_constants = false;

                        if op.negated {
                            // subtract coeff * (1 - bit_gadget) = coeff * ONE - coeff * bit_gadget
                            lc = lc - (coeff, CS::one()) + (coeff, bit.get_variable());
                        } else {
                            // Add coeff * (1 - bit_gadget) = coeff * ONE - coeff * bit_gadget
                            lc = lc + (coeff, CS::one()) - (coeff, bit.get_variable());
                        }
                    }
                    Boolean::Constant(bit) => {
                        if bit {
                            if op.negated {
                                lc = lc - (coeff, CS::one());
                            } else {
                                lc += (coeff, CS::one());
                            }
                        }
                    }
                }

                coeff.double_in_place();
            }
        }

        // The value of the actual result is modulo 2^128
        let modular_value = big_result_value.map(|v| v.to_u128());

        if all_constants {
            if let Some(val) = modular_value {
                // We can just return a constant, rather than
                // unpacking the result into allocated bits.

                return Ok(Self::constant(val));
            }
        }

        // Storage area for the resulting bits
        let mut result_bits = vec![];

        // Allocate each bit_gadget of the result
        let mut coeff = F::one();
        let mut i = 0;
        while !max_value.is_zero() {
            // Allocate the bit_gadget
            let b = AllocatedBit::alloc(cs.ns(|| format!("result bit_gadget {}", i)), || {
                big_result_value.map(|v| v.get_bit(i)).get()
            })?;

            // Subtract this bit_gadget from the linear combination to ensure the sums
            // balance out
            lc = lc - (coeff, b.get_variable());

            // Discard carry bits that we don't care about
            if result_bits.len() < 128 {
                result_bits.push(b.into());
            }

            max_value.div2();
            i += 1;
            coeff.double_in_place();
        }

        // Enforce that the linear combination equals zero
        cs.enforce(|| "modular addition", |lc| lc, |lc| lc, |_| lc);

        Ok(Self {
            bits: result_bits,
            negated: false,
            value: modular_value,
        })
    }
}

impl<F: PrimeField> Pow<F> for UInt128 {
    type ErrorType = UnsignedIntegerError;

    /// Bitwise multiplication of two `UInt128` objects.
    /// Reference: /snarkVM/models/src/curves/field.rs
    fn pow<CS: ConstraintSystem<F>>(&self, mut cs: CS, other: &Self) -> Result<Self, Self::ErrorType> {
        // let mut res = Self::one();
        //
        // let mut found_one = false;
        //
        // for i in BitIteratorBE::new(exp) {
        //     if !found_one {
        //         if i {
        //             found_one = true;
        //         } else {
        //             continue;
        //         }
        //     }
        //
        //     res.square_in_place();
        //
        //     if i {
        //         res *= self;
        //     }
        // }
        // res

        let is_constant = Boolean::constant(Self::result_is_constant(&self, &other));
        let constant_result = Self::constant(1u128);
        let allocated_result = Self::alloc(&mut cs.ns(|| "allocated_1u128"), || Ok(1u128))?;
        let mut result = Self::conditionally_select(
            &mut cs.ns(|| "constant_or_allocated"),
            &is_constant,
            &constant_result,
            &allocated_result,
        )?;

        for (i, bit) in other.bits.iter().rev().enumerate() {
            let found_one = Boolean::Constant(result.eq(&Self::constant(1u128)));
            let cond1 = Boolean::and(cs.ns(|| format!("found_one_{}", i)), &bit.not(), &found_one)?;
            let square = result.mul(cs.ns(|| format!("square_{}", i)), &result).unwrap();

            result = Self::conditionally_select(
                &mut cs.ns(|| format!("result_or_sqaure_{}", i)),
                &cond1,
                &result,
                &square,
            )?;

            let mul_by_self = result.mul(cs.ns(|| format!("multiply_by_self_{}", i)), &self).unwrap();

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
