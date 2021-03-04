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
        arithmetic::Sub,
        boolean::{AllocatedBit, Boolean},
        eq::{ConditionalEqGadget, EqGadget},
        num::Number,
        select::CondSelectGadget,
        uint::unsigned_integer::{UInt, UInt8},
        ToBytesGadget,
    },
};
use snarkvm_fields::{Field, FpParameters, PrimeField};
use snarkvm_r1cs::{errors::SynthesisError, Assignment, ConstraintSystem, LinearCombination};

use snarkvm_utilities::{
    biginteger::{BigInteger, BigInteger256},
    bytes::ToBytes,
};

use std::{borrow::Borrow, cmp::Ordering};

uint_impl_common!(UInt128, u128, 128);

impl Number for UInt128 {
    type IntegerType = u128;

    const SIGNED: bool = false;
    const SIZE: usize = 128;

    fn zero() -> Self {
        Self::constant(0)
    }

    fn one() -> Self {
        Self::constant(1)
    }

    fn is_constant(&self) -> bool {
        // If any bits of self are allocated bits, return false
        self.bits.iter().all(|bit| matches!(bit, Boolean::Constant(_)))
    }

    fn const_value(&self) -> Option<Self::IntegerType> {
        let mut value = 0;
        for (i, bit) in self.bits.iter().enumerate() {
            match bit {
                Boolean::Is(ref _bit) => return None,
                Boolean::Not(ref _bit) => return None,
                Boolean::Constant(bit) => {
                    let bit = if *bit { 1 } else { 0 };
                    value |= bit << i;
                }
            }
        }
        Some(value)
    }

    fn value(&self) -> Option<Self::IntegerType> {
        let mut value = 0;
        for (i, bit) in self.bits.iter().enumerate() {
            let bit = bit.get_value()?;
            let bit = if bit { 1 } else { 0 };
            value |= bit << i;
        }
        Some(value)
    }

    /// Turns this `UInt128` into its little-endian byte order representation.
    fn to_bits_le(&self) -> Vec<Boolean> {
        self.bits.clone()
    }

    /// Converts a little-endian byte order representation of bits into a
    /// `UInt128`.
    fn from_bits_le(bits: &[Boolean]) -> Self {
        assert_eq!(bits.len(), 128);

        let bits = bits.to_vec();

        let mut value = Some(0u128);
        for b in bits.iter().rev() {
            if let Some(v) = value.as_mut() {
                *v <<= 1;
            }

            match *b {
                Boolean::Constant(b) => {
                    if b {
                        if let Some(v) = value.as_mut() {
                            *v |= 1;
                        }
                    }
                }
                Boolean::Is(ref b) => match b.get_value() {
                    Some(true) => {
                        if let Some(v) = value.as_mut() {
                            *v |= 1;
                        }
                    }
                    Some(false) => {}
                    None => value = None,
                },
                Boolean::Not(ref b) => match b.get_value() {
                    Some(false) => {
                        if let Some(v) = value.as_mut() {
                            *v |= 1;
                        }
                    }
                    Some(true) => {}
                    None => value = None,
                },
            }
        }

        Self {
            value,
            negated: false,
            bits,
        }
    }
}

impl UInt for UInt128 {
    /// Returns the inverse UInt128
    fn negate(&self) -> Self {
        Self {
            bits: self.bits.clone(),
            negated: true,
            value: self.value,
        }
    }

    fn rotr(&self, by: usize) -> Self {
        let by = by % 128;

        let new_bits = self
            .bits
            .iter()
            .skip(by)
            .chain(self.bits.iter())
            .take(128)
            .cloned()
            .collect();

        Self {
            bits: new_bits,
            negated: false,
            value: self.value.map(|v| v.rotate_right(by as u32) as u128),
        }
    }

    /// XOR this `UInt128` with another `UInt128`
    fn xor<F: Field, CS: ConstraintSystem<F>>(&self, mut cs: CS, other: &Self) -> Result<Self, SynthesisError> {
        let new_value = match (self.value, other.value) {
            (Some(a), Some(b)) => Some(a ^ b),
            _ => None,
        };

        let bits = self
            .bits
            .iter()
            .zip(other.bits.iter())
            .enumerate()
            .map(|(i, (a, b))| Boolean::xor(cs.ns(|| format!("xor of bit_gadget {}", i)), a, b))
            .collect::<Result<_, _>>()?;

        Ok(Self {
            bits,
            negated: false,
            value: new_value,
        })
    }

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

    /// Perform unsafe subtraction of two `UInt128` objects which returns 0 if overflowed
    fn sub_unsafe<F: PrimeField, CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        other: &Self,
    ) -> Result<Self, SynthesisError> {
        match (self.value, other.value) {
            (Some(val1), Some(val2)) => {
                // Check for overflow
                if val1 < val2 {
                    // Instead of erroring, return 0

                    if Self::result_is_constant(&self, &other) {
                        // Return constant 0u128
                        Ok(Self::constant(0u128))
                    } else {
                        // Return allocated 0u128
                        let result_value = Some(0u128);
                        let modular_value = result_value.map(|v| v as u128);

                        // Storage area for the resulting bits
                        let mut result_bits = Vec::with_capacity(128);

                        // This is a linear combination that we will enforce to be "zero"
                        let mut lc = LinearCombination::zero();

                        // Allocate each bit_gadget of the result
                        let mut coeff = F::one();
                        for i in 0..128 {
                            // Allocate the bit_gadget
                            let b = AllocatedBit::alloc(cs.ns(|| format!("result bit_gadget {}", i)), || {
                                result_value.map(|v| (v >> i) & 1 == 1).get()
                            })?;

                            // Subtract this bit_gadget from the linear combination to ensure the sums
                            // balance out
                            lc = lc - (coeff, b.get_variable());

                            result_bits.push(b.into());

                            coeff.double_in_place();
                        }

                        // Enforce that the linear combination equals zero
                        cs.enforce(|| "unsafe subtraction", |lc| lc, |lc| lc, |_| lc);

                        Ok(Self {
                            bits: result_bits,
                            negated: false,
                            value: modular_value,
                        })
                    }
                } else {
                    // Perform subtraction
                    self.sub(&mut cs.ns(|| ""), &other)
                }
            }
            (_, _) => {
                // If either of our operands have unknown value, we won't
                // know the value of the result
                Err(SynthesisError::AssignmentMissing)
            }
        }
    }
}
