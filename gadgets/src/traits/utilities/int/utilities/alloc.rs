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
    fields::FpGadget,
    utilities::{
        alloc::AllocGadget,
        boolean::{AllocatedBit, Boolean},
        eq::EqGadget,
        int::*,
        ToBitsBEGadget,
    },
};
use snarkvm_fields::{traits::to_field_vec::ToConstraintField, Field, FpParameters, PrimeField};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use core::borrow::Borrow;

macro_rules! alloc_int_fn_impl {
    ($gadget: ident, $fn_name: ident) => {
        fn $fn_name<
            Fn: FnOnce() -> Result<T, SynthesisError>,
            T: Borrow<<$gadget as Int>::IntegerType>,
            CS: ConstraintSystem<F>,
        >(
            mut cs: CS,
            value_gen: Fn,
        ) -> Result<Self, SynthesisError> {
            let value = value_gen().map(|val| *val.borrow());
            let values = match value {
                Ok(mut val) => {
                    let mut v = Vec::with_capacity(<$gadget as Int>::SIZE);

                    for _ in 0..<$gadget as Int>::SIZE {
                        v.push(Some(val & 1 == 1));
                        val >>= 1;
                    }

                    v
                }
                _ => vec![None; <$gadget as Int>::SIZE],
            };

            let bits = values
                .into_iter()
                .enumerate()
                .map(|(i, v)| {
                    Ok(Boolean::from(AllocatedBit::$fn_name(
                        &mut cs.ns(|| format!("allocated bit_gadget {}", i)),
                        || v.ok_or(SynthesisError::AssignmentMissing),
                    )?))
                })
                .collect::<Result<Vec<_>, SynthesisError>>()?;

            Ok(Self {
                bits,
                value: value.ok(),
            })
        }
    };
}

macro_rules! alloc_int_impl {
    ($($gadget: ident)*) => ($(
        impl<F: Field> AllocGadget<<$gadget as Int>::IntegerType, F> for $gadget {
            alloc_int_fn_impl!($gadget, alloc);
            alloc_int_fn_impl!($gadget, alloc_input);
        }
    )*)
}

alloc_int_impl!(Int8 Int16 Int32 Int64 Int128);

/// Alloc the unsigned integer through field elements rather purely bits
/// to reduce the number of input allocations.
macro_rules! alloc_input_fe {
    ($($gadget: ident)*) => ($(
        impl $gadget {
            /// Allocates the unsigned integer gadget by first converting
            /// the little-endian byte representation of the unsigned integer to
            /// `F` elements, (thus reducing the number of input allocations),
            /// and then converts this list of `F` gadgets into the unsigned integer gadget
            pub fn alloc_input_fe<F, CS>(mut cs: CS, value: <$gadget as Int>::IntegerType) -> Result<Self, SynthesisError>
            where
                F: PrimeField,
                CS: ConstraintSystem<F>,
            {
                let value_bytes = value.to_le_bytes();
                let field_elements: Vec<F> = ToConstraintField::<F>::to_field_elements(&value_bytes[..]).unwrap();

                let max_size = 8 * (F::Parameters::CAPACITY / 8) as usize;
                let mut allocated_bits = Vec::new();
                for (i, field_element) in field_elements.into_iter().enumerate() {
                    let fe = FpGadget::alloc_input(&mut cs.ns(|| format!("Field element {}", i)), || Ok(field_element))?;
                    let mut fe_bits = fe.to_bits_be(cs.ns(|| format!("Convert fe to bits {}", i)))?;
                    // FpGadget::to_bits outputs a big-endian binary representation of
                    // fe_gadget's value, so we have to reverse it to get the little-endian
                    // form.
                    fe_bits.reverse();

                    // Remove the most significant bit, because we know it should be zero
                    // because `values.to_field_elements()` only
                    // packs field elements up to the penultimate bit.
                    // That is, the most significant bit (`F::NUM_BITS`-th bit) is
                    // unset, so we can just pop it off.
                    allocated_bits.extend_from_slice(&fe_bits[0..max_size]);
                }

                // Assert that the extra bits are false
                for (i, bit) in allocated_bits.iter().skip(<$gadget as Int>::SIZE).enumerate() {
                    bit.enforce_equal(&mut cs.ns(|| format!("bit {} is false", i + <$gadget as Int>::SIZE)), &Boolean::constant(false))?;
                }

                let bits = allocated_bits[0..<$gadget as Int>::SIZE].to_vec();

                Ok(Self {
                    bits,
                    value: Some(value),
                })
            }
        }
    )*)
}

alloc_input_fe!(Int8 Int16 Int32 Int64 Int128);
