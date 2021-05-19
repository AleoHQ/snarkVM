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

macro_rules! to_bytes_int_impl {
    ($name: ident, $_type: ty, $size: expr) => {
        impl<F: Field> ToBytesGadget<F> for $name {
            #[inline]
            fn to_bytes<CS: ConstraintSystem<F>>(&self, _cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
                use crate::utilities::integer::Integer;

                const BYTES_SIZE: usize = if $size == 128 { 16 } else { 8 };

                let value_chunks = match self.value.map(|val| {
                    let mut bytes = [0u8; BYTES_SIZE];
                    val.write(bytes.as_mut()).unwrap();
                    bytes
                }) {
                    Some(chunks) => [Some(chunks[0]), Some(chunks[1]), Some(chunks[2]), Some(chunks[3])],
                    None => [None, None, None, None],
                };
                let bits = self.to_bits_le();
                let mut bytes = Vec::with_capacity(bits.len() / 8);
                for (chunk8, value) in bits.chunks(8).into_iter().zip(value_chunks.iter()) {
                    let byte = UInt8 {
                        bits: chunk8.to_vec(),
                        negated: false,
                        value: *value,
                    };
                    bytes.push(byte);
                }

                Ok(bytes)
            }

            fn to_bytes_strict<CS: ConstraintSystem<F>>(&self, cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
                self.to_bytes(cs)
            }
        }
    };
}

macro_rules! cond_select_int_impl {
    ($name: ident, $_type: ty, $size: expr) => {
        impl<F: PrimeField> CondSelectGadget<F> for $name {
            fn conditionally_select<CS: ConstraintSystem<F>>(
                mut cs: CS,
                cond: &Boolean,
                first: &Self,
                second: &Self,
            ) -> Result<Self, SynthesisError> {
                use crate::utilities::integer::Integer;

                if let Boolean::Constant(cond) = *cond {
                    if cond {
                        Ok(first.clone())
                    } else {
                        Ok(second.clone())
                    }
                } else {
                    let mut is_negated = false;

                    let result_val = cond.get_value().and_then(|c| {
                        if c {
                            is_negated = first.negated;
                            first.value
                        } else {
                            is_negated = second.negated;
                            second.value
                        }
                    });

                    let mut result = Self::alloc(cs.ns(|| "cond_select_result"), || result_val.get().map(|v| v))?;

                    result.negated = is_negated;

                    for (i, (actual, (bit1, bit2))) in result
                        .to_bits_le()
                        .iter()
                        .zip(first.bits.iter().zip(&second.bits))
                        .enumerate()
                    {
                        let expected_bit = Boolean::conditionally_select(
                            &mut cs.ns(|| format!("{}_cond_select_{}", $size, i)),
                            cond,
                            bit1,
                            bit2,
                        )
                        .unwrap();
                        actual.enforce_equal(&mut cs.ns(|| format!("selected_result_bit_{}", i)), &expected_bit)?;
                    }

                    Ok(result)
                }
            }

            fn cost() -> usize {
                $size * (<Boolean as ConditionalEqGadget<F>>::cost() + <Boolean as CondSelectGadget<F>>::cost())
            }
        }
    };
}

macro_rules! uint_trait_common {
    ($self: ident) => {
        fn negate(&$self) -> Self {
            Self {
                bits: $self.bits.clone(),
                negated: true,
                value: $self.value,
            }
        }

        fn rotr(&$self, by: usize) -> Self {
            let by = by % <Self as Integer>::SIZE;

            let bits = $self
                .bits
                .iter()
                .skip(by)
                .chain($self.bits.iter())
                .take(<Self as Integer>::SIZE)
                .cloned()
                .collect();

            Self {
                bits,
                negated: false,
                value: $self.value.map(|v| v.rotate_right(by as u32) as <Self as Integer>::IntegerType),
            }
        }
    }
}

#[macro_export]
macro_rules! uint_impl_common {
    ($name: ident, $_type: ty, $size: expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            pub bits: Vec<Boolean>,
            pub negated: bool,
            pub value: Option<$_type>,
        }

        impl crate::utilities::integer::Integer for $name {
            type IntegerType = $_type;

            const SIZE: usize = $size;

            fn constant(value: $_type) -> Self {
                let mut bits = Vec::with_capacity($size);

                let mut tmp = value;

                for _ in 0..$size {
                    // If last bit is one, push one.
                    if tmp & 1 == 1 {
                        bits.push(Boolean::constant(true))
                    } else {
                        bits.push(Boolean::constant(false))
                    }

                    tmp >>= 1;
                }

                Self {
                    bits,
                    negated: false,
                    value: Some(value),
                }
            }

            fn one() -> Self {
                Self::constant(1 as $_type)
            }

            fn zero() -> Self {
                Self::constant(0 as $_type)
            }

            fn new(bits: Vec<Boolean>, value: Option<Self::IntegerType>) -> Self {
                Self {
                    bits,
                    value,
                    negated: false,
                }
            }

            fn is_constant(&self) -> bool {
                let mut constant = true;

                // If any bits of self are allocated bits, return false
                for bit in &self.bits {
                    match *bit {
                        Boolean::Is(ref _bit) => constant = false,
                        Boolean::Not(ref _bit) => constant = false,
                        Boolean::Constant(_bit) => {}
                    }
                }

                constant
            }

            fn to_bits_le(&self) -> Vec<Boolean> {
                self.bits.clone()
            }

            fn from_bits_le(bits: &[Boolean]) -> Self {
                assert_eq!(bits.len(), $size);

                let bits = bits.to_vec();

                let mut value = Some(0 as $_type);
                for b in bits.iter().rev() {
                    value.as_mut().map(|v| *v <<= 1);

                    match *b {
                        Boolean::Constant(b) => {
                            if b {
                                value.as_mut().map(|v| *v |= 1);
                            }
                        }
                        Boolean::Is(ref b) => match b.get_value() {
                            Some(true) => {
                                value.as_mut().map(|v| *v |= 1);
                            }
                            Some(false) => {}
                            None => value = None,
                        },
                        Boolean::Not(ref b) => match b.get_value() {
                            Some(false) => {
                                value.as_mut().map(|v| *v |= 1);
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

            fn get_value(&self) -> Option<String> {
                self.value.map(|num| num.to_string())
            }
        }

        cond_select_int_impl!($name, $_type, $size);
        to_bytes_int_impl!($name, $_type, $size);
    };
}

macro_rules! uint_impl {
    ($name: ident, $_type: ty, $size: expr) => {
        uint_impl_common!($name, $_type, $size);

        impl UInt for $name {
            uint_trait_common!(self);

            fn addmany<F: PrimeField, CS: ConstraintSystem<F>>(
                mut cs: CS,
                operands: &[Self],
            ) -> Result<Self, SynthesisError> {
                // Make some arbitrary bounds for ourselves to avoid overflows
                // in the scalar field
                assert!(F::Parameters::MODULUS_BITS >= 128);
                assert!(operands.len() >= 2); // Weird trivial cases that should never happen

                // Compute the maximum value of the sum we allocate enough bits for the result
                let mut max_value = (operands.len() as u128) * u128::from(<$_type>::max_value());

                // Keep track of the resulting value
                let mut result_value = Some(0u128);

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
                                result_value.as_mut().map(|v| *v -= u128::from(val));
                            } else {
                                // Perform addition
                                result_value.as_mut().map(|v| *v += u128::from(val));
                            }
                        }
                        None => {
                            // If any of our operands have unknown value, we won't
                            // know the value of the result
                            result_value = None;
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

                // The value of the actual result is modulo 2 ^ $size
                let modular_value = result_value.map(|v| v as $_type);

                if all_constants && modular_value.is_some() {
                    // We can just return a constant, rather than
                    // unpacking the result into allocated bits.

                    return Ok(Self::constant(modular_value.unwrap()));
                }

                // Storage area for the resulting bits
                let mut result_bits = vec![];

                // Allocate each bit_gadget of the result
                let mut coeff = F::one();
                let mut i = 0;
                while max_value != 0 {
                    // Allocate the bit_gadget
                    let b = AllocatedBit::alloc(cs.ns(|| format!("result bit_gadget {}", i)), || {
                        result_value.map(|v| (v >> i) & 1 == 1).get()
                    })?;

                    // Subtract this bit_gadget from the linear combination to ensure the sums
                    // balance out
                    lc = lc - (coeff, b.get_variable());

                    // Discard carry bits that we don't care about
                    if result_bits.len() < $size {
                        result_bits.push(b.into());
                    }

                    max_value >>= 1;
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
    };
}
