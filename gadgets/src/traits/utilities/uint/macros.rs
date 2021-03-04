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

macro_rules! alloc_int_fn_impl {
    ($name: ident, $_type: ty, $size: expr, $fn_name: ident) => {
        fn $fn_name<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<$_type>, CS: ConstraintSystem<F>>(
            mut cs: CS,
            value_gen: Fn,
        ) -> Result<Self, SynthesisError> {
            let value = value_gen().map(|val| *val.borrow());
            let values = match value {
                Ok(mut val) => {
                    let mut v = Vec::with_capacity($size);
                    for _ in 0..$size {
                        v.push(Some(val & 1 == 1));
                        val >>= 1;
                    }

                    v
                }
                _ => vec![None; $size],
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
                negated: false,
                value: value.ok(),
            })
        }
    };
}

macro_rules! alloc_int_impl {
    ($name: ident, $_type: ty, $size: expr) => {
        impl<F: Field> AllocGadget<$_type, F> for $name {
            alloc_int_fn_impl!($name, $_type, $size, alloc);

            alloc_int_fn_impl!($name, $_type, $size, alloc_input);
        }
    };
}

macro_rules! to_bytes_int_impl {
    ($name: ident, $_type: ty, $size: expr) => {
        impl<F: Field> ToBytesGadget<F> for $name {
            #[inline]
            fn to_bytes<CS: ConstraintSystem<F>>(&self, _cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
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

macro_rules! uint_impl_eq_ord {
    ($name: ident, $_type: ty, $size: expr) => {
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.value.is_some() && self.value == other.value
            }
        }

        impl Eq for $name {}

        impl PartialOrd for $name {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Option::from(self.value.cmp(&other.value))
            }
        }
    };
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

        impl $name {
            pub fn constant(value: $_type) -> Self {
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
        }

        alloc_int_impl!($name, $_type, $size);
        cond_select_int_impl!($name, $_type, $size);
        to_bytes_int_impl!($name, $_type, $size);
        uint_impl_eq_ord!($name, $_type, $size);
    };
}

macro_rules! uint_impl {
    ($name: ident, $_type: ty, $size: expr) => {
        uint_impl_common!($name, $_type, $size);

        impl Number for $name {
            type IntegerType = $_type;

            const SIGNED: bool = false;
            const SIZE: usize = $size;

            fn zero() -> Self {
                Self::constant(0 as $_type)
            }

            fn one() -> Self {
                Self::constant(1 as $_type)
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
        }

        impl UInt for $name {
            fn negate(&self) -> Self {
                Self {
                    bits: self.bits.clone(),
                    negated: true,
                    value: self.value,
                }
            }

            fn rotr(&self, by: usize) -> Self {
                let by = by % $size;

                let new_bits = self
                    .bits
                    .iter()
                    .skip(by)
                    .chain(self.bits.iter())
                    .take($size)
                    .cloned()
                    .collect();

                Self {
                    bits: new_bits,
                    negated: false,
                    value: self.value.map(|v| v.rotate_right(by as u32) as $_type),
                }
            }

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

            /// Used for division. Evaluates a - b, and when a - b < 0, returns 0.
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
                                // Return constant 0
                                Ok(Self::constant(0 as $_type))
                            } else {
                                // Return allocated 0
                                let result_value = Some(0u128);
                                let modular_value = result_value.map(|v| v as $_type);

                                // Storage area for the resulting bits
                                let mut result_bits = Vec::with_capacity($size);

                                // This is a linear combination that we will enforce to be "zero"
                                let mut lc = LinearCombination::zero();

                                // Allocate each bit_gadget of the result
                                let mut coeff = F::one();
                                for i in 0..$size {
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
                        return Err(SynthesisError::AssignmentMissing);
                    }
                }
            }
        }
    };
}
