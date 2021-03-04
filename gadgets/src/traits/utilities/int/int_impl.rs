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

use crate::utilities::{boolean::Boolean, num::Number};

use std::fmt::Debug;

pub trait Int: Debug + Clone + Number {}

/// Implements the base struct for a signed integer gadget
macro_rules! int_impl {
    ($name: ident, $type_: ty, $utype_: ty, $size: expr) => {
        #[derive(Clone, Debug)]
        pub struct $name {
            pub bits: Vec<Boolean>,
            pub value: Option<$type_>,
        }

        impl $name {
            pub fn constant(value: $type_) -> Self {
                let mut bits = Vec::with_capacity($size);

                for i in 0..$size {
                    // shift value by i
                    let mask = 1 << i as $type_;
                    let result = value & mask;

                    // If last bit is one, push one.
                    if result == mask {
                        bits.push(Boolean::constant(true))
                    } else {
                        bits.push(Boolean::constant(false))
                    }
                }

                Self {
                    bits,
                    value: Some(value),
                }
            }
        }

        impl Int for $name {}

        impl Number for $name {
            type IntegerType = $type_;

            const SIGNED: bool = true;
            const SIZE: usize = $size;

            fn one() -> Self {
                Self::constant(1 as $type_)
            }

            fn zero() -> Self {
                Self::constant(0 as $type_)
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

                let mut value = Some(0 as $utype_);
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
                    value: value.map(|x| x as $type_),
                    bits,
                }
            }
        }
    };
}

int_impl!(Int8, i8, u8, 8);
int_impl!(Int16, i16, u16, 16);
int_impl!(Int32, i32, u32, 32);
int_impl!(Int64, i64, u64, 64);
int_impl!(Int128, i128, u128, 128);
