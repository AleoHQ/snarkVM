// Copyright (C) 2019-2022 Aleo Systems Inc.
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

use super::*;

impl<E: Environment, I: IntegerType, M: Magnitude> ShlWrapped<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn shl_wrapped(&self, rhs: &Integer<E, M>) -> Self::Output {
        // Determine the variable mode.
        if self.is_constant() && rhs.is_constant() {
            // This cast is safe since `Magnitude`s can only be `u8`, `u16`, or `u32`.
            Integer::new(Mode::Constant, self.eject_value().wrapping_shl(rhs.eject_value().to_u32().unwrap()))
        } else {
            // Index of the first upper bit of rhs that we mask.
            let first_upper_bit_index = I::BITS.trailing_zeros() as usize;

            // Perform the left shift operation by exponentiation and multiplication.
            // By masking the upper bits, we have that rhs < I::BITS.
            // Therefore, 2^{rhs} < I::MAX.

            // Zero-extend `rhs` by `8`.
            let mut bits_le = rhs.bits_le[..first_upper_bit_index].to_vec();
            bits_le.extend(core::iter::repeat(Boolean::new(Mode::Constant, false)).take(8));

            // Use U8 for the exponent as it costs fewer constraints.
            let rhs_as_u8 = U8 { bits_le, phantom: Default::default() };

            if rhs_as_u8.is_constant() {
                // If the shift amount is a constant, then we can manually shift in bits and truncate the result.
                let shift_amount = rhs_as_u8.eject_value();
                let mut bits_le = vec![Boolean::new(self.eject_mode(), false); shift_amount as usize];

                bits_le.extend_from_slice(&self.bits_le);
                bits_le.truncate(I::BITS);

                Self { bits_le, phantom: Default::default() }
            } else {
                // Calculate the value of the shift directly in the field.
                // Since 2^{rhs} < I::MAX, we know that the operation will not overflow I::MAX or the field modulus.
                let two = BaseField::one() + BaseField::one();
                let mut shift_in_field = BaseField::one();
                for bit in rhs.bits_le[..first_upper_bit_index].iter().rev() {
                    shift_in_field = &shift_in_field * &shift_in_field;
                    shift_in_field = BaseField::ternary(bit, &(&shift_in_field * &two), &shift_in_field);
                }
                // TODO (@pranav) Avoid initializing the integer.
                let shift_as_multiplicand =
                    Self { bits_le: shift_in_field.to_lower_bits_le(I::BITS), phantom: Default::default() };
                self.mul_wrapped(&shift_as_multiplicand)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utilities::check_operation_passes;
    use snarkvm_circuits_environment::Circuit;
    use snarkvm_utilities::{test_rng, UniformRand};

    use std::{ops::RangeInclusive, panic::RefUnwindSafe};

    const ITERATIONS: usize = 32;

    #[rustfmt::skip]
    fn check_shl<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(
        name: &str,
        first: I,
        second: M,
        mode_a: Mode,
        mode_b: Mode,
        num_constants: usize,
        num_public: usize,
        num_private: usize,
        num_constraints: usize,
    ) {
        let expected = first.wrapping_shl(second.to_u32().unwrap());
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, M>::new(mode_b, second);
        let case = format!("({} << {})", a.eject_value(), b.eject_value());

        // Pass in the appropriate expected numbers based on the mode.
        let (num_constants, num_public, num_private, num_constraints) = match (mode_a, mode_b) {
            (Mode::Public, Mode::Constant) => (1, 1, 0, 1),
            (Mode::Private, Mode::Constant) => ( 1, 0, 1, 1),
            _ =>  (num_constants, num_public, num_private, num_constraints),
        };
        check_operation_passes(name, &case, expected, &a, &b, Integer::shl_wrapped, num_constants, num_public, num_private, num_constraints);
    }

    #[rustfmt::skip]
    fn run_test<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(
        mode_a: Mode,
        mode_b: Mode,
        num_constants: usize,
        num_public: usize,
        num_private: usize,
        num_constraints: usize,
    ) {
        let check_shl = | name: &str, first: I, second: M | check_shl(name, first, second, mode_a, mode_b, num_constants, num_public, num_private, num_constraints);

        for i in 0..ITERATIONS {
            let first: I = UniformRand::rand(&mut test_rng());
            let second: M = UniformRand::rand(&mut test_rng());

            let name = format!("Shl: {} << {} {}", mode_a, mode_b, i);
            check_shl(&name, first, second);

            // Check that shift left by one is computed correctly.
            let name = format!("Double: {} << {} {}", mode_a, mode_b, i);
            check_shl(&name, first, M::one());

            // Check that shift left by two is computed correctly.
            let name = format!("Quadruple: {} << {} {}", mode_a, mode_b, i);
            check_shl(&name, first, M::one() + M::one());
        }
    }

    #[rustfmt::skip]
    fn run_exhaustive_test<I: IntegerType + RefUnwindSafe, M: Magnitude + RefUnwindSafe>(
        mode_a: Mode,
        mode_b: Mode,
        num_constants: usize,
        num_public: usize,
        num_private: usize,
        num_constraints: usize,
    ) where
        RangeInclusive<I>: Iterator<Item = I>,
        RangeInclusive<M>: Iterator<Item = M>
    {
        for first in I::MIN..=I::MAX {
            for second in M::MIN..=M::MAX {
                let name = format!("Shl: ({} << {})", first, second);
                check_shl(&name, first, second, mode_a, mode_b, num_constants, num_public, num_private, num_constraints);
            }
        }
    }

    // Tests for u8, where shift magnitude is u8

    #[test]
    fn test_u8_constant_shl_u8_constant() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_u8_constant_shl_u8_public() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_constant_shl_u8_private() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_public_shl_u8_constant() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_private_shl_u8_constant() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_public_shl_u8_public() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_public_shl_u8_private() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_private_shl_u8_public() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_private_shl_u8_private() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 31, 33);
    }

    // Tests for i8, where shift magnitude is u8

    #[test]
    fn test_i8_constant_shl_u8_constant() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_i8_constant_shl_u8_public() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_constant_shl_u8_private() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_public_shl_u8_constant() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_private_shl_u8_constant() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_public_shl_u8_public() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_public_shl_u8_private() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_private_shl_u8_public() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_private_shl_u8_private() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 31, 33);
    }

    // Tests for u16, where shift magnitude is u8

    #[test]
    fn test_u16_constant_shl_u8_constant() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_u16_constant_shl_u8_public() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_constant_shl_u8_private() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_public_shl_u8_constant() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_private_shl_u8_constant() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_public_shl_u8_public() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_public_shl_u8_private() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_private_shl_u8_public() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_private_shl_u8_private() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 57, 59);
    }

    // Tests for i16, where shift magnitude is u8

    #[test]
    fn test_i16_constant_shl_u8_constant() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_i16_constant_shl_u8_public() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_constant_shl_u8_private() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_public_shl_u8_constant() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_private_shl_u8_constant() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_public_shl_u8_public() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_public_shl_u8_private() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_private_shl_u8_public() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_private_shl_u8_private() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 57, 59);
    }

    // Tests for u32, where shift magnitude is u8

    #[test]
    fn test_u32_constant_shl_u8_constant() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_u32_constant_shl_u8_public() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_constant_shl_u8_private() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_public_shl_u8_constant() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_private_shl_u8_constant() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_public_shl_u8_public() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_public_shl_u8_private() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_private_shl_u8_public() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_private_shl_u8_private() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 107, 109);
    }

    // Tests for i32, where shift magnitude is u8

    #[test]
    fn test_i32_constant_shl_u8_constant() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_i32_constant_shl_u8_public() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_constant_shl_u8_private() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_public_shl_u8_constant() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_private_shl_u8_constant() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_public_shl_u8_public() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_public_shl_u8_private() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_private_shl_u8_public() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_private_shl_u8_private() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 107, 109);
    }

    // Tests for u64, where shift magnitude is u8

    #[test]
    fn test_u64_constant_shl_u8_constant() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_u64_constant_shl_u8_public() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_constant_shl_u8_private() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_public_shl_u8_constant() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_private_shl_u8_constant() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_public_shl_u8_public() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_public_shl_u8_private() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_private_shl_u8_public() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_private_shl_u8_private() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 205, 207);
    }

    // Tests for i64, where shift magnitude is u8

    #[test]
    fn test_i64_constant_shl_u8_constant() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_i64_constant_shl_u8_public() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_constant_shl_u8_private() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_public_shl_u8_constant() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_private_shl_u8_constant() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_public_shl_u8_public() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_public_shl_u8_private() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_private_shl_u8_public() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_private_shl_u8_private() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 205, 207);
    }

    // Tests for u128, where shift magnitude is u8

    #[test]
    fn test_u128_constant_shl_u8_constant() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_u128_constant_shl_u8_public() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_constant_shl_u8_private() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_public_shl_u8_constant() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_private_shl_u8_constant() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_public_shl_u8_public() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_public_shl_u8_private() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_private_shl_u8_public() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_private_shl_u8_private() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 9, 0, 340, 342);
    }

    // Tests for i128, where shift magnitude is u8

    #[test]
    fn test_i128_constant_shl_u8_constant() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_i128_constant_shl_u8_public() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_constant_shl_u8_private() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_public_shl_u8_constant() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_private_shl_u8_constant() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_public_shl_u8_public() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_public_shl_u8_private() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_private_shl_u8_public() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_private_shl_u8_private() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 9, 0, 340, 342);
    }

    // Tests for u8, where shift magnitude is u16

    #[test]
    fn test_u8_constant_shl_u16_constant() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_u8_constant_shl_u16_public() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_constant_shl_u16_private() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_public_shl_u16_constant() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_private_shl_u16_constant() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_public_shl_u16_public() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_public_shl_u16_private() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_private_shl_u16_public() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_private_shl_u16_private() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 31, 33);
    }

    // Tests for i8, where shift magnitude is u16

    #[test]
    fn test_i8_constant_shl_u16_constant() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_i8_constant_shl_u16_public() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_constant_shl_u16_private() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_public_shl_u16_constant() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_private_shl_u16_constant() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_public_shl_u16_public() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_public_shl_u16_private() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_private_shl_u16_public() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_private_shl_u16_private() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 31, 33);
    }

    // Tests for u16, where shift magnitude is u16

    #[test]
    fn test_u16_constant_shl_u16_constant() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_u16_constant_shl_u16_public() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_constant_shl_u16_private() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_public_shl_u16_constant() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_private_shl_u16_constant() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_public_shl_u16_public() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_public_shl_u16_private() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_private_shl_u16_public() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_private_shl_u16_private() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 57, 59);
    }

    // Tests for i16, where shift magnitude is u16

    #[test]
    fn test_i16_constant_shl_u16_constant() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_i16_constant_shl_u16_public() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_constant_shl_u16_private() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_public_shl_u16_constant() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_private_shl_u16_constant() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_public_shl_u16_public() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_public_shl_u16_private() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_private_shl_u16_public() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_private_shl_u16_private() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 57, 59);
    }

    // Tests for u32, where shift magnitude is u16

    #[test]
    fn test_u32_constant_shl_u16_constant() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_u32_constant_shl_u16_public() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_constant_shl_u16_private() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_public_shl_u16_constant() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_private_shl_u16_constant() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_public_shl_u16_public() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_public_shl_u16_private() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_private_shl_u16_public() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_private_shl_u16_private() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 107, 109);
    }

    // Tests for i32, where shift magnitude is u16

    #[test]
    fn test_i32_constant_shl_u16_constant() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_i32_constant_shl_u16_public() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_constant_shl_u16_private() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_public_shl_u16_constant() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_private_shl_u16_constant() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_public_shl_u16_public() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_public_shl_u16_private() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_private_shl_u16_public() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_private_shl_u16_private() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 107, 109);
    }

    // Tests for u64, where shift magnitude is u16

    #[test]
    fn test_u64_constant_shl_u16_constant() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_u64_constant_shl_u16_public() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_constant_shl_u16_private() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_public_shl_u16_constant() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_private_shl_u16_constant() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_public_shl_u16_public() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_public_shl_u16_private() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_private_shl_u16_public() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_private_shl_u16_private() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 205, 207);
    }

    // Tests for i64, where shift magnitude is u16

    #[test]
    fn test_i64_constant_shl_u16_constant() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_i64_constant_shl_u16_public() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_constant_shl_u16_private() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_public_shl_u16_constant() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_private_shl_u16_constant() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_public_shl_u16_public() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_public_shl_u16_private() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_private_shl_u16_public() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_private_shl_u16_private() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 205, 207);
    }

    // Tests for u128, where shift magnitude is u16

    #[test]
    fn test_u128_constant_shl_u16_constant() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_u128_constant_shl_u16_public() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_constant_shl_u16_private() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_public_shl_u16_constant() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_private_shl_u16_constant() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_public_shl_u16_public() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_public_shl_u16_private() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_private_shl_u16_public() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_private_shl_u16_private() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 9, 0, 340, 342);
    }

    // Tests for i128, where shift magnitude is u16

    #[test]
    fn test_i128_constant_shl_u16_constant() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_i128_constant_shl_u16_public() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_constant_shl_u16_private() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_public_shl_u16_constant() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_private_shl_u16_constant() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_public_shl_u16_public() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_public_shl_u16_private() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_private_shl_u16_public() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_private_shl_u16_private() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 9, 0, 340, 342);
    }

    // Tests for u8, where shift magnitude is u32

    #[test]
    fn test_u8_constant_shl_u32_constant() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_u8_constant_shl_u32_public() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_constant_shl_u32_private() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_public_shl_u32_constant() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_private_shl_u32_constant() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_public_shl_u32_public() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_public_shl_u32_private() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_private_shl_u32_public() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_u8_private_shl_u32_private() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 31, 33);
    }

    // Tests for i8, where shift magnitude is u32

    #[test]
    fn test_i8_constant_shl_u32_constant() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_i8_constant_shl_u32_public() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_constant_shl_u32_private() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_public_shl_u32_constant() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_private_shl_u32_constant() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_public_shl_u32_public() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_public_shl_u32_private() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_private_shl_u32_public() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    fn test_i8_private_shl_u32_private() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 31, 33);
    }

    // Tests for u16, where shift magnitude is u32

    #[test]
    fn test_u16_constant_shl_u32_constant() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_u16_constant_shl_u32_public() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_constant_shl_u32_private() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_public_shl_u32_constant() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_private_shl_u32_constant() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_public_shl_u32_public() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_public_shl_u32_private() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_private_shl_u32_public() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_u16_private_shl_u32_private() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 57, 59);
    }

    // Tests for i16, where shift magnitude is u32

    #[test]
    fn test_i16_constant_shl_u32_constant() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_i16_constant_shl_u32_public() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_constant_shl_u32_private() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_public_shl_u32_constant() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_private_shl_u32_constant() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_public_shl_u32_public() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_public_shl_u32_private() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_private_shl_u32_public() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 57, 59);
    }

    #[test]
    fn test_i16_private_shl_u32_private() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 57, 59);
    }

    // Tests for u32, where shift magnitude is u32

    #[test]
    fn test_u32_constant_shl_u32_constant() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_u32_constant_shl_u32_public() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_constant_shl_u32_private() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_public_shl_u32_constant() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_private_shl_u32_constant() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_public_shl_u32_public() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_public_shl_u32_private() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_private_shl_u32_public() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_u32_private_shl_u32_private() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 107, 109);
    }

    // Tests for i32, where shift magnitude is u32

    #[test]
    fn test_i32_constant_shl_u32_constant() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_i32_constant_shl_u32_public() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_constant_shl_u32_private() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_public_shl_u32_constant() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_private_shl_u32_constant() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_public_shl_u32_public() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_public_shl_u32_private() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_private_shl_u32_public() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 107, 109);
    }

    #[test]
    fn test_i32_private_shl_u32_private() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 107, 109);
    }

    // Tests for u64, where shift magnitude is u32

    #[test]
    fn test_u64_constant_shl_u32_constant() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_u64_constant_shl_u32_public() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_constant_shl_u32_private() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_public_shl_u32_constant() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_private_shl_u32_constant() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_public_shl_u32_public() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_public_shl_u32_private() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_private_shl_u32_public() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_u64_private_shl_u32_private() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 205, 207);
    }

    // Tests for i64, where shift magnitude is u32

    #[test]
    fn test_i64_constant_shl_u32_constant() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_i64_constant_shl_u32_public() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_constant_shl_u32_private() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_public_shl_u32_constant() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_private_shl_u32_constant() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_public_shl_u32_public() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_public_shl_u32_private() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_private_shl_u32_public() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 205, 207);
    }

    #[test]
    fn test_i64_private_shl_u32_private() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 205, 207);
    }

    // Tests for u128, where shift magnitude is u32

    #[test]
    fn test_u128_constant_shl_u32_constant() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_u128_constant_shl_u32_public() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_constant_shl_u32_private() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_public_shl_u32_constant() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_private_shl_u32_constant() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_public_shl_u32_public() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_public_shl_u32_private() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_private_shl_u32_public() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_u128_private_shl_u32_private() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 9, 0, 340, 342);
    }

    // Tests for i128, where shift magnitude is u32

    #[test]
    fn test_i128_constant_shl_u32_constant() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_i128_constant_shl_u32_public() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_constant_shl_u32_private() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_public_shl_u32_constant() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_private_shl_u32_constant() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_public_shl_u32_public() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_public_shl_u32_private() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_private_shl_u32_public() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 9, 0, 340, 342);
    }

    #[test]
    fn test_i128_private_shl_u32_private() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 9, 0, 340, 342);
    }

    // Exhaustive tests for u8, where shift magnitude is u8

    #[test]
    #[ignore]
    fn test_exhaustive_u8_constant_shl_u8_constant() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_constant_shl_u8_public() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_constant_shl_u8_private() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_public_shl_u8_constant() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_private_shl_u8_constant() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_public_shl_u8_public() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_public_shl_u8_private() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_private_shl_u8_public() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_private_shl_u8_private() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 31, 33);
    }

    // Tests for i8, where shift magnitude is u8

    #[test]
    #[ignore]
    fn test_exhaustive_i8_constant_shl_u8_constant() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_constant_shl_u8_public() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_constant_shl_u8_private() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_public_shl_u8_constant() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_private_shl_u8_constant() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Constant, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_public_shl_u8_public() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_public_shl_u8_private() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Private, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_private_shl_u8_public() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Public, 3, 0, 31, 33);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_private_shl_u8_private() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Private, 3, 0, 31, 33);
    }
}
