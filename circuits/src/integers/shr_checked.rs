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

impl<E: Environment, I: IntegerType, M: private::Magnitude> Shr<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    fn shr(self, rhs: Integer<E, M>) -> Self::Output {
        self >> &rhs
    }
}

impl<E: Environment, I: IntegerType, M: private::Magnitude> Shr<Integer<E, M>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn shr(self, rhs: Integer<E, M>) -> Self::Output {
        self >> &rhs
    }
}

impl<E: Environment, I: IntegerType, M: private::Magnitude> Shr<&Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    fn shr(self, rhs: &Integer<E, M>) -> Self::Output {
        &self >> rhs
    }
}

impl<E: Environment, I: IntegerType, M: private::Magnitude> Shr<&Integer<E, M>> for &Integer<E, I> {
    type Output = Integer<E, I>;

    fn shr(self, rhs: &Integer<E, M>) -> Self::Output {
        let mut output = self.clone();
        output >>= rhs;
        output
    }
}

impl<E: Environment, I: IntegerType, M: private::Magnitude> ShrAssign<Integer<E, M>> for Integer<E, I> {
    fn shr_assign(&mut self, rhs: Integer<E, M>) {
        *self >>= &rhs
    }
}

impl<E: Environment, I: IntegerType, M: private::Magnitude> ShrAssign<&Integer<E, M>> for Integer<E, I> {
    fn shr_assign(&mut self, rhs: &Integer<E, M>) {
        // Stores the result of `self` >> `other` in `self`.
        *self = self.shr_checked(rhs);
    }
}

impl<E: Environment, I: IntegerType, M: private::Magnitude> ShrChecked<Integer<E, M>> for Integer<E, I> {
    type Output = Self;

    #[inline]
    fn shr_checked(&self, rhs: &Integer<E, M>) -> Self::Output {
        // Determine the variable mode.
        if self.is_constant() && rhs.is_constant() {
            // This cast is safe since `Magnitude`s can only be `u8`, `u16`, or `u32`.
            match self.eject_value().checked_shr(rhs.eject_value().to_u32().unwrap()) {
                Some(value) => Integer::new(Mode::Constant, value),
                None => E::halt("Constant shifted by constant exceeds the allowed bitwidth."),
            }
        } else {
            // Index of the first upper bit of rhs that must be zero.
            // This is a safe case as I::BITS = 8, 16, 32, or 128.
            // Therefore there is at least one trailing zero.
            let first_upper_bit_index = I::BITS.trailing_zeros() as usize;

            let upper_bits_are_nonzero =
                rhs.bits_le[first_upper_bit_index..].iter().fold(Boolean::new(Mode::Private, false), |a, b| a | b);

            // The below constraint is not enforced if it is a constant.
            if upper_bits_are_nonzero.is_constant() {
                E::halt("Constant shifted by constant exceeds the allowed bitwidth.")
            }
            // Enforce that the appropriate number of upper bits in rhs are zero.
            E::assert_eq(upper_bits_are_nonzero, E::zero());

            // Perform a wrapping shift right.
            self.shr_wrapped(&rhs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;
    use snarkvm_utilities::UniformRand;
    use test_utilities::*;

    use rand::thread_rng;
    use std::{ops::RangeInclusive, panic::RefUnwindSafe};

    const ITERATIONS: usize = 64;

    #[rustfmt::skip]
    fn check_shr<I: IntegerType + RefUnwindSafe, M: private::Magnitude + RefUnwindSafe>(
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
        let a = Integer::<Circuit, I>::new(mode_a, first);
        let b = Integer::<Circuit, M>::new(mode_b, second);
        let case = format!("({} >> {})", a.eject_value(), b.eject_value());

        // Pass in the appropriate expected numbers based on the mode.
        let (num_constants, num_public, num_private, num_constraints) = match (mode_a, mode_b, I::is_signed()) {
            (Mode::Public, Mode::Constant, true) | (Mode::Private, Mode::Constant, true) => (1, 0, 1, 2),
            (Mode::Public, Mode::Constant, false) | (Mode::Private, Mode::Constant, false) => (2, 0, 1, 2),
            _ =>  (num_constants, num_public, num_private, num_constraints),
        };

        match first.checked_shr(second.to_u32().unwrap()) {
            Some(value) => {
                check_operation_passes(name, &case, value, &a, &b, Integer::shr_checked, num_constants, num_public, num_private, num_constraints);
            }
            None => match (mode_a, mode_b) {
                (_, Mode::Constant) => check_operation_halts(&a, &b, Integer::shr_checked),
                _ => check_operation_fails(name, &case, &a, &b, Integer::shr_checked, num_constants, num_public, num_private, num_constraints),
            },
        };
    }

    #[rustfmt::skip]
    fn run_test<I: IntegerType + RefUnwindSafe, M: private::Magnitude + RefUnwindSafe>(
        mode_a: Mode,
        mode_b: Mode,
        num_constants: usize,
        num_public: usize,
        num_private: usize,
        num_constraints: usize,
    ) {
        let check_shr = | name: &str, first: I, second: M | check_shr(name, first, second, mode_a, mode_b, num_constants, num_public, num_private, num_constraints);

        for i in 0..ITERATIONS {
            let first: I = UniformRand::rand(&mut thread_rng());
            let second: M = UniformRand::rand(&mut thread_rng());

            let name = format!("Shr: {} >> {} {}", mode_a, mode_b, i);
            check_shr(&name, first, second);

            // Check that shift right by one is computed correctly.
            let name = format!("Half: {} >> {} {}", mode_a, mode_b, i);
            check_shr(&name, first, M::one());
        }
    }

    #[rustfmt::skip]
    fn run_exhaustive_test<I: IntegerType + RefUnwindSafe, M: private::Magnitude + RefUnwindSafe>(
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
                let name = format!("Shr: ({} >> {})", first, second);
                check_shr(&name, first, second, mode_a, mode_b, num_constants, num_public, num_private, num_constraints);
            }
        }
    }

    // Tests for u8, where shift magnitude is u8

    #[test]
    fn test_u8_constant_shr_u8_constant() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_u8_constant_shr_u8_public() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 39, 42);
    }

    #[test]
    fn test_u8_constant_shr_u8_private() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 39, 42);
    }

    #[test]
    fn test_u8_public_shr_u8_constant() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u8_private_shr_u8_constant() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u8_public_shr_u8_public() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 39, 42);
    }

    #[test]
    fn test_u8_public_shr_u8_private() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 39, 42);
    }

    #[test]
    fn test_u8_private_shr_u8_public() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 39, 42);
    }

    #[test]
    fn test_u8_private_shr_u8_private() {
        type I = u8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 39, 42);
    }

    // Tests for i8, where shift magnitude is u8

    #[test]
    fn test_i8_constant_shr_u8_constant() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_i8_constant_shr_u8_public() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 41, 0, 71, 77);
    }

    #[test]
    fn test_i8_constant_shr_u8_private() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 41, 0, 71, 77);
    }

    #[test]
    fn test_i8_public_shr_u8_constant() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i8_private_shr_u8_constant() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i8_public_shr_u8_public() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 35, 0, 98, 105);
    }

    #[test]
    fn test_i8_public_shr_u8_private() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 35, 0, 98, 105);
    }

    #[test]
    fn test_i8_private_shr_u8_public() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 35, 0, 98, 105);
    }

    #[test]
    fn test_i8_private_shr_u8_private() {
        type I = i8;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 35, 0, 98, 105);
    }

    // Tests for u16, where shift magnitude is u8

    #[test]
    fn test_u16_constant_shr_u8_constant() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_u16_constant_shr_u8_public() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 64, 67);
    }

    #[test]
    fn test_u16_constant_shr_u8_private() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 64, 67);
    }

    #[test]
    fn test_u16_public_shr_u8_constant() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u16_private_shr_u8_constant() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u16_public_shr_u8_public() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 64, 67);
    }

    #[test]
    fn test_u16_public_shr_u8_private() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 64, 67);
    }

    #[test]
    fn test_u16_private_shr_u8_public() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 64, 67);
    }

    #[test]
    fn test_u16_private_shr_u8_private() {
        type I = u16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 64, 67);
    }

    // Tests for i16, where shift magnitude is u8

    #[test]
    fn test_i16_constant_shr_u8_constant() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_i16_constant_shr_u8_public() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 73, 0, 120, 126);
    }

    #[test]
    fn test_i16_constant_shr_u8_private() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 73, 0, 120, 126);
    }

    #[test]
    fn test_i16_public_shr_u8_constant() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i16_private_shr_u8_constant() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i16_public_shr_u8_public() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 59, 0, 171, 178);
    }

    #[test]
    fn test_i16_public_shr_u8_private() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 59, 0, 171, 178);
    }

    #[test]
    fn test_i16_private_shr_u8_public() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 59, 0, 171, 178);
    }

    #[test]
    fn test_i16_private_shr_u8_private() {
        type I = i16;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 59, 0, 171, 178);
    }

    // Tests for u32, where shift magnitude is u8

    #[test]
    fn test_u32_constant_shr_u8_constant() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_u32_constant_shr_u8_public() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 113, 116);
    }

    #[test]
    fn test_u32_constant_shr_u8_private() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 113, 116);
    }

    #[test]
    fn test_u32_public_shr_u8_constant() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u32_private_shr_u8_constant() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u32_public_shr_u8_public() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 113, 116);
    }

    #[test]
    fn test_u32_public_shr_u8_private() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 113, 116);
    }

    #[test]
    fn test_u32_private_shr_u8_public() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 113, 116);
    }

    #[test]
    fn test_u32_private_shr_u8_private() {
        type I = u32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 113, 116);
    }

    // Tests for i32, where shift magnitude is u8

    #[test]
    fn test_i32_constant_shr_u8_constant() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_i32_constant_shr_u8_public() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 137, 0, 217, 223);
    }

    #[test]
    fn test_i32_constant_shr_u8_private() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 137, 0, 217, 223);
    }

    #[test]
    fn test_i32_public_shr_u8_constant() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i32_private_shr_u8_constant() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i32_public_shr_u8_public() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 107, 0, 316, 323);
    }

    #[test]
    fn test_i32_public_shr_u8_private() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 107, 0, 316, 323);
    }

    #[test]
    fn test_i32_private_shr_u8_public() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 107, 0, 316, 323);
    }

    #[test]
    fn test_i32_private_shr_u8_private() {
        type I = i32;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 107, 0, 316, 323);
    }

    // Tests for u64, where shift magnitude is u8

    #[test]
    fn test_u64_constant_shr_u8_constant() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_u64_constant_shr_u8_public() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 210, 213);
    }

    #[test]
    fn test_u64_constant_shr_u8_private() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 210, 213);
    }

    #[test]
    fn test_u64_public_shr_u8_constant() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u64_private_shr_u8_constant() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u64_public_shr_u8_public() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 210, 213);
    }

    #[test]
    fn test_u64_public_shr_u8_private() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 210, 213);
    }

    #[test]
    fn test_u64_private_shr_u8_public() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 210, 213);
    }

    #[test]
    fn test_u64_private_shr_u8_private() {
        type I = u64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 210, 213);
    }

    // Tests for i64, where shift magnitude is u8

    #[test]
    fn test_i64_constant_shr_u8_constant() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_i64_constant_shr_u8_public() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 265, 0, 410, 416);
    }

    #[test]
    fn test_i64_constant_shr_u8_private() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 265, 0, 410, 416);
    }

    #[test]
    fn test_i64_public_shr_u8_constant() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i64_private_shr_u8_constant() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i64_public_shr_u8_public() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 203, 0, 605, 612);
    }

    #[test]
    fn test_i64_public_shr_u8_private() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 203, 0, 605, 612);
    }

    #[test]
    fn test_i64_private_shr_u8_public() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 203, 0, 605, 612);
    }

    #[test]
    fn test_i64_private_shr_u8_private() {
        type I = i64;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 203, 0, 605, 612);
    }

    // Tests for u128, where shift magnitude is u8

    #[test]
    fn test_u128_constant_shr_u8_constant() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_u128_constant_shr_u8_public() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 403, 406);
    }

    #[test]
    fn test_u128_constant_shr_u8_private() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 403, 406);
    }

    #[test]
    fn test_u128_public_shr_u8_constant() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u128_private_shr_u8_constant() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u128_public_shr_u8_public() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 403, 406);
    }

    #[test]
    fn test_u128_public_shr_u8_private() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 403, 406);
    }

    #[test]
    fn test_u128_private_shr_u8_public() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 403, 406);
    }

    #[test]
    fn test_u128_private_shr_u8_private() {
        type I = u128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 403, 406);
    }

    // Tests for i128, where shift magnitude is u8

    #[test]
    fn test_i128_constant_shr_u8_constant() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_i128_constant_shr_u8_public() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Public, 521, 0, 795, 801);
    }

    #[test]
    fn test_i128_constant_shr_u8_private() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Constant, Mode::Private, 521, 0, 795, 801);
    }

    #[test]
    fn test_i128_public_shr_u8_constant() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i128_private_shr_u8_constant() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i128_public_shr_u8_public() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Public, 395, 0, 1182, 1189);
    }

    #[test]
    fn test_i128_public_shr_u8_private() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Public, Mode::Private, 395, 0, 1182, 1189);
    }

    #[test]
    fn test_i128_private_shr_u8_public() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Public, 395, 0, 1182, 1189);
    }

    #[test]
    fn test_i128_private_shr_u8_private() {
        type I = i128;
        type M = u8;
        run_test::<I, M>(Mode::Private, Mode::Private, 395, 0, 1182, 1189);
    }

    // Tests for u8, where shift magnitude is u16

    #[test]
    fn test_u8_constant_shr_u16_constant() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_u8_constant_shr_u16_public() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 47, 50);
    }

    #[test]
    fn test_u8_constant_shr_u16_private() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 47, 50);
    }

    #[test]
    fn test_u8_public_shr_u16_constant() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u8_private_shr_u16_constant() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u8_public_shr_u16_public() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 47, 50);
    }

    #[test]
    fn test_u8_public_shr_u16_private() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 47, 50);
    }

    #[test]
    fn test_u8_private_shr_u16_public() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 47, 50);
    }

    #[test]
    fn test_u8_private_shr_u16_private() {
        type I = u8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 47, 50);
    }

    // Tests for i8, where shift magnitude is u16

    #[test]
    fn test_i8_constant_shr_u16_constant() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_i8_constant_shr_u16_public() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 41, 0, 79, 85);
    }

    #[test]
    fn test_i8_constant_shr_u16_private() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 41, 0, 79, 85);
    }

    #[test]
    fn test_i8_public_shr_u16_constant() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i8_private_shr_u16_constant() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i8_public_shr_u16_public() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 35, 0, 106, 113);
    }

    #[test]
    fn test_i8_public_shr_u16_private() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 35, 0, 106, 113);
    }

    #[test]
    fn test_i8_private_shr_u16_public() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 35, 0, 106, 113);
    }

    #[test]
    fn test_i8_private_shr_u16_private() {
        type I = i8;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 35, 0, 106, 113);
    }

    // Tests for u16, where shift magnitude is u16

    #[test]
    fn test_u16_constant_shr_u16_constant() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_u16_constant_shr_u16_public() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 72, 75);
    }

    #[test]
    fn test_u16_constant_shr_u16_private() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 72, 75);
    }

    #[test]
    fn test_u16_public_shr_u16_constant() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u16_private_shr_u16_constant() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u16_public_shr_u16_public() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 72, 75);
    }

    #[test]
    fn test_u16_public_shr_u16_private() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 72, 75);
    }

    #[test]
    fn test_u16_private_shr_u16_public() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 72, 75);
    }

    #[test]
    fn test_u16_private_shr_u16_private() {
        type I = u16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 72, 75);
    }

    // Tests for i16, where shift magnitude is u16

    #[test]
    fn test_i16_constant_shr_u16_constant() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_i16_constant_shr_u16_public() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 73, 0, 128, 134);
    }

    #[test]
    fn test_i16_constant_shr_u16_private() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 73, 0, 128, 134);
    }

    #[test]
    fn test_i16_public_shr_u16_constant() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i16_private_shr_u16_constant() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i16_public_shr_u16_public() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 59, 0, 179, 186);
    }

    #[test]
    fn test_i16_public_shr_u16_private() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 59, 0, 179, 186);
    }

    #[test]
    fn test_i16_private_shr_u16_public() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 59, 0, 179, 186);
    }

    #[test]
    fn test_i16_private_shr_u16_private() {
        type I = i16;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 59, 0, 179, 186);
    }

    // Tests for u32, where shift magnitude is u16

    #[test]
    fn test_u32_constant_shr_u16_constant() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_u32_constant_shr_u16_public() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 121, 124);
    }

    #[test]
    fn test_u32_constant_shr_u16_private() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 121, 124);
    }

    #[test]
    fn test_u32_public_shr_u16_constant() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u32_private_shr_u16_constant() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u32_public_shr_u16_public() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 121, 124);
    }

    #[test]
    fn test_u32_public_shr_u16_private() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 121, 124);
    }

    #[test]
    fn test_u32_private_shr_u16_public() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 121, 124);
    }

    #[test]
    fn test_u32_private_shr_u16_private() {
        type I = u32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 121, 124);
    }

    // Tests for i32, where shift magnitude is u16

    #[test]
    fn test_i32_constant_shr_u16_constant() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_i32_constant_shr_u16_public() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 137, 0, 225, 231);
    }

    #[test]
    fn test_i32_constant_shr_u16_private() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 137, 0, 225, 231);
    }

    #[test]
    fn test_i32_public_shr_u16_constant() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i32_private_shr_u16_constant() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i32_public_shr_u16_public() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 107, 0, 324, 331);
    }

    #[test]
    fn test_i32_public_shr_u16_private() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 107, 0, 324, 331);
    }

    #[test]
    fn test_i32_private_shr_u16_public() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 107, 0, 324, 331);
    }

    #[test]
    fn test_i32_private_shr_u16_private() {
        type I = i32;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 107, 0, 324, 331);
    }

    // Tests for u64, where shift magnitude is u16

    #[test]
    fn test_u64_constant_shr_u16_constant() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_u64_constant_shr_u16_public() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 218, 221);
    }

    #[test]
    fn test_u64_constant_shr_u16_private() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 218, 221);
    }

    #[test]
    fn test_u64_public_shr_u16_constant() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u64_private_shr_u16_constant() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u64_public_shr_u16_public() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 218, 221);
    }

    #[test]
    fn test_u64_public_shr_u16_private() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 218, 221);
    }

    #[test]
    fn test_u64_private_shr_u16_public() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 218, 221);
    }

    #[test]
    fn test_u64_private_shr_u16_private() {
        type I = u64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 218, 221);
    }

    // Tests for i64, where shift magnitude is u16

    #[test]
    fn test_i64_constant_shr_u16_constant() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_i64_constant_shr_u16_public() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 265, 0, 418, 424);
    }

    #[test]
    fn test_i64_constant_shr_u16_private() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 265, 0, 418, 424);
    }

    #[test]
    fn test_i64_public_shr_u16_constant() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i64_private_shr_u16_constant() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i64_public_shr_u16_public() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 203, 0, 613, 620);
    }

    #[test]
    fn test_i64_public_shr_u16_private() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 203, 0, 613, 620);
    }

    #[test]
    fn test_i64_private_shr_u16_public() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 203, 0, 613, 620);
    }

    #[test]
    fn test_i64_private_shr_u16_private() {
        type I = i64;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 203, 0, 613, 620);
    }

    // Tests for u128, where shift magnitude is u16

    #[test]
    fn test_u128_constant_shr_u16_constant() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_u128_constant_shr_u16_public() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 411, 414);
    }

    #[test]
    fn test_u128_constant_shr_u16_private() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 411, 414);
    }

    #[test]
    fn test_u128_public_shr_u16_constant() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u128_private_shr_u16_constant() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u128_public_shr_u16_public() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 411, 414);
    }

    #[test]
    fn test_u128_public_shr_u16_private() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 411, 414);
    }

    #[test]
    fn test_u128_private_shr_u16_public() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 411, 414);
    }

    #[test]
    fn test_u128_private_shr_u16_private() {
        type I = u128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 411, 414);
    }

    // Tests for i128, where shift magnitude is u16

    #[test]
    fn test_i128_constant_shr_u16_constant() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_i128_constant_shr_u16_public() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Public, 521, 0, 803, 809);
    }

    #[test]
    fn test_i128_constant_shr_u16_private() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Constant, Mode::Private, 521, 0, 803, 809);
    }

    #[test]
    fn test_i128_public_shr_u16_constant() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i128_private_shr_u16_constant() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i128_public_shr_u16_public() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Public, 395, 0, 1190, 1197);
    }

    #[test]
    fn test_i128_public_shr_u16_private() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Public, Mode::Private, 395, 0, 1190, 1197);
    }

    #[test]
    fn test_i128_private_shr_u16_public() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Public, 395, 0, 1190, 1197);
    }

    #[test]
    fn test_i128_private_shr_u16_private() {
        type I = i128;
        type M = u16;
        run_test::<I, M>(Mode::Private, Mode::Private, 395, 0, 1190, 1197);
    }

    // Tests for u8, where shift magnitude is u32

    #[test]
    fn test_u8_constant_shr_u32_constant() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_u8_constant_shr_u32_public() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 63, 66);
    }

    #[test]
    fn test_u8_constant_shr_u32_private() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 63, 66);
    }

    #[test]
    fn test_u8_public_shr_u32_constant() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u8_private_shr_u32_constant() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u8_public_shr_u32_public() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 63, 66);
    }

    #[test]
    fn test_u8_public_shr_u32_private() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 63, 66);
    }

    #[test]
    fn test_u8_private_shr_u32_public() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 63, 66);
    }

    #[test]
    fn test_u8_private_shr_u32_private() {
        type I = u8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 63, 66);
    }

    // Tests for i8, where shift magnitude is u32

    #[test]
    fn test_i8_constant_shr_u32_constant() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    fn test_i8_constant_shr_u32_public() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 41, 0, 95, 101);
    }

    #[test]
    fn test_i8_constant_shr_u32_private() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 41, 0, 95, 101);
    }

    #[test]
    fn test_i8_public_shr_u32_constant() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i8_private_shr_u32_constant() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i8_public_shr_u32_public() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 35, 0, 122, 129);
    }

    #[test]
    fn test_i8_public_shr_u32_private() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 35, 0, 122, 129);
    }

    #[test]
    fn test_i8_private_shr_u32_public() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 35, 0, 122, 129);
    }

    #[test]
    fn test_i8_private_shr_u32_private() {
        type I = i8;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 35, 0, 122, 129);
    }

    // Tests for u16, where shift magnitude is u32

    #[test]
    fn test_u16_constant_shr_u32_constant() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_u16_constant_shr_u32_public() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 88, 91);
    }

    #[test]
    fn test_u16_constant_shr_u32_private() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 88, 91);
    }

    #[test]
    fn test_u16_public_shr_u32_constant() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u16_private_shr_u32_constant() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u16_public_shr_u32_public() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 88, 91);
    }

    #[test]
    fn test_u16_public_shr_u32_private() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 88, 91);
    }

    #[test]
    fn test_u16_private_shr_u32_public() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 88, 91);
    }

    #[test]
    fn test_u16_private_shr_u32_private() {
        type I = u16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 88, 91);
    }

    // Tests for i16, where shift magnitude is u32

    #[test]
    fn test_i16_constant_shr_u32_constant() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 16, 0, 0, 0);
    }

    #[test]
    fn test_i16_constant_shr_u32_public() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 73, 0, 144, 150);
    }

    #[test]
    fn test_i16_constant_shr_u32_private() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 73, 0, 144, 150);
    }

    #[test]
    fn test_i16_public_shr_u32_constant() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i16_private_shr_u32_constant() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i16_public_shr_u32_public() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 59, 0, 195, 202);
    }

    #[test]
    fn test_i16_public_shr_u32_private() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 59, 0, 195, 202);
    }

    #[test]
    fn test_i16_private_shr_u32_public() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 59, 0, 195, 202);
    }

    #[test]
    fn test_i16_private_shr_u32_private() {
        type I = i16;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 59, 0, 195, 202);
    }

    // Tests for u32, where shift magnitude is u32

    #[test]
    fn test_u32_constant_shr_u32_constant() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_u32_constant_shr_u32_public() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 137, 140);
    }

    #[test]
    fn test_u32_constant_shr_u32_private() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 137, 140);
    }

    #[test]
    fn test_u32_public_shr_u32_constant() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u32_private_shr_u32_constant() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u32_public_shr_u32_public() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 137, 140);
    }

    #[test]
    fn test_u32_public_shr_u32_private() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 137, 140);
    }

    #[test]
    fn test_u32_private_shr_u32_public() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 137, 140);
    }

    #[test]
    fn test_u32_private_shr_u32_private() {
        type I = u32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 137, 140);
    }

    // Tests for i32, where shift magnitude is u32

    #[test]
    fn test_i32_constant_shr_u32_constant() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 32, 0, 0, 0);
    }

    #[test]
    fn test_i32_constant_shr_u32_public() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 137, 0, 241, 247);
    }

    #[test]
    fn test_i32_constant_shr_u32_private() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 137, 0, 241, 247);
    }

    #[test]
    fn test_i32_public_shr_u32_constant() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i32_private_shr_u32_constant() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i32_public_shr_u32_public() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 107, 0, 340, 347);
    }

    #[test]
    fn test_i32_public_shr_u32_private() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 107, 0, 340, 347);
    }

    #[test]
    fn test_i32_private_shr_u32_public() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 107, 0, 340, 347);
    }

    #[test]
    fn test_i32_private_shr_u32_private() {
        type I = i32;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 107, 0, 340, 347);
    }

    // Tests for u64, where shift magnitude is u32

    #[test]
    fn test_u64_constant_shr_u32_constant() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_u64_constant_shr_u32_public() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 234, 237);
    }

    #[test]
    fn test_u64_constant_shr_u32_private() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 234, 237);
    }

    #[test]
    fn test_u64_public_shr_u32_constant() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u64_private_shr_u32_constant() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u64_public_shr_u32_public() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 234, 237);
    }

    #[test]
    fn test_u64_public_shr_u32_private() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 234, 237);
    }

    #[test]
    fn test_u64_private_shr_u32_public() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 234, 237);
    }

    #[test]
    fn test_u64_private_shr_u32_private() {
        type I = u64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 234, 237);
    }

    // Tests for i64, where shift magnitude is u32

    #[test]
    fn test_i64_constant_shr_u32_constant() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 64, 0, 0, 0);
    }

    #[test]
    fn test_i64_constant_shr_u32_public() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 265, 0, 434, 440);
    }

    #[test]
    fn test_i64_constant_shr_u32_private() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 265, 0, 434, 440);
    }

    #[test]
    fn test_i64_public_shr_u32_constant() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i64_private_shr_u32_constant() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i64_public_shr_u32_public() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 203, 0, 629, 636);
    }

    #[test]
    fn test_i64_public_shr_u32_private() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 203, 0, 629, 636);
    }

    #[test]
    fn test_i64_private_shr_u32_public() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 203, 0, 629, 636);
    }

    #[test]
    fn test_i64_private_shr_u32_private() {
        type I = i64;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 203, 0, 629, 636);
    }

    // Tests for u128, where shift magnitude is u32

    #[test]
    fn test_u128_constant_shr_u32_constant() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_u128_constant_shr_u32_public() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 427, 430);
    }

    #[test]
    fn test_u128_constant_shr_u32_private() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 427, 430);
    }

    #[test]
    fn test_u128_public_shr_u32_constant() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u128_private_shr_u32_constant() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_u128_public_shr_u32_public() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 427, 430);
    }

    #[test]
    fn test_u128_public_shr_u32_private() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 427, 430);
    }

    #[test]
    fn test_u128_private_shr_u32_public() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 427, 430);
    }

    #[test]
    fn test_u128_private_shr_u32_private() {
        type I = u128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 427, 430);
    }

    // Tests for i128, where shift magnitude is u32

    #[test]
    fn test_i128_constant_shr_u32_constant() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Constant, 128, 0, 0, 0);
    }

    #[test]
    fn test_i128_constant_shr_u32_public() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Public, 521, 0, 819, 825);
    }

    #[test]
    fn test_i128_constant_shr_u32_private() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Constant, Mode::Private, 521, 0, 819, 825);
    }

    #[test]
    fn test_i128_public_shr_u32_constant() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i128_private_shr_u32_constant() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    fn test_i128_public_shr_u32_public() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Public, 395, 0, 1206, 1213);
    }

    #[test]
    fn test_i128_public_shr_u32_private() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Public, Mode::Private, 395, 0, 1206, 1213);
    }

    #[test]
    fn test_i128_private_shr_u32_public() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Public, 395, 0, 1206, 1213);
    }

    #[test]
    fn test_i128_private_shr_u32_private() {
        type I = i128;
        type M = u32;
        run_test::<I, M>(Mode::Private, Mode::Private, 395, 0, 1206, 1213);
    }

    // Exhaustive tests for u8.

    #[test]
    #[ignore]
    fn test_exhaustive_u8_constant_shr_u8_constant() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_constant_shr_u8_public() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Public, 5, 0, 39, 42);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_constant_shr_u8_private() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Private, 5, 0, 39, 42);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_public_shr_u8_constant() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_private_shr_u8_constant() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_public_shr_u8_public() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Public, 5, 0, 39, 42);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_public_shr_u8_private() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Private, 5, 0, 39, 42);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_private_shr_u8_public() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Public, 5, 0, 39, 42);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_u8_private_shr_u8_private() {
        type I = u8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Private, 5, 0, 39, 42);
    }

    // Tests for i8, where shift magnitude is u8

    #[test]
    #[ignore]
    fn test_exhaustive_i8_constant_shr_u8_constant() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Constant, 8, 0, 0, 0);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_constant_shr_u8_public() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Public, 41, 0, 71, 77);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_constant_shr_u8_private() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Constant, Mode::Private, 41, 0, 71, 77);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_public_shr_u8_constant() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_private_shr_u8_constant() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Constant, 2, 0, 1, 2);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_public_shr_u8_public() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Public, 35, 0, 98, 105);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_public_shr_u8_private() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Public, Mode::Private, 35, 0, 98, 105);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_private_shr_u8_public() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Public, 35, 0, 98, 105);
    }

    #[test]
    #[ignore]
    fn test_exhaustive_i8_private_shr_u8_private() {
        type I = i8;
        type M = u8;
        run_exhaustive_test::<I, M>(Mode::Private, Mode::Private, 35, 0, 98, 105);
    }
}
