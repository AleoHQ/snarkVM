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

use crate::{FftField, FieldParameters};
use snarkvm_utilities::{biginteger::BigInteger, cmp::min, str::FromStr};

/// The interface for a prime field.
#[allow(clippy::wrong_self_convention)]
pub trait PrimeField: FftField<FftParameters = <Self as PrimeField>::Parameters> + FromStr {
    type Parameters: FieldParameters<BigInteger = Self::BigInteger>;
    type BigInteger: BigInteger;

    /// Returns a prime field element from its underlying representation.
    fn from_repr(repr: Self::BigInteger) -> Option<Self>;

    /// Returns the underlying representation of the prime field element.
    fn to_repr(&self) -> Self::BigInteger;

    /// Returns a prime field element from its underlying raw representation.
    fn from_repr_unchecked(repr: Self::BigInteger) -> Self;

    /// Returns the underlying raw representation of the prime field element.
    fn to_repr_unchecked(&self) -> Self::BigInteger;

    /// Returns the field size in bits.
    fn size_in_bits() -> usize {
        Self::Parameters::MODULUS_BITS as usize
    }

    /// Returns the trace.
    fn trace() -> Self::BigInteger {
        Self::Parameters::T
    }

    /// Returns the trace minus one divided by two.
    fn trace_minus_one_div_two() -> Self::BigInteger {
        Self::Parameters::T_MINUS_ONE_DIV_TWO
    }

    /// Returns the modulus minus one divided by two.
    fn modulus_minus_one_div_two() -> Self::BigInteger {
        Self::Parameters::MODULUS_MINUS_ONE_DIV_TWO
    }

    /// Reads bytes in big-endian, and converts them to a field element.
    /// If the bytes are larger than the modulus, it will reduce them.
    fn from_be_bytes_mod_order(bytes: &[u8]) -> Self {
        let num_modulus_bytes = ((Self::Parameters::MODULUS_BITS + 7) / 8) as usize;
        let num_bytes_to_directly_convert = min(num_modulus_bytes - 1, bytes.len());
        // Copy the leading big-endian bytes directly into a field element.
        // The number of bytes directly converted must be less than the
        // number of bytes needed to represent the modulus, as we must begin
        // modular reduction once the data is of the same number of bytes as the modulus.
        let mut bytes_to_directly_convert = Vec::new();
        bytes_to_directly_convert.extend(bytes[..num_bytes_to_directly_convert].iter().rev());
        // Guaranteed to not be None, as the input is less than the modulus size.
        let mut res = Self::from_random_bytes(&bytes_to_directly_convert).unwrap();

        // Update the result, byte by byte.
        // We go through existing field arithmetic, which handles the reduction.
        let window_size = Self::from(256u64);
        for byte in bytes[num_bytes_to_directly_convert..].iter() {
            res *= window_size;
            res += Self::from(*byte);
        }
        res
    }

    /// Reads bytes in little-endian, and converts them to a field element.
    /// If the bytes are larger than the modulus, it will reduce them.
    fn from_le_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut bytes_copy = bytes.to_vec();
        bytes_copy.reverse();
        Self::from_be_bytes_mod_order(&bytes_copy)
    }
}
