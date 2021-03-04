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

use std::fmt::Debug;

use super::boolean::Boolean;

pub mod cast;
pub use cast::*;

pub trait Number: Debug + Clone + PartialOrd + Eq + PartialEq {
    type IntegerType;
    const SIZE: usize;
    const SIGNED: bool;

    fn one() -> Self;

    fn zero() -> Self;

    /// Returns true if all bits in this `Number` are constant
    fn is_constant(&self) -> bool;

    /// Returns a constant value if all bits in this `Number` are constant
    fn const_value(&self) -> Option<Self::IntegerType>;

    /// Returns a value if all bits in this `Number` are known
    fn value(&self) -> Option<Self::IntegerType>;

    /// Returns true if both `Number` objects have constant bits
    fn result_is_constant(first: &Self, second: &Self) -> bool {
        first.is_constant() && second.is_constant()
    }

    fn to_bits_le(&self) -> Vec<Boolean>;

    fn from_bits_le(bits: &[Boolean]) -> Self;
}
