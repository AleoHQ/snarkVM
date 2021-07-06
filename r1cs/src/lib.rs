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

mod assignment;
pub use assignment::*;

mod constraint_counter;
pub use constraint_counter::*;

mod constraint_system;
pub use constraint_system::{ConstraintSynthesizer, ConstraintSystem, OptimizationGoal};

mod constraint_variable;
pub use constraint_variable::*;

pub mod errors;
pub use errors::*;

mod linear_combination;
pub use linear_combination::*;

mod namespace;
pub use namespace::*;

mod optional_vec;
pub use optional_vec::*;

mod test_constraint_system;
pub use test_constraint_system::TestConstraintSystem;

mod test_fr;
pub use test_fr::*;

pub use snarkvm_fields::ToConstraintField;

use snarkvm_utilities::{errors::SerializationError, serialize::*};

use std::cmp::Ordering;

/// Represents a variable in a constraint system.
#[derive(PartialOrd, Ord, PartialEq, Eq, Copy, Clone, Debug, Hash)]
pub struct Variable(Index);

impl Variable {
    /// This constructs a variable with an arbitrary index.
    /// Circuit implementations are not recommended to use this.
    pub fn new_unchecked(idx: Index) -> Variable {
        Variable(idx)
    }

    /// This returns the index underlying the variable.
    /// Circuit implementations are not recommended to use this.
    pub fn get_unchecked(&self) -> Index {
        self.0
    }

    /// Mutably borrows the index underlying the variable.
    /// Circuit implementations are not recommended to use this.
    pub fn mut_unchecked(&mut self) -> &mut Index {
        &mut self.0
    }
}

/// Represents the index of either a public variable (input) or a private variable (auxiliary).
#[derive(Copy, Clone, PartialEq, Debug, Eq, Hash)]
pub enum Index {
    /// Index of an public variable.
    Public(usize),
    /// Index of an private variable.
    Private(usize),
}

impl PartialOrd for Index {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Index {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Index::Public(ref idx1), Index::Public(ref idx2))
            | (Index::Private(ref idx1), Index::Private(ref idx2)) => idx1.cmp(idx2),
            (Index::Public(_), Index::Private(_)) => Ordering::Less,
            (Index::Private(_), Index::Public(_)) => Ordering::Greater,
        }
    }
}

impl CanonicalSerialize for Index {
    #[inline]
    fn serialize<W: Write>(&self, writer: &mut W) -> Result<(), SerializationError> {
        let inner = match *self {
            Index::Public(inner) => {
                true.serialize(writer)?;
                inner
            }
            Index::Private(inner) => {
                false.serialize(writer)?;
                inner
            }
        };
        inner.serialize(writer)?;
        Ok(())
    }

    #[inline]
    fn serialized_size(&self) -> usize {
        Self::SERIALIZED_SIZE
    }
}

impl ConstantSerializedSize for Index {
    const SERIALIZED_SIZE: usize = usize::SERIALIZED_SIZE + 1;
    const UNCOMPRESSED_SIZE: usize = Self::SERIALIZED_SIZE;
}

impl CanonicalDeserialize for Index {
    #[inline]
    fn deserialize<R: Read>(reader: &mut R) -> Result<Self, SerializationError> {
        let is_input = bool::deserialize(reader)?;
        let inner = usize::deserialize(reader)?;
        Ok(if is_input {
            Index::Public(inner)
        } else {
            Index::Private(inner)
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn serialize_index() {
        serialize_index_test(true);
        serialize_index_test(false);
    }

    fn serialize_index_test(input: bool) {
        let idx = if input { Index::Public(32) } else { Index::Private(32) };

        let mut v = vec![];
        idx.serialize(&mut v).unwrap();
        let idx2 = Index::deserialize(&mut &v[..]).unwrap();
        assert_eq!(idx, idx2);
    }
}
