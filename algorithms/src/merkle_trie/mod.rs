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

#![allow(clippy::module_inception)]

pub mod merkle_trie_path;
pub use merkle_trie_path::*;

pub mod merkle_trie;
pub use merkle_trie::*;

pub mod merkle_trie_node;
pub use merkle_trie_node::*;

#[cfg(test)]
pub mod tests;

#[macro_export]
/// Defines a Merkle trie using the provided hash and max depth.
macro_rules! define_merkle_trie_parameters {
    ($struct_name:ident, $hash:ty, $branch:expr, $key_size:expr, $value_size:expr) => {
        #[derive(Clone, PartialEq, Eq, Debug)]
        pub struct $struct_name($hash);

        impl MerkleTrieParameters for $struct_name {
            type H = $hash;

            const KEY_SIZE: usize = $key_size;
            const MAX_BRANCH: usize = $branch;
            const VALUE_SIZE: usize = $value_size;

            fn setup(message: &str) -> Self {
                Self(Self::H::setup(message))
            }

            fn crh(&self) -> &Self::H {
                &self.0
            }
        }

        impl From<$hash> for $struct_name {
            fn from(crh: $hash) -> Self {
                Self(crh)
            }
        }
    };
}
