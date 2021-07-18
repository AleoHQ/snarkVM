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

pub mod merkle_path;
pub use merkle_path::*;

pub mod merkle_tree;
pub use merkle_tree::*;

#[cfg(test)]
pub mod tests;

// TODO (howardwu): TEMPORARY - Deprecate this with a ledger rearchitecture.
// Setup message to instantiate the Merkle Tree parameters
pub const fn setup_message() -> &'static str {
    "MerkleTreeParameters"
}

#[macro_export]
/// Defines a Merkle tree using the provided hash and depth.
macro_rules! define_merkle_tree_parameters {
    ($struct_name:ident, $hash:ty, $depth:expr) => {
#[rustfmt::skip]
        #[allow(unused_imports)]
        use $crate::{
            merkle_tree::MerkleTree,MerkleError,
            traits::{CRH, LoadableMerkleParameters, MaskedMerkleParameters, MerkleParameters},
        };

        #[derive(Clone, PartialEq, Eq, Debug)]
        pub struct $struct_name($hash);

        impl MerkleParameters for $struct_name {
            type H = $hash;

            const DEPTH: usize = $depth;

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

        impl LoadableMerkleParameters for $struct_name {}

        // TODO (howardwu): TEMPORARY - Deprecate this with a ledger rearchitecture.
        impl Default for $struct_name {
            fn default() -> Self {
                // TODO (howardwu): Switch to a better default.
                Self(<Self as MerkleParameters>::H::setup(
                    $crate::merkle_tree::setup_message(),
                ))
            }
        }
    };
}

#[macro_export]
macro_rules! define_masked_merkle_tree_parameters {
    ($struct_name:ident, $hash:ty, $depth:expr) => {
#[rustfmt::skip]
        #[allow(unused_imports)]
        use $crate::{
            merkle_tree::MerkleTree,MerkleError,
            CRH, MaskedMerkleParameters, MerkleParameters,
        };

        #[derive(Clone, PartialEq, Eq, Debug)]
        pub struct $struct_name($hash, $hash);

        impl MerkleParameters for $struct_name {
            type H = $hash;

            const DEPTH: usize = $depth;

            fn setup(message: &str) -> Self {
                Self(Self::H::setup(message), Self::H::setup(message))
            }

            fn crh(&self) -> &Self::H {
                &self.0
            }
        }

        impl MaskedMerkleParameters for $struct_name {
            fn mask_parameters(&self) -> &Self::H {
                &self.1
            }
        }

        impl Default for $struct_name {
            fn default() -> Self {
                Self(
                    // TODO (howardwu): Remove this unwrap and switch to a better default.
                    <Self as MerkleParameters>::H::setup($crate::merkle_tree::setup_message()),
                    <Self as MerkleParameters>::H::setup($crate::merkle_tree::setup_message()),
                )
            }
        }
    };
}
