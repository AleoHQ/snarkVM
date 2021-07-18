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

use std::sync::Arc;

use crate::{
    errors::MerkleError,
    traits::{MerkleParameters, CRH},
};
use snarkvm_utilities::ToBytes;

pub type MerkleTreeDigest<P> = <<P as MerkleParameters>::H as CRH>::Output;

/// Stores the hashes of a particular path (in order) from leaf to root.
/// Our path `is_left_child()` if the boolean in `path` is true.
#[derive(Clone, Debug)]
pub struct MerklePath<P: MerkleParameters> {
    pub parameters: Arc<P>,
    pub path: Vec<MerkleTreeDigest<P>>,
    pub leaf_index: usize,
}

impl<P: MerkleParameters> MerklePath<P> {
    pub fn verify<L: ToBytes>(&self, root_hash: &MerkleTreeDigest<P>, leaf: &L) -> Result<bool, MerkleError> {
        // Check that the given leaf matches the leaf in the membership proof.
        if !self.path.is_empty() {
            let hash_input_size_in_bytes = (P::H::INPUT_SIZE_BITS / 8) * 2;
            let mut buffer = vec![0u8; hash_input_size_in_bytes];

            let claimed_leaf_hash = self.parameters.hash_leaf::<L>(leaf, &mut buffer)?;
            let mut index = self.leaf_index;

            let mut curr_path_node = claimed_leaf_hash;
            let mut buffer = vec![0u8; hash_input_size_in_bytes];

            // Check levels between leaf level and root.
            for level in 0..self.path.len() {
                // Check if path node at this level is left or right.
                let (left_bytes, right_bytes) =
                    Self::select_left_right_bytes(index, &curr_path_node, &self.path[level])?;
                // Update the current path node.
                curr_path_node = self
                    .parameters
                    .hash_inner_node(&left_bytes, &right_bytes, &mut buffer)?;
                index >>= 1;
            }

            // Check if final hash is root
            if &curr_path_node != root_hash {
                return Ok(false);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Convert `computed_hash` and `sibling_hash` to bytes. `index` is the first `path.len()` bits of
    /// the position of tree.
    ///
    /// If the least significant bit of `index` is 0, then `input_1` will be left and `input_2` will be right.
    /// Otherwise, `input_1` will be right and `input_2` will be left.
    ///
    /// Returns: (left, right)
    fn select_left_right_bytes(
        index: usize,
        computed_hash: &<P::H as CRH>::Output,
        sibling_hash: &<P::H as CRH>::Output,
    ) -> Result<(<P::H as CRH>::Output, <P::H as CRH>::Output), MerkleError> {
        let is_left = index & 1 == 0;
        let mut left_bytes = computed_hash;
        let mut right_bytes = sibling_hash;
        if !is_left {
            core::mem::swap(&mut left_bytes, &mut right_bytes);
        }
        Ok((*left_bytes, *right_bytes))
    }

    /// The position of on_path node in `leaf_and_sibling_hash` and `non_leaf_and_sibling_hash_path`.
    /// `position[i]` is 0 (false) iff `i`th on-path node from top to bottom is on the left.
    ///
    /// This function simply converts `self.leaf_index` to boolean array in big endian form.
    pub fn position_list(&self) -> impl Iterator<Item = bool> + '_ {
        (0..self.path.len()).map(move |i| ((self.leaf_index >> i) & 1) != 0)
    }
}

impl<P: MerkleParameters> Default for MerklePath<P> {
    fn default() -> Self {
        let mut path = Vec::with_capacity(P::DEPTH);
        for _i in 0..P::DEPTH {
            path.push(MerkleTreeDigest::<P>::default());
        }
        Self {
            parameters: Arc::new(P::default()),
            path,
            leaf_index: 0,
        }
    }
}
