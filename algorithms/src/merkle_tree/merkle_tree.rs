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

use crate::{
    errors::MerkleError,
    merkle_tree::{MerklePath, MerkleTreeDigest},
    traits::{MerkleParameters, CRH},
};
use snarkvm_utilities::ToBytes;
use std::sync::Arc;

#[derive(Default)]
pub struct MerkleTree<P: MerkleParameters> {
    /// The computed root of the full Merkle tree.
    root: Option<MerkleTreeDigest<P>>,

    /// The internal hashes, from root to hashed leaves, of the full Merkle tree.
    tree: Vec<MerkleTreeDigest<P>>,

    /// The index from which hashes of each non-empty leaf in the Merkle tree can be obtained.
    hashed_leaves_index: usize,

    /// For each level after a full tree has been built from the leaves,
    /// keeps both the roots the siblings that are used to get to the desired depth.
    padding_tree: Vec<(MerkleTreeDigest<P>, MerkleTreeDigest<P>)>,

    /// The Merkle tree parameters (e.g. the hash function).
    parameters: Arc<P>,
}

#[cfg(feature = "parallel")]
use rayon::prelude::*;

impl<P: MerkleParameters + Send + Sync> MerkleTree<P> {
    pub const DEPTH: u8 = P::DEPTH as u8;

    fn hash_row<L: ToBytes + Send + Sync>(
        parameters: &P,
        leaves: &[L],
    ) -> Result<Vec<Vec<<<P as MerkleParameters>::H as CRH>::Output>>, MerkleError> {
        let hash_input_size_in_bytes = (P::H::INPUT_SIZE_BITS / 8) * 2;
        cfg_chunks!(leaves, 500) // arbitrary, experimentally derived
            .map(|chunk| -> Result<Vec<_>, MerkleError> {
                let mut buffer = vec![0u8; hash_input_size_in_bytes];
                let mut out = Vec::with_capacity(chunk.len());
                for leaf in chunk.into_iter() {
                    out.push(parameters.hash_leaf(&leaf, &mut buffer)?);
                }
                Ok(out)
            })
            .collect::<Result<Vec<_>, MerkleError>>()
    }

    pub fn new<L: ToBytes + Send + Sync>(parameters: Arc<P>, leaves: &[L]) -> Result<Self, MerkleError> {
        let new_time = start_timer!(|| "MerkleTree::new");

        let last_level_size = leaves.len().next_power_of_two();
        let tree_size = 2 * last_level_size - 1;
        let tree_depth = tree_depth(tree_size);

        if tree_depth > Self::DEPTH as usize {
            return Err(MerkleError::InvalidTreeDepth(tree_depth, Self::DEPTH as usize));
        }

        // Initialize the Merkle tree.
        let empty_hash = parameters.hash_empty()?;
        let mut tree = vec![empty_hash.clone(); tree_size];

        // Compute the starting index (on the left) for each level of the tree.
        let mut index = 0;
        let mut level_indices = Vec::with_capacity(tree_depth);
        for _ in 0..=tree_depth {
            level_indices.push(index);
            index = left_child(index);
        }

        // Compute and store the hash values for each leaf.
        let hash_input_size_in_bytes = (P::H::INPUT_SIZE_BITS / 8) * 2;
        let last_level_index = level_indices.pop().unwrap_or(0);

        let subsections = Self::hash_row(&*parameters, leaves)?;

        let mut subsection_index = 0;
        for subsection in subsections.into_iter() {
            tree[last_level_index + subsection_index..last_level_index + subsection_index + subsection.len()]
                .copy_from_slice(&subsection[..]);
            subsection_index += subsection.len();
        }

        // Compute the hash values for every node in the tree.
        let mut upper_bound = last_level_index;
        let mut buffer = vec![0u8; hash_input_size_in_bytes];
        level_indices.reverse();
        for &start_index in &level_indices {
            // Iterate over the current level.
            let hashings = (start_index..upper_bound)
                .map(|i| (&tree[left_child(i)], &tree[right_child(i)]))
                .collect::<Vec<_>>();

            let hashes = Self::hash_row(&*parameters, &hashings[..])?;

            let mut subsection_index = 0;
            for subsection in hashes.into_iter() {
                tree[start_index + subsection_index..start_index + subsection_index + subsection.len()]
                    .copy_from_slice(&subsection[..]);
                subsection_index += subsection.len();
            }

            upper_bound = start_index;
        }

        // Finished computing actual tree.
        // Now, we compute the dummy nodes until we hit our DEPTH goal.
        let mut current_depth = tree_depth;
        let mut padding_tree = Vec::with_capacity((Self::DEPTH as usize).saturating_sub(current_depth + 1));
        let mut current_hash = tree[0].clone();
        while current_depth < Self::DEPTH as usize {
            current_hash = parameters.hash_inner_node(&current_hash, &empty_hash, &mut buffer)?;

            // do not pad at the top-level of the tree
            if current_depth < Self::DEPTH as usize - 1 {
                padding_tree.push((current_hash.clone(), empty_hash.clone()));
            }
            current_depth += 1;
        }
        let root_hash = current_hash;

        end_timer!(new_time);

        Ok(MerkleTree {
            tree,
            padding_tree,
            hashed_leaves_index: last_level_index,
            parameters,
            root: Some(root_hash),
        })
    }

    pub fn rebuild<L: ToBytes + Send + Sync>(&self, start_index: usize, new_leaves: &[L]) -> Result<Self, MerkleError> {
        let new_time = start_timer!(|| "MerkleTree::rebuild");

        let last_level_size = (start_index + new_leaves.len()).next_power_of_two();
        let tree_size = 2 * last_level_size - 1;
        let tree_depth = tree_depth(tree_size);

        if tree_depth > Self::DEPTH as usize {
            return Err(MerkleError::InvalidTreeDepth(tree_depth, Self::DEPTH as usize));
        }

        // Initialize the Merkle tree.
        let empty_hash = self.parameters.hash_empty()?;
        let mut tree = vec![empty_hash.clone(); tree_size];

        // Compute the starting index (on the left) for each level of the tree.
        let mut index = 0;
        let mut level_indices = Vec::with_capacity(tree_depth);
        for _ in 0..=tree_depth {
            level_indices.push(index);
            index = left_child(index);
        }

        // Track the indices of newly added leaves.
        let new_indices = (start_index..start_index + new_leaves.len()).collect::<Vec<_>>();

        // Compute and store the hash values for each leaf.
        let hash_input_size_in_bytes = (P::H::INPUT_SIZE_BITS / 8) * 2;
        let last_level_index = level_indices.pop().unwrap_or(0);

        // The beginning of the tree can be reconstructed from pre-existing hashed leaves.
        tree[last_level_index..][..start_index].clone_from_slice(&self.hashed_leaves()[..start_index]);

        // The new leaves require hashing.
        let subsections = Self::hash_row(&*self.parameters, new_leaves)?;

        for (i, subsection) in subsections.into_iter().enumerate() {
            tree[last_level_index + start_index + i..last_level_index + start_index + i + subsection.len()]
                .copy_from_slice(&subsection[..]);
        }

        // Compute the hash values for every node in the tree.
        let mut upper_bound = last_level_index;
        let mut buffer = vec![0u8; hash_input_size_in_bytes];
        level_indices.reverse();
        for &start_index in &level_indices {
            // Iterate over the current level.
            for current_index in start_index..upper_bound {
                let left_index = left_child(current_index);
                let right_index = right_child(current_index);

                // Hash only the tree paths that are altered by the addition of new leaves or are brand new.
                if new_indices.contains(&current_index)
                    || self.tree.get(left_index) != tree.get(left_index)
                    || self.tree.get(right_index) != tree.get(right_index)
                    || new_indices
                        .iter()
                        .any(|&idx| Ancestors(idx).into_iter().find(|&i| i == current_index).is_some())
                {
                    // Compute Hash(left || right).
                    tree[current_index] =
                        self.parameters
                            .hash_inner_node(&tree[left_index], &tree[right_index], &mut buffer)?;
                } else {
                    tree[current_index] = self.tree[current_index].clone();
                }
            }
            upper_bound = start_index;
        }

        // Finished computing actual tree.
        // Now, we compute the dummy nodes until we hit our DEPTH goal.
        let mut current_depth = tree_depth;
        let mut current_hash = tree[0].clone();

        // The whole padding tree can be reused if the current hash matches the previous one.
        let new_padding_tree = if current_hash == self.tree[0] {
            current_hash =
                self.parameters
                    .hash_inner_node(&self.padding_tree.last().unwrap().0, &empty_hash, &mut buffer)?;

            None
        } else {
            let mut padding_tree = Vec::with_capacity((Self::DEPTH as usize).saturating_sub(current_depth + 1));

            while current_depth < Self::DEPTH as usize {
                current_hash = self
                    .parameters
                    .hash_inner_node(&current_hash, &empty_hash, &mut buffer)?;

                // do not pad at the top-level of the tree
                if current_depth < Self::DEPTH as usize - 1 {
                    padding_tree.push((current_hash.clone(), empty_hash.clone()));
                }
                current_depth += 1;
            }

            Some(padding_tree)
        };
        let root_hash = current_hash;

        end_timer!(new_time);

        // update the values at the very end so the original tree is not altered in case of failure
        Ok(MerkleTree {
            root: Some(root_hash),
            tree,
            hashed_leaves_index: last_level_index,
            padding_tree: if let Some(padding_tree) = new_padding_tree {
                padding_tree
            } else {
                self.padding_tree.clone()
            },
            parameters: self.parameters.clone(),
        })
    }

    #[inline]
    pub fn root(&self) -> <P::H as CRH>::Output {
        self.root.clone().unwrap()
    }

    #[inline]
    pub fn tree(&self) -> &[<P::H as CRH>::Output] {
        &self.tree
    }

    #[inline]
    pub fn hashed_leaves(&self) -> &[<P::H as CRH>::Output] {
        &self.tree[self.hashed_leaves_index..]
    }

    pub fn generate_proof<L: ToBytes>(&self, index: usize, leaf: &L) -> Result<MerklePath<P>, MerkleError> {
        let prove_time = start_timer!(|| "MerkleTree::generate_proof");
        let mut path = vec![];

        let hash_input_size_in_bytes = (P::H::INPUT_SIZE_BITS / 8) * 2;
        let mut buffer = vec![0u8; hash_input_size_in_bytes];

        let leaf_hash = self.parameters.hash_leaf(leaf, &mut buffer)?;

        let tree_depth = tree_depth(self.tree.len());
        let tree_index = convert_index_to_last_level(index, tree_depth);

        // Check that the given index corresponds to the correct leaf.
        if leaf_hash != self.tree[tree_index] {
            return Err(MerkleError::IncorrectLeafIndex(tree_index));
        }

        // Iterate from the leaf's parent up to the root, storing all intermediate hash values.
        let mut current_node = tree_index;
        while !is_root(current_node) {
            let sibling_node = sibling(current_node).unwrap();
            path.push(self.tree[sibling_node].clone());
            current_node = parent(current_node).unwrap();
        }

        // Store the root node. Set boolean as true for consistency with digest location.
        if path.len() > Self::DEPTH as usize {
            return Err(MerkleError::InvalidPathLength(path.len(), Self::DEPTH as usize));
        }

        if path.len() != Self::DEPTH as usize {
            let empty_hash = self.parameters.hash_empty()?;
            path.push(empty_hash);

            for &(ref _hash, ref sibling_hash) in &self.padding_tree {
                path.push(sibling_hash.clone());
            }
        }
        end_timer!(prove_time);

        if path.len() != Self::DEPTH as usize {
            Err(MerkleError::IncorrectPathLength(path.len()))
        } else {
            Ok(MerklePath {
                parameters: self.parameters.clone(),
                path,
                leaf_index: index,
            })
        }
    }
}

/// Returns the depth of the tree, given the size of the tree.
#[inline]
fn tree_depth(tree_size: usize) -> usize {
    // Returns the log2 value of the given number.
    fn log2(number: usize) -> usize {
        (number as f64).log2() as usize
    }

    log2(tree_size)
}

/// Returns true iff the index represents the root.
#[inline]
fn is_root(index: usize) -> bool {
    index == 0
}

/// Returns the index of the left child, given an index.
#[inline]
fn left_child(index: usize) -> usize {
    2 * index + 1
}

/// Returns the index of the right child, given an index.
#[inline]
fn right_child(index: usize) -> usize {
    2 * index + 2
}

/// Returns the index of the sibling, given an index.
#[inline]
fn sibling(index: usize) -> Option<usize> {
    if index == 0 {
        None
    } else if is_left_child(index) {
        Some(index + 1)
    } else {
        Some(index - 1)
    }
}

/// Returns true iff the given index represents a left child.
#[inline]
fn is_left_child(index: usize) -> bool {
    index % 2 == 1
}

/// Returns the index of the parent, given an index.
#[inline]
fn parent(index: usize) -> Option<usize> {
    if index > 0 { Some((index - 1) >> 1) } else { None }
}

#[inline]
fn convert_index_to_last_level(index: usize, tree_depth: usize) -> usize {
    index + (1 << tree_depth) - 1
}

pub struct Ancestors(usize);

impl Iterator for Ancestors {
    type Item = usize;

    fn next(&mut self) -> Option<usize> {
        if let Some(parent) = parent(self.0) {
            self.0 = parent;
            Some(parent)
        } else {
            None
        }
    }
}
