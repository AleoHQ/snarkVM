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

use crate::{errors::MerkleError, CRH};
use snarkvm_utilities::ToBytes;

use std::io::Cursor;

pub trait MerkleParameters: Send + Sync + Clone + Default {
    type H: CRH;

    const DEPTH: usize;

    /// Setup the MerkleParameters
    fn setup(message: &str) -> Self;

    /// Returns the collision-resistant hash function used by the Merkle tree.
    fn crh(&self) -> &Self::H;

    /// Returns the hash of a given leaf.
    fn hash_leaf<L: ToBytes>(&self, leaf: &L, buffer: &mut [u8]) -> Result<<Self::H as CRH>::Output, MerkleError> {
        let mut writer = Cursor::new(buffer);
        leaf.write_le(&mut writer)?;

        let buffer = writer.into_inner();
        Ok(self.crh().hash(&buffer[..(Self::H::INPUT_SIZE_BITS / 8)])?)
    }

    /// Returns the output hash, given a left and right hash value.
    fn hash_inner_node(
        &self,
        left: &<Self::H as CRH>::Output,
        right: &<Self::H as CRH>::Output,
        buffer: &mut [u8],
    ) -> Result<<Self::H as CRH>::Output, MerkleError> {
        let mut writer = Cursor::new(buffer);

        // Construct left input.
        left.write_le(&mut writer)?;

        // Construct right input.
        right.write_le(&mut writer)?;

        let buffer = writer.into_inner();
        Ok(self.crh().hash(&buffer[..(<Self::H as CRH>::INPUT_SIZE_BITS / 8)])?)
    }

    fn hash_empty(&self) -> Result<<Self::H as CRH>::Output, MerkleError> {
        let empty_buffer = vec![0u8; <Self::H as CRH>::INPUT_SIZE_BITS / 8];
        Ok(self.crh().hash(&empty_buffer)?)
    }
}

// TODO (howardwu): TEMPORARY - Deprecate this with a ledger rearchitecture.
pub trait LoadableMerkleParameters: MerkleParameters + From<<Self as MerkleParameters>::H> {}

pub trait MaskedMerkleParameters: MerkleParameters {
    /// Returns the collision-resistant hash function masking parameters used by the Merkle tree.
    fn mask_parameters(&self) -> &Self::H;
}
