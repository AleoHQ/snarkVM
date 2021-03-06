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
    traits::{CommitmentScheme, CRH},
};
use snarkvm_utilities::{to_bytes_le, FromBytes, ToBytes};
use std::io::{Read, Result as IoResult, Write};

#[derive(Derivative)]
#[derivative(
    Clone(bound = "C: CommitmentScheme, H: CRH"),
    PartialEq(bound = "C: CommitmentScheme, H: CRH"),
    Eq(bound = "C: CommitmentScheme, H: CRH")
)]
pub struct CommitmentMerklePath<C: CommitmentScheme, H: CRH> {
    pub leaves: (<C as CommitmentScheme>::Output, <C as CommitmentScheme>::Output),
    pub inner_hashes: (<H as CRH>::Output, <H as CRH>::Output),
}

impl<C: CommitmentScheme, H: CRH> CommitmentMerklePath<C, H> {
    pub fn verify(
        &self,
        parameters: &H,
        root_hash: &<H as CRH>::Output,
        leaf: &<C as CommitmentScheme>::Output,
    ) -> Result<bool, MerkleError> {
        // Check if the leaf is included in the path
        if leaf != &self.leaves.0 && leaf != &self.leaves.1 {
            return Ok(false);
        };

        // Check that the inner hash is included in the path
        let inner_hash = hash_inner_node(parameters, &self.leaves.0, &self.leaves.1)?;

        if inner_hash != self.inner_hashes.0 && inner_hash != self.inner_hashes.1 {
            return Ok(false);
        };

        // Check that the root hash is valid.
        let root = hash_inner_node(parameters, &self.inner_hashes.0, &self.inner_hashes.1)?;

        if &root != root_hash {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Returns the output hash, given a left and right hash value.
fn hash_inner_node<H: CRH, L: ToBytes>(crh: &H, left: &L, right: &L) -> Result<<H as CRH>::Output, MerkleError> {
    let input = to_bytes_le![left, right]?;
    Ok(crh.hash(&input)?)
}

impl<C: CommitmentScheme, H: CRH> ToBytes for CommitmentMerklePath<C, H> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.leaves.0.write_le(&mut writer)?;
        self.leaves.1.write_le(&mut writer)?;
        self.inner_hashes.0.write_le(&mut writer)?;
        self.inner_hashes.1.write_le(&mut writer)
    }
}

impl<C: CommitmentScheme, H: CRH> FromBytes for CommitmentMerklePath<C, H> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let leaves = (C::Output::read_le(&mut reader)?, C::Output::read_le(&mut reader)?);
        let inner_hashes = (H::Output::read_le(&mut reader)?, H::Output::read_le(&mut reader)?);

        Ok(Self { leaves, inner_hashes })
    }
}
