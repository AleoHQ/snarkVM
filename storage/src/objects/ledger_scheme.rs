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

use crate::*;
use snarkvm_algorithms::merkle_tree::*;
use snarkvm_errors::dpc::LedgerError;
use snarkvm_models::{
    algorithms::LoadableMerkleParameters,
    objects::{LedgerScheme, Transaction},
};
use snarkvm_objects::Block;
use snarkvm_utilities::{
    bytes::{FromBytes, ToBytes},
    to_bytes,
};

use parking_lot::RwLock;
use std::{fs, marker::PhantomData, path::Path, sync::Arc};

impl<T: Transaction, P: LoadableMerkleParameters> LedgerScheme for Ledger<T, P> {
    type Block = Block<Self::Transaction>;
    type Commitment = T::Commitment;
    type MerkleParameters = P;
    type MerklePath = MerklePath<Self::MerkleParameters>;
    type MerkleTreeDigest = MerkleTreeDigest<Self::MerkleParameters>;
    type SerialNumber = T::SerialNumber;
    type Transaction = T;

    /// Instantiates a new ledger with a genesis block.
    fn new(
        path: Option<&Path>,
        parameters: Self::MerkleParameters,
        genesis_block: Self::Block,
    ) -> anyhow::Result<Self> {
        let storage = if let Some(path) = path {
            fs::create_dir_all(&path).map_err(|err| LedgerError::Message(err.to_string()))?;

            match Storage::open_cf(path, NUM_COLS) {
                Ok(storage) => storage,
                Err(err) => return Err(err.into()),
            }
        } else {
            unimplemented!()
        };

        if let Some(block_num) = storage.get(COL_META, KEY_BEST_BLOCK_NUMBER.as_bytes())? {
            if bytes_to_u32(block_num) != 0 {
                return Err(LedgerError::ExistingDatabase.into());
            }
        }

        let leaves: Vec<[u8; 32]> = vec![];
        let empty_cm_merkle_tree = MerkleTree::<Self::MerkleParameters>::new(parameters.clone(), &leaves)?;

        let ledger_storage = Self {
            latest_block_height: RwLock::new(0),
            storage: Arc::new(storage),
            cm_merkle_tree: RwLock::new(empty_cm_merkle_tree),
            ledger_parameters: parameters,
            _transaction: PhantomData,
        };

        ledger_storage.insert_and_commit(&genesis_block)?;

        Ok(ledger_storage)
    }

    /// Returns the number of blocks including the genesis block
    fn len(&self) -> usize {
        self.get_latest_block_height() as usize + 1
    }

    /// Return the parameters used to construct the ledger Merkle tree.
    fn parameters(&self) -> &Self::MerkleParameters {
        &self.ledger_parameters
    }

    /// Return a digest of the latest ledger Merkle tree.
    fn digest(&self) -> Option<Self::MerkleTreeDigest> {
        let digest: Self::MerkleTreeDigest = FromBytes::read(&self.current_digest().unwrap()[..]).unwrap();
        Some(digest)
    }

    /// Check that st_{ts} is a valid digest for some (past) ledger state.
    fn validate_digest(&self, digest: &Self::MerkleTreeDigest) -> bool {
        self.storage.exists(COL_DIGEST, &to_bytes![digest].unwrap())
    }

    /// Returns true if the given commitment exists in the ledger.
    fn contains_cm(&self, cm: &Self::Commitment) -> bool {
        self.storage.exists(COL_COMMITMENT, &to_bytes![cm].unwrap())
    }

    /// Returns true if the given serial number exists in the ledger.
    fn contains_sn(&self, sn: &Self::SerialNumber) -> bool {
        self.storage.exists(COL_SERIAL_NUMBER, &to_bytes![sn].unwrap())
    }

    /// Returns true if the given memo exists in the ledger.
    fn contains_memo(&self, memo: &<Self::Transaction as Transaction>::Memorandum) -> bool {
        self.storage.exists(COL_MEMO, &to_bytes![memo].unwrap())
    }

    /// Returns the Merkle path to the latest ledger digest
    /// for a given commitment, if it exists in the ledger.
    fn prove_cm(&self, cm: &Self::Commitment) -> anyhow::Result<Self::MerklePath> {
        let cm_index = self.get_cm_index(&to_bytes![cm]?)?.ok_or(LedgerError::InvalidCmIndex)?;
        let result = self.cm_merkle_tree.read().generate_proof(cm_index, cm)?;

        Ok(result)
    }

    /// Returns true if the given Merkle path is a valid witness for
    /// the given ledger digest and commitment.
    fn verify_cm(
        _parameters: &Self::MerkleParameters,
        digest: &Self::MerkleTreeDigest,
        cm: &Self::Commitment,
        witness: &Self::MerklePath,
    ) -> bool {
        witness.verify(&digest, cm).unwrap()
    }
}
