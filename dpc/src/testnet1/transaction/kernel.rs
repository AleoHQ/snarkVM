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
    prelude::*,
    testnet1::{EncryptedRecord, LocalData, Record, Testnet1Components, Transaction},
};
use snarkvm_algorithms::{commitment_tree::CommitmentMerkleTree, prelude::*};
use snarkvm_utilities::{to_bytes_le, FromBytes, ToBytes};

use std::{
    fmt,
    io::{Read, Result as IoResult, Write},
    str::FromStr,
};

/// Returned by `DPC::execute_offline_phase`. Stores data required to produce the
/// final transaction after `execute_offline_phase` has created old serial numbers,
/// new records and commitments. For convenience, it also
/// stores references to existing information such as old records.
#[derive(Derivative)]
#[derivative(
    Clone(bound = "C: Testnet1Components"),
    PartialEq(bound = "C: Testnet1Components"),
    Eq(bound = "C: Testnet1Components"),
    Debug(bound = "C: Testnet1Components")
)]
pub struct TransactionKernel<C: Testnet1Components> {
    // Old record stuff
    pub old_records: Vec<Record<C>>,
    pub old_serial_numbers: Vec<<C::AccountSignature as SignatureScheme>::PublicKey>,
    pub old_randomizers: Vec<<C::AccountSignature as SignatureScheme>::Randomizer>,

    // New record stuff
    pub new_records: Vec<Record<C>>,
    pub new_sn_nonce_randomness: Vec<[u8; 32]>,
    pub new_commitments: Vec<<C::RecordCommitment as CommitmentScheme>::Output>,

    pub new_records_encryption_randomness: Vec<<C::AccountEncryption as EncryptionScheme>::Randomness>,
    pub new_encrypted_records: Vec<EncryptedRecord<C>>,
    pub new_encrypted_record_hashes: Vec<<C::EncryptedRecordCRH as CRH>::Output>,

    // Program and local data root and randomness
    pub program_commitment: <C::ProgramIDCommitment as CommitmentScheme>::Output,
    pub program_randomness: <C::ProgramIDCommitment as CommitmentScheme>::Randomness,

    pub local_data_merkle_tree: CommitmentMerkleTree<C::LocalDataCommitment, C::LocalDataCRH>,
    pub local_data_commitment_randomizers: Vec<<C::LocalDataCommitment as CommitmentScheme>::Randomness>,

    pub value_balance: AleoAmount,
    pub memorandum: <Transaction<C> as TransactionScheme>::Memorandum,
    pub network_id: u8,
}

impl<C: Testnet1Components> TransactionKernel<C> {
    #[allow(clippy::wrong_self_convention)]
    pub fn into_local_data(&self) -> LocalData<C> {
        LocalData {
            old_records: self.old_records.to_vec(),
            old_serial_numbers: self.old_serial_numbers.to_vec(),

            new_records: self.new_records.to_vec(),

            local_data_merkle_tree: self.local_data_merkle_tree.clone(),
            local_data_commitment_randomizers: self.local_data_commitment_randomizers.clone(),

            memorandum: self.memorandum,
            network_id: self.network_id,
        }
    }
}

impl<C: Testnet1Components> ToBytes for TransactionKernel<C> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write old record components

        for old_record in &self.old_records {
            old_record.write_le(&mut writer)?;
        }

        for old_serial_number in &self.old_serial_numbers {
            old_serial_number.write_le(&mut writer)?;
        }

        for old_randomizer in &self.old_randomizers {
            old_randomizer.write_le(&mut writer)?;
        }

        // Write new record components

        for new_record in &self.new_records {
            new_record.write_le(&mut writer)?;
        }

        for new_sn_nonce_randomness in &self.new_sn_nonce_randomness {
            new_sn_nonce_randomness.write_le(&mut writer)?;
        }

        for new_commitment in &self.new_commitments {
            new_commitment.write_le(&mut writer)?;
        }

        for new_records_encryption_randomness in &self.new_records_encryption_randomness {
            new_records_encryption_randomness.write_le(&mut writer)?;
        }

        for new_encrypted_record in &self.new_encrypted_records {
            new_encrypted_record.write_le(&mut writer)?;
        }

        for new_encrypted_record_hash in &self.new_encrypted_record_hashes {
            new_encrypted_record_hash.write_le(&mut writer)?;
        }

        // Write transaction components

        self.program_commitment.write_le(&mut writer)?;
        self.program_randomness.write_le(&mut writer)?;

        self.local_data_merkle_tree.write_le(&mut writer)?;

        for local_data_commitment_randomizer in &self.local_data_commitment_randomizers {
            local_data_commitment_randomizer.write_le(&mut writer)?;
        }

        self.value_balance.write_le(&mut writer)?;
        self.memorandum.write_le(&mut writer)?;
        self.network_id.write_le(&mut writer)
    }
}

impl<C: Testnet1Components> FromBytes for TransactionKernel<C> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read old record components

        let mut old_records = vec![];
        for _ in 0..C::NUM_INPUT_RECORDS {
            let old_record: Record<C> = FromBytes::read_le(&mut reader)?;
            old_records.push(old_record);
        }

        let mut old_serial_numbers = vec![];
        for _ in 0..C::NUM_INPUT_RECORDS {
            let old_serial_number: <C::AccountSignature as SignatureScheme>::PublicKey =
                FromBytes::read_le(&mut reader)?;
            old_serial_numbers.push(old_serial_number);
        }

        let mut old_randomizers = vec![];
        for _ in 0..C::NUM_INPUT_RECORDS {
            let old_randomizer: <C::AccountSignature as SignatureScheme>::Randomizer = FromBytes::read_le(&mut reader)?;
            old_randomizers.push(old_randomizer);
        }

        // Read new record components

        let mut new_records = vec![];
        for _ in 0..C::NUM_OUTPUT_RECORDS {
            let new_record: Record<C> = FromBytes::read_le(&mut reader)?;
            new_records.push(new_record);
        }

        let mut new_sn_nonce_randomness = vec![];
        for _ in 0..C::NUM_OUTPUT_RECORDS {
            let randomness: [u8; 32] = FromBytes::read_le(&mut reader)?;
            new_sn_nonce_randomness.push(randomness);
        }

        let mut new_commitments = vec![];
        for _ in 0..C::NUM_OUTPUT_RECORDS {
            let new_commitment: <C::RecordCommitment as CommitmentScheme>::Output = FromBytes::read_le(&mut reader)?;
            new_commitments.push(new_commitment);
        }

        let mut new_records_encryption_randomness = vec![];
        for _ in 0..C::NUM_OUTPUT_RECORDS {
            let encryption_randomness: <C::AccountEncryption as EncryptionScheme>::Randomness =
                FromBytes::read_le(&mut reader)?;
            new_records_encryption_randomness.push(encryption_randomness);
        }

        let mut new_encrypted_records = vec![];
        for _ in 0..C::NUM_OUTPUT_RECORDS {
            let encrypted_record: EncryptedRecord<C> = FromBytes::read_le(&mut reader)?;
            new_encrypted_records.push(encrypted_record);
        }

        let mut new_encrypted_record_hashes = vec![];
        for _ in 0..C::NUM_OUTPUT_RECORDS {
            let encrypted_record_hash: <C::EncryptedRecordCRH as CRH>::Output = FromBytes::read_le(&mut reader)?;
            new_encrypted_record_hashes.push(encrypted_record_hash);
        }

        // Read transaction components

        let program_commitment: <C::ProgramIDCommitment as CommitmentScheme>::Output = FromBytes::read_le(&mut reader)?;
        let program_randomness: <C::ProgramIDCommitment as CommitmentScheme>::Randomness =
            FromBytes::read_le(&mut reader)?;

        let local_data_merkle_tree = CommitmentMerkleTree::<C::LocalDataCommitment, C::LocalDataCRH>::from_bytes(
            &mut reader,
            C::local_data_crh().clone(),
        )
        .expect("Could not load local data merkle tree");

        let mut local_data_commitment_randomizers = vec![];
        for _ in 0..4 {
            let local_data_commitment_randomizer: <C::LocalDataCommitment as CommitmentScheme>::Randomness =
                FromBytes::read_le(&mut reader)?;
            local_data_commitment_randomizers.push(local_data_commitment_randomizer);
        }

        let value_balance: AleoAmount = FromBytes::read_le(&mut reader)?;
        let memorandum: <Transaction<C> as TransactionScheme>::Memorandum = FromBytes::read_le(&mut reader)?;
        let network_id: u8 = FromBytes::read_le(&mut reader)?;

        Ok(Self {
            old_records,
            old_serial_numbers,
            old_randomizers,

            new_records,
            new_sn_nonce_randomness,
            new_commitments,

            new_records_encryption_randomness,
            new_encrypted_records,
            new_encrypted_record_hashes,

            program_commitment,
            program_randomness,
            local_data_merkle_tree,
            local_data_commitment_randomizers,
            value_balance,
            memorandum,
            network_id,
        })
    }
}

impl<C: Testnet1Components> FromStr for TransactionKernel<C> {
    type Err = TransactionError;

    fn from_str(kernel: &str) -> Result<Self, Self::Err> {
        Ok(Self::read_le(&hex::decode(kernel)?[..])?)
    }
}

impl<C: Testnet1Components> fmt::Display for TransactionKernel<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            hex::encode(to_bytes_le![self].expect("couldn't serialize to bytes"))
        )
    }
}
