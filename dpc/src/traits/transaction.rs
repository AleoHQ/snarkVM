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

use crate::errors::TransactionError;
use snarkvm_utilities::{FromBytes, ToBytes};

use std::hash::Hash;

pub trait TransactionScheme: Clone + Eq + FromBytes + ToBytes {
    type Commitment: Clone + Eq + Hash + FromBytes + ToBytes + Sync + Send;
    type Digest: Clone + Eq + Hash + FromBytes + ToBytes;
    type InnerCircuitID: Clone + Eq + FromBytes + ToBytes;
    type LocalDataRoot: Clone + Eq + Hash + FromBytes + ToBytes;
    type Memorandum: Clone + Eq + Hash + FromBytes + ToBytes;
    type SerialNumber: Clone + Eq + Hash + FromBytes + ToBytes;
    type EncryptedRecord: Clone + Eq + FromBytes + ToBytes;
    type ValueBalance: Clone + Eq + FromBytes + ToBytes;
    type Signature: Clone + Eq + FromBytes + ToBytes;

    /// Returns the transaction identifier.
    fn transaction_id(&self) -> Result<[u8; 32], TransactionError>;

    /// Returns the network_id in the transaction.
    fn network_id(&self) -> u8;

    /// Returns the ledger digest.
    fn ledger_digest(&self) -> &Self::Digest;

    /// Returns the inner circuit ID.
    fn inner_circuit_id(&self) -> &Self::InnerCircuitID;

    /// Returns the old serial numbers.
    fn old_serial_numbers(&self) -> &[Self::SerialNumber];

    /// Returns the new commitments.
    fn new_commitments(&self) -> &[Self::Commitment];

    /// Returns the memorandum.
    fn memorandum(&self) -> &Self::Memorandum;

    /// Returns the local data root in the transaction.
    fn local_data_root(&self) -> &Self::LocalDataRoot;

    /// Returns the value balance in the transaction.
    fn value_balance(&self) -> Self::ValueBalance;

    /// Returns the signatures.
    fn signatures(&self) -> &[Self::Signature];

    /// Returns the encrypted records
    fn encrypted_records(&self) -> &[Self::EncryptedRecord];

    /// Returns the transaction size in bytes.
    fn size(&self) -> usize;
}
