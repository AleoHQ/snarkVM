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

use crate::traits::{AccountScheme, LedgerScheme, RecordScheme, TransactionScheme};

use rand::{CryptoRng, Rng};
use std::sync::Arc;

pub trait DPCScheme<L: LedgerScheme>: Sized {
    type Account: AccountScheme;
    type Execution;
    type Record: RecordScheme<Owner = <Self::Account as AccountScheme>::Address>;
    type Transaction: TransactionScheme<SerialNumber = <Self::Record as RecordScheme>::SerialNumber>;
    type TransactionKernel;

    /// Initializes a new instance of DPC.
    fn setup<R: Rng + CryptoRng>(ledger_parameters: &Arc<L::MerkleParameters>, rng: &mut R) -> anyhow::Result<Self>;

    /// Loads the saved instance of DPC.
    fn load(verify_only: bool) -> anyhow::Result<Self>;

    /// Returns an account, given the system parameters, metadata, and an RNG.
    fn create_account<R: Rng + CryptoRng>(&self, rng: &mut R) -> anyhow::Result<Self::Account>;

    /// Returns the execution context required for program snark and DPC transaction generation.
    #[allow(clippy::too_many_arguments)]
    fn execute_offline_phase<R: Rng + CryptoRng>(
        &self,
        old_private_keys: &Vec<<Self::Account as AccountScheme>::PrivateKey>,
        old_records: Vec<Self::Record>,
        new_records: Vec<Self::Record>,
        memorandum: <Self::Transaction as TransactionScheme>::Memorandum,
        rng: &mut R,
    ) -> anyhow::Result<Self::TransactionKernel>;

    /// Returns new records and a transaction based on the authorized
    /// consumption of old records.
    fn execute_online_phase<R: Rng + CryptoRng>(
        &self,
        old_private_keys: &Vec<<Self::Account as AccountScheme>::PrivateKey>,
        transaction_kernel: Self::TransactionKernel,
        program_proofs: Vec<Self::Execution>,
        ledger: &L,
        rng: &mut R,
    ) -> anyhow::Result<(Vec<Self::Record>, Self::Transaction)>;

    /// Returns true iff the transaction is valid according to the ledger.
    fn verify(&self, transaction: &Self::Transaction, ledger: &L) -> bool;

    /// Returns true iff all the transactions in the block are valid according to the ledger.
    fn verify_transactions(&self, block: &[Self::Transaction], ledger: &L) -> bool;
}
