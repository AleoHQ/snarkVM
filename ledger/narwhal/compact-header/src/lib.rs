// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![forbid(unsafe_code)]
#![warn(clippy::cast_possible_truncation)]
#![allow(clippy::too_many_arguments)]

mod bytes;
mod serialize;
mod string;

use bit_set::BitSet;
use console::{
    account::{Address, Signature},
    prelude::*,
    types::Field,
};
use indexmap::IndexSet;
use ledger_coinbase::PuzzleCommitment;
use narwhal_batch_header::BatchHeader;
use narwhal_transmission_id::TransmissionID;

#[derive(Clone, PartialEq, Eq)]
pub struct CompactHeader<N: Network> {
    /// The batch ID, defined as the hash of the author, round number, timestamp, transmission IDs,
    /// previous batch certificate IDs, and last election certificate IDs.
    batch_id: Field<N>,
    /// The author of the batch.
    author: Address<N>,
    /// The round number.
    round: u64,
    /// The timestamp.
    timestamp: i64,
    /// The set of transaction indices in a block.
    transaction_indices: BitSet,
    /// The set of solution indices in a block.
    solution_indices: BitSet,
    /// The batch certificate IDs of the previous round.
    previous_certificate_ids: IndexSet<Field<N>>,
    /// The last election batch certificate IDs.
    last_election_certificate_ids: IndexSet<Field<N>>,
    /// The signature of the batch ID from the creator.
    signature: Signature<N>,
}

impl<N: Network> CompactHeader<N> {
    /// The maximum number of certificates in a batch.
    pub const MAX_CERTIFICATES: usize = BatchHeader::<N>::MAX_CERTIFICATES;
    /// The maximum number of solutions in a batch.
    pub const MAX_SOLUTIONS: usize = BatchHeader::<N>::MAX_SOLUTIONS;
    /// The maximum number of transactions in a batch.
    pub const MAX_TRANSACTIONS: usize = BatchHeader::<N>::MAX_TRANSACTIONS;
    /// The maximum number of transmissions in a batch.
    pub const MAX_TRANSMISSIONS: usize = BatchHeader::<N>::MAX_TRANSMISSIONS;
}

impl<N: Network> CompactHeader<N> {
    /// Initializes a new batch header.
    pub fn new<'a>(
        batch_header: &BatchHeader<N>,
        _ratifications: impl ExactSizeIterator<Item = &'a N::RatificationID>,
        solutions: Option<impl ExactSizeIterator<Item = &'a PuzzleCommitment<N>>>,
        prior_solutions: impl ExactSizeIterator<Item = &'a PuzzleCommitment<N>>,
        transactions: impl ExactSizeIterator<Item = &'a N::TransactionID>,
        prior_transactions: impl ExactSizeIterator<Item = &'a N::TransactionID>,
        aborted_transactions: impl ExactSizeIterator<Item = &'a N::TransactionID>,
    ) -> Result<Self> {
        let transmission_ids = batch_header.transmission_ids();

        // Check the number of transactions and solutions in the batch.
        let mut num_transactions = 0;
        let mut num_solutions = 0;
        for id in transmission_ids.iter() {
            match id {
                TransmissionID::Solution(_) => num_solutions += 1,
                TransmissionID::Transaction(_) => num_transactions += 1,
                TransmissionID::Ratification => bail!("Invalid batch, contains ratifications"),
            }
        }

        // Check which transaction_indices the certificate contains.
        let mut transaction_indices = BitSet::with_capacity(num_transactions);
        for (i, transaction_id) in transactions.chain(aborted_transactions).chain(prior_transactions).enumerate() {
            let transmission_id = TransmissionID::Transaction(*transaction_id);
            if transmission_ids.contains(&transmission_id) {
                transaction_indices.insert(i);
            }
        }

        // Check which solution_indices the certificate contains.
        let solution_indices = match solutions {
            Some(solutions) => {
                Self::create_solution_indices(solutions.chain(prior_solutions), transmission_ids, num_solutions)
            }
            None => Self::create_solution_indices(prior_solutions, transmission_ids, num_solutions),
        };

        // Check if we found all Transmission IDs.
        ensure!(
            transaction_indices.len() + solution_indices.len() == transmission_ids.len(),
            "Could not find all transmission_ids"
        );

        // Return the compact header.
        Ok(Self {
            author: batch_header.author(),
            batch_id: batch_header.batch_id(),
            round: batch_header.round(),
            timestamp: batch_header.timestamp(),
            transaction_indices,
            solution_indices,
            previous_certificate_ids: batch_header.previous_certificate_ids().clone(),
            last_election_certificate_ids: batch_header.last_election_certificate_ids().clone(),
            signature: *batch_header.signature(),
        })
    }

    /// Creates solution_indices from transmission_ids.
    fn create_solution_indices<'a>(
        block_solutions: impl Iterator<Item = &'a PuzzleCommitment<N>>,
        transmission_ids: &IndexSet<TransmissionID<N>>,
        num_solutions_in_batch: usize,
    ) -> BitSet {
        let mut solution_indices = BitSet::with_capacity(num_solutions_in_batch);
        for (i, solution_id) in block_solutions.enumerate() {
            if transmission_ids.contains(&TransmissionID::Solution(*solution_id)) {
                solution_indices.insert(i);
            }
        }
        solution_indices
    }

    /// Initializes a new compact header.
    /// This does not recompute the batch_id.
    pub fn from(
        batch_id: Field<N>,
        author: Address<N>,
        round: u64,
        timestamp: i64,
        transaction_indices: BitSet,
        solution_indices: BitSet,
        previous_certificate_ids: IndexSet<Field<N>>,
        last_election_certificate_ids: IndexSet<Field<N>>,
        signature: Signature<N>,
    ) -> Result<Self> {
        match round {
            0 | 1 => {
                // If the round is zero or one, then there should be no previous certificate IDs.
                ensure!(previous_certificate_ids.is_empty(), "Invalid round number, must not have certificates");
                // If the round is zero or one, then there should be no last election certificate IDs.
                ensure!(last_election_certificate_ids.is_empty(), "Invalid batch, contains election certificates");
            }
            // If the round is not zero and not one, then there should be at least one previous certificate ID.
            _ => ensure!(!previous_certificate_ids.is_empty(), "Invalid round number, must have certificates"),
        }

        // Ensure that the number of transmissions is within bounds.
        ensure!(
            transaction_indices.len() + solution_indices.len() <= Self::MAX_TRANSMISSIONS,
            "Invalid number of transmission ids"
        );
        // Ensure that the number of previous certificate IDs is within bounds.
        ensure!(previous_certificate_ids.len() <= Self::MAX_CERTIFICATES, "Invalid number of previous certificate IDs");
        // Ensure the number of last election certificate IDs is within bounds.
        ensure!(
            last_election_certificate_ids.len() <= Self::MAX_CERTIFICATES,
            "Invalid number of last election certificate IDs"
        );

        // Verify the signature.
        if !signature.verify(&author, &[batch_id]) {
            bail!("Invalid signature for the batch header");
        }
        // Return the compact header.
        Ok(Self {
            author,
            batch_id,
            round,
            timestamp,
            transaction_indices,
            solution_indices,
            previous_certificate_ids,
            last_election_certificate_ids,
            signature,
        })
    }
}

impl<N: Network> CompactHeader<N> {
    /// Returns the batch ID.
    pub const fn batch_id(&self) -> Field<N> {
        self.batch_id
    }

    /// Returns the author.
    pub const fn author(&self) -> Address<N> {
        self.author
    }

    /// Returns the round number.
    pub const fn round(&self) -> u64 {
        self.round
    }

    /// Returns the timestamp.
    pub const fn timestamp(&self) -> i64 {
        self.timestamp
    }

    /// Returns the transaction indices.
    pub const fn transaction_indices(&self) -> &BitSet {
        &self.transaction_indices
    }

    /// Returns the solution indices.
    pub const fn solution_indices(&self) -> &BitSet {
        &self.solution_indices
    }

    /// Returns the batch certificate IDs for the previous round.
    pub const fn previous_certificate_ids(&self) -> &IndexSet<Field<N>> {
        &self.previous_certificate_ids
    }

    /// Returns the last election batch certificate IDs.
    pub const fn last_election_certificate_ids(&self) -> &IndexSet<Field<N>> {
        &self.last_election_certificate_ids
    }

    /// Returns the signature.
    pub const fn signature(&self) -> &Signature<N> {
        &self.signature
    }

    /// Convert compact header to batch header
    pub fn into_batch_header<'a>(
        self,
        _ratifications: impl ExactSizeIterator<Item = &'a N::RatificationID>,
        solutions: Option<impl Iterator<Item = &'a PuzzleCommitment<N>>>,
        prior_solutions: impl ExactSizeIterator<Item = &'a PuzzleCommitment<N>>,
        transactions: impl Iterator<Item = &'a N::TransactionID>,
        prior_transactions: impl ExactSizeIterator<Item = &'a N::TransactionID>,
        rejected_transactions: impl Iterator<Item = &'a N::TransactionID>,
    ) -> Result<BatchHeader<N>> {
        // TODO (howardwu): For mainnet - Remove this version from the struct, we only use it here for backwards compatibility.
        //  NOTE: You must keep the version encoding in the byte serialization, just remove it from the struct in memory.
        // TODO (howardwu): For mainnet - Remove the version from BatchHeader.
        let version = 2u8;

        let mut transmission_ids = IndexSet::new();
        transactions.chain(rejected_transactions).chain(prior_transactions).enumerate().for_each(
            |(index, transaction_id)| {
                if self.transaction_indices.contains(index) {
                    transmission_ids.insert(TransmissionID::Transaction(*transaction_id));
                }
            },
        );
        match solutions {
            Some(solutions) => {
                solutions.chain(prior_solutions).enumerate().for_each(|(index, puzzle_commitment)| {
                    if self.transaction_indices.contains(index) {
                        transmission_ids.insert(TransmissionID::Solution(*puzzle_commitment));
                    }
                });
            }
            None => {
                prior_solutions.enumerate().for_each(|(index, puzzle_commitment)| {
                    if self.transaction_indices.contains(index) {
                        transmission_ids.insert(TransmissionID::Solution(*puzzle_commitment));
                    }
                });
            }
        };

        ensure!(
            transmission_ids.len() == self.transaction_indices.len() + self.solution_indices.len(),
            "Could not find all transmission_ids"
        );
        BatchHeader::from(
            version,
            self.author,
            self.round,
            self.timestamp,
            transmission_ids,
            self.previous_certificate_ids,
            self.last_election_certificate_ids,
            self.signature,
        )
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use console::{network::Testnet3, prelude::TestRng};

    use narwhal_batch_header::test_helpers::sample_batch_header_for_round_with_previous_certificate_ids;

    type CurrentNetwork = Testnet3;

    /// Returns a sample batch header, sampled at random.
    pub fn sample_compact_header(rng: &mut TestRng) -> CompactHeader<CurrentNetwork> {
        sample_compact_header_for_round(rng.gen(), rng)
    }

    /// Returns a sample compact header with a given round; the rest is sampled at random.
    pub fn sample_compact_header_for_round(round: u64, rng: &mut TestRng) -> CompactHeader<CurrentNetwork> {
        // Sample certificate IDs.
        let certificate_ids = (0..10).map(|_| Field::<CurrentNetwork>::rand(rng)).collect::<IndexSet<_>>();
        // Return the batch header.
        sample_compact_header_for_round_with_previous_certificate_ids(round, certificate_ids, rng)
    }

    /// Returns a sample compact header with a given round and set of previous certificate IDs; the rest is sampled at random.
    pub fn sample_compact_header_for_round_with_previous_certificate_ids(
        round: u64,
        previous_certificate_ids: IndexSet<Field<CurrentNetwork>>,
        rng: &mut TestRng,
    ) -> CompactHeader<CurrentNetwork> {
        // Sample a batch header.
        let batch_header =
            sample_batch_header_for_round_with_previous_certificate_ids(round, previous_certificate_ids, rng);
        // Construct a set of all transmission IDs.
        let mut solutions = IndexSet::new();
        let mut prior_solutions = IndexSet::new();
        let mut tx_ids = IndexSet::new();
        let mut prior_tx_ids = IndexSet::new();
        let mut rejected_tx_ids = IndexSet::new();
        for (i, transmission_id) in batch_header.transmission_ids().iter().enumerate() {
            match transmission_id {
                TransmissionID::Solution(solution) => match i % 2 {
                    0 => {
                        solutions.insert(*solution);
                    }
                    1 => {
                        prior_solutions.insert(*solution);
                    }
                    _ => panic!("Invalid solution index"),
                },
                TransmissionID::Transaction(transaction_id) => match i % 3 {
                    0 => {
                        tx_ids.insert(*transaction_id);
                    }
                    1 => {
                        prior_tx_ids.insert(*transaction_id);
                    }
                    2 => {
                        rejected_tx_ids.insert(*transaction_id);
                    }
                    _ => panic!("Invalid solution index"),
                },
                TransmissionID::Ratification => {}
            }
        }

        // Return the compact header.
        let compact_header = CompactHeader::new(
            &batch_header,
            std::iter::empty(),
            Some(solutions.iter()),
            prior_solutions.iter(),
            tx_ids.iter(),
            prior_tx_ids.iter(),
            rejected_tx_ids.iter(),
        )
        .unwrap();

        let check_batch_header = compact_header
            .clone()
            .into_batch_header(
                std::iter::empty(),
                Some(solutions.iter()),
                prior_solutions.iter(),
                tx_ids.iter(),
                prior_tx_ids.iter(),
                rejected_tx_ids.iter(),
            )
            .unwrap();
        assert_eq!(batch_header, check_batch_header);
        compact_header
    }

    /// Returns a list of sample compact headers, sampled at random.
    pub fn sample_compact_headers(rng: &mut TestRng) -> Vec<CompactHeader<CurrentNetwork>> {
        // Initialize a sample vector.
        let mut sample = Vec::with_capacity(10);
        // Append sample batches.
        for _ in 0..10 {
            // Append the batch header.
            sample.push(sample_compact_header(rng));
        }
        // Return the sample vector.
        sample
    }
}
