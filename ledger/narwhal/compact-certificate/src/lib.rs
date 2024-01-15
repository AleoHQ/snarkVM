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

mod bytes;
mod serialize;
mod string;

use bit_set::BitSet;
use console::{
    account::{Address, Signature},
    prelude::*,
    types::Field,
};
use ledger_coinbase::PuzzleCommitment;
use narwhal_batch_certificate::BatchCertificate;
use narwhal_compact_header::CompactHeader;
use narwhal_traits::NarwhalCertificate;

use core::hash::{Hash, Hasher};
use indexmap::IndexSet;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

#[derive(Clone)]
pub struct CompactCertificate<N: Network> {
    /// The compact header.
    compact_header: CompactHeader<N>,
    /// The signatures for the batch ID from the committee.
    signatures: IndexSet<Signature<N>>,
}

impl<N: Network> CompactCertificate<N> {
    /// The maximum number of signatures in a compact certificate.
    pub const MAX_SIGNATURES: usize = CompactHeader::<N>::MAX_CERTIFICATES;
}

impl<N: Network> CompactCertificate<N> {
    /// Initializes a new compact certificate.
    pub fn from(compact_header: CompactHeader<N>, signatures: IndexSet<Signature<N>>) -> Result<Self> {
        // Ensure that the number of signatures is within bounds.
        ensure!(signatures.len() <= Self::MAX_SIGNATURES, "Invalid number of signatures");

        // Verify the signatures are valid.
        cfg_iter!(signatures).try_for_each(|signature| {
            if !signature.verify(&signature.to_address(), &[compact_header.batch_id()]) {
                bail!("Invalid compact certificate signature")
            }
            Ok(())
        })?;
        // Return the compact certificate.
        Self::from_unchecked(compact_header, signatures)
    }

    /// Initializes a new compact certificate.
    pub fn from_unchecked(compact_header: CompactHeader<N>, signatures: IndexSet<Signature<N>>) -> Result<Self> {
        // Ensure the signatures are not empty.
        ensure!(!signatures.is_empty(), "Compact certificate must contain signatures");
        // Return the compact certificate.
        Ok(Self { compact_header, signatures })
    }

    /// Initializes a new compact certificate from a batch certificate.
    pub fn from_batch_certificate<'a>(
        batch_certificate: BatchCertificate<N>,
        ratifications: impl ExactSizeIterator<Item = &'a N::RatificationID>,
        solutions: Option<impl ExactSizeIterator<Item = &'a PuzzleCommitment<N>>>,
        transactions: impl ExactSizeIterator<Item = &'a N::TransactionID>,
        rejected_transactions: impl ExactSizeIterator<Item = &'a N::TransactionID>,
    ) -> Result<Self> {
        let compact_header = CompactHeader::new(
            batch_certificate.batch_header(),
            ratifications,
            solutions,
            transactions,
            rejected_transactions,
        )?;
        let signatures = match batch_certificate {
            BatchCertificate::V1 { signatures, .. } => signatures.into_iter().map(|(s, _)| s).collect(),
            BatchCertificate::V2 { signatures, .. } => signatures,
        };
        // Return the compact certificate.
        Self::from_unchecked(compact_header, signatures)
    }
}

impl<N: Network> PartialEq for CompactCertificate<N> {
    fn eq(&self, other: &Self) -> bool {
        self.batch_id() == other.batch_id()
    }
}

impl<N: Network> Eq for CompactCertificate<N> {}

impl<N: Network> Hash for CompactCertificate<N> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.compact_header.batch_id().hash(state);
    }
}

impl<N: Network> CompactCertificate<N> {
    /// Returns the compact header.
    pub const fn compact_header(&self) -> &CompactHeader<N> {
        &self.compact_header
    }

    /// Returns the transaction indices.
    pub const fn transaction_indices(&self) -> &BitSet {
        self.compact_header().transaction_indices()
    }

    /// Returns the solution indices.
    pub const fn solution_indices(&self) -> &BitSet {
        self.compact_header().solution_indices()
    }

    /// Returns the certificate IDs for the last election.
    pub const fn last_election_certificate_ids(&self) -> &IndexSet<Field<N>> {
        self.compact_header().last_election_certificate_ids()
    }

    /// Returns the signature of the compact header.
    pub const fn signature(&self) -> &Signature<N> {
        self.compact_header.signature()
    }

    /// Convert compact certificate to batch certificate
    pub fn into_batch_certificate<'a>(
        self,
        ratifications: impl ExactSizeIterator<Item = &'a N::RatificationID>,
        solutions: Option<impl Iterator<Item = &'a PuzzleCommitment<N>>>,
        transactions: impl Iterator<Item = &'a N::TransactionID>,
        rejected_transactions: impl Iterator<Item = &'a N::TransactionID>,
    ) -> Result<BatchCertificate<N>> {
        let CompactCertificate { compact_header, signatures } = self;
        let batch_header =
            compact_header.into_batch_header(ratifications, solutions, transactions, rejected_transactions)?;
        BatchCertificate::from(batch_header, signatures)
    }
}

impl<N: Network> NarwhalCertificate<N> for CompactCertificate<N> {
    /// Returns the certificate ID.
    fn id(&self) -> Field<N> {
        self.compact_header.batch_id()
    }

    /// Returns the batch ID.
    fn batch_id(&self) -> Field<N> {
        self.compact_header().batch_id()
    }

    /// Returns the author.
    fn author(&self) -> Address<N> {
        self.compact_header().author()
    }

    /// Returns the round.
    fn round(&self) -> u64 {
        self.compact_header().round()
    }

    /// Returns the certificate IDs for the previous round.
    fn previous_certificate_ids(&self) -> &IndexSet<Field<N>> {
        self.compact_header().previous_certificate_ids()
    }

    /// Returns the timestamp of the compact header.
    fn timestamp(&self) -> i64 {
        self.compact_header.timestamp()
    }

    /// Returns the signatures of the batch ID from the committee.
    fn signatures(&self) -> Box<dyn '_ + ExactSizeIterator<Item = &Signature<N>>> {
        Box::new(self.signatures.iter())
    }
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use console::{account::PrivateKey, network::Testnet3, prelude::TestRng, types::Field};

    use indexmap::IndexSet;

    type CurrentNetwork = Testnet3;

    /// Returns a sample compact certificate, sampled at random.
    pub fn sample_compact_certificate(rng: &mut TestRng) -> CompactCertificate<CurrentNetwork> {
        sample_compact_certificate_for_round(rng.gen(), rng)
    }

    /// Returns a sample compact certificate with a given round; the rest is sampled at random.
    pub fn sample_compact_certificate_for_round(round: u64, rng: &mut TestRng) -> CompactCertificate<CurrentNetwork> {
        // Sample certificate IDs.
        let certificate_ids = (0..10).map(|_| Field::<CurrentNetwork>::rand(rng)).collect::<IndexSet<_>>();
        // Return the compact certificate.
        sample_compact_certificate_for_round_with_previous_certificate_ids(round, certificate_ids, rng)
    }

    /// Returns a sample compact certificate with a given round; the rest is sampled at random.
    pub fn sample_compact_certificate_for_round_with_previous_certificate_ids(
        round: u64,
        previous_certificate_ids: IndexSet<Field<CurrentNetwork>>,
        rng: &mut TestRng,
    ) -> CompactCertificate<CurrentNetwork> {
        // Sample a compact header.
        let compact_header =
            narwhal_compact_header::test_helpers::sample_compact_header_for_round_with_previous_certificate_ids(
                round,
                previous_certificate_ids,
                rng,
            );
        // Sample a list of signatures.
        let mut signatures = IndexSet::with_capacity(5);
        for _ in 0..5 {
            let private_key = PrivateKey::new(rng).unwrap();
            signatures.insert(private_key.sign(&[compact_header.batch_id()], rng).unwrap());
        }
        // Return the compact certificate.
        CompactCertificate::from(compact_header, signatures).unwrap()
    }

    /// Returns a list of sample compact certificates, sampled at random.
    pub fn sample_compact_certificates(rng: &mut TestRng) -> IndexSet<CompactCertificate<CurrentNetwork>> {
        // Initialize a sample vector.
        let mut sample = IndexSet::with_capacity(10);
        // Append sample compact certificates.
        for _ in 0..10 {
            sample.insert(sample_compact_certificate(rng));
        }
        // Return the sample vector.
        sample
    }

    /// Returns a sample compact certificate with previous certificates, sampled at random.
    pub fn sample_compact_certificate_with_previous_certificates(
        round: u64,
        rng: &mut TestRng,
    ) -> (CompactCertificate<CurrentNetwork>, Vec<CompactCertificate<CurrentNetwork>>) {
        assert!(round > 1, "Round must be greater than 1");

        // Initialize the round parameters.
        let previous_round = round - 1; // <- This must be an even number, for `BFT::update_dag` to behave correctly below.
        let current_round = round;

        assert_eq!(previous_round % 2, 0, "Previous round must be even");

        // Sample the previous certificates.
        let previous_certificates = vec![
            sample_compact_certificate_for_round(previous_round, rng),
            sample_compact_certificate_for_round(previous_round, rng),
            sample_compact_certificate_for_round(previous_round, rng),
            sample_compact_certificate_for_round(previous_round, rng),
        ];
        // Construct the previous certificate IDs.
        let previous_certificate_ids: IndexSet<_> = previous_certificates.iter().map(|c| c.id()).collect();
        // Sample the leader certificate.
        let certificate = sample_compact_certificate_for_round_with_previous_certificate_ids(
            current_round,
            previous_certificate_ids.clone(),
            rng,
        );

        (certificate, previous_certificates)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type CurrentNetwork = console::network::Testnet3;

    #[test]
    fn test_maximum_signatures() {
        assert_eq!(
            CompactHeader::<CurrentNetwork>::MAX_CERTIFICATES,
            CompactCertificate::<CurrentNetwork>::MAX_SIGNATURES
        );
    }
}
