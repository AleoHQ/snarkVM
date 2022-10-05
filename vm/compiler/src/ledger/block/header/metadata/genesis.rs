// Copyright (C) 2019-2022 Aleo Systems Inc.
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

use super::*;

impl<N: Network> Metadata<N> {
    /// Initializes the genesis metadata.
    pub fn genesis() -> Result<Self> {
        // Prepare a genesis metadata.
        let network = N::ID;
        let round = 0;
        let height = 0;
        let coinbase_target = u64::MAX;
        let proof_target = u64::MAX;
        let timestamp = 0;

        // Return the genesis metadata.
        Self::new(network, round, height, coinbase_target, proof_target, timestamp)
    }

    /// Returns `true` if the metadata is a genesis metadata.
    pub fn is_genesis(&self) -> bool {
        // Ensure the network ID is correct.
        self.network == N::ID
            // Ensure the round in the genesis block is 0.
            && self.round == 0u64
            // Ensure the height in the genesis block is 0.
            && self.height == 0u32
            // Ensure the coinbase target in the genesis block is u64::MAX.
            && self.coinbase_target == u64::MAX
            // Ensure the proof target in the genesis block is u64::MAX.
            && self.proof_target == u64::MAX
            // Ensure the timestamp in the genesis block is 0.
            && self.timestamp == 0i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::Testnet3;

    type CurrentNetwork = Testnet3;

    /// Returns the expected metadata size by summing its subcomponent sizes.
    /// Update this method if the contents of the metadata have changed.
    fn get_expected_size<N: Network>() -> usize {
        // Metadata size.
        2 + 4 + 8 + 8 + 8 + 8
            // Add an additional 2 bytes for versioning.
            + 2
    }

    #[test]
    fn test_genesis_metadata_size() {
        let mut rng = TestRng::default();

        // Prepare the expected size.
        let expected_size = get_expected_size::<CurrentNetwork>();
        // Prepare the genesis metadata.
        let genesis_metadata = *crate::ledger::test_helpers::sample_genesis_block(&mut rng).metadata();
        // Ensure the size of the genesis metadata is correct.
        assert_eq!(expected_size, genesis_metadata.to_bytes_le().unwrap().len());
    }

    #[test]
    fn test_genesis_metadata() {
        let mut rng = TestRng::default();

        // Prepare the genesis metadata.
        let metadata = *crate::ledger::test_helpers::sample_genesis_block(&mut rng).metadata();
        // Ensure the metadata is a genesis metadata.
        assert!(metadata.is_genesis());

        // Ensure the genesis block contains the following.
        assert_eq!(metadata.network(), CurrentNetwork::ID);
        assert_eq!(metadata.height(), 0);
        assert_eq!(metadata.round(), 0);
        assert_eq!(metadata.coinbase_target(), u64::MAX);
        assert_eq!(metadata.proof_target(), u64::MAX);
        assert_eq!(metadata.timestamp(), 0);
    }
}
