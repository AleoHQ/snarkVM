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

mod contains;
pub use contains::*;

mod get;
pub use get::*;

mod iterators;
pub use iterators::*;

mod latest;
pub use latest::*;

use crate::ledger::{
    map::{memory_map::MemoryMap, Map, MapReader},
    store::{TransactionMemory, TransactionStorage, TransactionStore},
    Block,
    Deployment,
    Header,
    HeaderLeaf,
    Origin,
    Signature,
    StatePath,
    Transaction,
    Transition,
};

use console::{
    collections::merkle_tree::MerklePath,
    network::{prelude::*, BHPMerkleTree},
    program::{Plaintext, Record},
    types::{Field, Group},
};
use snarkvm_parameters::testnet3::GenesisBytes;

use anyhow::Result;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// The depth of the Merkle tree for the blocks.
const BLOCKS_DEPTH: u8 = 32;

/// The Merkle tree for the block state.
pub type BlockTree<N> = BHPMerkleTree<N, BLOCKS_DEPTH>;
/// The Merkle path for the state tree blocks.
pub type BlockPath<N> = MerklePath<N, BLOCKS_DEPTH>;

/// A trait for block storage.
pub trait BlockStorage<N: Network>: Clone {
    type HashesMap: for<'a> Map<'a, u32, N::BlockHash>;
    type HeadersMap: for<'a> Map<'a, N::BlockHash, Header<N>>;
    type SignaturesMap: for<'a> Map<'a, N::BlockHash, Signature<N>>;
    type TransactionsMap: for<'a> Map<'a, N::BlockHash, Vec<N::TransactionID>>;
}

/// An in-memory block storage.
#[derive(Clone)]
pub struct BlockMemory<N: Network>(core::marker::PhantomData<N>);

#[rustfmt::skip]
impl<N: Network> BlockStorage<N> for BlockMemory<N> {
    type HashesMap = MemoryMap<u32, N::BlockHash>;
    type HeadersMap = MemoryMap<N::BlockHash, Header<N>>;
    type SignaturesMap = MemoryMap<N::BlockHash, Signature<N>>;
    type TransactionsMap = MemoryMap<N::BlockHash, Vec<N::TransactionID>>;
}

#[derive(Clone)]
pub struct BlockStore<N: Network, B: BlockStorage<N>, T: TransactionStorage<N>> {
    /// The current block hash.
    current_hash: N::BlockHash,
    /// The current block height.
    current_height: u32,
    /// The current round number.
    current_round: u64,
    /// The current block tree.
    block_tree: BlockTree<N>,
    /// The map of block hashes.
    hashes: B::HashesMap,
    /// The map of block headers.
    headers: B::HeadersMap,
    /// The map of block signatures.
    signatures: B::SignaturesMap,
    /// The map of block transactions.
    transactions: B::TransactionsMap,
    /// The store of transaction state.
    transaction_store: TransactionStore<N, T>,
}

impl<N: Network> BlockStore<N, BlockMemory<N>, TransactionMemory<N>> {
    /// Initializes a new instance of `BlockStore` with the genesis block.
    pub fn new() -> Result<Self> {
        // Load the genesis block.
        let genesis = Block::<N>::from_bytes_le(GenesisBytes::load_bytes())?;
        // Initialize the ledger.
        Self::from_genesis(&genesis)
    }

    /// Initializes a new instance of `BlockStore` with the given genesis block.
    pub fn from_genesis(genesis: &Block<N>) -> Result<Self> {
        // Initialize the block store.
        let mut block_store = Self {
            current_hash: Default::default(),
            current_height: 0,
            current_round: 0,
            block_tree: N::merkle_tree_bhp(&[])?,
            hashes: [].into_iter().collect(),
            headers: [].into_iter().collect(),
            transactions: [].into_iter().collect(),
            signatures: [].into_iter().collect(),
            transaction_store: TransactionStore::new(),
        };

        // Add the genesis block.
        block_store.add_next_block(genesis)?;

        // Return the block store.
        Ok(block_store)
    }
}

impl<N: Network, B: BlockStorage<N>, T: TransactionStorage<N>> BlockStore<N, B, T> {
    /// Initializes a new instance of `Ledger` from the given maps.
    pub fn from_maps(
        hashes: B::HashesMap,
        headers: B::HeadersMap,
        signatures: B::SignaturesMap,
        transactions: B::TransactionsMap,
        deployments: T::DeploymentsMap,
        executions: T::ExecutionsMap,
        transitions: T::TransitionsMap,
        transition_public_keys: T::TransitionPublicKeysMap,
        origins: T::OriginsMap,
        serial_numbers: T::SerialNumbersMap,
        commitments: T::CommitmentsMap,
        nonce: T::NonceMap,
    ) -> Result<Self> {
        // Initialize the ledger.
        let mut block_store = Self {
            current_hash: Default::default(),
            current_height: 0,
            current_round: 0,
            block_tree: N::merkle_tree_bhp(&[])?,
            hashes,
            headers,
            transactions,
            signatures,
            transaction_store: TransactionStore::from_maps(
                deployments,
                executions,
                transitions,
                transition_public_keys,
                origins,
                serial_numbers,
                commitments,
                nonce,
            )?,
        };

        // Fetch the latest height.
        let latest_height = match block_store.hashes.keys().max() {
            Some(height) => *height,
            // If there are no previous hashes, add the genesis block.
            None => {
                // Load the genesis block.
                let genesis = Block::<N>::from_bytes_le(GenesisBytes::load_bytes())?;

                // Add the genesis block.
                block_store.hashes.insert(genesis.height(), genesis.hash())?;
                block_store.headers.insert(genesis.hash(), *genesis.header())?;
                block_store
                    .transactions
                    .insert(genesis.hash(), genesis.transactions().iter().map(|(_, tx)| tx.id()).collect())?;
                block_store.signatures.insert(genesis.hash(), *genesis.signature())?;

                // Return the genesis height.
                genesis.height()
            }
        };

        // Fetch the latest block.
        let block = block_store.get_block(latest_height)?;

        // Set the current hash, height, and round.
        block_store.current_hash = block.hash();
        block_store.current_height = block.height();
        block_store.current_round = block.round();

        // Generate the block tree.
        block_store.block_tree =
            N::merkle_tree_bhp(&block_store.hashes.values().map(|hash| (*hash).to_bits_le()).collect::<Vec<_>>())?;

        // Safety check the existence of every block.
        (0..=latest_height).into_par_iter().try_for_each(|height| {
            block_store.get_block(height)?;
            Ok::<_, Error>(())
        })?;

        Ok(block_store)
    }

    /// Checks the given block is valid next block.
    pub fn check_next_block(&self, block: &Block<N>) -> Result<()> {
        // Ensure the previous block hash is correct.
        if self.current_hash != block.previous_hash() {
            bail!("The given block has an incorrect previous block hash")
        }

        // Ensure the block hash does not already exist.
        if self.contains_block_hash(&block.hash()) {
            bail!("Block hash '{}' already exists in the ledger", block.hash())
        }

        // Ensure the next block height is correct.
        if self.latest_height() > 0 && self.latest_height() + 1 != block.height() {
            bail!("The given block has an incorrect block height")
        }

        // Ensure the block height does not already exist.
        if self.contains_height(block.height())? {
            bail!("Block height '{}' already exists in the ledger", block.height())
        }

        // TODO (raychu86): Ensure the next round number includes timeouts.
        // Ensure the next round is correct.
        if self.latest_round() > 0 && self.latest_round() + 1 /*+ block.number_of_timeouts()*/ != block.round() {
            bail!("The given block has an incorrect round number")
        }

        // TODO (raychu86): Ensure the next block timestamp is the median of proposed blocks.
        // Ensure the next block timestamp is after the current block timestamp.
        if block.height() > 0 && block.header().timestamp() <= self.latest_block()?.header().timestamp() {
            bail!("The given block timestamp is before the current timestamp")
        }

        // TODO (raychu86): Add proof and coinbase target verification.

        // Ensure that the transactions do not have collisions.
        for (_, transaction) in block.transactions().iter() {
            self.transaction_store.check_transaction(transaction)?;
        }

        Ok(())
    }

    /// Adds the given block as the next block in the chain.
    pub fn add_next_block(&mut self, block: &Block<N>) -> Result<()> {
        // Ensure the given block is a valid next block.
        self.check_next_block(block)?;

        /* ATOMIC CODE SECTION */

        // Add the block to the ledger. This code section executes atomically.
        {
            let mut block_store = self.clone();

            // Update the blocks.
            block_store.current_hash = block.hash();
            block_store.current_height = block.height();
            block_store.current_round = block.round();
            block_store.block_tree.append(&[block.hash().to_bits_le()])?;
            block_store.hashes.insert(block.height(), block.hash())?;
            block_store.headers.insert(block.hash(), *block.header())?;
            block_store.signatures.insert(block.hash(), *block.signature())?;
            block_store
                .transactions
                .insert(block.hash(), block.transactions().iter().map(|(_, tx)| tx.id()).collect())?;

            for (_, transaction) in block.transactions().iter() {
                block_store.transaction_store.insert(transaction.clone())?;
            }

            *self = Self {
                current_hash: block_store.current_hash,
                current_height: block_store.current_height,
                current_round: block_store.current_round,
                block_tree: block_store.block_tree,
                hashes: block_store.hashes,
                headers: block_store.headers,
                signatures: block_store.signatures,
                transactions: block_store.transactions,
                transaction_store: block_store.transaction_store,
            };
        }

        Ok(())
    }

    /// Returns the block tree.
    pub fn to_block_tree(&self) -> &BlockTree<N> {
        &self.block_tree
    }

    /// Returns a state path for the given commitment.
    pub fn to_state_path(&self, commitment: &Field<N>) -> Result<StatePath<N>> {
        // TODO (raychu86): Find a faster way than scanning through all the transactions.
        // Find the transaction that contains the record commitment.
        let transaction = self
            .transactions()
            .filter(|transaction| transaction.commitments().contains(&commitment))
            .map(|transaction| transaction.into_owned())
            .collect::<Vec<Transaction<N>>>();

        if transaction.len() != 1 {
            bail!("Multiple transactions associated with commitment {}", commitment.to_string())
        }

        let transaction = &transaction[0];

        // Find the block height that contains the record transaction id.
        let block_hash = self
            .transactions
            .iter()
            .filter_map(|(block_hash, transaction_ids)| match transaction_ids.contains(&transaction.id()) {
                true => Some(block_hash),
                false => None,
            })
            .collect::<Vec<_>>();

        if block_hash.len() != 1 {
            bail!("Multiple block hashes associated with transaction id {}", transaction.id().to_string())
        }

        let block_hash = *block_hash[0];
        let block_height = self.get_block_height(block_hash)?;
        let block_header = self.get_header(block_height)?;

        // Find the transition that contains the record commitment.
        let transition = transaction
            .transitions()
            .filter(|transition| transition.commitments().contains(&commitment))
            .collect::<Vec<_>>();

        if transition.len() != 1 {
            bail!("Multiple transitions associated with commitment {}", commitment.to_string())
        }

        let transition = transition[0];
        let transition_id = transition.id();

        // Construct the transition path and transaction leaf.
        let transition_leaf = transition.to_leaf(commitment, false)?;
        let transition_path = transition.to_path(&transition_leaf)?;

        // Construct the transaction path and transaction leaf.
        let transaction_leaf = transaction.to_leaf(transition_id)?;
        let transaction_path = transaction.to_path(&transaction_leaf)?;

        // Construct the transactions path.
        let transactions = self.get_transactions(block_height)?;
        let transaction_index = transactions.iter().position(|(id, _)| id == &transaction.id()).unwrap();
        let transactions_path = transactions.to_path(transaction_index, *transaction.id())?;

        // Construct the block header path.
        let header_root = block_header.to_root()?;
        let header_leaf = HeaderLeaf::<N>::new(1, *block_header.transactions_root());
        let header_path = block_header.to_path(&header_leaf)?;

        // Construct the block path.
        let latest_block_height = self.latest_height();
        let latest_block_hash = self.latest_hash();
        let previous_block_hash = self.get_previous_hash(latest_block_height)?;

        // Construct the state root and block path.
        let state_root = *self.latest_state_root();
        let block_path = self.block_tree.prove(latest_block_height as usize, &latest_block_hash.to_bits_le())?;

        StatePath::new(
            state_root.into(),
            block_path,
            latest_block_hash,
            previous_block_hash,
            header_root,
            header_path,
            header_leaf,
            transactions_path,
            transaction.id(),
            transaction_path,
            transaction_leaf,
            transition_path,
            transition_leaf,
        )
    }

    /// Returns the expected coinbase target given the previous block and expected next block details.
    pub fn compute_coinbase_target(_anchor_block_header: &Header<N>, _block_timestamp: i64, _block_height: u32) -> u64 {
        unimplemented!()
    }

    /// Returns the expected proof target given the previous block and expected next block details.
    pub fn compute_proof_target(_anchor_block_header: &Header<N>, _block_timestamp: i64, _block_height: u32) -> u64 {
        unimplemented!()
    }
}
