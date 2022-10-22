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

impl<N: Network, B: BlockStorage<N>, P: ProgramStorage<N>> Ledger<N, B, P> {
    /// Returns the block for the given block height.
    pub fn get_block(&self, height: u32) -> Result<Block<N>> {
        // Retrieve the block hash.
        let block_hash = match self.blocks.get_block_hash(height)? {
            Some(block_hash) => block_hash,
            None => bail!("Block {height} does not exist in storage"),
        };
        // Retrieve the block.
        match self.blocks.get_block(&block_hash)? {
            Some(block) => Ok(block),
            None => bail!("Block {height} ('{block_hash}') does not exist in storage"),
        }
    }

    /// Returns the block hash for the given block height.
    pub fn get_hash(&self, height: u32) -> Result<N::BlockHash> {
        match self.blocks.get_block_hash(height)? {
            Some(block_hash) => Ok(block_hash),
            None => bail!("Missing block hash for block {height}"),
        }
    }

    /// Returns the previous block hash for the given block height.
    pub fn get_previous_hash(&self, height: u32) -> Result<N::BlockHash> {
        match self.blocks.get_previous_block_hash(height)? {
            Some(previous_hash) => Ok(previous_hash),
            None => bail!("Missing previous block hash for block {height}"),
        }
    }

    /// Returns the block header for the given block height.
    pub fn get_header(&self, height: u32) -> Result<Header<N>> {
        // Retrieve the block hash.
        let block_hash = match self.blocks.get_block_hash(height)? {
            Some(block_hash) => block_hash,
            None => bail!("Block {height} does not exist in storage"),
        };
        // Retrieve the block header.
        match self.blocks.get_block_header(&block_hash)? {
            Some(header) => Ok(header),
            None => bail!("Missing block header for block {height}"),
        }
    }

    /// Returns the block transactions for the given block height.
    pub fn get_transactions(&self, height: u32) -> Result<Transactions<N>> {
        // Retrieve the block hash.
        let block_hash = match self.blocks.get_block_hash(height)? {
            Some(block_hash) => block_hash,
            None => bail!("Block {height} does not exist in storage"),
        };
        // Retrieve the block transaction.
        match self.blocks.get_block_transactions(&block_hash)? {
            Some(transactions) => Ok(transactions),
            None => bail!("Missing block transactions for block {height}"),
        }
    }

    /// Returns the transaction for the given transaction id.
    pub fn get_transaction(&self, transaction_id: N::TransactionID) -> Result<Transaction<N>> {
        // Retrieve the transaction.
        match self.transactions.get_transaction(&transaction_id)? {
            Some(transaction) => Ok(transaction),
            None => bail!("Missing transaction for id {transaction_id}"),
        }
    }

    /// Returns the program for the given program id.
    pub fn get_program(&self, program_id: ProgramID<N>) -> Result<Program<N>> {
        match self.transactions.get_program(&program_id)? {
            Some(program) => Ok(program),
            None => bail!("Missing program for id {program_id}"),
        }
    }

    /// Returns the block coinbase proof for the given block height.
    pub fn get_coinbase_proof(&self, height: u32) -> Result<Option<CoinbaseSolution<N>>> {
        // Retrieve the block hash.
        let block_hash = match self.blocks.get_block_hash(height)? {
            Some(block_hash) => block_hash,
            None => bail!("Block {height} does not exist in storage"),
        };
        // Retrieve the block coinbase proof.
        self.blocks.get_block_coinbase_proof(&block_hash)
    }

    /// Returns the block signature for the given block height.
    pub fn get_signature(&self, height: u32) -> Result<Signature<N>> {
        // Retrieve the block hash.
        let block_hash = match self.blocks.get_block_hash(height)? {
            Some(block_hash) => block_hash,
            None => bail!("Block {height} does not exist in storage"),
        };
        // Retrieve the block signature.
        match self.blocks.get_block_signature(&block_hash)? {
            Some(signature) => Ok(signature),
            None => bail!("Missing signature for block {height}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::test_helpers::CurrentLedger;
    use console::network::Testnet3;

    type CurrentNetwork = Testnet3;

    #[test]
    fn test_get_block() {
        // Load the genesis block.
        let genesis = Block::from_bytes_le(CurrentNetwork::genesis_bytes()).unwrap();

        // Initialize a new ledger.
        let ledger = CurrentLedger::new(None).unwrap();
        // Retrieve the genesis block.
        let candidate = ledger.get_block(0).unwrap();
        // Ensure the genesis block matches.
        assert_eq!(genesis, candidate);
    }
}
