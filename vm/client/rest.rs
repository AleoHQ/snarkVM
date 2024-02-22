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

use super::*;

impl<N: Network> Client<N> {
    pub async fn latest_height(&self) -> Result<u32> {
        let url = format!("{}/testnet3/latest/height", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(height) => Ok(height),
            Err(error) => bail!("Failed to parse the latest block height: {error}"),
        }
    }

    pub async fn latest_hash(&self) -> Result<N::BlockHash> {
        let url = format!("{}/testnet3/latest/hash", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(hash) => Ok(hash),
            Err(error) => bail!("Failed to parse the latest block hash: {error}"),
        }
    }

    pub async fn latest_block(&self) -> Result<Block<N>> {
        let url = format!("{}/testnet3/latest/block", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(block) => Ok(block),
            Err(error) => bail!("Failed to parse the latest block: {error}"),
        }
    }

    pub async fn latest_committee(&self) -> Result<Committee<N>> {
        let url = format!("{}/testnet3/latest/committee", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(block) => Ok(block),
            Err(error) => bail!("Failed to parse the latest block: {error}"),
        }
    }

    pub async fn get_block(&self, height: u32) -> Result<Block<N>> {
        let url = format!("{}/testnet3/block/{height}", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(block) => Ok(block),
            Err(error) => bail!("Failed to parse block {height}: {error}"),
        }
    }

    pub async fn get_blocks(&self, start_height: u32, end_height: u32) -> Result<Vec<Block<N>>> {
        if start_height >= end_height {
            bail!("Start height must be less than end height");
        } else if end_height - start_height > 50 {
            bail!("Cannot request more than 50 blocks at a time");
        }

        let url = format!("{}/testnet3/blocks?start={start_height}&end={end_height}", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(blocks) => Ok(blocks),
            Err(error) => {
                bail!("Failed to parse blocks {start_height} (inclusive) to {end_height} (exclusive): {error}")
            }
        }
    }

    pub async fn get_block_from_hash(&self, block_hash: N::BlockHash) -> Result<Block<N>> {
        let url = format!("{}/testnet3/block/{block_hash}", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(block) => Ok(block),
            Err(error) => bail!("Failed to parse block {block_hash}: {error}"),
        }
    }

    pub async fn get_transaction(&self, transaction_id: N::TransactionID) -> Result<Transaction<N>> {
        let url = format!("{}/testnet3/transaction/{transaction_id}", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(transaction) => Ok(transaction),
            Err(error) => bail!("Failed to parse transaction '{transaction_id}': {error}"),
        }
    }

    pub async fn get_memory_pool_transactions(&self) -> Result<Vec<Transaction<N>>> {
        let url = format!("{}/testnet3/memoryPool/transactions", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(transactions) => Ok(transactions),
            Err(error) => bail!("Failed to parse memory pool transactions: {error}"),
        }
    }

    pub async fn get_program(&self, program_id: impl TryInto<ProgramID<N>>) -> Result<Program<N>> {
        // Prepare the program ID.
        let program_id = program_id.try_into().map_err(|_| anyhow!("Invalid program ID"))?;
        // Perform the request.
        let url = format!("{}/testnet3/program/{program_id}", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(program) => Ok(program),
            Err(error) => bail!("Failed to parse program {program_id}: {error}"),
        }
    }

    pub async fn get_mapping_value(
        &self,
        program_id: impl TryInto<ProgramID<N>>,
        mapping_name: impl TryInto<Identifier<N>>,
        key: impl TryInto<Plaintext<N>>,
    ) -> Result<Option<Value<N>>> {
        // Prepare the program ID.
        let program_id = program_id.try_into().map_err(|_| anyhow!("Invalid program ID"))?;
        // Prepare the mapping name.
        let mapping_name = mapping_name.try_into().map_err(|_| anyhow!("Invalid mapping name"))?;
        // Prepare the key.
        let key = key.try_into().map_err(|_| anyhow!("Invalid key"))?;
        // Perform the request.
        let url = format!("{}/testnet3/program/{program_id}/mapping/{mapping_name}/{key}", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(program) => Ok(program),
            Err(error) => bail!("Failed to get mapping value for {program_id}/{mapping_name}/{key}: {error}"),
        }
    }

    pub async fn find_block_hash(&self, transaction_id: N::TransactionID) -> Result<N::BlockHash> {
        let url = format!("{}/testnet3/find/blockHash/{transaction_id}", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(hash) => Ok(hash),
            Err(error) => bail!("Failed to parse block hash: {error}"),
        }
    }

    /// Returns the transition ID that contains the given `input ID` or `output ID`.
    pub async fn find_transition_id(&self, input_or_output_id: Field<N>) -> Result<N::TransitionID> {
        let url = format!("{}/testnet3/find/transitionID/{input_or_output_id}", self.node_url());
        match self.client.get(url).send().await?.json().await {
            Ok(transition_id) => Ok(transition_id),
            Err(error) => bail!("Failed to parse transition ID: {error}"),
        }
    }

    pub async fn transaction_broadcast(&self, transaction: Transaction<N>) -> Result<Block<N>> {
        let url = format!("{}/testnet3/transaction/broadcast", self.node_url());
        match self.client.post(url).body(serde_json::to_string(&transaction)?).send().await?.json().await {
            Ok(block) => Ok(block),
            Err(error) => bail!("Failed to parse memory pool transactions: {error}"),
        }
    }
}
