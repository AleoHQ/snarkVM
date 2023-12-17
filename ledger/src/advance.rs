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

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Returns a candidate for the next block in the ledger, using a committed subdag and its transmissions.
    pub fn prepare_advance_to_next_quorum_block(
        &self,
        subdag: Subdag<N>,
        transmissions: IndexMap<TransmissionID<N>, Transmission<N>>,
    ) -> Result<Block<N>> {
        // Retrieve the latest block as the previous block (for the next block).
        let previous_block = self.latest_block();

        // Decouple the transmissions into ratifications, solutions, and transactions.
        let (ratifications, solutions, transactions) = decouple_transmissions(transmissions.into_iter())?;
        // Currently, we do not support ratifications from the memory pool.
        ensure!(ratifications.is_empty(), "Ratifications are currently unsupported from the memory pool");
        // Construct the block template.
        let (header, ratifications, solutions, transactions, aborted_transaction_ids) =
            self.construct_block_template(&previous_block, Some(&subdag), ratifications, solutions, transactions)?;

        // Construct the new quorum block.
        Block::new_quorum(
            previous_block.hash(),
            header,
            subdag,
            ratifications,
            solutions,
            transactions,
            aborted_transaction_ids,
        )
    }

    /// Returns a candidate for the next block in the ledger.
    pub fn prepare_advance_to_next_beacon_block<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        candidate_ratifications: Vec<Ratify<N>>,
        candidate_solutions: Vec<ProverSolution<N>>,
        candidate_transactions: Vec<Transaction<N>>,
        rng: &mut R,
    ) -> Result<Block<N>> {
        // Currently, we do not support ratifications from the memory pool.
        ensure!(candidate_ratifications.is_empty(), "Ratifications are currently unsupported from the memory pool");

        // Retrieve the latest block as the previous block (for the next block).
        let previous_block = self.latest_block();

        // Construct the block template.
        let (header, ratifications, solutions, transactions, aborted_transaction_ids) = self.construct_block_template(
            &previous_block,
            None,
            candidate_ratifications,
            candidate_solutions,
            candidate_transactions,
        )?;

        // Construct the new beacon block.
        Block::new_beacon(
            private_key,
            previous_block.hash(),
            header,
            ratifications,
            solutions,
            transactions,
            aborted_transaction_ids,
            rng,
        )
    }

    /// Adds the given block as the next block in the ledger.
    pub fn advance_to_next_block(&mut self, block: &Block<N>) -> Result<()> {
        // Read current block
        let current_block = &mut self.current_ctx.block;
        // Update the VM.
        self.vm.add_next_block(block)?;
        // Update the current block.
        *current_block = block.clone();

        // Update the cached committee from storage.
        if let Ok(current_committee) = self.vm.finalize_store().committee_store().current_committee() {
            self.current_ctx.committee = Some(current_committee);
        }

        // If the block is the start of a new epoch, or the epoch challenge has not been set, update the current epoch challenge.
        if block.height() % N::NUM_BLOCKS_PER_EPOCH == 0 || self.current_ctx.epoch_challenge.is_none() {
            // Update the current epoch challenge.
            self.current_ctx.epoch_challenge = Some(self.get_epoch_challenge(block.height())?);
        }

        Ok(())
    }
}

impl<N: Network, C: ConsensusStorage<N>> Ledger<N, C> {
    /// Constructs a block template for the next block in the ledger.
    #[allow(clippy::type_complexity)]
    fn construct_block_template(
        &self,
        previous_block: &Block<N>,
        subdag: Option<&Subdag<N>>,
        candidate_ratifications: Vec<Ratify<N>>,
        candidate_solutions: Vec<ProverSolution<N>>,
        candidate_transactions: Vec<Transaction<N>>,
    ) -> Result<(Header<N>, Ratifications<N>, Option<CoinbaseSolution<N>>, Transactions<N>, Vec<N::TransactionID>)>
    {
        // Construct the solutions.
        let (solutions, solutions_root, combined_proof_target) = match candidate_solutions.is_empty() {
            true => (None, Field::<N>::zero(), 0u128),
            false => {
                // Retrieve the coinbase verifying key.
                let coinbase_verifying_key = self.coinbase_puzzle.coinbase_verifying_key();
                // Retrieve the latest epoch challenge.
                let latest_epoch_challenge = self.latest_epoch_challenge()?;
                // Separate the candidate solutions into valid and aborted solutions.
                // TODO: Add `aborted_solution_ids` to the block.
                let (valid_candidate_solutions, _aborted_candidate_solutions): (Vec<_>, Vec<_>) =
                    cfg_into_iter!(candidate_solutions).partition(|solution| {
                        solution
                            .verify(coinbase_verifying_key, &latest_epoch_challenge, self.latest_proof_target())
                            .unwrap_or(false)
                    });
                // Check if there are any valid solutions.
                match valid_candidate_solutions.is_empty() {
                    true => (None, Field::<N>::zero(), 0u128),
                    false => {
                        // Construct the solutions.
                        let solutions = CoinbaseSolution::new(valid_candidate_solutions)?;
                        // Compute the solutions root.
                        let solutions_root = solutions.to_accumulator_point()?;
                        // Compute the combined proof target.
                        let combined_proof_target = solutions.to_combined_proof_target()?;
                        // Output the solutions, solutions root, and combined proof target.
                        (Some(solutions), solutions_root, combined_proof_target)
                    }
                }
            }
        };

        // Retrieve the latest state root.
        let latest_state_root = self.latest_state_root();
        // Retrieve the latest cumulative proof target.
        let latest_cumulative_proof_target = previous_block.cumulative_proof_target();
        // Retrieve the latest coinbase target.
        let latest_coinbase_target = previous_block.coinbase_target();

        // Compute the next round number.
        let next_round = match subdag {
            Some(subdag) => subdag.anchor_round(),
            None => previous_block.round().saturating_add(1),
        };
        // Compute the next height.
        let next_height = previous_block.height().saturating_add(1);
        // Determine the timestamp for the next block.
        let next_timestamp = match subdag {
            Some(subdag) => subdag.timestamp(),
            None => OffsetDateTime::now_utc().unix_timestamp(),
        };
        // Compute the next cumulative weight.
        let next_cumulative_weight = previous_block.cumulative_weight().saturating_add(combined_proof_target);
        // Compute the next cumulative proof target.
        let next_cumulative_proof_target = latest_cumulative_proof_target.saturating_add(combined_proof_target);
        // Determine if the coinbase target is reached.
        let is_coinbase_target_reached = next_cumulative_proof_target >= latest_coinbase_target as u128;
        // Update the next cumulative proof target, if necessary.
        let next_cumulative_proof_target = match is_coinbase_target_reached {
            true => 0,
            false => next_cumulative_proof_target,
        };
        // Construct the next coinbase target.
        let next_coinbase_target = coinbase_target(
            previous_block.last_coinbase_target(),
            previous_block.last_coinbase_timestamp(),
            next_timestamp,
            N::ANCHOR_TIME,
            N::NUM_BLOCKS_PER_EPOCH,
            N::GENESIS_COINBASE_TARGET,
        )?;
        // Construct the next proof target.
        let next_proof_target = proof_target(next_coinbase_target, N::GENESIS_PROOF_TARGET);

        // Construct the next last coinbase target and next last coinbase timestamp.
        let (next_last_coinbase_target, next_last_coinbase_timestamp) = match is_coinbase_target_reached {
            true => (next_coinbase_target, next_timestamp),
            false => (previous_block.last_coinbase_target(), previous_block.last_coinbase_timestamp()),
        };

        // Calculate the coinbase reward.
        let coinbase_reward = coinbase_reward(
            next_height,
            N::STARTING_SUPPLY,
            N::ANCHOR_HEIGHT,
            N::BLOCK_TIME,
            combined_proof_target,
            u64::try_from(latest_cumulative_proof_target)?,
            latest_coinbase_target,
        )?;

        // Construct the finalize state.
        let state = FinalizeGlobalState::new::<N>(
            next_round,
            next_height,
            next_cumulative_weight,
            next_cumulative_proof_target,
            previous_block.hash(),
        )?;
        // Speculate over the ratifications, solutions, and transactions.
        let (ratifications, transactions, aborted_transaction_ids, ratified_finalize_operations) = self.vm.speculate(
            state,
            Some(coinbase_reward),
            candidate_ratifications,
            solutions.as_ref(),
            candidate_transactions.iter(),
        )?;

        // Compute the ratifications root.
        let ratifications_root = ratifications.to_ratifications_root()?;

        // Construct the subdag root.
        let subdag_root = match subdag {
            Some(subdag) => subdag.to_subdag_root()?,
            None => Field::zero(),
        };

        // Construct the metadata.
        let metadata = Metadata::new(
            N::ID,
            next_round,
            next_height,
            next_cumulative_weight,
            next_cumulative_proof_target,
            next_coinbase_target,
            next_proof_target,
            next_last_coinbase_target,
            next_last_coinbase_timestamp,
            next_timestamp,
        )?;

        // Construct the header.
        let header = Header::from(
            latest_state_root,
            transactions.to_transactions_root()?,
            transactions.to_finalize_root(ratified_finalize_operations)?,
            ratifications_root,
            solutions_root,
            subdag_root,
            metadata,
        )?;

        // Return the block template.
        Ok((header, ratifications, solutions, transactions, aborted_transaction_ids))
    }
}
