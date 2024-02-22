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

mod helpers;
pub use helpers::*;

mod authorize;
mod deploy;
mod execute;
mod finalize;
mod verify;

#[cfg(test)]
mod tests;

use crate::{cast_mut_ref, cast_ref, process};
use console::{
    account::{Address, PrivateKey},
    network::prelude::*,
    program::{Identifier, Literal, Locator, Plaintext, ProgramID, ProgramOwner, Record, Value},
    types::{Field, Group, U64},
};
use ledger_block::{
    Block,
    ConfirmedTransaction,
    Deployment,
    Execution,
    Fee,
    Header,
    Ratifications,
    Ratify,
    Rejected,
    Transaction,
    Transactions,
};
use ledger_coinbase::CoinbaseSolution;
use ledger_committee::Committee;
use ledger_query::Query;
use ledger_store::{
    atomic_finalize,
    BlockStore,
    ConsensusStorage,
    ConsensusStore,
    FinalizeMode,
    FinalizeStore,
    TransactionStorage,
    TransactionStore,
    TransitionStore,
};
use synthesizer_process::{Authorization, Process, Trace};
use synthesizer_program::{FinalizeGlobalState, FinalizeOperation, FinalizeStoreTrait, Program};

use aleo_std::prelude::{finish, lap, timer};
use indexmap::{IndexMap, IndexSet};
use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use std::{num::NonZeroUsize, sync::Arc};

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

#[derive(Clone)]
pub struct VM<N: Network, C: ConsensusStorage<N>> {
    /// The process.
    process: Arc<RwLock<Process<N>>>,
    /// The VM store.
    store: ConsensusStore<N, C>,
    /// The lock to guarantee atomicity over calls to speculate and finalize.
    atomic_lock: Arc<Mutex<()>>,
    /// The lock for ensuring there is no concurrency when advancing blocks.
    block_lock: Arc<Mutex<()>>,
    /// A cache containing the list of recent partially-verified transactions.
    partially_verified_transactions: Arc<RwLock<LruCache<N::TransactionID, ()>>>,
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Initializes the VM from storage.
    #[inline]
    pub fn from(store: ConsensusStore<N, C>) -> Result<Self> {
        // Initialize a new process.
        let mut process = Process::load()?;

        // Initialize the store for 'credits.aleo'.
        let credits = Program::<N>::credits()?;
        for mapping in credits.mappings().values() {
            // Ensure that all mappings are initialized.
            if !store.finalize_store().contains_mapping_confirmed(credits.id(), mapping.name())? {
                // Initialize the mappings for 'credits.aleo'.
                store.finalize_store().initialize_mapping(*credits.id(), *mapping.name())?;
            }
        }

        // A helper function to retrieve all the deployments.
        fn load_deployment_and_imports<N: Network, T: TransactionStorage<N>>(
            process: &Process<N>,
            transaction_store: &TransactionStore<N, T>,
            transaction_id: N::TransactionID,
        ) -> Result<Vec<(ProgramID<N>, Deployment<N>)>> {
            // Retrieve the deployment from the transaction id.
            let deployment = match transaction_store.get_deployment(&transaction_id)? {
                Some(deployment) => deployment,
                None => bail!("Deployment transaction '{transaction_id}' is not found in storage."),
            };

            // Fetch the program from the deployment.
            let program = deployment.program();
            let program_id = program.id();

            // Return early if the program is already loaded.
            if process.contains_program(program_id) {
                return Ok(vec![]);
            }

            // Prepare a vector for the deployments.
            let mut deployments = vec![];

            // Iterate through the program imports.
            for import_program_id in program.imports().keys() {
                // Add the imports to the process if does not exist yet.
                if !process.contains_program(import_program_id) {
                    // Fetch the deployment transaction id.
                    let Some(transaction_id) =
                        transaction_store.deployment_store().find_transaction_id_from_program_id(import_program_id)?
                    else {
                        bail!("Transaction id for '{program_id}' is not found in storage.");
                    };

                    // Add the deployment and its imports found recursively.
                    deployments.extend_from_slice(&load_deployment_and_imports(
                        process,
                        transaction_store,
                        transaction_id,
                    )?);
                }
            }

            // Once all the imports have been included, add the parent deployment.
            deployments.push((*program_id, deployment));

            Ok(deployments)
        }

        // Retrieve the transaction store.
        let transaction_store = store.transaction_store();
        // Retrieve the list of deployment transaction IDs.
        let deployment_ids = transaction_store.deployment_transaction_ids().collect::<Vec<_>>();
        // Load the deployments from the store.
        for (i, chunk) in deployment_ids.chunks(256).enumerate() {
            debug!(
                "Loading deployments {}-{} (of {})...",
                i * 256,
                ((i + 1) * 256).min(deployment_ids.len()),
                deployment_ids.len()
            );
            let deployments = cfg_iter!(chunk)
                .map(|transaction_id| {
                    // Load the deployment and its imports.
                    load_deployment_and_imports(&process, transaction_store, **transaction_id)
                })
                .collect::<Result<Vec<_>>>()?;

            for (program_id, deployment) in deployments.iter().flatten() {
                // Load the deployment if it does not exist in the process yet.
                if !process.contains_program(program_id) {
                    process.load_deployment(deployment)?;
                }
            }
        }

        // Return the new VM.
        Ok(Self {
            process: Arc::new(RwLock::new(process)),
            store,
            atomic_lock: Arc::new(Mutex::new(())),
            block_lock: Arc::new(Mutex::new(())),
            partially_verified_transactions: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(Transactions::<console::network::Testnet3>::MAX_TRANSACTIONS).unwrap(),
            ))),
        })
    }

    /// Returns `true` if a program with the given program ID exists.
    #[inline]
    pub fn contains_program(&self, program_id: &ProgramID<N>) -> bool {
        self.process.read().contains_program(program_id)
    }

    /// Returns the process.
    #[inline]
    pub fn process(&self) -> Arc<RwLock<Process<N>>> {
        self.process.clone()
    }

    /// Returns the partially-verified transactions.
    #[inline]
    pub fn partially_verified_transactions(&self) -> Arc<RwLock<LruCache<N::TransactionID, ()>>> {
        self.partially_verified_transactions.clone()
    }
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Returns the finalize store.
    #[inline]
    pub fn finalize_store(&self) -> &FinalizeStore<N, C::FinalizeStorage> {
        self.store.finalize_store()
    }

    /// Returns the block store.
    #[inline]
    pub fn block_store(&self) -> &BlockStore<N, C::BlockStorage> {
        self.store.block_store()
    }

    /// Returns the transaction store.
    #[inline]
    pub fn transaction_store(&self) -> &TransactionStore<N, C::TransactionStorage> {
        self.store.transaction_store()
    }

    /// Returns the transition store.
    #[inline]
    pub fn transition_store(&self) -> &TransitionStore<N, C::TransitionStorage> {
        self.store.transition_store()
    }
}

impl<N: Network, C: ConsensusStorage<N>> VM<N, C> {
    /// Returns a new genesis block for a beacon chain.
    pub fn genesis_beacon<R: Rng + CryptoRng>(&self, private_key: &PrivateKey<N>, rng: &mut R) -> Result<Block<N>> {
        let private_keys = [*private_key, PrivateKey::new(rng)?, PrivateKey::new(rng)?, PrivateKey::new(rng)?];

        // Construct the committee members.
        let members = indexmap::indexmap! {
            Address::try_from(private_keys[0])? => (ledger_committee::MIN_VALIDATOR_STAKE, true),
            Address::try_from(private_keys[1])? => (ledger_committee::MIN_VALIDATOR_STAKE, true),
            Address::try_from(private_keys[2])? => (ledger_committee::MIN_VALIDATOR_STAKE, true),
            Address::try_from(private_keys[3])? => (ledger_committee::MIN_VALIDATOR_STAKE, true),
        };
        // Construct the committee.
        let committee = Committee::<N>::new_genesis(members)?;

        // Compute the remaining supply.
        let remaining_supply = N::STARTING_SUPPLY - (ledger_committee::MIN_VALIDATOR_STAKE * 4);
        // Construct the public balances.
        let public_balances = indexmap::indexmap! {
            Address::try_from(private_keys[0])? => remaining_supply / 4,
            Address::try_from(private_keys[1])? => remaining_supply / 4,
            Address::try_from(private_keys[2])? => remaining_supply / 4,
            Address::try_from(private_keys[3])? => remaining_supply / 4,
        };
        // Return the genesis block.
        self.genesis_quorum(private_key, committee, public_balances, rng)
    }

    /// Returns a new genesis block for a quorum chain.
    pub fn genesis_quorum<R: Rng + CryptoRng>(
        &self,
        private_key: &PrivateKey<N>,
        committee: Committee<N>,
        public_balances: IndexMap<Address<N>, u64>,
        rng: &mut R,
    ) -> Result<Block<N>> {
        // Retrieve the total stake.
        let total_stake = committee.total_stake();
        // Compute the account supply.
        let account_supply = public_balances.values().fold(0u64, |acc, x| acc.saturating_add(*x));
        // Compute the total supply.
        let total_supply = total_stake.checked_add(account_supply).ok_or_else(|| anyhow!("Invalid total supply"))?;
        // Ensure the total supply matches.
        ensure!(total_supply == N::STARTING_SUPPLY, "Invalid total supply");

        // Prepare the caller.
        let caller = Address::try_from(private_key)?;
        // Prepare the locator.
        let locator = ("credits.aleo", "transfer_public_to_private");
        // Prepare the amount for each call to the function.
        let amount = ledger_committee::MIN_VALIDATOR_STAKE;
        // Prepare the function inputs.
        let inputs = [caller.to_string(), format!("{amount}_u64")];

        // Prepare the ratifications.
        let ratifications = vec![Ratify::Genesis(committee, public_balances)];
        // Prepare the solutions.
        let solutions = None; // The genesis block does not require solutions.
        // Prepare the transactions.
        let transactions = (0..Block::<N>::NUM_GENESIS_TRANSACTIONS)
            .map(|_| self.execute(private_key, locator, inputs.iter(), None, 0, None, rng))
            .collect::<Result<Vec<_>, _>>()?;

        // Construct the finalize state.
        let state = FinalizeGlobalState::new_genesis::<N>()?;
        // Speculate on the ratifications, solutions, and transactions.
        let (ratifications, transactions, aborted_transaction_ids, ratified_finalize_operations) =
            self.speculate(state, None, ratifications, solutions.as_ref(), transactions.iter())?;
        ensure!(
            aborted_transaction_ids.is_empty(),
            "Failed to initialize a genesis block - found aborted transaction IDs"
        );

        // Prepare the block header.
        let header = Header::genesis(&ratifications, &transactions, ratified_finalize_operations)?;
        // Prepare the previous block hash.
        let previous_hash = N::BlockHash::default();

        // Construct the block.
        let block = Block::new_beacon(
            private_key,
            previous_hash,
            header,
            ratifications,
            solutions,
            transactions,
            aborted_transaction_ids,
            rng,
        )?;
        // Ensure the block is valid genesis block.
        match block.is_genesis() {
            true => Ok(block),
            false => bail!("Failed to initialize a genesis block"),
        }
    }

    /// Adds the given block into the VM.
    #[inline]
    pub fn add_next_block(&self, block: &Block<N>) -> Result<()> {
        // Acquire the block lock, which is needed to ensure this function is not called concurrently.
        // Note: This lock must be held for the entire scope of this function.
        let _block_lock = self.block_lock.lock();

        // Construct the finalize state.
        let state = FinalizeGlobalState::new::<N>(
            block.round(),
            block.height(),
            block.cumulative_weight(),
            block.cumulative_proof_target(),
            block.previous_hash(),
        )?;

        // Pause the atomic writes, so that both the insertion and finalization belong to a single batch.
        #[cfg(feature = "rocks")]
        self.block_store().pause_atomic_writes()?;

        // First, insert the block.
        self.block_store().insert(block)?;
        // Next, finalize the transactions.
        match self.finalize(state, block.ratifications(), block.solutions(), block.transactions()) {
            Ok(_ratified_finalize_operations) => {
                // Unpause the atomic writes, executing the ones queued from block insertion and finalization.
                #[cfg(feature = "rocks")]
                self.block_store().unpause_atomic_writes::<false>()?;
                Ok(())
            }
            Err(finalize_error) => {
                if cfg!(feature = "rocks") {
                    // Clear all pending atomic operations so that unpausing the atomic writes
                    // doesn't execute any of the queued storage operations.
                    self.block_store().abort_atomic();
                    self.finalize_store().abort_atomic();
                    // Disable the atomic batch override.
                    // Note: This call is guaranteed to succeed (without error), because `DISCARD_BATCH == true`.
                    self.block_store().unpause_atomic_writes::<true>()?;
                    // Rollback the Merkle tree.
                    self.block_store().remove_last_n_from_tree_only(1).map_err(|removal_error| {
                        // Log the finalize error.
                        error!("Failed to finalize block {} - {finalize_error}", block.height());
                        // Return the removal error.
                        removal_error
                    })?;
                } else {
                    // Rollback the block.
                    self.block_store().remove_last_n(1).map_err(|removal_error| {
                        // Log the finalize error.
                        error!("Failed to finalize block {} - {finalize_error}", block.height());
                        // Return the removal error.
                        removal_error
                    })?;
                }
                // Return the finalize error.
                Err(finalize_error)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use console::{
        account::{Address, ViewKey},
        network::Testnet3,
        program::Value,
        types::Field,
    };
    use ledger_block::{Block, Header, Metadata, Transition};
    use ledger_store::helpers::memory::ConsensusMemory;
    use synthesizer_program::Program;

    use indexmap::IndexMap;
    use once_cell::sync::OnceCell;
    use std::borrow::Borrow;

    pub(crate) type CurrentNetwork = Testnet3;

    /// Samples a new finalize state.
    pub(crate) fn sample_finalize_state(block_height: u32) -> FinalizeGlobalState {
        FinalizeGlobalState::from(block_height as u64, block_height, [0u8; 32])
    }

    pub(crate) fn sample_vm() -> VM<CurrentNetwork, ConsensusMemory<CurrentNetwork>> {
        // Initialize a new VM.
        VM::from(ConsensusStore::open(None).unwrap()).unwrap()
    }

    pub(crate) fn sample_genesis_private_key(rng: &mut TestRng) -> PrivateKey<CurrentNetwork> {
        static INSTANCE: OnceCell<PrivateKey<CurrentNetwork>> = OnceCell::new();
        *INSTANCE.get_or_init(|| {
            // Initialize a new caller.
            PrivateKey::<CurrentNetwork>::new(rng).unwrap()
        })
    }

    pub(crate) fn sample_genesis_block(rng: &mut TestRng) -> Block<CurrentNetwork> {
        static INSTANCE: OnceCell<Block<CurrentNetwork>> = OnceCell::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize the VM.
                let vm = crate::vm::test_helpers::sample_vm();
                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                // Return the block.
                vm.genesis_beacon(&caller_private_key, rng).unwrap()
            })
            .clone()
    }

    pub(crate) fn sample_vm_with_genesis_block(
        rng: &mut TestRng,
    ) -> VM<CurrentNetwork, ConsensusMemory<CurrentNetwork>> {
        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();
        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();
        // Return the VM.
        vm
    }

    pub(crate) fn sample_program() -> Program<CurrentNetwork> {
        static INSTANCE: OnceCell<Program<CurrentNetwork>> = OnceCell::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new program.
                Program::<CurrentNetwork>::from_str(
                    r"
program testing.aleo;

struct message:
    amount as u128;

mapping account:
    key as address.public;
    value as u64.public;

record token:
    owner as address.private;
    amount as u64.private;

function initialize:
    input r0 as address.private;
    input r1 as u64.private;
    cast r0 r1 into r2 as token.record;
    output r2 as token.record;

function compute:
    input r0 as message.private;
    input r1 as message.public;
    input r2 as message.private;
    input r3 as token.record;
    add r0.amount r1.amount into r4;
    cast r3.owner r3.amount into r5 as token.record;
    output r4 as u128.public;
    output r5 as token.record;",
                )
                .unwrap()
            })
            .clone()
    }

    pub(crate) fn sample_deployment_transaction(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        static INSTANCE: OnceCell<Transaction<CurrentNetwork>> = OnceCell::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize the program.
                let program = sample_program();

                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

                // Initialize the genesis block.
                let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

                // Fetch the unspent records.
                let records =
                    genesis.transitions().cloned().flat_map(Transition::into_records).collect::<IndexMap<_, _>>();
                trace!("Unspent Records:\n{:#?}", records);

                // Prepare the fee.
                let credits = Some(records.values().next().unwrap().decrypt(&caller_view_key).unwrap());

                // Initialize the VM.
                let vm = sample_vm();
                // Update the VM.
                vm.add_next_block(&genesis).unwrap();

                // Deploy.
                let transaction = vm.deploy(&caller_private_key, &program, credits, 10, None, rng).unwrap();
                // Verify.
                vm.check_transaction(&transaction, None, rng).unwrap();
                // Return the transaction.
                transaction
            })
            .clone()
    }

    pub(crate) fn sample_execution_transaction_without_fee(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        static INSTANCE: OnceCell<Transaction<CurrentNetwork>> = OnceCell::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

                // Initialize the genesis block.
                let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

                // Fetch the unspent records.
                let records =
                    genesis.transitions().cloned().flat_map(Transition::into_records).collect::<IndexMap<_, _>>();
                trace!("Unspent Records:\n{:#?}", records);

                // Select a record to spend.
                let record = records.values().next().unwrap().decrypt(&caller_view_key).unwrap();

                // Initialize the VM.
                let vm = sample_vm();
                // Update the VM.
                vm.add_next_block(&genesis).unwrap();

                // Prepare the inputs.
                let inputs =
                    [Value::<CurrentNetwork>::Record(record), Value::<CurrentNetwork>::from_str("1u64").unwrap()]
                        .into_iter();

                // Authorize.
                let authorization = vm.authorize(&caller_private_key, "credits.aleo", "split", inputs, rng).unwrap();
                assert_eq!(authorization.len(), 1);

                // Construct the execute transaction.
                let transaction = vm.execute_authorization(authorization, None, None, rng).unwrap();
                // Verify.
                vm.check_transaction(&transaction, None, rng).unwrap();
                // Return the transaction.
                transaction
            })
            .clone()
    }

    pub(crate) fn sample_execution_transaction_with_private_fee(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        static INSTANCE: OnceCell<Transaction<CurrentNetwork>> = OnceCell::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
                let address = Address::try_from(&caller_private_key).unwrap();

                // Initialize the genesis block.
                let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

                // Fetch the unspent records.
                let records =
                    genesis.transitions().cloned().flat_map(Transition::into_records).collect::<IndexMap<_, _>>();
                trace!("Unspent Records:\n{:#?}", records);

                // Select a record to spend.
                let record = Some(records.values().next().unwrap().decrypt(&caller_view_key).unwrap());

                // Initialize the VM.
                let vm = sample_vm();
                // Update the VM.
                vm.add_next_block(&genesis).unwrap();

                // Prepare the inputs.
                let inputs = [
                    Value::<CurrentNetwork>::from_str(&address.to_string()).unwrap(),
                    Value::<CurrentNetwork>::from_str("1u64").unwrap(),
                ]
                .into_iter();

                // Execute.
                let transaction = vm
                    .execute(&caller_private_key, ("credits.aleo", "transfer_public"), inputs, record, 0, None, rng)
                    .unwrap();
                // Verify.
                vm.check_transaction(&transaction, None, rng).unwrap();
                // Return the transaction.
                transaction
            })
            .clone()
    }

    pub(crate) fn sample_execution_transaction_with_public_fee(rng: &mut TestRng) -> Transaction<CurrentNetwork> {
        static INSTANCE: OnceCell<Transaction<CurrentNetwork>> = OnceCell::new();
        INSTANCE
            .get_or_init(|| {
                // Initialize a new caller.
                let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
                let address = Address::try_from(&caller_private_key).unwrap();

                // Initialize the genesis block.
                let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

                // Initialize the VM.
                let vm = sample_vm();
                // Update the VM.
                vm.add_next_block(&genesis).unwrap();

                // Prepare the inputs.
                let inputs = [
                    Value::<CurrentNetwork>::from_str(&address.to_string()).unwrap(),
                    Value::<CurrentNetwork>::from_str("1u64").unwrap(),
                ]
                .into_iter();

                // Execute.
                let transaction_without_fee = vm
                    .execute(&caller_private_key, ("credits.aleo", "transfer_public"), inputs, None, 0, None, rng)
                    .unwrap();
                let execution = transaction_without_fee.execution().unwrap().clone();

                // Authorize the fee.
                let authorization = vm
                    .authorize_fee_public(
                        &caller_private_key,
                        10_000_000,
                        100,
                        execution.to_execution_id().unwrap(),
                        rng,
                    )
                    .unwrap();
                // Compute the fee.
                let fee = vm.execute_fee_authorization(authorization, None, rng).unwrap();

                // Construct the transaction.
                let transaction = Transaction::from_execution(execution, Some(fee)).unwrap();
                // Verify.
                vm.check_transaction(&transaction, None, rng).unwrap();
                // Return the transaction.
                transaction
            })
            .clone()
    }

    pub fn sample_next_block<R: Rng + CryptoRng>(
        vm: &VM<Testnet3, ConsensusMemory<Testnet3>>,
        private_key: &PrivateKey<Testnet3>,
        transactions: &[Transaction<Testnet3>],
        rng: &mut R,
    ) -> Result<Block<Testnet3>> {
        // Get the most recent block.
        let block_hash =
            vm.block_store().get_block_hash(*vm.block_store().heights().max().unwrap().borrow()).unwrap().unwrap();
        let previous_block = vm.block_store().get_block(&block_hash).unwrap().unwrap();

        // Construct the new block header.
        let (ratifications, transactions, aborted_transaction_ids, ratified_finalize_operations) =
            vm.speculate(sample_finalize_state(1), None, vec![], None, transactions.iter())?;
        assert!(aborted_transaction_ids.is_empty());

        // Construct the metadata associated with the block.
        let metadata = Metadata::new(
            Testnet3::ID,
            previous_block.round() + 1,
            previous_block.height() + 1,
            0,
            0,
            Testnet3::GENESIS_COINBASE_TARGET,
            Testnet3::GENESIS_PROOF_TARGET,
            previous_block.last_coinbase_target(),
            previous_block.last_coinbase_timestamp(),
            Testnet3::GENESIS_TIMESTAMP + 1,
        )?;

        let header = Header::from(
            vm.block_store().current_state_root(),
            transactions.to_transactions_root().unwrap(),
            transactions.to_finalize_root(ratified_finalize_operations).unwrap(),
            ratifications.to_ratifications_root().unwrap(),
            Field::zero(),
            Field::zero(),
            metadata,
        )?;

        // Construct the new block.
        Block::new_beacon(
            private_key,
            previous_block.hash(),
            header,
            ratifications,
            None,
            transactions,
            aborted_transaction_ids,
            rng,
        )
    }

    #[test]
    fn test_multiple_deployments_and_multiple_executions() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
        let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Fetch the unspent records.
        let records = genesis.transitions().cloned().flat_map(Transition::into_records).collect::<IndexMap<_, _>>();
        trace!("Unspent Records:\n{:#?}", records);

        // Select a record to spend.
        let record = records.values().next().unwrap().decrypt(&caller_view_key).unwrap();

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Split once.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "split"),
                [Value::Record(record), Value::from_str("1000000000u64").unwrap()].iter(), // 1000 credits
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let records = transaction.records().collect_vec();
        let first_record = records[0].1.clone().decrypt(&caller_view_key).unwrap();
        let second_record = records[1].1.clone().decrypt(&caller_view_key).unwrap();
        let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
        vm.add_next_block(&block).unwrap();

        // Split again.
        let mut transactions = Vec::new();
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "split"),
                [Value::Record(first_record), Value::from_str("100000000u64").unwrap()].iter(), // 100 credits
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let records = transaction.records().collect_vec();
        let first_record = records[0].1.clone().decrypt(&caller_view_key).unwrap();
        let third_record = records[1].1.clone().decrypt(&caller_view_key).unwrap();
        transactions.push(transaction);
        // Split again.
        let transaction = vm
            .execute(
                &caller_private_key,
                ("credits.aleo", "split"),
                [Value::Record(second_record), Value::from_str("100000000u64").unwrap()].iter(), // 100 credits
                None,
                0,
                None,
                rng,
            )
            .unwrap();
        let records = transaction.records().collect_vec();
        let second_record = records[0].1.clone().decrypt(&caller_view_key).unwrap();
        let fourth_record = records[1].1.clone().decrypt(&caller_view_key).unwrap();
        transactions.push(transaction);
        // Add the split transactions to a block and update the VM.
        let fee_block = sample_next_block(&vm, &caller_private_key, &transactions, rng).unwrap();
        vm.add_next_block(&fee_block).unwrap();

        // Deploy the programs.
        let first_program = r"
program test_program_1.aleo;
mapping map_0:
    key as field.public;
    value as field.public;
function init:
    async init into r0;
    output r0 as test_program_1.aleo/init.future;
finalize init:
    set 0field into map_0[0field];
function getter:
    async getter into r0;
    output r0 as test_program_1.aleo/getter.future;
finalize getter:
    get map_0[0field] into r0;
        ";
        let second_program = r"
program test_program_2.aleo;
mapping map_0:
    key as field.public;
    value as field.public;
function init:
    async init into r0;
    output r0 as test_program_2.aleo/init.future;
finalize init:
    set 0field into map_0[0field];
function getter:
    async getter into r0;
    output r0 as test_program_2.aleo/getter.future;
finalize getter:
    get map_0[0field] into r0;
        ";
        let first_deployment = vm
            .deploy(&caller_private_key, &Program::from_str(first_program).unwrap(), Some(first_record), 1, None, rng)
            .unwrap();
        let second_deployment = vm
            .deploy(&caller_private_key, &Program::from_str(second_program).unwrap(), Some(second_record), 1, None, rng)
            .unwrap();
        let deployment_block =
            sample_next_block(&vm, &caller_private_key, &[first_deployment, second_deployment], rng).unwrap();
        vm.add_next_block(&deployment_block).unwrap();

        // Execute the programs.
        let first_execution = vm
            .execute(
                &caller_private_key,
                ("test_program_1.aleo", "init"),
                Vec::<Value<Testnet3>>::new().iter(),
                Some(third_record),
                1,
                None,
                rng,
            )
            .unwrap();
        let second_execution = vm
            .execute(
                &caller_private_key,
                ("test_program_2.aleo", "init"),
                Vec::<Value<Testnet3>>::new().iter(),
                Some(fourth_record),
                1,
                None,
                rng,
            )
            .unwrap();
        let execution_block =
            sample_next_block(&vm, &caller_private_key, &[first_execution, second_execution], rng).unwrap();
        vm.add_next_block(&execution_block).unwrap();
    }

    #[test]
    fn test_load_deployments_with_imports() {
        // NOTE: This seed was chosen for the CI's RNG to ensure that the test passes.
        let rng = &mut TestRng::fixed(123456789);

        // Initialize a new caller.
        let caller_private_key = PrivateKey::<CurrentNetwork>::new(rng).unwrap();
        let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

        // Initialize the VM.
        let vm = crate::vm::test_helpers::sample_vm();
        // Initialize the genesis block.
        let genesis = vm.genesis_beacon(&caller_private_key, rng).unwrap();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Fetch the unspent records.
        let records = genesis.transitions().cloned().flat_map(Transition::into_records).collect::<Vec<(_, _)>>();
        trace!("Unspent Records:\n{:#?}", records);
        let record_0 = records[0].1.decrypt(&caller_view_key).unwrap();
        let record_1 = records[1].1.decrypt(&caller_view_key).unwrap();
        let record_2 = records[2].1.decrypt(&caller_view_key).unwrap();
        let record_3 = records[3].1.decrypt(&caller_view_key).unwrap();

        // Create the deployment for the first program.
        let program_1 = r"
program first_program.aleo;

function c:
    input r0 as u8.private;
    input r1 as u8.private;
    add r0 r1 into r2;
    output r2 as u8.private;
        ";
        let deployment_1 = vm
            .deploy(&caller_private_key, &Program::from_str(program_1).unwrap(), Some(record_0), 0, None, rng)
            .unwrap();

        // Deploy the first program.
        let deployment_block = sample_next_block(&vm, &caller_private_key, &[deployment_1.clone()], rng).unwrap();
        vm.add_next_block(&deployment_block).unwrap();

        // Create the deployment for the second program.
        let program_2 = r"
import first_program.aleo;

program second_program.aleo;

function b:
    input r0 as u8.private;
    input r1 as u8.private;
    call first_program.aleo/c r0 r1 into r2;
    output r2 as u8.private;
        ";
        let deployment_2 = vm
            .deploy(&caller_private_key, &Program::from_str(program_2).unwrap(), Some(record_1), 0, None, rng)
            .unwrap();

        // Deploy the second program.
        let deployment_block = sample_next_block(&vm, &caller_private_key, &[deployment_2.clone()], rng).unwrap();
        vm.add_next_block(&deployment_block).unwrap();

        // Create the deployment for the third program.
        let program_3 = r"
import second_program.aleo;

program third_program.aleo;

function a:
    input r0 as u8.private;
    input r1 as u8.private;
    call second_program.aleo/b r0 r1 into r2;
    output r2 as u8.private;
        ";
        let deployment_3 = vm
            .deploy(&caller_private_key, &Program::from_str(program_3).unwrap(), Some(record_2), 0, None, rng)
            .unwrap();

        // Create the deployment for the fourth program.
        let program_4 = r"
import second_program.aleo;
import first_program.aleo;

program fourth_program.aleo;

function a:
    input r0 as u8.private;
    input r1 as u8.private;
    call second_program.aleo/b r0 r1 into r2;
    output r2 as u8.private;
        ";
        let deployment_4 = vm
            .deploy(&caller_private_key, &Program::from_str(program_4).unwrap(), Some(record_3), 0, None, rng)
            .unwrap();

        // Deploy the third and fourth program together.
        let deployment_block =
            sample_next_block(&vm, &caller_private_key, &[deployment_3.clone(), deployment_4.clone()], rng).unwrap();
        vm.add_next_block(&deployment_block).unwrap();

        // Check that the iterator ordering is not the same as the deployment ordering.
        let deployment_transaction_ids =
            vm.transaction_store().deployment_transaction_ids().map(|id| *id).collect::<Vec<_>>();
        // This `assert_ne` check is here to ensure that we are properly loading imports even though any order will work for `VM::from`.
        // Note: `deployment_transaction_ids` is sorted lexicographically by transaction id, so the order may change if we update internal methods.
        assert_ne!(deployment_transaction_ids, vec![
            deployment_1.id(),
            deployment_2.id(),
            deployment_3.id(),
            deployment_4.id()
        ]);

        // Enforce that the VM can load properly with the imports.
        assert!(VM::from(vm.store.clone()).is_ok());
    }

    #[test]
    fn test_multiple_external_calls() {
        let rng = &mut TestRng::default();

        // Initialize a new caller.
        let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
        let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
        let address = Address::try_from(&caller_private_key).unwrap();

        // Initialize the genesis block.
        let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

        // Fetch the unspent records.
        let records =
            genesis.transitions().cloned().flat_map(Transition::into_records).take(3).collect::<IndexMap<_, _>>();
        trace!("Unspent Records:\n{:#?}", records);
        let record_0 = records.values().next().unwrap().decrypt(&caller_view_key).unwrap();
        let record_1 = records.values().nth(1).unwrap().decrypt(&caller_view_key).unwrap();
        let record_2 = records.values().nth(2).unwrap().decrypt(&caller_view_key).unwrap();

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the program.
        let program = Program::from_str(
            r"
import credits.aleo;

program test_multiple_external_calls.aleo;

function multitransfer:
    input r0 as credits.aleo/credits.record;
    input r1 as address.private;
    input r2 as u64.private;
    call credits.aleo/transfer_private r0 r1 r2 into r3 r4;
    call credits.aleo/transfer_private r4 r1 r2 into r5 r6;
    output r4 as credits.aleo/credits.record;
    output r5 as credits.aleo/credits.record;
    output r6 as credits.aleo/credits.record;
    ",
        )
        .unwrap();
        let deployment = vm.deploy(&caller_private_key, &program, Some(record_0), 1, None, rng).unwrap();
        vm.add_next_block(&sample_next_block(&vm, &caller_private_key, &[deployment], rng).unwrap()).unwrap();

        // Execute the programs.
        let inputs = [
            Value::<Testnet3>::Record(record_1),
            Value::<Testnet3>::from_str(&address.to_string()).unwrap(),
            Value::<Testnet3>::from_str("10u64").unwrap(),
        ];
        let execution = vm
            .execute(
                &caller_private_key,
                ("test_multiple_external_calls.aleo", "multitransfer"),
                inputs.into_iter(),
                Some(record_2),
                1,
                None,
                rng,
            )
            .unwrap();
        vm.add_next_block(&sample_next_block(&vm, &caller_private_key, &[execution], rng).unwrap()).unwrap();
    }

    #[test]
    fn test_nested_deployment_with_assert() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the base program.
        let program = Program::from_str(
            r"
program child_program.aleo;

function check:
    input r0 as field.private;
    assert.eq r0 123456789123456789123456789123456789123456789123456789field;
        ",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // Check that program is deployed.
        assert!(vm.contains_program(&ProgramID::from_str("child_program.aleo").unwrap()));

        // Deploy the program that calls the program from the previous layer.
        let program = Program::from_str(
            r"
import child_program.aleo;

program parent_program.aleo;

function check:
    input r0 as field.private;
    call child_program.aleo/check r0;
        ",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // Check that program is deployed.
        assert!(vm.contains_program(&ProgramID::from_str("parent_program.aleo").unwrap()));
    }

    #[test]
    fn test_deployment_with_external_records() {
        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the program.
        let program = Program::from_str(
            r"
import credits.aleo;
program test_program.aleo;

function transfer:
    input r0 as credits.aleo/credits.record;
    input r1 as u64.private;
    input r2 as u64.private;
    input r3 as [address; 10u32].private;
    call credits.aleo/transfer_private r0 r3[0u32] r1 into r4 r5;
    call credits.aleo/transfer_private r5 r3[0u32] r2 into r6 r7;
",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
        assert!(vm.check_transaction(&deployment, None, rng).is_ok());
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // Check that program is deployed.
        assert!(vm.contains_program(&ProgramID::from_str("test_program.aleo").unwrap()));
    }

    #[test]
    #[ignore]
    fn test_deployment_memory_overload() {
        const NUM_DEPLOYMENTS: usize = 32;

        let rng = &mut TestRng::default();

        // Initialize a private key.
        let private_key = sample_genesis_private_key(rng);

        // Initialize a view key.
        let view_key = ViewKey::try_from(&private_key).unwrap();

        // Initialize the genesis block.
        let genesis = sample_genesis_block(rng);

        // Initialize the VM.
        let vm = sample_vm();
        // Update the VM.
        vm.add_next_block(&genesis).unwrap();

        // Deploy the base program.
        let program = Program::from_str(
            r"
program program_layer_0.aleo;

mapping m:
    key as u8.public;
    value as u32.public;

function do:
    input r0 as u32.public;
    async do r0 into r1;
    output r1 as program_layer_0.aleo/do.future;

finalize do:
    input r0 as u32.public;
    set r0 into m[0u8];",
        )
        .unwrap();

        let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();
        vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();

        // For each layer, deploy a program that calls the program from the previous layer.
        for i in 1..NUM_DEPLOYMENTS {
            let mut program_string = String::new();
            // Add the import statements.
            for j in 0..i {
                program_string.push_str(&format!("import program_layer_{}.aleo;\n", j));
            }
            // Add the program body.
            program_string.push_str(&format!(
                "program program_layer_{i}.aleo;

mapping m:
    key as u8.public;
    value as u32.public;

function do:
    input r0 as u32.public;
    call program_layer_{prev}.aleo/do r0 into r1;
    async do r0 r1 into r2;
    output r2 as program_layer_{i}.aleo/do.future;

finalize do:
    input r0 as u32.public;
    input r1 as program_layer_{prev}.aleo/do.future;
    await r1;
    set r0 into m[0u8];",
                prev = i - 1
            ));
            // Construct the program.
            let program = Program::from_str(&program_string).unwrap();

            // Deploy the program.
            let deployment = vm.deploy(&private_key, &program, None, 0, None, rng).unwrap();

            vm.add_next_block(&sample_next_block(&vm, &private_key, &[deployment], rng).unwrap()).unwrap();
        }

        // Fetch the unspent records.
        let records = genesis.transitions().cloned().flat_map(Transition::into_records).collect::<IndexMap<_, _>>();
        trace!("Unspent Records:\n{:#?}", records);

        // Select a record to spend.
        let record = Some(records.values().next().unwrap().decrypt(&view_key).unwrap());

        // Prepare the inputs.
        let inputs = [Value::<CurrentNetwork>::from_str("1u32").unwrap()].into_iter();

        // Execute.
        let transaction =
            vm.execute(&private_key, ("program_layer_30.aleo", "do"), inputs, record, 0, None, rng).unwrap();

        // Verify.
        vm.check_transaction(&transaction, None, rng).unwrap();
    }
}
