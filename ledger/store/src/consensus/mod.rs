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

use crate::{
    BFTStorage,
    BFTStore,
    BlockStorage,
    BlockStore,
    FinalizeStorage,
    FinalizeStore,
    TransactionStorage,
    TransactionStore,
    TransitionStorage,
    TransitionStore,
};
use console::network::prelude::*;

use anyhow::Result;
use core::marker::PhantomData;

/// A trait for consensus storage.
pub trait ConsensusStorage<N: Network>: 'static + Clone + Send + Sync {
    /// The BFT storage.
    type BFTStorage: BFTStorage<N>;
    /// The finalize storage.
    type FinalizeStorage: FinalizeStorage<N>;
    /// The block storage.
    type BlockStorage: BlockStorage<N, TransactionStorage = Self::TransactionStorage, TransitionStorage = Self::TransitionStorage>;
    /// The transaction storage.
    type TransactionStorage: TransactionStorage<N, TransitionStorage = Self::TransitionStorage>;
    /// The transition storage.
    type TransitionStorage: TransitionStorage<N>;

    /// Initializes the consensus storage.
    fn open(dev: Option<u16>) -> Result<Self>;

    /// Returns the BFT storage.
    fn bft_store(&self) -> &BFTStore<N, Self::BFTStorage>;
    /// Returns the finalize storage.
    fn finalize_store(&self) -> &FinalizeStore<N, Self::FinalizeStorage>;
    /// Returns the block storage.
    fn block_store(&self) -> &BlockStore<N, Self::BlockStorage>;
    /// Returns the transaction store.
    fn transaction_store(&self) -> &TransactionStore<N, Self::TransactionStorage> {
        self.block_store().transaction_store()
    }
    /// Returns the transition store.
    fn transition_store(&self) -> &TransitionStore<N, Self::TransitionStorage> {
        self.block_store().transition_store()
    }
    /// Returns the optional development ID.
    fn dev(&self) -> Option<u16> {
        debug_assert!(self.bft_store().dev() == self.finalize_store().dev());
        debug_assert!(self.finalize_store().dev() == self.block_store().dev());
        debug_assert!(self.block_store().dev() == self.transaction_store().dev());
        debug_assert!(self.transaction_store().dev() == self.transition_store().dev());
        self.transition_store().dev()
    }

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.bft_store().start_atomic();
        self.finalize_store().start_atomic();
        self.block_store().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.bft_store().is_atomic_in_progress()
            || self.finalize_store().is_atomic_in_progress()
            || self.block_store().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.bft_store().atomic_checkpoint();
        self.finalize_store().atomic_checkpoint();
        self.block_store().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.bft_store().clear_latest_checkpoint();
        self.finalize_store().clear_latest_checkpoint();
        self.block_store().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.bft_store().atomic_rewind();
        self.finalize_store().atomic_rewind();
        self.block_store().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.bft_store().abort_atomic();
        self.finalize_store().abort_atomic();
        self.block_store().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.bft_store().finish_atomic()?;
        self.finalize_store().finish_atomic()?;
        self.block_store().finish_atomic()
    }
}

/// The consensus store.
#[derive(Clone)]
pub struct ConsensusStore<N: Network, C: ConsensusStorage<N>> {
    /// The consensus storage.
    storage: C,
    /// PhantomData.
    _phantom: PhantomData<N>,
}

impl<N: Network, C: ConsensusStorage<N>> ConsensusStore<N, C> {
    /// Initializes the consensus store.
    pub fn open(dev: Option<u16>) -> Result<Self> {
        // Initialize the consensus storage.
        let storage = C::open(dev)?;
        // Return the consensus store.
        Ok(Self { storage, _phantom: PhantomData })
    }

    /// Initializes a consensus store from storage.
    pub fn from(storage: C) -> Self {
        Self { storage, _phantom: PhantomData }
    }

    /// Returns the BFT store.
    pub fn bft_store(&self) -> &BFTStore<N, C::BFTStorage> {
        self.storage.bft_store()
    }

    /// Returns the finalize store.
    pub fn finalize_store(&self) -> &FinalizeStore<N, C::FinalizeStorage> {
        self.storage.finalize_store()
    }

    /// Returns the block store.
    pub fn block_store(&self) -> &BlockStore<N, C::BlockStorage> {
        self.storage.block_store()
    }

    /// Returns the transaction store.
    pub fn transaction_store(&self) -> &TransactionStore<N, C::TransactionStorage> {
        self.storage.transaction_store()
    }

    /// Returns the transition store.
    pub fn transition_store(&self) -> &TransitionStore<N, C::TransitionStorage> {
        self.storage.transition_store()
    }

    /// Starts an atomic batch write operation.
    pub fn start_atomic(&self) {
        self.storage.start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    pub fn is_atomic_in_progress(&self) -> bool {
        self.storage.is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    pub fn atomic_checkpoint(&self) {
        self.storage.atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    pub fn clear_latest_checkpoint(&self) {
        self.storage.clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    pub fn atomic_rewind(&self) {
        self.storage.atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    pub fn abort_atomic(&self) {
        self.storage.abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    pub fn finish_atomic(&self) -> Result<()> {
        self.storage.finish_atomic()
    }

    /// Returns the optional development ID.
    pub fn dev(&self) -> Option<u16> {
        self.storage.dev()
    }
}
