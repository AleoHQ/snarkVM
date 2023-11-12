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
    helpers::rocksdb::{BlockDB, FinalizeDB, TransactionDB, TransitionDB, BFTDB},
    BFTStore,
    BlockStore,
    ConsensusStorage,
    FinalizeStore,
};
use console::prelude::*;

/// An RocksDB consensus storage.
#[derive(Clone)]
pub struct ConsensusDB<N: Network> {
    /// The BFT store.
    bft_store: BFTStore<N, BFTDB<N>>,
    /// The finalize store.
    finalize_store: FinalizeStore<N, FinalizeDB<N>>,
    /// The block store.
    block_store: BlockStore<N, BlockDB<N>>,
}

#[rustfmt::skip]
impl<N: Network> ConsensusStorage<N> for ConsensusDB<N> {
    type BFTStorage = BFTDB<N>;
    type FinalizeStorage = FinalizeDB<N>;
    type BlockStorage = BlockDB<N>;
    type TransactionStorage = TransactionDB<N>;
    type TransitionStorage = TransitionDB<N>;

    /// Initializes the consensus storage.
    fn open(dev: Option<u16>) -> Result<Self> {
        // Initialize the BFT store.
        let bft_store = BFTStore::<N, BFTDB<N>>::open(dev)?;
        // Initialize the finalize store.
        let finalize_store = FinalizeStore::<N, FinalizeDB<N>>::open(dev)?;
        // Initialize the block store.
        let block_store = BlockStore::<N, BlockDB<N>>::open(dev)?;
        // Return the consensus storage.
        Ok(Self {
            bft_store,
            finalize_store,
            block_store,
        })
    }

    /// Returns the BFT store.
    fn bft_store(&self) -> &BFTStore<N, Self::BFTStorage> {
        &self.bft_store
    }

    /// Returns the finalize store.
    fn finalize_store(&self) -> &FinalizeStore<N, Self::FinalizeStorage> {
        &self.finalize_store
    }

    /// Returns the block store.
    fn block_store(&self) -> &BlockStore<N, Self::BlockStorage> {
        &self.block_store
    }
}
