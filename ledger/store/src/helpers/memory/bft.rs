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

use crate::{helpers::memory::NestedMemoryMap, BFTStorage, TransmissionStorage, TransmissionStore};
use console::prelude::*;
use ledger_narwhal_transmission::Transmission;
use ledger_narwhal_transmission_id::TransmissionID;

/// An in-memory BFT storage.
#[derive(Clone)]
pub struct BFTMemory<N: Network> {
    /// The transmission store.
    transmission_store: TransmissionStore<N, TransmissionMemory<N>>,
    /// The optional development ID.
    dev: Option<u16>,
}

#[rustfmt::skip]
impl<N: Network> BFTStorage<N> for BFTMemory<N> {
    type TransmissionStorage = TransmissionMemory<N>;

    /// Initializes the BFT storage.
    fn open(dev: Option<u16>) -> Result<Self> {
        Ok(Self {
            transmission_store: TransmissionStore::<N, TransmissionMemory<N>>::open(dev)?,
            dev,
        })
    }

    /// Initializes the test-variant of the storage.
    #[cfg(any(test, feature = "test"))]
    fn open_testing(_: std::path::PathBuf, dev: Option<u16>) -> Result<Self> {
        Self::open(dev)
    }

    /// Returns the transmission store.
    fn transmission_store(&self) -> &TransmissionStore<N, Self::TransmissionStorage> {
        &self.transmission_store
    }

    /// Returns the optional development ID.
    fn dev(&self) -> Option<u16> {
        self.dev
    }
}

/// An in-memory transmission storage.
#[derive(Clone)]
pub struct TransmissionMemory<N: Network> {
    /// The transmission map.
    transmission_map: NestedMemoryMap<TransmissionID<N>, u64, Transmission<N>>,
    /// The optional development ID.
    dev: Option<u16>,
}

#[rustfmt::skip]
impl<N: Network> TransmissionStorage<N> for TransmissionMemory<N> {
    type TransmissionMap = NestedMemoryMap<TransmissionID<N>, u64, Transmission<N>>;

    /// Initializes the transmission storage.
    fn open(dev: Option<u16>) -> Result<Self> {
        Ok(Self {
            transmission_map: NestedMemoryMap::default(),
            dev,
        })
    }

    /// Initializes the test-variant of the storage.
    #[cfg(any(test, feature = "test"))]
    fn open_testing(_: std::path::PathBuf, dev: Option<u16>) -> Result<Self> {
        Self::open(dev)
    }

    /// Returns the transmission map.
    fn transmission_map(&self) -> &Self::TransmissionMap {
        &self.transmission_map
    }

    /// Returns the optional development ID.
    fn dev(&self) -> Option<u16> {
        self.dev
    }
}
