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
    atomic_batch_scope,
    cow_to_cloned,
    helpers::{NestedMap, NestedMapRead},
};
use console::network::prelude::*;
use ledger_narwhal_transmission::Transmission;
use ledger_narwhal_transmission_id::TransmissionID;

use anyhow::Result;
use std::marker::PhantomData;

/// A trait for transmission storage.
pub trait TransmissionStorage<N: Network>: 'static + Clone + Send + Sync {
    /// The mapping of `transmission ID => round => transmission`.
    type TransmissionMap: for<'a> NestedMap<'a, TransmissionID<N>, u64, Transmission<N>>;

    /// Initializes the transmission storage.
    fn open(dev: Option<u16>) -> Result<Self>;

    /// Initializes the test-variant of the storage.
    #[cfg(any(test, feature = "test"))]
    fn open_testing(temp_dir: std::path::PathBuf, dev: Option<u16>) -> Result<Self>;

    /// Returns the transmission map.
    fn transmission_map(&self) -> &Self::TransmissionMap;

    /// Returns the optional development ID.
    fn dev(&self) -> Option<u16>;

    /// Starts an atomic batch write operation.
    fn start_atomic(&self) {
        self.transmission_map().start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    fn is_atomic_in_progress(&self) -> bool {
        self.transmission_map().is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    fn atomic_checkpoint(&self) {
        self.transmission_map().atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    fn clear_latest_checkpoint(&self) {
        self.transmission_map().clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    fn atomic_rewind(&self) {
        self.transmission_map().atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    fn abort_atomic(&self) {
        self.transmission_map().abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    fn finish_atomic(&self) -> Result<()> {
        self.transmission_map().finish_atomic()
    }

    /// Stores the given round, transmission ID, and transmission into storage.
    fn insert_transmission(
        &self,
        round: u64,
        transmission_id: TransmissionID<N>,
        transmission: Transmission<N>,
    ) -> Result<()> {
        atomic_batch_scope!(self, {
            // Insert the `(transmission ID, round, transmission)` entry.
            self.transmission_map().insert(transmission_id, round, transmission)?;
            Ok(())
        })
    }

    /// Stores the given `(transmission ID, transmission)` pairs for the given round into storage.
    fn insert_transmissions(&self, round: u64, transmissions: Vec<(TransmissionID<N>, Transmission<N>)>) -> Result<()> {
        atomic_batch_scope!(self, {
            for (transmission_id, transmission) in transmissions.into_iter() {
                // Insert the `(transmission ID, round, transmission)` entry.
                self.transmission_map().insert(transmission_id, round, transmission)?
            }
            Ok(())
        })
    }

    /// Removes the transmission for the given `transmission ID` from storage.
    fn remove_transmission(&self, transmission_id: TransmissionID<N>) -> Result<()> {
        atomic_batch_scope!(self, {
            // Insert the transmission from all rounds.
            self.transmission_map().remove_map(&transmission_id)?;
            Ok(())
        })
    }

    /// Removes the transmission for the given `round` and `transmission ID` from storage.
    fn remove_transmission_for_round(&self, round: u64, transmission_id: TransmissionID<N>) -> Result<()> {
        atomic_batch_scope!(self, {
            // Insert the transmission for the round.
            self.transmission_map().remove_key(&transmission_id, &round)?;

            Ok(())
        })
    }

    /// Returns `true` if the given `transmission ID` exists.
    fn contains_transmission(&self, transmission_id: &TransmissionID<N>) -> Result<bool> {
        self.transmission_map().contains_map_confirmed(transmission_id)
    }

    /// Returns `true` if the given `round` and `transmission ID` exists.
    fn contains_transmission_for_round(&self, round: u64, transmission_id: &TransmissionID<N>) -> Result<bool> {
        self.transmission_map().contains_key_confirmed(transmission_id, &round)
    }

    /// Returns the transmission for the given `transmission ID`.
    fn get_transmission(&self, transmission_id: &TransmissionID<N>) -> Result<Option<Transmission<N>>> {
        match self.transmission_map().get_any_map_entry_confirmed(transmission_id)? {
            Some((_, transmission)) => Ok(Some(transmission)),
            None => Ok(None),
        }
    }

    /// Returns the transmission for the given `round` and `transmission ID`.
    fn get_transmission_for_round(
        &self,
        round: u64,
        transmission_id: &TransmissionID<N>,
    ) -> Result<Option<Transmission<N>>> {
        match self.transmission_map().get_value_confirmed(transmission_id, &round)? {
            Some(transmission) => Ok(Some(cow_to_cloned!(transmission))),
            None => Ok(None),
        }
    }
}

/// The transmission store.
#[derive(Clone)]
pub struct TransmissionStore<N: Network, T: TransmissionStorage<N>> {
    /// The transmission storage.
    storage: T,
    /// PhantomData.
    _phantom: PhantomData<N>,
}

impl<N: Network, T: TransmissionStorage<N>> TransmissionStore<N, T> {
    /// Initializes the transmission store.
    pub fn open(dev: Option<u16>) -> Result<Self> {
        // Initialize the transmission storage.
        let storage = T::open(dev)?;

        // Return the transmission store.
        Ok(Self { storage, _phantom: PhantomData })
    }

    /// Initializes the test-variant of the storage.
    #[cfg(any(test, feature = "test"))]
    pub fn open_testing(temp_dir: std::path::PathBuf, dev: Option<u16>) -> Result<Self> {
        Self::from(T::open_testing(temp_dir, dev)?)
    }

    /// Initializes a transmission store from storage.
    pub fn from(storage: T) -> Result<Self> {
        // Return the transmission store.
        Ok(Self { storage, _phantom: PhantomData })
    }

    /// Starts an atomic batch write operation.
    pub(crate) fn start_atomic(&self) {
        self.storage.start_atomic();
    }

    /// Checks if an atomic batch is in progress.
    pub(crate) fn is_atomic_in_progress(&self) -> bool {
        self.storage.is_atomic_in_progress()
    }

    /// Checkpoints the atomic batch.
    pub(crate) fn atomic_checkpoint(&self) {
        self.storage.atomic_checkpoint();
    }

    /// Clears the latest atomic batch checkpoint.
    pub(crate) fn clear_latest_checkpoint(&self) {
        self.storage.clear_latest_checkpoint();
    }

    /// Rewinds the atomic batch to the previous checkpoint.
    pub(crate) fn atomic_rewind(&self) {
        self.storage.atomic_rewind();
    }

    /// Aborts an atomic batch write operation.
    pub(crate) fn abort_atomic(&self) {
        self.storage.abort_atomic();
    }

    /// Finishes an atomic batch write operation.
    pub(crate) fn finish_atomic(&self) -> Result<()> {
        self.storage.finish_atomic()
    }

    /// Returns the optional development ID.
    pub(crate) fn dev(&self) -> Option<u16> {
        self.storage.dev()
    }
}

impl<N: Network, T: TransmissionStorage<N>> TransmissionStore<N, T> {
    /// Stores the given round, transmission ID, and transmission into storage.
    pub(crate) fn insert_transmission(
        &self,
        round: u64,
        transmission_id: TransmissionID<N>,
        transmission: Transmission<N>,
    ) -> Result<()> {
        self.storage.insert_transmission(round, transmission_id, transmission)
    }

    /// Stores the given `(transmission ID, transmission)` pairs for the given round into storage.
    pub(crate) fn insert_transmissions(
        &self,
        round: u64,
        transmissions: Vec<(TransmissionID<N>, Transmission<N>)>,
    ) -> Result<()> {
        self.storage.insert_transmissions(round, transmissions)
    }

    /// Removes the transmission for the given `transmission ID` from storage.
    pub(crate) fn remove_transmission(&self, transmission_id: TransmissionID<N>) -> Result<()> {
        self.storage.remove_transmission(transmission_id)
    }

    /// Removes the transmission for the given `round` and `transmission ID` from storage.
    pub(crate) fn remove_transmission_for_round(&self, round: u64, transmission_id: TransmissionID<N>) -> Result<()> {
        self.storage.remove_transmission_for_round(round, transmission_id)
    }

    /// Returns `true` if the given `transmission ID` exists.
    pub(crate) fn contains_transmission(&self, transmission_id: &TransmissionID<N>) -> Result<bool> {
        self.storage.contains_transmission(transmission_id)
    }

    /// Returns `true` if the given `round` and `transmission ID` exists.
    pub(crate) fn contains_transmission_for_round(
        &self,
        round: u64,
        transmission_id: &TransmissionID<N>,
    ) -> Result<bool> {
        self.storage.contains_transmission_for_round(round, transmission_id)
    }

    /// Returns the transmission for the given `transmission ID`.
    pub(crate) fn get_transmission(&self, transmission_id: &TransmissionID<N>) -> Result<Option<Transmission<N>>> {
        self.storage.get_transmission(transmission_id)
    }

    /// Returns the transmission for the given `round` and `transmission ID`.
    pub(crate) fn get_transmission_for_round(
        &self,
        round: u64,
        transmission_id: &TransmissionID<N>,
    ) -> Result<Option<Transmission<N>>> {
        self.storage.get_transmission_for_round(round, transmission_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ledger_narwhal_transmission::test_helpers::sample_transmissions;
    use ledger_narwhal_transmission_id::test_helpers::sample_transmission_ids;

    /// Samples a new transmission store.
    macro_rules! sample_transmission_store {
        () => {{
            #[cfg(not(feature = "rocks"))]
            let store =
                TransmissionStore::from(crate::helpers::memory::TransmissionMemory::open(None).unwrap()).unwrap();
            #[cfg(feature = "rocks")]
            let store = {
                let temp_dir = tempfile::tempdir().expect("Failed to open temporary directory").into_path();
                TransmissionStore::from(crate::helpers::rocksdb::TransmissionDB::open_testing(temp_dir, None).unwrap())
                    .unwrap()
            };
            store
        }};
    }

    #[test]
    fn test_insert_get_remove_transmission() {
        let rng = &mut TestRng::default();

        // Initialize a new transmission store.
        let store = sample_transmission_store!();

        // Sample the transmissions.
        let transmissions = sample_transmissions(rng);
        let transmission_ids = sample_transmission_ids(rng);
        assert_eq!(transmissions.len(), transmission_ids.len());

        // Sample a list of rounds.
        let rounds = (0..10).map(|_| rng.gen()).collect::<Vec<u64>>();

        for (transmission_id, transmission) in transmission_ids.iter().zip_eq(transmissions) {
            // Insert the transmission into the rounds.
            for round in &rounds {
                // Insert the transmission.
                store.insert_transmission(*round, *transmission_id, transmission.clone()).unwrap();

                // Get the transmission for the round.
                let candidate = store.get_transmission_for_round(*round, transmission_id).unwrap();
                assert_eq!(Some(transmission.clone()), candidate);
            }

            // Get the transmission.
            let candidate = store.get_transmission(transmission_id).unwrap();
            assert_eq!(Some(transmission.clone()), candidate);

            // Get the transmission for the rounds.
            for round in &rounds {
                // Get the transmission for the round.
                let candidate = store.get_transmission_for_round(*round, transmission_id).unwrap();
                assert_eq!(Some(transmission.clone()), candidate);
            }

            // Remove the transmission for the rounds.
            for round in &rounds {
                // Ensure the transmission is found (should succeed on all iterations).
                let candidate = store.get_transmission(transmission_id).unwrap();
                assert_eq!(Some(transmission.clone()), candidate);

                // Remove the transmission for the round.
                store.remove_transmission_for_round(*round, *transmission_id).unwrap();

                // Ensure the transmission is not found for the round.
                let candidate = store.get_transmission_for_round(*round, transmission_id).unwrap();
                assert_eq!(None, candidate);
            }

            // Ensure the transmission is not found.
            let candidate = store.get_transmission(transmission_id).unwrap();
            assert_eq!(None, candidate);
        }
    }

    #[test]
    fn test_contains_transmission() {
        let rng = &mut TestRng::default();

        // Initialize a new transmission store.
        let store = sample_transmission_store!();

        // Sample the transmissions.
        let transmissions = sample_transmissions(rng);
        let transmission_ids = sample_transmission_ids(rng);
        assert_eq!(transmissions.len(), transmission_ids.len());

        // Sample a list of rounds.
        let rounds = (0..10).map(|_| rng.gen()).collect::<Vec<u64>>();

        for (transmission_id, transmission) in transmission_ids.iter().zip_eq(transmissions) {
            // Ensure the transmission does not exist.
            assert!(!store.contains_transmission(transmission_id).unwrap());
            // Ensure the transmission does not exist for any round.
            for round in &rounds {
                assert!(!store.contains_transmission_for_round(*round, transmission_id).unwrap());
            }

            // Insert the transmission into the rounds.
            for round in &rounds {
                // Insert the transmission.
                store.insert_transmission(*round, *transmission_id, transmission.clone()).unwrap();

                // Ensure the transmission exists.
                assert!(store.contains_transmission(transmission_id).unwrap());
                // Ensure the transmission exists for the round.
                assert!(store.contains_transmission_for_round(*round, transmission_id).unwrap());
            }
        }

        for transmission_id in transmission_ids.iter() {
            // Ensure the transmission exists for the rounds.
            for round in &rounds {
                // Ensure the transmission exists.
                assert!(store.contains_transmission(transmission_id).unwrap());
                // Ensure the transmission exists for the round.
                assert!(store.contains_transmission_for_round(*round, transmission_id).unwrap());
            }

            // Remove the transmission for the rounds.
            for round in &rounds {
                // Ensure the transmission exists (should succeed on all iterations).
                assert!(store.contains_transmission(transmission_id).unwrap());

                // Remove the transmission for the round.
                store.remove_transmission_for_round(*round, *transmission_id).unwrap();

                // Ensure the transmission does not exist for the round.
                assert!(!store.contains_transmission_for_round(*round, transmission_id).unwrap());
            }

            // Ensure the transmission does not exist.
            assert!(!store.contains_transmission(transmission_id).unwrap());
        }
    }
}
