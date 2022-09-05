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

pub mod memory_map;

use console::network::prelude::*;

use core::{borrow::Borrow, hash::Hash};
use std::borrow::Cow;

pub enum BatchOperation<K: Copy + Clone + PartialEq + Eq + Hash + Send + Sync, V: Clone + PartialEq + Eq + Send + Sync>
{
    Insert(K, V),
    Remove(K),
}

/// A trait representing map-like storage operations with read-write capabilities.
pub trait Map<
    'a,
    K: 'a + Copy + Clone + PartialEq + Eq + Hash + Serialize + Deserialize<'a> + Send + Sync,
    V: 'a + Clone + PartialEq + Eq + Serialize + Deserialize<'a> + Send + Sync,
>: Clone + MapRead<'a, K, V> + Sync
{
    ///
    /// Inserts the given key-value pair into the map.
    ///
    fn insert(&self, key: K, value: V) -> Result<()>;

    ///
    /// Removes the key-value pair for the given key from the map.
    ///
    fn remove(&self, key: &K) -> Result<()>;

    ///
    /// Begins an atomic operation. Any further calls to `insert` and `remove` will be queued
    /// without an actual write taking place until `finish_atomic` is called.
    ///
    fn start_atomic(&self);

    ///
    /// Checks whether an atomic operation is currently in progress. This can be done to ensure
    /// that lower-level operations don't start or finish their individual atomic write batch
    /// if they are already part of a larger one.
    ///
    fn is_atomic_in_progress(&self) -> bool;

    ///
    /// Aborts the current atomic operation.
    ///
    fn abort_atomic(&self);

    ///
    /// Finishes an atomic operation, performing all the queued writes.
    ///
    fn finish_atomic(&self) -> Result<()>;
}

/// A trait representing map-like storage operations with read-only capabilities.
pub trait MapRead<
    'a,
    K: 'a + Copy + Clone + PartialEq + Eq + Hash + Serialize + Deserialize<'a> + Sync,
    V: 'a + Clone + PartialEq + Eq + Serialize + Deserialize<'a> + Sync,
>
{
    type Iterator: Iterator<Item = (Cow<'a, K>, Cow<'a, V>)>;
    type Keys: Iterator<Item = Cow<'a, K>>;
    type Values: Iterator<Item = Cow<'a, V>>;

    ///
    /// Returns `true` if the given key exists in the map.
    ///
    fn contains_key<Q>(&self, key: &Q) -> Result<bool>
    where
        K: Borrow<Q>,
        Q: PartialEq + Eq + Hash + Serialize + ?Sized;

    ///
    /// Returns the value for the given key from the map, if it exists.
    ///
    fn get<Q>(&'a self, key: &Q) -> Result<Option<Cow<'a, V>>>
    where
        K: Borrow<Q>,
        Q: PartialEq + Eq + Hash + Serialize + ?Sized;

    ///
    /// Returns an iterator visiting each key-value pair in the map.
    ///
    fn iter(&'a self) -> Self::Iterator;

    ///
    /// Returns an iterator over each key in the map.
    ///
    fn keys(&'a self) -> Self::Keys;

    ///
    /// Returns an iterator over each value in the map.
    ///
    fn values(&'a self) -> Self::Values;
}

/// This macro executes the given block of operations as a new atomic write batch IFF there is no
/// atomic write batch in progress yet. This ensures that complex atomic operations consisting of
/// multiple lower-level operations - which might also need to be atomic if executed individually -
/// are executed as a single large atomic operation regardless.
#[macro_export]
macro_rules! atomic_write_batch {
    ($self:expr, $ops:block) => {
        // Check if an atomic batch write is already in progress. If there isn't one, this means
        // this operation is a "top-level" one and is the one to start and finalize the batch.
        let is_part_of_atomic_batch = $self.is_atomic_in_progress();

        // Start an atomic batch write operation IFF it's not already part of one.
        if !is_part_of_atomic_batch {
            $self.start_atomic();
        }

        // Wrap the operations that should be batched in a closure to be able to abort the entire
        // write batch if any of them fails.
        let run_atomic_ops = || -> Result<()> { $ops };

        // Abort the batch if any of the associated operations has failed. It's crucial that there
        // is an early return (via `?`) here, in order for any higher-level atomic write batch to
        // also abort, cascading to all the owned storage objects.
        run_atomic_ops().map_err(|err| {
            $self.abort_atomic();
            err
        })?;

        // Finish an atomic batch write operation IFF it's not already part of a larger one.
        if !is_part_of_atomic_batch {
            $self.finish_atomic()?;
        }
    };
}
