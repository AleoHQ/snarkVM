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

// TODO: search if this new directory needs to be included in any of the higher up files/dirs.

use console::{
    program::{Network, Signature},
    types::{Address, Field},
};
use core::hash::Hash;
use indexmap::IndexSet;

pub trait NarwhalCertificate<N: Network>: Clone + Eq + PartialEq + Hash {
    /// Returns the certificate ID.
    fn id(&self) -> Field<N>;

    /// Returns the batch ID.
    fn batch_id(&self) -> Field<N>;

    /// Returns the author.
    fn author(&self) -> Address<N>;

    /// Returns the round.
    fn round(&self) -> u64;

    /// Returns the certificate IDs for the previous round.
    fn previous_certificate_ids(&self) -> &IndexSet<Field<N>>;

    /// Returns the timestamp of the compact header.
    fn timestamp(&self) -> i64;

    /// Returns the signatures of the batch ID from the committee.
    fn signatures(&self) -> Box<dyn '_ + ExactSizeIterator<Item = &Signature<N>>>;
}
