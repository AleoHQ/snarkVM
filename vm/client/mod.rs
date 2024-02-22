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

mod execute;
mod rest;
mod scan;

use anyhow::{anyhow, bail, Result};
use core::{convert::TryInto, ops::Range};
use reqwest::Url;

use crate::{
    console::{
        account::{PrivateKey, ViewKey},
        program::{Ciphertext, Field, Identifier, Network, Plaintext, ProgramID, Record, Value},
    },
    ledger::{
        block::{Block, Transaction},
        committee::Committee,
        query::Query,
        store::{
            helpers::memory::{BlockMemory, ConsensusMemory},
            ConsensusStore,
        },
    },
    synthesizer::{Program, VM},
};

#[derive(Clone)]
pub struct Client<N: Network> {
    client: reqwest::Client,
    base_url: Url,
    vm: VM<N, ConsensusMemory<N>>,
}

impl<N: Network> Client<N> {
    /// Initializes a new client with the given node URL.
    pub fn new(node_url: &str) -> Result<Self> {
        // Initialize a new in-memory store.
        let store = ConsensusStore::open(None)?;
        // Initialize a new client.
        Ok(Self { client: reqwest::Client::new(), base_url: Url::parse(node_url)?, vm: VM::from(store)? })
    }

    /// Returns the node URL.
    pub fn node_url(&self) -> &str {
        let mut base_url_str = self.base_url.as_str();

        // Remove the trailing slash if it exists.
        if base_url_str.ends_with('/') {
            base_url_str = &base_url_str[..base_url_str.len().saturating_sub(1)];
        }

        base_url_str
    }

    /// Returns the underlying REST client.
    pub fn inner(&self) -> &reqwest::Client {
        &self.client
    }
}
