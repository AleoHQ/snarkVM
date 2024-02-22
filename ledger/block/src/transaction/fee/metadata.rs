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

use std::marker::PhantomData;

#[derive(Copy, Clone, Debug)]
pub struct FeeMetadata<N: Network> {
    /// The number of blocks after the current block that the fee is valid for.
    expires_in: Option<u16>,
    /// PhantomData.
    _phantom: PhantomData<N>,
}

impl<N: Network> FeeMetadata<N> {
    /// Specifies the number of blocks until expiration.
    const EXPIRES_IN: u16 = 21600 / N::BLOCK_TIME;

    // 21000 blocks / 10 seconds per block = ~6 hours

    /// Initializes a new `FeeMetadata` instance with the given expiration.
    pub fn new(expires_in: Option<u16>) -> Result<Self> {
        if let Some(num_blocks) = &expires_in {
            if *num_blocks > Self::EXPIRES_IN {
                bail!("Fee expiration is too far in the future")
            }
        }

        Ok(Self { expires_in, _phantom: PhantomData })
    }
}
