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

use snarkvm_utilities::ToBitsInto;

impl<N: Network> ToBitsInto for TransactionLeaf<N> {
    /// Returns the little-endian bits of the Merkle leaf.
    fn to_bits_le_into(&self, vec: &mut Vec<bool>) {
        // Construct the leaf as (variant || index || ID).
        self.variant.to_bits_le_into(vec);
        self.index.to_bits_le_into(vec);
        self.id.to_bits_le_into(vec);
    }

    /// Returns the big-endian bits of the Merkle leaf.
    fn to_bits_be_into(&self, vec: &mut Vec<bool>) {
        // Construct the leaf as (variant || index || ID).
        self.variant.to_bits_be_into(vec);
        self.index.to_bits_be_into(vec);
        self.id.to_bits_be_into(vec);
    }
}
