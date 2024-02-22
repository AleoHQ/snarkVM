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

impl<E: Environment> ASWaksman<E> {
    /// Returns `true` if `first` is a permutation of `second`, given the `selectors` for the switches in the network.
    pub fn check_permutation(&self, first: &[Field<E>], second: &[Field<E>], selectors: &[Boolean<E>]) -> Boolean<E> {
        // Check that the two sequences are the same length.
        if first.len() != second.len() {
            return E::halt("The two sequences must be the same length.");
        }

        // Run the network on the first sequence, using the given selectors.
        let output = self.run(first, selectors);

        // Check that the output of the network is element-wise equal to the second sequence.
        output.iter().zip_eq(second).fold(Boolean::constant(true), |acc, (a, b)| acc & a.is_equal(b))
    }
}
