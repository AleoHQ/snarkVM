// Copyright (C) 2019-2021 Aleo Systems Inc.
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

use crate::FieldParameters;

/// An entry in the default Poseidon parameters
pub struct PoseidonDefaultParametersEntry {
    /// The rate (in terms of number of field elements).
    pub rate: usize,
    /// Exponent used in S-boxes.
    pub alpha: usize,
    /// Number of rounds in a full-round operation.
    pub full_rounds: usize,
    /// Number of rounds in a partial-round operation.
    pub partial_rounds: usize,
    /// Number of matrices to skip when generating parameters using the Grain LFSR.
    ///
    /// The matrices being skipped are those that do not satisfy all the desired properties.
    /// See the [reference implementation](https://extgit.iaik.tugraz.at/krypto/hadeshash/-/blob/master/code/generate_parameters_grain.sage) for more detail.
    pub skip_matrices: usize,
}

impl PoseidonDefaultParametersEntry {
    /// Create an entry in PoseidonDefaultParameters.
    pub const fn new(
        rate: usize,
        alpha: usize,
        full_rounds: usize,
        partial_rounds: usize,
        skip_matrices: usize,
    ) -> Self {
        Self {
            rate,
            alpha,
            full_rounds,
            partial_rounds,
            skip_matrices,
        }
    }
}

/// A trait for default Poseidon parameters associated with a prime field
pub trait PoseidonDefaultParameters: FieldParameters {
    /// An array of the parameters optimized for constraints
    /// (rate, alpha, full_rounds, partial_rounds, skip_matrices)
    /// for rate = 2, 3, 4, 5, 6, 7, 8
    ///
    /// Here, `skip_matrices` denote how many matrices to skip before
    /// finding one that satisfy all the requirements.
    const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultParametersEntry; 7];

    /// An array of the parameters optimized for weights
    /// (rate, alpha, full_rounds, partial_rounds, skip_matrices)
    /// for rate = 2, 3, 4, 5, 6, 7, 8
    const PARAMS_OPT_FOR_WEIGHTS: [PoseidonDefaultParametersEntry; 7];
}
