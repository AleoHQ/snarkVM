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

use crate::marlin::CircuitVerifyingKey;

use snarkvm_fields::PrimeField;
use snarkvm_polycommit::PolynomialCommitment;

/// Verification key, prepared (preprocessed) for use in pairings.
pub struct PreparedCircuitVerifyingKey<F: PrimeField, PC: PolynomialCommitment<F>> {
    /// Size of the variable domain.
    pub domain_h_size: u64,
    /// Size of the matrix domain.
    pub domain_k_size: u64,
    /// Commitments to the index polynomials, prepared.
    pub prepared_index_comms: Vec<PC::PreparedCommitment>,
    /// Prepared version of the poly-commit scheme's verification key.
    pub prepared_verifier_key: PC::PreparedVerifierKey,
    /// Non-prepared verification key, for use in native "prepared verify" (which
    /// is actually standard verify), as well as in absorbing the original vk into
    /// the Fiat-Shamir sponge.
    pub orig_vk: CircuitVerifyingKey<F, PC>,
}

impl<F: PrimeField, PC: PolynomialCommitment<F>> Clone for PreparedCircuitVerifyingKey<F, PC> {
    fn clone(&self) -> Self {
        PreparedCircuitVerifyingKey {
            domain_h_size: self.domain_h_size,
            domain_k_size: self.domain_k_size,
            prepared_index_comms: self.prepared_index_comms.clone(),
            prepared_verifier_key: self.prepared_verifier_key.clone(),
            orig_vk: self.orig_vk.clone(),
        }
    }
}
