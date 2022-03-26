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

use crate::{
    polycommit::PolynomialCommitment,
    snark::marlin::{CircuitVerifyingKey, MarlinMode},
};
use snarkvm_fields::PrimeField;

/// Verification key, prepared (preprocessed) for use in pairings.

#[derive(Clone)]
pub struct PreparedCircuitVerifyingKey<F: PrimeField, CF: PrimeField, PC: PolynomialCommitment<F, CF>, MM: MarlinMode> {
    /// Size of the variable domain.
    pub constraint_domain_size: u64,
    /// Size of the domain that represents A.
    pub non_zero_a_domain_size: u64,
    /// Size of the domain that represents B.
    pub non_zero_b_domain_size: u64,
    /// Size of the domain that represents C.
    pub non_zero_c_domain_size: u64,
    /// Commitments to the index polynomials, prepared.
    pub prepared_index_comms: Vec<PC::PreparedCommitment>,
    /// Prepared version of the poly-commit scheme's verification key.
    pub prepared_verifier_key: PC::PreparedVerifierKey,
    /// Non-prepared verification key, for use in native "prepared verify" (which
    /// is actually standard verify), as well as in absorbing the original vk into
    /// the Fiat-Shamir sponge.
    pub orig_vk: CircuitVerifyingKey<F, CF, PC, MM>,
}
