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

use crate::{
    ahp::indexer::*,
    fiat_shamir::{FiatShamirError, FiatShamirRng},
    marlin::{CircuitProvingKey, PreparedCircuitVerifyingKey},
    Vec,
};
use snarkvm_algorithms::Prepare;
use snarkvm_fields::{ConstraintFieldError, PrimeField, ToConstraintField};
use snarkvm_polycommit::PolynomialCommitment;
use snarkvm_utilities::{error, errors::SerializationError, serialize::*, FromBytes, ToBytes};

use derivative::Derivative;
use snarkvm_algorithms::fft::EvaluationDomain;
use snarkvm_r1cs::SynthesisError;
use std::io::{
    Read,
    Write,
    {self},
};

/// Verification key for a specific index (i.e., R1CS matrices).
#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitVerifyingKey<F: PrimeField, PC: PolynomialCommitment<F>> {
    /// Stores information about the size of the circuit, as well as its defined field.
    pub circuit_info: CircuitInfo<F>,
    /// Commitments to the indexed polynomials.
    pub circuit_commitments: Vec<PC::Commitment>,
    /// The verifier key for this index, trimmed from the universal SRS.
    pub verifier_key: PC::VerifierKey,
}

impl<F: PrimeField, PC: PolynomialCommitment<F>> ToBytes for CircuitVerifyingKey<F, PC> {
    fn write_le<W: Write>(&self, mut w: W) -> io::Result<()> {
        CanonicalSerialize::serialize(self, &mut w).map_err(|_| error("could not serialize CircuitVerifyingKey"))
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>> FromBytes for CircuitVerifyingKey<F, PC> {
    fn read_le<R: Read>(mut r: R) -> io::Result<Self> {
        CanonicalDeserialize::deserialize(&mut r).map_err(|_| error("could not deserialize CircuitVerifyingKey"))
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>> CircuitVerifyingKey<F, PC> {
    /// Iterate over the commitments to indexed polynomials in `self`.
    pub fn iter(&self) -> impl Iterator<Item = &PC::Commitment> {
        self.circuit_commitments.iter()
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>> From<CircuitProvingKey<F, PC>> for CircuitVerifyingKey<F, PC> {
    fn from(other: CircuitProvingKey<F, PC>) -> Self {
        other.circuit_verifying_key
    }
}

impl<F: PrimeField, PC: PolynomialCommitment<F>> From<PreparedCircuitVerifyingKey<F, PC>>
    for CircuitVerifyingKey<F, PC>
{
    fn from(other: PreparedCircuitVerifyingKey<F, PC>) -> Self {
        other.orig_vk
    }
}

/// Compute the hash of the circuit verifying key.
/// Used internally in Marlin
pub(crate) fn compute_vk_hash<TargetField, BaseField, PC, FS>(
    vk: &CircuitVerifyingKey<TargetField, PC>,
) -> Result<Vec<BaseField>, FiatShamirError>
where
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    FS: FiatShamirRng<TargetField, BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
{
    let mut vk_hash_rng = FS::new();
    vk_hash_rng.absorb_native_field_elements(&vk.circuit_commitments);
    vk_hash_rng.squeeze_native_field_elements(1)
}

impl<F, PC> Prepare<PreparedCircuitVerifyingKey<F, PC>> for CircuitVerifyingKey<F, PC>
where
    F: PrimeField,
    PC: PolynomialCommitment<F>,
{
    /// Prepare the circuit verifying key.
    fn prepare(&self) -> PreparedCircuitVerifyingKey<F, PC> {
        let mut prepared_index_comms = Vec::<PC::PreparedCommitment>::new();
        for (_, comm) in self.circuit_commitments.iter().enumerate() {
            prepared_index_comms.push(comm.prepare());
        }

        let prepared_verifier_key = self.verifier_key.prepare();

        let domain_h = EvaluationDomain::<F>::new(self.circuit_info.num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)
            .unwrap();
        let domain_k = EvaluationDomain::<F>::new(self.circuit_info.num_non_zero)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)
            .unwrap();

        let domain_h_size = domain_h.size();
        let domain_k_size = domain_k.size();

        PreparedCircuitVerifyingKey::<F, PC> {
            domain_h_size: domain_h_size as u64,
            domain_k_size: domain_k_size as u64,
            prepared_index_comms,
            prepared_verifier_key,
            orig_vk: (*self).clone(),
        }
    }
}

impl<F, CF, PC> ToConstraintField<CF> for CircuitVerifyingKey<F, PC>
where
    F: PrimeField,
    CF: PrimeField,
    PC: PolynomialCommitment<F>,
    PC::Commitment: ToConstraintField<CF>,
    PC::VerifierKey: ToConstraintField<CF>,
{
    fn to_field_elements(&self) -> Result<Vec<CF>, ConstraintFieldError> {
        let domain_h = EvaluationDomain::<CF>::new(self.circuit_info.num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)
            .unwrap();
        let domain_k = EvaluationDomain::<CF>::new(self.circuit_info.num_non_zero)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)
            .unwrap();

        let mut res = Vec::new();
        res.append(&mut CF::from(domain_h.size() as u128).to_field_elements()?);
        res.append(&mut CF::from(domain_k.size() as u128).to_field_elements()?);
        for comm in self.circuit_commitments.iter() {
            res.append(&mut comm.to_field_elements()?);
        }
        // TODO: this overhead can be cut.
        res.append(&mut self.verifier_key.to_field_elements()?);

        Ok(res)
    }
}
