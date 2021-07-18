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

use snarkvm_curves::PairingEngine;
use snarkvm_gadgets::{fields::FpGadget, traits::curves::PairingGadget};
use snarkvm_r1cs::ToConstraintField;

use crate::{marlin_pc::PreparedCommitmentVar, String};

/// Prepared gadget for a Marlin-KZG10 commitment, with a string label and degree bound.
pub struct PreparedLabeledCommitmentVar<
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
> where
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    /// A text label for the commitment.
    pub label: String,
    /// The plain commitment.
    pub prepared_commitment: PreparedCommitmentVar<TargetCurve, BaseCurve, PG>,
    /// Optionally, a bound on the polynomial degree.
    pub degree_bound: Option<FpGadget<<BaseCurve as PairingEngine>::Fr>>,
}

impl<TargetCurve, BaseCurve, PG> Clone for PreparedLabeledCommitmentVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            label: self.label.clone(),
            prepared_commitment: self.prepared_commitment.clone(),
            degree_bound: self.degree_bound.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use snarkvm_algorithms::{fft::DensePolynomial, Prepare};
    use snarkvm_curves::{
        bls12_377::{Bls12_377, Fq, Fr},
        bw6_761::BW6_761,
        AffineCurve,
    };
    use snarkvm_gadgets::{
        curves::bls12_377::PairingGadget as Bls12_377PairingGadget,
        traits::{alloc::AllocGadget, eq::EqGadget},
        PrepareGadget,
    };
    use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};
    use snarkvm_utilities::rand::test_rng;

    use crate::{
        marlin_pc::{LabeledCommitmentVar, MarlinKZG10},
        LabeledPolynomial,
        PolynomialCommitment,
        ToString,
    };

    use super::*;

    type PC = MarlinKZG10<Bls12_377>;
    type PG = Bls12_377PairingGadget;
    type BaseCurve = BW6_761;

    const MAX_DEGREE: usize = 383;
    const SUPPORTED_DEGREE: usize = 300;
    const SUPPORTED_HIDING_BOUND: usize = 1;

    #[test]
    fn test_prepare() {
        let rng = &mut test_rng();

        let cs = &mut TestConstraintSystem::<Fq>::new();

        // Construct the universal params.
        let pp = PC::setup(MAX_DEGREE, rng).unwrap();

        // Construct the verifying key.
        let (committer_key, _vk) = PC::trim(&pp, SUPPORTED_DEGREE, SUPPORTED_HIDING_BOUND, None).unwrap();

        // Construct a polynomial.
        let random_polynomial = DensePolynomial::<Fr>::rand(SUPPORTED_DEGREE - 1, rng);
        let labeled_polynomial = LabeledPolynomial::new("test_polynomial".to_string(), random_polynomial, None, None);

        // Construct commitments.
        let (commitments, _randomness) = PC::commit(&committer_key, vec![&labeled_polynomial], Some(rng)).unwrap();

        for (i, commitment) in commitments.iter().enumerate() {
            let prepared_commitment = commitment.commitment().prepare();
            let commitment_gadget =
                LabeledCommitmentVar::<_, BaseCurve, PG>::alloc(cs.ns(|| format!("commitment_{}", i)), || {
                    Ok(commitment)
                })
                .unwrap();

            let prepared_commitment_gadget = commitment_gadget
                .prepare(cs.ns(|| format!("prepare_commitment_{}", i)))
                .unwrap();

            for (j, (comm_element, comm_element_gadget)) in prepared_commitment
                .prepared_comm
                .0
                .iter()
                .zip(prepared_commitment_gadget.prepared_commitment.prepared_comm)
                .enumerate()
            {
                // Check commitment.
                let expected_commitment_gadget = <PG as PairingGadget<_, _>>::G1Gadget::alloc(
                    cs.ns(|| format!("prepared_commitment_{}_{}", i, j)),
                    || Ok(comm_element.into_projective()),
                )
                .unwrap();

                comm_element_gadget
                    .enforce_equal(
                        cs.ns(|| format!("commitment_conditional_enforce_equal_{}_{}", i, j)),
                        &expected_commitment_gadget,
                    )
                    .unwrap();
            }

            // Check shifted commitment.

            assert_eq!(
                prepared_commitment.shifted_comm.is_some(),
                prepared_commitment_gadget.prepared_commitment.shifted_comm.is_some()
            );

            if let (Some(shifted_comm), Some(shifted_comm_gadget)) = (
                &prepared_commitment.shifted_comm,
                prepared_commitment_gadget.prepared_commitment.shifted_comm,
            ) {
                let expected_shifted_commitment_gadget = <PG as PairingGadget<_, _>>::G1Gadget::alloc(
                    cs.ns(|| format!("shifted_commitment_gadget_{}", i)),
                    || Ok(shifted_comm.0.into_projective()),
                )
                .unwrap();

                shifted_comm_gadget
                    .enforce_equal(
                        cs.ns(|| format!("shifted_commitment_conditional_enforce_equal_{}", i)),
                        &expected_shifted_commitment_gadget,
                    )
                    .unwrap();
            }

            assert!(cs.is_satisfied());
        }
    }
}
