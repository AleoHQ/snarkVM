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

use core::borrow::Borrow;

use snarkvm_curves::PairingEngine;
use snarkvm_gadgets::{
    fields::FpGadget,
    traits::{alloc::AllocGadget, curves::PairingGadget},
    PrepareGadget,
};
use snarkvm_r1cs::{ConstraintSystem, SynthesisError, ToConstraintField};

use crate::{
    marlin_pc::{Commitment, CommitmentVar, PreparedLabeledCommitmentVar},
    LabeledCommitment,
    String,
    ToString,
};

/// Gadget for a Marlin-KZG10 commitment, with a string label and degree bound.
pub struct LabeledCommitmentVar<
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
    pub commitment: CommitmentVar<TargetCurve, BaseCurve, PG>,
    /// Optionally, a bound on the polynomial degree.
    pub degree_bound: Option<FpGadget<<BaseCurve as PairingEngine>::Fr>>,
}

impl<TargetCurve, BaseCurve, PG> Clone for LabeledCommitmentVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    fn clone(&self) -> Self {
        LabeledCommitmentVar {
            label: self.label.clone(),
            commitment: self.commitment.clone(),
            degree_bound: self.degree_bound.clone(),
        }
    }
}

impl<TargetCurve, BaseCurve, PG>
    AllocGadget<LabeledCommitment<Commitment<TargetCurve>>, <BaseCurve as PairingEngine>::Fr>
    for LabeledCommitmentVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    fn alloc_constant<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<LabeledCommitment<Commitment<TargetCurve>>>,
        CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        value_gen().and_then(|labeled_commitment| {
            let labeled_commitment = labeled_commitment.borrow().clone();
            let label = labeled_commitment.label().to_string();
            let commitment = labeled_commitment.commitment();
            let degree_bound = labeled_commitment.degree_bound();

            let commitment = CommitmentVar::alloc_constant(cs.ns(|| "commitment"), || Ok(commitment))?;

            let degree_bound = if let Some(degree_bound) = degree_bound {
                FpGadget::<<BaseCurve as PairingEngine>::Fr>::alloc_constant(cs.ns(|| "degree_bound"), || {
                    Ok(<<BaseCurve as PairingEngine>::Fr as From<u128>>::from(
                        degree_bound as u128,
                    ))
                })
                .ok()
            } else {
                None
            };

            Ok(Self {
                label,
                commitment,
                degree_bound,
            })
        })
    }

    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<LabeledCommitment<Commitment<TargetCurve>>>,
        CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        value_gen().and_then(|labeled_commitment| {
            let labeled_commitment = labeled_commitment.borrow().clone();
            let label = labeled_commitment.label().to_string();
            let commitment = labeled_commitment.commitment();
            let degree_bound = labeled_commitment.degree_bound();

            let commitment = CommitmentVar::alloc(cs.ns(|| "commitment"), || Ok(commitment))?;

            let degree_bound = if let Some(degree_bound) = degree_bound {
                FpGadget::<<BaseCurve as PairingEngine>::Fr>::alloc(cs.ns(|| "degree_bound"), || {
                    Ok(<<BaseCurve as PairingEngine>::Fr as From<u128>>::from(
                        degree_bound as u128,
                    ))
                })
                .ok()
            } else {
                None
            };

            Ok(Self {
                label,
                commitment,
                degree_bound,
            })
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<LabeledCommitment<Commitment<TargetCurve>>>,
        CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        value_gen().and_then(|labeled_commitment| {
            let labeled_commitment = labeled_commitment.borrow().clone();
            let label = labeled_commitment.label().to_string();
            let commitment = labeled_commitment.commitment();
            let degree_bound = labeled_commitment.degree_bound();

            let commitment = CommitmentVar::alloc_input(cs.ns(|| "commitment"), || Ok(commitment))?;

            let degree_bound = if let Some(degree_bound) = degree_bound {
                FpGadget::<<BaseCurve as PairingEngine>::Fr>::alloc_input(cs.ns(|| "degree_bound"), || {
                    Ok(<<BaseCurve as PairingEngine>::Fr as From<u128>>::from(
                        degree_bound as u128,
                    ))
                })
                .ok()
            } else {
                None
            };

            Ok(Self {
                label,
                commitment,
                degree_bound,
            })
        })
    }
}

impl<TargetCurve, BaseCurve, PG>
    PrepareGadget<PreparedLabeledCommitmentVar<TargetCurve, BaseCurve, PG>, <BaseCurve as PairingEngine>::Fr>
    for LabeledCommitmentVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    fn prepare<CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>>(
        &self,
        cs: CS,
    ) -> Result<PreparedLabeledCommitmentVar<TargetCurve, BaseCurve, PG>, SynthesisError> {
        Ok(PreparedLabeledCommitmentVar::<TargetCurve, BaseCurve, PG> {
            label: self.label.clone(),
            prepared_commitment: self.commitment.prepare(cs)?,
            degree_bound: self.degree_bound.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use snarkvm_algorithms::fft::DensePolynomial;
    use snarkvm_curves::{
        bls12_377::{Bls12_377, Fq, Fr},
        bw6_761::BW6_761,
        AffineCurve,
    };
    use snarkvm_gadgets::{
        bits::ToBytesGadget,
        curves::bls12_377::PairingGadget as Bls12_377PairingGadget,
        traits::eq::EqGadget,
    };
    use snarkvm_r1cs::TestConstraintSystem;
    use snarkvm_utilities::rand::test_rng;

    use crate::{marlin_pc::MarlinKZG10, LabeledPolynomial, PolynomialCommitment};

    use super::*;

    type PC = MarlinKZG10<Bls12_377>;
    type PG = Bls12_377PairingGadget;
    type BaseCurve = BW6_761;

    const MAX_DEGREE: usize = 383;
    const SUPPORTED_DEGREE: usize = 300;
    const SUPPORTED_HIDING_BOUND: usize = 1;

    #[test]
    fn test_alloc() {
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
            let commitment_gadget =
                LabeledCommitmentVar::<_, BaseCurve, PG>::alloc(cs.ns(|| format!("commitment_{}", i)), || {
                    Ok(commitment)
                })
                .unwrap();

            // Check that the attributes are equivalent.

            assert_eq!(commitment.label(), &commitment_gadget.label);

            // Check degree bound.

            assert_eq!(
                commitment.degree_bound().is_some(),
                commitment_gadget.degree_bound.is_some()
            );

            if let (Some(degree_bound), Some(degree_bound_gadget)) =
                (commitment.degree_bound(), commitment_gadget.degree_bound)
            {
                let expected_degree_bound = FpGadget::alloc(cs.ns(|| format!("degree_bound_{}", i)), || {
                    Ok(Fq::from(degree_bound as u32))
                })
                .unwrap();

                expected_degree_bound
                    .enforce_equal(
                        cs.ns(|| format!("degree_bound_enforce_equal_{}", i)),
                        &degree_bound_gadget,
                    )
                    .unwrap();
            }

            // Check commitment.
            let expected_commitment_gadget =
                <PG as PairingGadget<_, _>>::G1Gadget::alloc(cs.ns(|| format!("commitment_gadget_{}", i)), || {
                    Ok(commitment.commitment().comm.0.into_projective())
                })
                .unwrap();

            commitment_gadget
                .commitment
                .comm
                .enforce_equal(
                    cs.ns(|| format!("commitment_conditional_enforce_equal_{}", i)),
                    &expected_commitment_gadget,
                )
                .unwrap();

            // Check shifted commitment.

            assert_eq!(
                commitment.commitment().shifted_comm.is_some(),
                commitment_gadget.commitment.shifted_comm.is_some()
            );

            if let (Some(shifted_comm), Some(shifted_comm_gadget)) = (
                &commitment.commitment().shifted_comm,
                commitment_gadget.commitment.shifted_comm,
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
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_to_bytes() {
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
            let commitment_gadget =
                LabeledCommitmentVar::<_, BaseCurve, PG>::alloc(cs.ns(|| format!("commitment_{}", i)), || {
                    Ok(commitment)
                })
                .unwrap();

            // Convert the gadget commitments to bytes
            let _commitment_gadget_bytes = commitment_gadget
                .commitment
                .to_bytes(cs.ns(|| format!("commitment_to_bytes_{}", i)))
                .unwrap();
        }
    }
}
