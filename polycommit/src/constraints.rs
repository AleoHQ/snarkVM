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

use hashbrown::{HashMap, HashSet};

use snarkvm_fields::PrimeField;
use snarkvm_gadgets::{
    bits::Boolean,
    fields::FpGadget,
    nonnative::NonNativeFieldVar,
    traits::alloc::AllocGadget,
    PrepareGadget,
    ToBytesGadget,
    ToConstraintFieldGadget,
};
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};

use crate::{BatchLCProof, LCTerm, LabeledCommitment, LinearCombination, PolynomialCommitment, String, Vec};

/// A coefficient of `LinearCombination`.
#[derive(Clone, Debug)]
pub enum LinearCombinationCoeffVar<TargetField: PrimeField, BaseField: PrimeField> {
    /// Coefficient 1.
    One,
    /// Coefficient -1.
    MinusOne,
    /// Other coefficient, represented as a nonnative field element.
    Var(NonNativeFieldVar<TargetField, BaseField>),
}

/// An allocated version of `LinearCombination`.
#[derive(Clone)]
pub struct LinearCombinationVar<TargetField: PrimeField, BaseField: PrimeField> {
    /// The label.
    pub label: String,
    /// The linear combination of `(coeff, poly_label)` pairs.
    pub terms: Vec<(LinearCombinationCoeffVar<TargetField, BaseField>, LCTerm)>,
}

impl<TargetField: PrimeField, BaseField: PrimeField> AllocGadget<LinearCombination<TargetField>, BaseField>
    for LinearCombinationVar<TargetField, BaseField>
{
    #[inline]
    fn alloc_constant<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<LinearCombination<TargetField>>,
    {
        let LinearCombination { label, terms } = value_gen()?.borrow().clone();

        let new_terms: Vec<(LinearCombinationCoeffVar<TargetField, BaseField>, LCTerm)> = terms
            .iter()
            .enumerate()
            .map(|(i, term)| {
                let (coefficient, lc_term) = term;

                let fg =
                    NonNativeFieldVar::alloc_constant(cs.ns(|| format!("term_{}", i)), || Ok(coefficient)).unwrap();

                (LinearCombinationCoeffVar::Var(fg), lc_term.clone())
            })
            .collect();

        Ok(Self {
            label,
            terms: new_terms,
        })
    }

    #[inline]
    fn alloc<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<LinearCombination<TargetField>>,
    {
        let LinearCombination { label, terms } = value_gen()?.borrow().clone();

        let new_terms: Vec<(LinearCombinationCoeffVar<TargetField, BaseField>, LCTerm)> = terms
            .iter()
            .enumerate()
            .map(|(i, term)| {
                let (coefficient, lc_term) = term;

                let fg = NonNativeFieldVar::alloc(cs.ns(|| format!("term_{}", i)), || Ok(coefficient)).unwrap();

                (LinearCombinationCoeffVar::Var(fg), lc_term.clone())
            })
            .collect();

        Ok(Self {
            label,
            terms: new_terms,
        })
    }

    #[inline]
    fn alloc_input<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<LinearCombination<TargetField>>,
    {
        let LinearCombination { label, terms } = value_gen()?.borrow().clone();

        let new_terms: Vec<(LinearCombinationCoeffVar<TargetField, BaseField>, LCTerm)> = terms
            .iter()
            .enumerate()
            .map(|(i, term)| {
                let (coefficient, lc_term) = term;

                let fg = NonNativeFieldVar::alloc_input(cs.ns(|| format!("term_{}", i)), || Ok(coefficient)).unwrap();

                (LinearCombinationCoeffVar::Var(fg), lc_term.clone())
            })
            .collect();

        Ok(Self {
            label,
            terms: new_terms,
        })
    }
}

/// A collection of random data used in the polynomial commitment checking.
#[derive(Clone, Debug)]
pub struct PCCheckRandomDataVar<TargetField: PrimeField, BaseField: PrimeField> {
    /// Opening challenges.
    /// The prover and the verifier MUST use the same opening challenges.
    pub opening_challenges: Vec<NonNativeFieldVar<TargetField, BaseField>>,
    /// Bit representations of the opening challenges.
    pub opening_challenges_bits: Vec<Vec<Boolean>>,
    /// Batching random numbers.
    /// The verifier can choose these numbers freely, as long as they are random.
    pub batching_rands: Vec<NonNativeFieldVar<TargetField, BaseField>>,
    /// Bit representations of the batching random numbers.
    pub batching_rands_bits: Vec<Vec<Boolean>>,
}

/// Describes the interface for a gadget for a `PolynomialCommitment`
/// verifier.
pub trait PCCheckVar<PCF: PrimeField, PC: PolynomialCommitment<PCF>, ConstraintF: PrimeField>: Clone {
    /// An allocated version of `PC::VerifierKey`.
    type VerifierKeyVar: AllocGadget<PC::VerifierKey, ConstraintF>
        + Clone
        + ToBytesGadget<ConstraintF>
        + ToConstraintFieldGadget<ConstraintF>
        + PrepareGadget<Self::PreparedVerifierKeyVar, ConstraintF>;
    /// An allocated version of `PC::PreparedVerifierKey`.
    type PreparedVerifierKeyVar: AllocGadget<PC::PreparedVerifierKey, ConstraintF> + Clone + Into<Self::VerifierKeyVar>;
    /// An allocated version of `PC::Commitment`.
    type CommitmentVar: AllocGadget<PC::Commitment, ConstraintF>
        + Clone
        + ToBytesGadget<ConstraintF>
        + ToConstraintFieldGadget<ConstraintF>
        + PrepareGadget<Self::PreparedCommitmentVar, ConstraintF>;
    /// An allocated version of `PC::PreparedCommitment`.
    type PreparedCommitmentVar: AllocGadget<PC::PreparedCommitment, ConstraintF> + Clone;
    /// An allocated version of `LabeledCommitment<PC::Commitment>`.
    type LabeledCommitmentVar: AllocGadget<LabeledCommitment<PC::Commitment>, ConstraintF> + Clone;
    /// A prepared, allocated version of `LabeledCommitment<PC::Commitment>`.
    type PreparedLabeledCommitmentVar: Clone;
    /// An allocated version of `PC::Proof`.
    type ProofVar: AllocGadget<PC::Proof, ConstraintF> + Clone;

    /// An allocated version of `PC::BatchLCProof`.
    type BatchLCProofVar: AllocGadget<BatchLCProof<PCF, PC>, ConstraintF> + Clone;

    /// Add to `ConstraintSystem<ConstraintF>` new constraints that check that `proof_i` is a valid evaluation
    /// proof at `point_i` for the polynomial in `commitment_i`.
    fn batch_check_evaluations<CS: ConstraintSystem<ConstraintF>>(
        cs: CS,
        verification_key: &Self::VerifierKeyVar,
        commitments: &[Self::LabeledCommitmentVar],
        query_set: &QuerySetVar<PCF, ConstraintF>,
        evaluations: &EvaluationsVar<PCF, ConstraintF>,
        proofs: &[Self::ProofVar],
        rand_data: &PCCheckRandomDataVar<PCF, ConstraintF>,
    ) -> Result<Boolean, SynthesisError>;

    /// Add to `ConstraintSystem<ConstraintF>` new constraints that conditionally check that `proof` is a valid evaluation
    /// proof at the points in `query_set` for the combinations `linear_combinations`.
    fn prepared_check_combinations<CS: ConstraintSystem<ConstraintF>>(
        cs: CS,
        prepared_verification_key: &Self::PreparedVerifierKeyVar,
        linear_combinations: &[LinearCombinationVar<PCF, ConstraintF>],
        prepared_commitments: &[Self::PreparedLabeledCommitmentVar],
        query_set: &QuerySetVar<PCF, ConstraintF>,
        evaluations: &EvaluationsVar<PCF, ConstraintF>,
        proof: &Self::BatchLCProofVar,
        rand_data: &PCCheckRandomDataVar<PCF, ConstraintF>,
    ) -> Result<Boolean, SynthesisError>;

    /// Create the labeled commitment gadget from the commitment gadget
    fn create_labeled_commitment(
        label: String,
        commitment: Self::CommitmentVar,
        degree_bound: Option<FpGadget<ConstraintF>>,
    ) -> Self::LabeledCommitmentVar;

    /// Create the prepared labeled commitment gadget from the commitment gadget
    fn create_prepared_labeled_commitment(
        label: String,
        commitment: Self::PreparedCommitmentVar,
        degree_bound: Option<FpGadget<ConstraintF>>,
    ) -> Self::PreparedLabeledCommitmentVar;
}

#[derive(Clone, Hash, PartialEq, Eq)]
/// A labeled point variable, for queries to a polynomial commitment.
pub struct LabeledPointVar<TargetField: PrimeField, BaseField: PrimeField> {
    /// The label of the point.
    /// MUST be a unique identifier in a query set.
    pub name: String,
    /// The point value.
    pub value: NonNativeFieldVar<TargetField, BaseField>,
}

/// An allocated version of `QuerySet`.
#[derive(Clone)]
pub struct QuerySetVar<TargetField: PrimeField, BaseField: PrimeField>(
    pub HashSet<(String, LabeledPointVar<TargetField, BaseField>)>,
);

/// An allocated version of `Evaluations`.
#[derive(Clone)]
pub struct EvaluationsVar<TargetField: PrimeField, BaseField: PrimeField>(
    pub HashMap<LabeledPointVar<TargetField, BaseField>, NonNativeFieldVar<TargetField, BaseField>>,
);

impl<TargetField: PrimeField, BaseField: PrimeField> EvaluationsVar<TargetField, BaseField> {
    /// find the evaluation result
    pub fn get_lc_eval(
        &self,
        lc_string: &str,
        point: &NonNativeFieldVar<TargetField, BaseField>,
    ) -> Result<NonNativeFieldVar<TargetField, BaseField>, SynthesisError> {
        let key = LabeledPointVar::<TargetField, BaseField> {
            name: String::from(lc_string),
            value: point.clone(),
        };
        Ok(self.0.get(&key).map(|v| (*v).clone()).unwrap())
    }
}
