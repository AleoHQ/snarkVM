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

use hashbrown::HashMap;

use snarkvm_fields::{PrimeField, ToConstraintField};
use snarkvm_gadgets::{
    nonnative::NonNativeFieldVar,
    traits::{alloc::AllocGadget, fields::ToConstraintFieldGadget},
    AllocBytesGadget,
};
use snarkvm_polycommit::PCCheckVar;
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};

use crate::{marlin::Proof, PolynomialCommitment};
use snarkvm_utilities::FromBytes;

/// The prover message gadget
#[repr(transparent)]
pub struct ProverMessageVar<TargetField: PrimeField, BaseField: PrimeField> {
    /// The field elements comprising the message in nonnative field gadgets.
    pub field_elements: Vec<NonNativeFieldVar<TargetField, BaseField>>,
}

impl<TargetField: PrimeField, BaseField: PrimeField> Clone for ProverMessageVar<TargetField, BaseField> {
    fn clone(&self) -> Self {
        ProverMessageVar {
            field_elements: self.field_elements.clone(),
        }
    }
}

/// The Marlin proof gadget
pub struct ProofVar<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> {
    /// The commitments
    pub commitments: Vec<Vec<PCG::CommitmentVar>>,
    /// The evaluations
    pub evaluations: HashMap<String, NonNativeFieldVar<TargetField, BaseField>>,
    /// The prover messages
    pub prover_messages: Vec<ProverMessageVar<TargetField, BaseField>>,
    /// The polynomial commitment batch proof
    pub pc_batch_proof: PCG::BatchLCProofVar,
}

impl<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> Clone for ProofVar<TargetField, BaseField, PC, PCG>
{
    fn clone(&self) -> Self {
        ProofVar {
            commitments: self.commitments.clone(),
            evaluations: self.evaluations.clone(),
            prover_messages: self.prover_messages.clone(),
            pc_batch_proof: self.pc_batch_proof.clone(),
        }
    }
}

impl<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> ProofVar<TargetField, BaseField, PC, PCG>
{
    /// Instantiates a new instance of `ProofGadget`.
    pub fn new(
        commitments: Vec<Vec<PCG::CommitmentVar>>,
        evaluations: HashMap<String, NonNativeFieldVar<TargetField, BaseField>>,
        prover_messages: Vec<ProverMessageVar<TargetField, BaseField>>,
        pc_batch_proof: PCG::BatchLCProofVar,
    ) -> Self {
        Self {
            commitments,
            evaluations,
            prover_messages,
            pc_batch_proof,
        }
    }
}

impl<TargetField, BaseField, PC, PCG> AllocGadget<Proof<TargetField, PC>, BaseField>
    for ProofVar<TargetField, BaseField, PC, PCG>
where
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
    PC::VerifierKey: ToConstraintField<BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
    PCG::VerifierKeyVar: ToConstraintFieldGadget<BaseField>,
    PCG::CommitmentVar: ToConstraintFieldGadget<BaseField>,
{
    #[inline]
    fn alloc_constant<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Proof<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let Proof {
            commitments,
            evaluations,
            prover_messages,
            pc_proof,
            ..
        } = tmp.borrow();

        let commitment_gadgets: Vec<Vec<PCG::CommitmentVar>> = commitments
            .iter()
            .map(|lst| {
                lst.iter()
                    .enumerate()
                    .map(|(i, comm)| {
                        PCG::CommitmentVar::alloc_constant(cs.ns(|| format!("alloc_constant_commitment_{}", i)), || {
                            Ok(comm)
                        })
                        .unwrap()
                    })
                    .collect()
            })
            .collect();

        let evaluation_gadgets_vec: Vec<NonNativeFieldVar<TargetField, BaseField>> = evaluations
            .iter()
            .enumerate()
            .map(|(i, eval)| {
                NonNativeFieldVar::alloc_constant(cs.ns(|| format!("alloc_constant_evaluations_{}", i)), || Ok(eval))
                    .unwrap()
            })
            .collect();

        let prover_message_gadgets: Vec<ProverMessageVar<TargetField, BaseField>> = prover_messages
            .iter()
            .enumerate()
            .map(|(i, msg)| {
                let field_elements: Vec<NonNativeFieldVar<TargetField, BaseField>> = msg
                    .field_elements
                    .iter()
                    .enumerate()
                    .map(|(j, elem)| {
                        NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_constant_message_{}_{}", i, j)), || Ok(elem))
                            .unwrap()
                    })
                    .collect();

                ProverMessageVar { field_elements }
            })
            .collect();

        let pc_batch_proof = PCG::BatchLCProofVar::alloc_constant(cs.ns(|| "alloc_constant_proof"), || Ok(pc_proof))?;

        let mut evaluation_gadgets = HashMap::<String, NonNativeFieldVar<TargetField, BaseField>>::new();

        const ALL_POLYNOMIALS: [&str; 10] = [
            "a_denom",
            "b_denom",
            "c_denom",
            "g_1",
            "g_2",
            "t",
            "vanishing_poly_h_alpha",
            "vanishing_poly_h_beta",
            "vanishing_poly_k_gamma",
            "z_b",
        ];

        for (s, eval) in ALL_POLYNOMIALS.iter().zip(evaluation_gadgets_vec.iter()) {
            evaluation_gadgets.insert(s.to_string(), (*eval).clone());
        }

        Ok(ProofVar {
            commitments: commitment_gadgets,
            evaluations: evaluation_gadgets,
            prover_messages: prover_message_gadgets,
            pc_batch_proof,
        })
    }

    #[inline]
    fn alloc<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Proof<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let Proof {
            commitments,
            evaluations,
            prover_messages,
            pc_proof,
            ..
        } = tmp.borrow();

        let commitment_gadgets: Vec<Vec<PCG::CommitmentVar>> = commitments
            .iter()
            .enumerate()
            .map(|(i, lst)| {
                lst.iter()
                    .enumerate()
                    .map(|(j, comm)| {
                        PCG::CommitmentVar::alloc(cs.ns(|| format!("alloc_commitment_{}_{}", i, j)), || Ok(comm))
                            .unwrap()
                    })
                    .collect()
            })
            .collect();

        let evaluation_gadgets_vec: Vec<NonNativeFieldVar<TargetField, BaseField>> = evaluations
            .iter()
            .enumerate()
            .map(|(i, eval)| {
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_evaluations_{}", i)), || Ok(eval)).unwrap()
            })
            .collect();

        let prover_message_gadgets: Vec<ProverMessageVar<TargetField, BaseField>> = prover_messages
            .iter()
            .enumerate()
            .map(|(i, msg)| {
                let field_elements: Vec<NonNativeFieldVar<TargetField, BaseField>> = msg
                    .field_elements
                    .iter()
                    .enumerate()
                    .map(|(j, elem)| {
                        NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_prover_message_{}_{}", i, j)), || Ok(elem))
                            .unwrap()
                    })
                    .collect();
                ProverMessageVar { field_elements }
            })
            .collect();

        let pc_batch_proof = PCG::BatchLCProofVar::alloc(cs.ns(|| "alloc_proof"), || Ok(pc_proof))?;

        let mut evaluation_gadgets = HashMap::<String, NonNativeFieldVar<TargetField, BaseField>>::new();

        const ALL_POLYNOMIALS: [&str; 10] = [
            "a_denom",
            "b_denom",
            "c_denom",
            "g_1",
            "g_2",
            "t",
            "vanishing_poly_h_alpha",
            "vanishing_poly_h_beta",
            "vanishing_poly_k_gamma",
            "z_b",
        ];

        for (s, eval) in ALL_POLYNOMIALS.iter().zip(evaluation_gadgets_vec.iter()) {
            evaluation_gadgets.insert(s.to_string(), (*eval).clone());
        }

        Ok(ProofVar {
            commitments: commitment_gadgets,
            evaluations: evaluation_gadgets,
            prover_messages: prover_message_gadgets,
            pc_batch_proof,
        })
    }

    #[inline]
    fn alloc_input<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Proof<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let Proof {
            commitments,
            evaluations,
            prover_messages,
            pc_proof,
            ..
        } = tmp.borrow();

        let commitment_gadgets: Vec<Vec<PCG::CommitmentVar>> = commitments
            .iter()
            .map(|lst| {
                lst.iter()
                    .enumerate()
                    .map(|(i, comm)| {
                        PCG::CommitmentVar::alloc_input(cs.ns(|| format!("alloc_input_commitment_{}", i)), || Ok(comm))
                            .unwrap()
                    })
                    .collect()
            })
            .collect();

        let evaluation_gadgets_vec: Vec<NonNativeFieldVar<TargetField, BaseField>> = evaluations
            .iter()
            .enumerate()
            .map(|(i, eval)| {
                NonNativeFieldVar::alloc_input(cs.ns(|| format!("alloc_input_evaluations_{}", i)), || Ok(eval)).unwrap()
            })
            .collect();

        let prover_message_gadgets: Vec<ProverMessageVar<TargetField, BaseField>> = prover_messages
            .iter()
            .enumerate()
            .map(|(i, msg)| {
                let field_elements: Vec<NonNativeFieldVar<TargetField, BaseField>> = msg
                    .field_elements
                    .iter()
                    .enumerate()
                    .map(|(j, elem)| {
                        NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_input_prover_message_{}_{}", i, j)), || {
                            Ok(elem)
                        })
                        .unwrap()
                    })
                    .collect();

                ProverMessageVar { field_elements }
            })
            .collect();

        let pc_batch_proof = PCG::BatchLCProofVar::alloc_input(cs.ns(|| "alloc_input_proof"), || Ok(pc_proof))?;

        let mut evaluation_gadgets = HashMap::<String, NonNativeFieldVar<TargetField, BaseField>>::new();

        const ALL_POLYNOMIALS: [&str; 10] = [
            "a_denom",
            "b_denom",
            "c_denom",
            "g_1",
            "g_2",
            "t",
            "vanishing_poly_h_alpha",
            "vanishing_poly_h_beta",
            "vanishing_poly_k_gamma",
            "z_b",
        ];

        for (s, eval) in ALL_POLYNOMIALS.iter().zip(evaluation_gadgets_vec.iter()) {
            evaluation_gadgets.insert(s.to_string(), (*eval).clone());
        }

        Ok(ProofVar {
            commitments: commitment_gadgets,
            evaluations: evaluation_gadgets,
            prover_messages: prover_message_gadgets,
            pc_batch_proof,
        })
    }
}

impl<TargetField, BaseField, PC, PCG> AllocBytesGadget<Vec<u8>, BaseField> for ProofVar<TargetField, BaseField, PC, PCG>
where
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
    PC::VerifierKey: ToConstraintField<BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
    PCG::VerifierKeyVar: ToConstraintFieldGadget<BaseField>,
    PCG::CommitmentVar: ToConstraintFieldGadget<BaseField>,
{
    #[inline]
    fn alloc_bytes<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Vec<u8>>,
    {
        value_gen().and_then(|proof_bytes| {
            let proof: Proof<TargetField, PC> = FromBytes::read_le(&proof_bytes.borrow()[..])?;

            Self::alloc(cs.ns(|| "alloc_bytes"), || Ok(proof))
        })
    }

    #[inline]
    fn alloc_input_bytes<FN, T, CS: ConstraintSystem<BaseField>>(
        mut cs: CS,
        value_gen: FN,
    ) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Vec<u8>>,
    {
        value_gen().and_then(|proof_bytes| {
            let proof: Proof<TargetField, PC> = FromBytes::read_le(&proof_bytes.borrow()[..])?;

            Self::alloc_input(cs.ns(|| "alloc_input_bytes"), || Ok(proof))
        })
    }
}
