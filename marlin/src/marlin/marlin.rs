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
    ahp::{AHPError, AHPForR1CS, EvaluationsProvider},
    fiat_shamir::traits::FiatShamirRng,
    marlin::{compute_vk_hash, CircuitProvingKey, CircuitVerifyingKey, MarlinError, MarlinMode, Proof, UniversalSRS},
};
use snarkvm_algorithms::fft::EvaluationDomain;
use snarkvm_fields::{PrimeField, ToConstraintField};
use snarkvm_gadgets::nonnative::params::OptimizationType;
use snarkvm_polycommit::{Evaluations, LabeledCommitment, LabeledPolynomial, PCUniversalParams, PolynomialCommitment};
use snarkvm_r1cs::{ConstraintSynthesizer, SynthesisError};
use snarkvm_utilities::{to_bytes_le, ToBytes};

use crate::marlin::PreparedCircuitVerifyingKey;
use core::marker::PhantomData;
use rand_core::RngCore;

/// The Marlin proof system.
pub struct MarlinSNARK<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    FS: FiatShamirRng<TargetField, BaseField>,
    MM: MarlinMode,
>(
    #[doc(hidden)] PhantomData<TargetField>,
    #[doc(hidden)] PhantomData<BaseField>,
    #[doc(hidden)] PhantomData<PC>,
    #[doc(hidden)] PhantomData<FS>,
    #[doc(hidden)] PhantomData<MM>,
);

impl<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    FS: FiatShamirRng<TargetField, BaseField>,
    MM: MarlinMode,
> MarlinSNARK<TargetField, BaseField, PC, FS, MM>
where
    PC::VerifierKey: ToConstraintField<BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
{
    /// The personalization string for this protocol.
    /// Used to personalize the Fiat-Shamir RNG.
    pub const PROTOCOL_NAME: &'static [u8] = b"MARLIN-2019";

    /// Generates the universal proving and verifying keys for the argument system.
    pub fn universal_setup<R: RngCore>(
        num_constraints: usize,
        num_variables: usize,
        num_non_zero: usize,
        rng: &mut R,
    ) -> Result<UniversalSRS<TargetField, PC>, MarlinError<PC::Error>> {
        let max_degree = AHPForR1CS::<TargetField>::max_degree(num_constraints, num_variables, num_non_zero)?;
        let setup_time = start_timer!(|| {
            format!(
                "Marlin::UniversalSetup with max_degree {}, computed for a maximum of {} constraints, {} vars, {} non_zero",
                max_degree, num_constraints, num_variables, num_non_zero,
            )
        });

        let srs = PC::setup(max_degree, rng).map_err(MarlinError::from_pc_err);
        end_timer!(setup_time);
        srs
    }

    /// Generate the index-specific (i.e., circuit-specific) prover and verifier
    /// keys. This is a trusted setup.
    #[allow(clippy::type_complexity)]
    pub fn circuit_specific_setup<C: ConstraintSynthesizer<TargetField>, R: RngCore>(
        c: &C,
        rng: &mut R,
    ) -> Result<(CircuitProvingKey<TargetField, PC>, CircuitVerifyingKey<TargetField, PC>), MarlinError<PC::Error>>
    {
        let index_time = start_timer!(|| "Marlin::CircuitSpecificSetup");

        let for_recursion = MM::RECURSION;

        // TODO: Add check that c is in the correct mode.
        let circuit = AHPForR1CS::index(c)?;
        let srs = PC::setup(circuit.max_degree(), rng).map_err(MarlinError::from_pc_err)?;

        let coeff_support = AHPForR1CS::get_degree_bounds(&circuit.index_info);

        // Marlin only needs degree 2 random polynomials
        let supported_hiding_bound = 1;
        let (committer_key, verifier_key) =
            PC::trim(&srs, circuit.max_degree(), supported_hiding_bound, Some(&coeff_support))
                .map_err(MarlinError::from_pc_err)?;

        let mut vanishing_polys = vec![];
        if for_recursion {
            let domain_h = EvaluationDomain::new(circuit.index_info.num_constraints)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            let domain_k = EvaluationDomain::new(circuit.index_info.num_non_zero)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

            vanishing_polys = vec![
                LabeledPolynomial::new(
                    "vanishing_poly_h".to_string(),
                    domain_h.vanishing_polynomial().into(),
                    None,
                    None,
                ),
                LabeledPolynomial::new(
                    "vanishing_poly_k".to_string(),
                    domain_k.vanishing_polynomial().into(),
                    None,
                    None,
                ),
            ];
        }

        let commit_time = start_timer!(|| "Commit to index polynomials");
        let (circuit_commitments, circuit_commitment_randomness): (_, _) =
            PC::commit(&committer_key, circuit.iter().chain(vanishing_polys.iter()), None)
                .map_err(MarlinError::from_pc_err)?;
        end_timer!(commit_time);

        let circuit_commitments = circuit_commitments
            .into_iter()
            .map(|c| c.commitment().clone())
            .collect();
        let index_vk = CircuitVerifyingKey {
            circuit_info: circuit.index_info,
            circuit_commitments,
            verifier_key,
        };

        let index_pk = CircuitProvingKey {
            circuit,
            circuit_commitment_randomness,
            circuit_verifying_key: index_vk.clone(),
            committer_key,
        };

        end_timer!(index_time);

        Ok((index_pk, index_vk))
    }

    /// Generates the circuit proving and verifying keys.
    /// This is a deterministic algorithm that anyone can rerun.
    #[allow(clippy::type_complexity)]
    pub fn circuit_setup<C: ConstraintSynthesizer<TargetField>>(
        universal_srs: &UniversalSRS<TargetField, PC>,
        circuit: &C,
    ) -> Result<(CircuitProvingKey<TargetField, PC>, CircuitVerifyingKey<TargetField, PC>), MarlinError<PC::Error>>
    {
        let index_time = start_timer!(|| "Marlin::CircuitSetup");

        let is_recursion = MM::RECURSION;

        // TODO: Add check that c is in the correct mode.
        let index = AHPForR1CS::index(circuit)?;
        if universal_srs.max_degree() < index.max_degree() {
            return Err(MarlinError::IndexTooLarge(
                universal_srs.max_degree(),
                index.max_degree(),
            ));
        }

        let coefficient_support = AHPForR1CS::get_degree_bounds(&index.index_info);

        // Marlin only needs degree 2 random polynomials.
        let supported_hiding_bound = 1;
        let (committer_key, verifier_key) = PC::trim(
            &universal_srs,
            index.max_degree(),
            supported_hiding_bound,
            Some(&coefficient_support),
        )
        .map_err(MarlinError::from_pc_err)?;

        let mut vanishing_polynomials = vec![];
        if is_recursion {
            let domain_h = EvaluationDomain::new(index.index_info.num_constraints)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            let domain_k =
                EvaluationDomain::new(index.index_info.num_non_zero).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

            vanishing_polynomials = vec![
                LabeledPolynomial::new(
                    "vanishing_poly_h".to_string(),
                    domain_h.vanishing_polynomial().into(),
                    None,
                    None,
                ),
                LabeledPolynomial::new(
                    "vanishing_poly_k".to_string(),
                    domain_k.vanishing_polynomial().into(),
                    None,
                    None,
                ),
            ];
        }

        let commit_time = start_timer!(|| "Commit to index polynomials");
        let (circuit_commitments, circuit_commitment_randomness): (_, _) =
            PC::commit(&committer_key, index.iter().chain(vanishing_polynomials.iter()), None)
                .map_err(MarlinError::from_pc_err)?;
        end_timer!(commit_time);

        let circuit_commitments = circuit_commitments
            .into_iter()
            .map(|c| c.commitment().clone())
            .collect();
        let circuit_verifying_key = CircuitVerifyingKey {
            circuit_info: index.index_info,
            circuit_commitments,
            verifier_key,
        };

        let circuit_proving_key = CircuitProvingKey {
            circuit: index,
            circuit_commitment_randomness,
            circuit_verifying_key: circuit_verifying_key.clone(),
            committer_key,
        };

        end_timer!(index_time);

        Ok((circuit_proving_key, circuit_verifying_key))
    }

    /// Create a zkSNARK asserting that the constraint system is satisfied.
    pub fn prove<C: ConstraintSynthesizer<TargetField>, R: RngCore>(
        circuit_proving_key: &CircuitProvingKey<TargetField, PC>,
        circuit: &C,
        zk_rng: &mut R,
    ) -> Result<Proof<TargetField, PC>, MarlinError<PC::Error>> {
        let prover_time = start_timer!(|| "Marlin::Prover");
        // TODO: Add check that c is in the correct mode.

        let is_recursion = MM::RECURSION;

        let prover_init_state = AHPForR1CS::prover_init(&circuit_proving_key.circuit, circuit)?;
        let public_input = prover_init_state.public_input();

        let mut fs_rng = FS::new();

        let hiding = true;

        if is_recursion {
            fs_rng.absorb_bytes(&to_bytes_le![&Self::PROTOCOL_NAME].unwrap());
            fs_rng.absorb_native_field_elements(&compute_vk_hash::<TargetField, BaseField, PC, FS>(
                &circuit_proving_key.circuit_verifying_key,
            )?);
            fs_rng.absorb_nonnative_field_elements(&public_input, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(
                &to_bytes_le![
                    &Self::PROTOCOL_NAME,
                    &circuit_proving_key.circuit_verifying_key,
                    &public_input
                ]
                .unwrap(),
            );
        }

        // --------------------------------------------------------------------
        // First round

        let (prover_first_message, prover_first_oracles, prover_state) =
            AHPForR1CS::prover_first_round(prover_init_state, zk_rng, hiding)?;

        let first_round_comm_time = start_timer!(|| "Committing to first round polys");
        let (first_commitments, first_commitment_randomnesses) = PC::commit(
            &circuit_proving_key.committer_key,
            prover_first_oracles.iter(),
            Some(zk_rng),
        )
        .map_err(MarlinError::from_pc_err)?;
        end_timer!(first_round_comm_time);

        if is_recursion {
            fs_rng.absorb_native_field_elements(&first_commitments);
            if !prover_first_message.field_elements.is_empty() {
                fs_rng.absorb_nonnative_field_elements(&prover_first_message.field_elements, OptimizationType::Weight);
            }
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![first_commitments, prover_first_message].unwrap());
        }

        let (verifier_first_message, verifier_state) =
            AHPForR1CS::verifier_first_round(circuit_proving_key.circuit_verifying_key.circuit_info, &mut fs_rng)?;
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Second round

        let (prover_second_message, prover_second_oracles, prover_state) =
            AHPForR1CS::prover_second_round(&verifier_first_message, prover_state, zk_rng, hiding);

        let second_round_comm_time = start_timer!(|| "Committing to second round polys");
        let (second_commitments, second_commitment_randomnesses) = PC::commit(
            &circuit_proving_key.committer_key,
            prover_second_oracles.iter(),
            Some(zk_rng),
        )
        .map_err(MarlinError::from_pc_err)?;
        end_timer!(second_round_comm_time);

        if is_recursion {
            fs_rng.absorb_native_field_elements(&second_commitments);
            if !prover_second_message.field_elements.is_empty() {
                fs_rng.absorb_nonnative_field_elements(&prover_second_message.field_elements, OptimizationType::Weight);
            }
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![second_commitments, prover_second_message].unwrap());
        }

        let (verifier_second_msg, verifier_state) = AHPForR1CS::verifier_second_round(verifier_state, &mut fs_rng)?;
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Third round
        let (prover_third_message, prover_third_oracles) =
            AHPForR1CS::prover_third_round(&verifier_second_msg, prover_state, zk_rng)?;

        let third_round_comm_time = start_timer!(|| "Committing to third round polys");
        let (third_commitments, third_commitment_randomnesses) = PC::commit(
            &circuit_proving_key.committer_key,
            prover_third_oracles.iter(),
            Some(zk_rng),
        )
        .map_err(MarlinError::from_pc_err)?;
        end_timer!(third_round_comm_time);

        if is_recursion {
            fs_rng.absorb_native_field_elements(&third_commitments);
            if !prover_third_message.field_elements.is_empty() {
                fs_rng.absorb_nonnative_field_elements(&prover_third_message.field_elements, OptimizationType::Weight);
            }
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![third_commitments, prover_third_message].unwrap());
        }

        let verifier_state = AHPForR1CS::verifier_third_round(verifier_state, &mut fs_rng)?;
        // --------------------------------------------------------------------

        let vanishing_polys = if is_recursion {
            let domain_h = EvaluationDomain::new(circuit_proving_key.circuit.index_info.num_constraints)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            let domain_k = EvaluationDomain::new(circuit_proving_key.circuit.index_info.num_non_zero)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

            vec![
                LabeledPolynomial::new(
                    "vanishing_poly_h".to_string(),
                    domain_h.vanishing_polynomial().into(),
                    None,
                    None,
                ),
                LabeledPolynomial::new(
                    "vanishing_poly_k".to_string(),
                    domain_k.vanishing_polynomial().into(),
                    None,
                    None,
                ),
            ]
        } else {
            vec![]
        };

        // Gather prover polynomials in one vector.
        let polynomials: Vec<_> = circuit_proving_key
            .circuit
            .iter() // 12 items
            .chain(vanishing_polys.iter()) // 0 or 2 items
            .chain(prover_first_oracles.iter()) // 4 items
            .chain(prover_second_oracles.iter())// 3 items
            .chain(prover_third_oracles.iter())// 2 items
            .collect();

        // Sanity check, whose length should be updated if the underlying structs are updated.
        match is_recursion {
            true => assert_eq!(23, polynomials.len()),
            false => assert_eq!(21, polynomials.len()),
        };

        // Gather commitments in one vector.
        #[rustfmt::skip]
            let commitments = vec![
            first_commitments.iter().map(|p| p.commitment()).cloned().collect(),
            second_commitments.iter().map(|p| p.commitment()).cloned().collect(),
            third_commitments.iter().map(|p| p.commitment()).cloned().collect(),
        ];

        let indexer_polynomials = if is_recursion {
            AHPForR1CS::<TargetField>::INDEXER_POLYNOMIALS_WITH_VANISHING
                .clone()
                .to_vec()
        } else {
            AHPForR1CS::<TargetField>::INDEXER_POLYNOMIALS.clone().to_vec()
        };

        let labeled_commitments: Vec<_> = circuit_proving_key
            .circuit_verifying_key
            .iter()
            .cloned()
            .zip(indexer_polynomials)
            .map(|(c, l)| LabeledCommitment::new(l.to_string(), c, None))
            .chain(first_commitments.into_iter())
            .chain(second_commitments.into_iter())
            .chain(third_commitments.into_iter())
            .collect();

        // Gather commitment randomness together.
        let commitment_randomnesses: Vec<PC::Randomness> = circuit_proving_key
            .circuit_commitment_randomness
            .clone()
            .into_iter()
            .chain(first_commitment_randomnesses)
            .chain(second_commitment_randomnesses)
            .chain(third_commitment_randomnesses)
            .collect();

        // Compute the AHP verifier's query set.
        let (query_set, verifier_state) = AHPForR1CS::verifier_query_set(verifier_state, &mut fs_rng, is_recursion);
        let lc_s =
            AHPForR1CS::construct_linear_combinations(&public_input, &polynomials, &verifier_state, is_recursion)?;

        let eval_time = start_timer!(|| "Evaluating linear combinations over query set");
        let mut evaluations_unsorted = Vec::new();
        for (label, (_point_name, point)) in &query_set {
            let lc = lc_s
                .iter()
                .find(|lc| &lc.label == label)
                .ok_or_else(|| AHPError::MissingEval(label.to_string()))?;
            let evaluation = polynomials.get_lc_eval(&lc, *point)?;
            if !AHPForR1CS::<TargetField>::LC_WITH_ZERO_EVAL.contains(&lc.label.as_ref()) {
                evaluations_unsorted.push((label.to_string(), evaluation));
            }
        }

        evaluations_unsorted.sort_by(|a, b| a.0.cmp(&b.0));
        let evaluations = evaluations_unsorted.iter().map(|x| x.1).collect::<Vec<TargetField>>();
        end_timer!(eval_time);

        if is_recursion {
            fs_rng.absorb_nonnative_field_elements(&evaluations, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&evaluations].unwrap());
        }

        let pc_proof = if is_recursion {
            let num_open_challenges: usize = 7;

            let mut opening_challenges = Vec::new();
            opening_challenges.append(&mut fs_rng.squeeze_128_bits_nonnative_field_elements(num_open_challenges)?);

            let opening_challenges_f = |i| opening_challenges[i as usize];

            PC::open_combinations_individual_opening_challenges(
                &circuit_proving_key.committer_key,
                &lc_s,
                polynomials,
                &labeled_commitments,
                &query_set,
                &opening_challenges_f,
                &commitment_randomnesses,
            )
            .map_err(MarlinError::from_pc_err)?
        } else {
            let opening_challenge: TargetField = fs_rng.squeeze_128_bits_nonnative_field_elements(1)?[0];

            PC::open_combinations(
                &circuit_proving_key.committer_key,
                &lc_s,
                polynomials,
                &labeled_commitments,
                &query_set,
                opening_challenge,
                &commitment_randomnesses,
                Some(zk_rng),
            )
            .map_err(MarlinError::from_pc_err)?
        };

        // Gather prover messages together.
        let prover_messages = vec![prover_first_message, prover_second_message, prover_third_message];

        let proof = Proof::new(commitments, evaluations, prover_messages, pc_proof);
        proof.print_size_info();
        end_timer!(prover_time);

        Ok(proof)
    }

    /// Verify that a proof for the constraint system defined by `C` asserts that
    /// all constraints are satisfied.
    pub fn verify(
        circuit_verifying_key: &CircuitVerifyingKey<TargetField, PC>,
        public_input: &[TargetField],
        proof: &Proof<TargetField, PC>,
    ) -> Result<bool, MarlinError<PC::Error>> {
        let verifier_time = start_timer!(|| "Marlin::Verify");

        let public_input = {
            let domain_x = EvaluationDomain::<TargetField>::new(public_input.len() + 1).unwrap();

            if cfg!(debug_assertions) {
                println!("Number of given public inputs: {}", public_input.len());
                println!("Size of evaluation domain x: {}", domain_x.size());
            }

            let mut new_input = public_input.to_vec();
            new_input.resize(
                core::cmp::max(public_input.len(), domain_x.size() - 1),
                TargetField::zero(),
            );
            new_input
        };

        if cfg!(debug_assertions) {
            println!("Number of padded public variables: {}", public_input.len());
        }

        let is_recursion = MM::RECURSION;

        let mut fs_rng = FS::new();

        if is_recursion {
            fs_rng.absorb_bytes(&to_bytes_le![&Self::PROTOCOL_NAME].unwrap());
            fs_rng.absorb_native_field_elements(&compute_vk_hash::<TargetField, BaseField, PC, FS>(
                circuit_verifying_key,
            )?);
            fs_rng.absorb_nonnative_field_elements(&public_input, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&Self::PROTOCOL_NAME, &circuit_verifying_key, &public_input].unwrap());
        }

        // --------------------------------------------------------------------
        // First round

        let first_commitments = &proof.commitments[0];

        if is_recursion {
            fs_rng.absorb_native_field_elements(&first_commitments);
            if !proof.prover_messages[0].field_elements.is_empty() {
                fs_rng.absorb_nonnative_field_elements(
                    &proof.prover_messages[0].field_elements,
                    OptimizationType::Weight,
                );
            };
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![first_commitments, proof.prover_messages[0]].unwrap());
        }

        let (_, verifier_state) = AHPForR1CS::verifier_first_round(circuit_verifying_key.circuit_info, &mut fs_rng)?;
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Second round
        let second_commitments = &proof.commitments[1];

        if is_recursion {
            fs_rng.absorb_native_field_elements(&second_commitments);
            if !proof.prover_messages[1].field_elements.is_empty() {
                fs_rng.absorb_nonnative_field_elements(
                    &proof.prover_messages[1].field_elements,
                    OptimizationType::Weight,
                );
            };
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![second_commitments, proof.prover_messages[1]].unwrap());
        }

        let (_, verifier_state) = AHPForR1CS::verifier_second_round(verifier_state, &mut fs_rng)?;
        // --------------------------------------------------------------------

        // --------------------------------------------------------------------
        // Third round
        let third_commitments = &proof.commitments[2];

        if is_recursion {
            fs_rng.absorb_native_field_elements(&third_commitments);
            if !proof.prover_messages[2].field_elements.is_empty() {
                fs_rng.absorb_nonnative_field_elements(
                    &proof.prover_messages[2].field_elements,
                    OptimizationType::Weight,
                );
            };
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![third_commitments, proof.prover_messages[2]].unwrap());
        }

        let verifier_state = AHPForR1CS::verifier_third_round(verifier_state, &mut fs_rng)?;
        // --------------------------------------------------------------------

        // Collect degree bounds for commitments. Indexed polynomials have *no*
        // degree bounds because we know the committed index polynomial has the
        // correct degree.
        let index_info = circuit_verifying_key.circuit_info;
        let degree_bounds = vec![None; circuit_verifying_key.circuit_commitments.len()]
            .into_iter()
            .chain(AHPForR1CS::prover_first_round_degree_bounds(&index_info))
            .chain(AHPForR1CS::prover_second_round_degree_bounds(&index_info))
            .chain(AHPForR1CS::prover_third_round_degree_bounds(&index_info));

        let polynomial_labels: Vec<String> = if is_recursion {
            AHPForR1CS::<TargetField>::polynomial_labels_with_vanishing().collect()
        } else {
            AHPForR1CS::<TargetField>::polynomial_labels().collect()
        };

        // Gather commitments in one vector.
        let commitments: Vec<_> = circuit_verifying_key
            .iter()
            .chain(first_commitments)
            .chain(second_commitments)
            .chain(third_commitments)
            .cloned()
            .zip(polynomial_labels)
            .zip(degree_bounds)
            .map(|((c, l), d)| LabeledCommitment::new(l, c, d))
            .collect();

        let (query_set, verifier_state) = AHPForR1CS::verifier_query_set(verifier_state, &mut fs_rng, is_recursion);

        if is_recursion {
            fs_rng.absorb_nonnative_field_elements(&proof.evaluations, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&proof.evaluations].unwrap());
        }

        let mut evaluations = Evaluations::new();

        let mut evaluation_labels = Vec::<(String, TargetField)>::new();

        for (label, (_point_name, q)) in query_set.iter().cloned() {
            if AHPForR1CS::<TargetField>::LC_WITH_ZERO_EVAL.contains(&label.as_ref()) {
                evaluations.insert((label, q), TargetField::zero());
            } else {
                evaluation_labels.push((label, q));
            }
        }
        evaluation_labels.sort_by(|a, b| a.0.cmp(&b.0));
        for (q, eval) in evaluation_labels.into_iter().zip(&proof.evaluations) {
            evaluations.insert(q, *eval);
        }

        let lc_s =
            AHPForR1CS::construct_linear_combinations(&public_input, &evaluations, &verifier_state, is_recursion)?;

        let evaluations_are_correct = if is_recursion {
            let num_open_challenges: usize = 7;

            let mut opening_challenges = Vec::new();
            opening_challenges.append(&mut fs_rng.squeeze_128_bits_nonnative_field_elements(num_open_challenges)?);

            let opening_challenges_f = |i| opening_challenges[i as usize];

            PC::check_combinations_individual_opening_challenges(
                &circuit_verifying_key.verifier_key,
                &lc_s,
                &commitments,
                &query_set,
                &evaluations,
                &proof.pc_proof,
                &opening_challenges_f,
                &mut fs_rng,
            )
            .map_err(MarlinError::from_pc_err)?
        } else {
            let opening_challenge: TargetField = fs_rng.squeeze_128_bits_nonnative_field_elements(1)?[0];

            PC::check_combinations(
                &circuit_verifying_key.verifier_key,
                &lc_s,
                &commitments,
                &query_set,
                &evaluations,
                &proof.pc_proof,
                opening_challenge,
                &mut fs_rng,
            )
            .map_err(MarlinError::from_pc_err)?
        };

        if !evaluations_are_correct {
            eprintln!("PC::Check failed");
        }
        end_timer!(verifier_time, || format!(
            " PC::Check for AHP Verifier linear equations: {}",
            evaluations_are_correct
        ));
        Ok(evaluations_are_correct)
    }

    /// Verify that a proof for the constraint system defined by `C` asserts that
    /// all constraints are satisfied using the prepared verifying key.
    pub fn prepared_verify(
        prepared_vk: &PreparedCircuitVerifyingKey<TargetField, PC>,
        public_input: &[TargetField],
        proof: &Proof<TargetField, PC>,
    ) -> Result<bool, MarlinError<PC::Error>> {
        Self::verify(&prepared_vk.orig_vk, public_input, proof)
    }
}
