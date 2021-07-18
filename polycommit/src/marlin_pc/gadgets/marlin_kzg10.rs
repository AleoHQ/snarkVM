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

use core::{convert::TryInto, marker::PhantomData};

use snarkvm_curves::PairingEngine;
use snarkvm_gadgets::{
    bits::{Boolean, ToBitsLEGadget},
    fields::FpGadget,
    nonnative::{NonNativeFieldMulResultVar, NonNativeFieldVar},
    traits::{
        curves::{GroupGadget, PairingGadget},
        eq::EqGadget,
        fields::FieldGadget,
        select::CondSelectGadget,
    },
};
use snarkvm_r1cs::{ConstraintSystem, SynthesisError, ToConstraintField};

use crate::{
    marlin_pc::{
        prepared_labeled_commitment::PreparedLabeledCommitmentVar,
        proof::{batch_lc_proof::BatchLCProofVar, ProofVar},
        verifier_key::{prepared_verifier_key::PreparedVerifierKeyVar, VerifierKeyVar},
        CommitmentVar,
        LabeledCommitmentVar,
        MarlinKZG10,
        PreparedCommitmentVar,
    },
    BTreeMap,
    BTreeSet,
    EvaluationsVar,
    LabeledPointVar,
    LinearCombinationCoeffVar,
    LinearCombinationVar,
    PCCheckRandomDataVar,
    PCCheckVar,
    QuerySetVar,
    String,
    Vec,
};

/// Gadget for the Marlin-KZG10 polynomial commitment verifier.
pub struct MarlinKZG10Gadget<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    _target_curve: PhantomData<TargetCurve>,
    _base_curve: PhantomData<BaseCurve>,
    _pairing_gadget: PhantomData<PG>,
}

impl<TargetCurve, BaseCurve, PG> Clone for MarlinKZG10Gadget<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            _target_curve: PhantomData,
            _base_curve: PhantomData,
            _pairing_gadget: PhantomData,
        }
    }
}

impl<TargetCurve, BaseCurve, PG> MarlinKZG10Gadget<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    #[allow(clippy::type_complexity, clippy::too_many_arguments)]
    fn prepared_batch_check_evaluations<CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>>(
        mut cs: CS,
        prepared_verification_key: &<Self as PCCheckVar<
            <TargetCurve as PairingEngine>::Fr,
            MarlinKZG10<TargetCurve>,
            <BaseCurve as PairingEngine>::Fr,
        >>::PreparedVerifierKeyVar,
        lc_info: &[(
            String,
            Vec<(
                Option<NonNativeFieldVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>>,
                Option<FpGadget<<BaseCurve as PairingEngine>::Fr>>,
                PreparedCommitmentVar<TargetCurve, BaseCurve, PG>,
                bool,
            )>,
        )],
        query_set: &QuerySetVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
        evaluations: &EvaluationsVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
        proofs: &[<Self as PCCheckVar<
            <TargetCurve as PairingEngine>::Fr,
            MarlinKZG10<TargetCurve>,
            <BaseCurve as PairingEngine>::Fr,
        >>::ProofVar],
        opening_challenges: &[NonNativeFieldVar<
            <TargetCurve as PairingEngine>::Fr,
            <BaseCurve as PairingEngine>::Fr,
        >],
        opening_challenges_bits: &[Vec<Boolean>],
        batching_rands: &[NonNativeFieldVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>],
        batching_rands_bits: &[Vec<Boolean>],
    ) -> Result<Boolean, SynthesisError> {
        let mut batching_rands = batching_rands.to_vec();
        let mut batching_rands_bits = batching_rands_bits.to_vec();

        let commitment_lcs: BTreeMap<
            String,
            (
                String,
                Vec<(
                    Option<NonNativeFieldVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>>,
                    Option<FpGadget<<BaseCurve as PairingEngine>::Fr>>,
                    PreparedCommitmentVar<TargetCurve, BaseCurve, PG>,
                    bool,
                )>,
            ),
        > = lc_info.iter().map(|c| (c.0.clone(), c.clone())).collect();

        let mut query_to_labels_map: BTreeMap<
            String,
            (
                NonNativeFieldVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
                BTreeSet<&String>,
            ),
        > = BTreeMap::new();

        // Sort the query set to match the native impl.
        let mut sorted_query_set_gadgets: Vec<_> = query_set.0.iter().collect();
        sorted_query_set_gadgets.sort_by(|a, b| a.0.cmp(&b.0));

        for (label, point) in sorted_query_set_gadgets.iter() {
            let labels = query_to_labels_map
                .entry(point.name.clone())
                .or_insert((point.value.clone(), BTreeSet::new()));
            labels.1.insert(label);
        }

        eprintln!("before PC combining commitments: constraints: {}", cs.num_constraints());

        let zero = PG::G1Gadget::zero(cs.ns(|| format!("g1_zero")))?;

        // Accumulate commitments and evaluations for each query.
        let mut combined_queries = Vec::new();
        let mut combined_comms = Vec::new();
        let mut combined_evals = Vec::new();
        for (i, (_, (point, labels))) in query_to_labels_map.into_iter().enumerate() {
            let mut comms_to_combine = Vec::<
                Vec<(
                    Option<NonNativeFieldVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>>,
                    Option<FpGadget<<BaseCurve as PairingEngine>::Fr>>,
                    PreparedCommitmentVar<TargetCurve, BaseCurve, PG>,
                    bool,
                )>,
            >::new();
            let mut values_to_combine = Vec::new();
            for label in labels.into_iter() {
                let commitment_lc = commitment_lcs.get(label).unwrap().clone();

                let v_i = evaluations
                    .0
                    .get(&LabeledPointVar {
                        name: label.clone(),
                        value: point.clone(),
                    })
                    .unwrap();

                comms_to_combine.push(commitment_lc.1.clone());
                values_to_combine.push(v_i.clone());
            }

            // Accumulate the commitments and evaluations corresponding to `query`.
            let mut combined_comm = PG::G1Gadget::zero(cs.ns(|| format!("comm_zero_{}", i)))?;
            let mut combined_eval = NonNativeFieldMulResultVar::<
                <TargetCurve as PairingEngine>::Fr,
                <BaseCurve as PairingEngine>::Fr,
            >::zero();

            let mut opening_challenges_counter = 0;

            for (j, (commitment_lcs, value)) in comms_to_combine.into_iter().zip(values_to_combine).enumerate() {
                let challenge = opening_challenges[opening_challenges_counter].clone();

                let challenge_bits = opening_challenges_bits[opening_challenges_counter].clone();
                opening_challenges_counter += 1;

                for (k, (coeff, degree_bound, comm, negate)) in commitment_lcs.iter().enumerate() {
                    let PreparedCommitmentVar { shifted_comm, .. } = comm;

                    if coeff.is_none() {
                        // To combine the commitments, we multiply each by one of the random challenges, and sum.
                        let mut comm_times_challenge = PG::G1Gadget::zero(cs.ns(|| format!("zero_{}_{}_{}", i, j, k)))?;
                        {
                            for (l, (bit, base_power)) in
                                challenge_bits.iter().zip(comm.prepared_comm.iter()).enumerate()
                            {
                                let mut new_encoded = base_power.clone();
                                new_encoded = new_encoded.add(
                                    cs.ns(|| format!("new_encoded_plus_comm_times_challenge_{}_{}_{}_{}", i, j, k, l)),
                                    &comm_times_challenge,
                                )?;
                                comm_times_challenge = PG::G1Gadget::conditionally_select(
                                    cs.ns(|| format!("comm_times_challenge_cond_select_{}_{}_{}_{}", i, j, k, l)),
                                    bit,
                                    &new_encoded,
                                    &comm_times_challenge,
                                )?;
                            }
                        }

                        if negate.eq(&true) {
                            comm_times_challenge = comm_times_challenge
                                .negate(cs.ns(|| format!("negate_comm_times_challenge_{}_{}_{}", i, j, k)))?;
                        }

                        combined_comm = combined_comm.add(
                            cs.ns(|| format!("combined_comm_plus_comm_times_challenge_{}_{}_{}", i, j, k)),
                            &comm_times_challenge,
                        )?;

                        // If the degree bound is specified, we include the adjusted degree-shifted commitment
                        // (that is, c_i' - v_i beta^{D - d_i} G), where d_i is the specific degree bound and
                        // v_i is the evaluation, in the combined commitment,
                        if let Some(degree_bound) = degree_bound {
                            let challenge_shifted_bits = opening_challenges_bits[opening_challenges_counter].clone();
                            opening_challenges_counter += 1;

                            let mut shifted_comm = shifted_comm.clone().unwrap();

                            if negate.eq(&true) {
                                shifted_comm =
                                    shifted_comm.negate(cs.ns(|| format!("shifted_comm_negate_{}_{}_{}", i, j, k)))?;
                            }

                            let value_bits =
                                value.to_bits_le(cs.ns(|| format!("value_to_bits_le_{}_{}_{}", i, j, k)))?;
                            let shift_power = prepared_verification_key
                                .get_shift_power(
                                    cs.ns(|| format!("prepared_vk_get_shift_power_{}_{}_{}", i, j, k)),
                                    degree_bound,
                                )
                                .unwrap();

                            let mut shift_power_times_value =
                                PG::G1Gadget::zero(cs.ns(|| format!("shift_power_times_value_zero{}_{}_{}", i, j, k)))?;
                            {
                                for (l, (bit, base_power)) in value_bits.iter().zip(&shift_power).enumerate() {
                                    let mut new_encoded = base_power.clone();
                                    new_encoded = new_encoded.add(
                                        cs.ns(|| {
                                            format!("new_encoded_add_shift_power_times_value_{}_{}_{}_{}", i, j, k, l)
                                        }),
                                        &shift_power_times_value,
                                    )?;

                                    shift_power_times_value = PG::G1Gadget::conditionally_select(
                                        cs.ns(|| format!("shift_power_times_value_cond_select{}_{}_{}_{}", i, j, k, l)),
                                        bit,
                                        &new_encoded,
                                        &shift_power_times_value,
                                    )?;
                                }
                            }
                            let mut adjusted_comm = shifted_comm;
                            adjusted_comm = adjusted_comm.sub(
                                cs.ns(|| format!("adjusted_comm_minus_shift_power_times_value_{}_{}_{}", i, j, k)),
                                &shift_power_times_value,
                            )?;

                            let adjusted_comm_times_challenge = adjusted_comm.mul_bits(
                                cs.ns(|| format!("adjusted_comm_times_challenge_{}_{}_{}", i, j, k)),
                                &zero,
                                challenge_shifted_bits.into_iter(),
                            )?;

                            combined_comm = combined_comm.add(
                                cs.ns(|| format!("combined_comm_add_adjusted_comm_times_challenge_{}_{}_{}", i, j, k)),
                                &adjusted_comm_times_challenge,
                            )?;
                        }
                    } else {
                        assert!(degree_bound.is_none());

                        let mut comm_times_challenge = PG::G1Gadget::zero(cs.ns(|| format!("zero_{}_{}_{}", i, j, k)))?;
                        let coeff = coeff.clone().unwrap();

                        let challenge_times_coeff = challenge.mul(
                            &mut cs.ns(|| format!("challenge_times_coeff_{}_{}_{}", i, j, k)),
                            &coeff,
                        )?;

                        let challenge_times_coeff_bits = challenge_times_coeff
                            .to_bits_le(cs.ns(|| format!("challenge_times_coeff_to_bits_le_{}_{}_{}", i, j, k)))?;

                        {
                            for (l, (bit, base_power)) in
                                challenge_times_coeff_bits.iter().zip(&comm.prepared_comm).enumerate()
                            {
                                let mut new_encoded = comm_times_challenge.clone();
                                new_encoded = new_encoded.add(
                                    cs.ns(|| format!("new_encoded_add_base_power_{}_{}_{}_{}", i, j, k, l)),
                                    &base_power,
                                )?;

                                comm_times_challenge = PG::G1Gadget::conditionally_select(
                                    cs.ns(|| format!("comm_times_challenge_cond_select_{}_{}_{}_{}", i, j, k, l)),
                                    bit,
                                    &new_encoded,
                                    &comm_times_challenge,
                                )?;
                            }
                        }

                        if negate.eq(&true) {
                            comm_times_challenge = comm_times_challenge
                                .negate(cs.ns(|| format!("comm_times_challenge_negate_{}_{}_{}", i, j, k)))?;
                        }

                        combined_comm = combined_comm.add(
                            &mut cs.ns(|| format!("combined_comm_add_comm_times_challenge_{}_{}_{}", i, j, k)),
                            &comm_times_challenge,
                        )?;
                    }
                }
                // Similarly, we add up the evaluations, multiplied with random challenges.
                let value_times_challenge_unreduced =
                    value.mul_without_reduce(cs.ns(|| format!("value_mul_without_reduce_{}_{}", i, j)), &challenge)?;

                combined_eval = combined_eval.add(
                    &mut cs.ns(|| format!("combined_eval_add_value_times_challenge_unreduced_{}_{}", i, j)),
                    &value_times_challenge_unreduced,
                )?;
            }

            let combined_eval_reduced = combined_eval.reduce(&mut cs.ns(|| format!("combined_eval_reduced_{}", i)))?;

            combined_queries.push(point.clone());
            combined_comms.push(combined_comm);
            combined_evals.push(combined_eval_reduced);
        }

        eprintln!("before PC batch check: constraints: {}", cs.num_constraints());

        // Perform the batch check.
        {
            let mut total_c = PG::G1Gadget::zero(cs.ns(|| "zero_c"))?;
            let mut total_w = PG::G1Gadget::zero(cs.ns(|| "zero_w"))?;

            let mut g_multiplier = NonNativeFieldMulResultVar::<
                <TargetCurve as PairingEngine>::Fr,
                <BaseCurve as PairingEngine>::Fr,
            >::zero();
            let mut g_multiplier_reduced = NonNativeFieldVar::<
                <TargetCurve as PairingEngine>::Fr,
                <BaseCurve as PairingEngine>::Fr,
            >::zero(cs.ns(|| "zero_g_multiplier"))?;

            let mut gamma_g_multiplier = NonNativeFieldMulResultVar::<
                <TargetCurve as PairingEngine>::Fr,
                <BaseCurve as PairingEngine>::Fr,
            >::zero();
            let mut gamma_g_multiplier_reduced = NonNativeFieldVar::<
                <TargetCurve as PairingEngine>::Fr,
                <BaseCurve as PairingEngine>::Fr,
            >::zero(cs.ns(|| "zero_gamma_g_multiplier"))?;

            for (i, (((c, z), v), proof)) in combined_comms
                .iter()
                .zip(combined_queries)
                .zip(combined_evals)
                .zip(proofs)
                .enumerate()
            {
                let z_bits = z.to_bits_le(cs.ns(|| format!("z_bits_to_le_{}", i)))?;

                let w_times_z =
                    proof
                        .w
                        .mul_bits(cs.ns(|| format!("w_times_z_mul_bits_{}", i)), &zero, z_bits.into_iter())?;

                let mut c_plus_w_times_z = c.clone();
                c_plus_w_times_z =
                    c_plus_w_times_z.add(cs.ns(|| format!("c_plus_w_times_z_plus_w_times_z_{}", i)), &w_times_z)?;

                if i != 0 {
                    let randomizer = batching_rands.remove(0);
                    let randomizer_bits = batching_rands_bits.remove(0);

                    let randomizer_times_v =
                        randomizer.mul_without_reduce(cs.ns(|| format!("mul_without_reduce_{}", i)), &v)?;

                    g_multiplier = g_multiplier.add(
                        &mut cs.ns(|| format!("g_multiplier_plus_randomizer_times_v_{}", i)),
                        &randomizer_times_v,
                    )?;

                    if let Some(random_v) = &proof.random_v {
                        let randomizer_times_random_v = randomizer
                            .mul_without_reduce(cs.ns(|| format!("mul_without_reduce_{}_random_v", i)), random_v)?;

                        gamma_g_multiplier = gamma_g_multiplier.add(
                            &mut cs.ns(|| format!("gamma_g_multiplier_plus_randomizer_times_random_v_{}", i)),
                            &randomizer_times_random_v,
                        )?;
                    }

                    let c_times_randomizer = c_plus_w_times_z.mul_bits(
                        cs.ns(|| format!("c_plus_w_times_z_mul_bits{}", i)),
                        &zero,
                        randomizer_bits.clone().into_iter(),
                    )?;
                    let w_times_randomizer = proof.w.mul_bits(
                        cs.ns(|| format!("proof_w_mul_bits{}", i)),
                        &zero,
                        randomizer_bits.into_iter(),
                    )?;

                    total_c = total_c.add(
                        &mut cs.ns(|| format!("total_c_plus_c_times_randomizer_{}", i)),
                        &c_times_randomizer,
                    )?;
                    total_w = total_w.add(
                        &mut cs.ns(|| format!("total_w_plus_w_times_randomizer_{}", i)),
                        &w_times_randomizer,
                    )?;
                } else {
                    g_multiplier_reduced =
                        g_multiplier_reduced.add(&mut cs.ns(|| format!("g_multiplier_reduced_plus_v_{}", i)), &v)?;
                    if let Some(random_v) = &proof.random_v {
                        gamma_g_multiplier_reduced = gamma_g_multiplier_reduced.add(
                            &mut cs.ns(|| format!("gamma_g_multiplier_plus_randomizer_times_random_v_{}", i)),
                            &random_v,
                        )?;
                    }
                    total_c = total_c.add(
                        &mut cs.ns(|| format!("total_c_plus_c_plus_w_times_z_{}", i)),
                        &c_plus_w_times_z,
                    )?;
                    total_w = total_w.add(&mut cs.ns(|| format!("total_w_plus_proof_w{}", i)), &proof.w)?;
                }
            }

            // Prepare each input to the pairing.
            let (prepared_total_w, prepared_beta_h, prepared_total_c, prepared_h) = {
                let reduced = g_multiplier.reduce(&mut cs.ns(|| "g_multiplier_reduce_sum"))?;
                let g_multiplier_reduced = g_multiplier_reduced.add(&mut cs.ns(|| "g_multiplier_reduce"), &reduced)?;
                let g_multiplier_bits = g_multiplier_reduced.to_bits_le(&mut cs.ns(|| "g_multiplier_to_bits_le"))?;

                let gamma_g_multiplier_reduced = {
                    let reduced = gamma_g_multiplier.reduce(&mut cs.ns(|| "gamma_g_multiplier_reduce_sum"))?;
                    gamma_g_multiplier_reduced.add(&mut cs.ns(|| "gamma_g_multiplier_reduce"), &reduced)?
                };
                let gamma_g_multiplier_bits =
                    gamma_g_multiplier_reduced.to_bits_le(&mut cs.ns(|| "gamma_g_multiplier_to_bits_le"))?;

                let mut g_times_mul = PG::G1Gadget::zero(cs.ns(|| "g_times_mul_zero"))?;
                {
                    for (i, (bit, base_power)) in g_multiplier_bits
                        .iter()
                        .zip(&prepared_verification_key.prepared_g)
                        .enumerate()
                    {
                        let mut new_encoded = g_times_mul.clone();
                        new_encoded =
                            new_encoded.add(cs.ns(|| format!("new_encoded_plus_base_power_{}", i)), base_power)?;

                        g_times_mul = PG::G1Gadget::conditionally_select(
                            cs.ns(|| format!("g_times_mul_cond_select_{}", i)),
                            bit,
                            &new_encoded,
                            &g_times_mul,
                        )?;
                    }
                }

                let mut gamma_g_times_mul = PG::G1Gadget::zero(cs.ns(|| "gamma_g_times_mul_zero"))?;
                {
                    for (i, (bit, base_power)) in gamma_g_multiplier_bits
                        .iter()
                        .zip(&prepared_verification_key.prepared_gamma_g)
                        .enumerate()
                    {
                        let mut new_encoded = gamma_g_times_mul.clone();
                        new_encoded = new_encoded.add(
                            cs.ns(|| format!("new_encoded_plus_base_power_{}_gamma_g", i)),
                            base_power,
                        )?;

                        gamma_g_times_mul = PG::G1Gadget::conditionally_select(
                            cs.ns(|| format!("gamma_g_times_mul_cond_select_{}", i)),
                            bit,
                            &new_encoded,
                            &gamma_g_times_mul,
                        )?;
                    }
                }

                total_c = total_c.sub(&mut cs.ns(|| "total_c_minus_g_times_mul"), &g_times_mul)?;
                total_c = total_c.sub(&mut cs.ns(|| "total_c_minus_gamma_g_times_mul"), &gamma_g_times_mul)?;
                total_w = total_w.negate(cs.ns(|| "total_w_negate"))?;

                let prepared_total_w = PG::prepare_g1(cs.ns(|| "prepared_total_w"), total_w)?;
                let prepared_beta_h = prepared_verification_key.prepared_beta_h.clone();
                let prepared_total_c = PG::prepare_g1(cs.ns(|| "prepared_total_c"), total_c)?;
                let prepared_h = prepared_verification_key.prepared_h.clone();

                (prepared_total_w, prepared_beta_h, prepared_total_c, prepared_h)
            };

            let lhs = PG::product_of_pairings(
                cs.ns(|| "lhs_product_of_pairings"),
                &[prepared_total_w, prepared_total_c],
                &[prepared_beta_h, prepared_h],
            )?;

            eprintln!("after PC batch check: constraints: {}", cs.num_constraints());

            let rhs = &PG::GTGadget::one(cs.ns(|| "rhs"))?;
            lhs.is_eq(cs.ns(|| "lhs_is_eq_rhs"), &rhs)
        }
    }
}

impl<TargetCurve, BaseCurve, PG>
    PCCheckVar<<TargetCurve as PairingEngine>::Fr, MarlinKZG10<TargetCurve>, <BaseCurve as PairingEngine>::Fr>
    for MarlinKZG10Gadget<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    type BatchLCProofVar = BatchLCProofVar<TargetCurve, BaseCurve, PG>;
    type CommitmentVar = CommitmentVar<TargetCurve, BaseCurve, PG>;
    type LabeledCommitmentVar = LabeledCommitmentVar<TargetCurve, BaseCurve, PG>;
    type PreparedCommitmentVar = PreparedCommitmentVar<TargetCurve, BaseCurve, PG>;
    type PreparedLabeledCommitmentVar = PreparedLabeledCommitmentVar<TargetCurve, BaseCurve, PG>;
    type PreparedVerifierKeyVar = PreparedVerifierKeyVar<TargetCurve, BaseCurve, PG>;
    type ProofVar = ProofVar<TargetCurve, BaseCurve, PG>;
    type VerifierKeyVar = VerifierKeyVar<TargetCurve, BaseCurve, PG>;

    #[allow(clippy::type_complexity)]
    fn batch_check_evaluations<CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>>(
        mut cs: CS,
        verification_key: &Self::VerifierKeyVar,
        commitments: &[Self::LabeledCommitmentVar],
        query_set: &QuerySetVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
        evaluations: &EvaluationsVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
        proofs: &[Self::ProofVar],
        rand_data: &PCCheckRandomDataVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
    ) -> Result<Boolean, SynthesisError> {
        let mut batching_rands = rand_data.batching_rands.to_vec();
        let mut batching_rands_bits = rand_data.batching_rands_bits.to_vec();

        let commitments: BTreeMap<_, _> = commitments.iter().map(|c| (c.label.clone(), c)).collect();
        let mut query_to_labels_map: BTreeMap<
            <TargetCurve as PairingEngine>::Fr,
            (
                NonNativeFieldVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
                BTreeSet<&String>,
            ),
        > = BTreeMap::new();

        // Sort the query set to match the native impl.
        let mut sorted_query_set_gadgets: Vec<_> = query_set.0.iter().collect();
        sorted_query_set_gadgets.sort_by(|a, b| a.0.cmp(&b.0));

        for (label, point) in sorted_query_set_gadgets.iter() {
            // (raychu86): Changed entry `point.name` to `point.value` to preserve the same ordering,
            // as the native implementation
            let labels = query_to_labels_map
                .entry(point.value.value()?)
                .or_insert((point.value.clone(), BTreeSet::new()));
            labels.1.insert(label);
        }

        // Accumulate commitments and evaluations for each query.
        let mut combined_queries = Vec::new();
        let mut combined_comms = Vec::new();
        let mut combined_evals = Vec::new();
        for (i, (_, (point, labels))) in query_to_labels_map.into_iter().enumerate() {
            let mut comms_to_combine: Vec<Self::LabeledCommitmentVar> = Vec::new();
            let mut values_to_combine = Vec::new();
            for label in labels.into_iter() {
                let commitment = &(*commitments.get(label).unwrap()).clone();
                let degree_bound = commitment.degree_bound.clone();
                assert_eq!(degree_bound.is_some(), commitment.commitment.shifted_comm.is_some());

                let v_i = evaluations
                    .0
                    .get(&LabeledPointVar {
                        name: label.clone(),
                        value: point.clone(),
                    })
                    .unwrap();

                comms_to_combine.push(commitment.clone());
                values_to_combine.push(v_i.clone());
            }

            // Accumulate the commitments and evaluations corresponding to `query`.
            let mut combined_comm = PG::G1Gadget::zero(cs.ns(|| format!("comm_zero_{}", i)))?;
            let mut combined_eval = NonNativeFieldMulResultVar::<
                <TargetCurve as PairingEngine>::Fr,
                <BaseCurve as PairingEngine>::Fr,
            >::zero();

            let zero = PG::G1Gadget::zero(cs.ns(|| format!("g1_zero_{}", i)))?;

            let mut opening_challenges_counter = 0;

            for (j, (labeled_commitment, value)) in
                comms_to_combine.into_iter().zip(values_to_combine.iter()).enumerate()
            {
                let challenge = rand_data.opening_challenges[opening_challenges_counter].clone();
                let challenge_bits = rand_data.opening_challenges_bits[opening_challenges_counter].clone();
                opening_challenges_counter += 1;

                let LabeledCommitmentVar {
                    commitment,
                    degree_bound,
                    ..
                } = labeled_commitment;
                let CommitmentVar { shifted_comm, .. } = commitment;

                // To combine the commitments, we multiply each by one of the random challenges, and sum.
                let temp = commitment.comm.mul_bits(
                    cs.ns(|| format!("comm_mul_bits_{}_{}", i, j)),
                    &zero,
                    challenge_bits.into_iter(),
                )?;
                combined_comm = combined_comm.add(
                    cs.ns(|| format!("combined_comm_plus_scalar_product_{}_{}", i, j)),
                    &temp,
                )?;

                // Similarly, we add up the evaluations, multiplied with random challenges.
                let value_times_challenge_unreduced =
                    value.mul_without_reduce(cs.ns(|| format!("value_mul_without_reduce_{}_{}", i, j)), &challenge)?;

                combined_eval = combined_eval.add(
                    &mut cs.ns(|| format!("combined_eval_add_value_times_challenge_unreduced_{}_{}", i, j)),
                    &value_times_challenge_unreduced,
                )?;

                // If the degree bound is specified, we include the adjusted degree-shifted commitment
                // (that is, c_i' - v_i beta^{D - d_i} G), where d_i is the specific degree bound and
                // v_i is the evaluation, in the cocmbined commitment,
                if let Some(degree_bound) = degree_bound {
                    let challenge_shifted_bits = rand_data.opening_challenges_bits[opening_challenges_counter].clone();
                    opening_challenges_counter += 1;

                    let shifted_comm = shifted_comm.as_ref().unwrap().clone();

                    let value_bits = value.to_bits_le(cs.ns(|| format!("value_to_bits_le_{}_{}", i, j)))?;
                    let shift_power = verification_key
                        .get_shift_power(cs.ns(|| format!("get_shift_key_{}_{}", i, j)), &degree_bound)
                        .unwrap();

                    let shift_power_times_value = shift_power.mul_bits(
                        cs.ns(|| format!("shift_power_mul_bits_{}_{}", i, j)),
                        &zero,
                        value_bits.into_iter(),
                    )?;
                    let mut adjusted_comm = shifted_comm;
                    adjusted_comm = adjusted_comm.sub(
                        &mut cs.ns(|| format!("adjusted_comm_minus_shift_power_times_value_{}_{}", i, j)),
                        &shift_power_times_value,
                    )?;

                    let adjusted_comm_times_challenge = adjusted_comm.mul_bits(
                        cs.ns(|| format!("adjusted_comm_mul_bits_{}_{}", i, j)),
                        &zero,
                        challenge_shifted_bits.into_iter(),
                    )?;
                    combined_comm = combined_comm.add(
                        &mut cs.ns(|| format!("combined_comm_plus_adjusted_comm_times_challenge_{}_{}", i, j)),
                        &adjusted_comm_times_challenge,
                    )?;
                }
            }

            combined_queries.push(point.clone());
            combined_comms.push(combined_comm);
            combined_evals.push(combined_eval);
        }

        // Perform the batch check.
        {
            let mut total_c = PG::G1Gadget::zero(cs.ns(|| "zero_c"))?;
            let mut total_w = PG::G1Gadget::zero(cs.ns(|| "zero_w"))?;

            let zero = PG::G1Gadget::zero(cs.ns(|| format!("batch_check_g1_zero")))?;

            let mut g_multiplier = NonNativeFieldMulResultVar::<
                <TargetCurve as PairingEngine>::Fr,
                <BaseCurve as PairingEngine>::Fr,
            >::zero();
            for (i, (((c, z), v), proof)) in combined_comms
                .iter()
                .zip(combined_queries)
                .zip(combined_evals)
                .zip(proofs)
                .enumerate()
            {
                let z_bits = z.to_bits_le(cs.ns(|| format!("z_to_bits_le_{}", i)))?;

                let w_times_z =
                    proof
                        .w
                        .mul_bits(cs.ns(|| format!("proof_w_mul_bits_{}", i)), &zero, z_bits.into_iter())?;
                let mut c_plus_w_times_z = c.clone();
                c_plus_w_times_z = c_plus_w_times_z.add(
                    &mut cs.ns(|| format!("c_plus_w_times_z_plus_c_plus_w_times_z_{}", i)),
                    &w_times_z,
                )?;

                let randomizer = batching_rands.remove(0);
                let randomizer_bits = batching_rands_bits.remove(0);

                let v_reduced = v.reduce(&mut cs.ns(|| format!("v_reduce_{}", i)))?;
                let randomizer_times_v =
                    randomizer.mul_without_reduce(cs.ns(|| format!("randomizer_times_v_{}", i)), &v_reduced)?;

                g_multiplier = g_multiplier.add(
                    &mut cs.ns(|| format!("g_multiplier_plus_randomizer_times_v_{}", i)),
                    &randomizer_times_v,
                )?;

                let c_times_randomizer = c_plus_w_times_z.mul_bits(
                    cs.ns(|| format!("c_plus_w_times_z_mul_bits_{}", i)),
                    &zero,
                    randomizer_bits.clone().into_iter(),
                )?;
                let w_times_randomizer = proof.w.mul_bits(
                    cs.ns(|| format!("w_times_randomizer_mul_bits_{}", i)),
                    &zero,
                    randomizer_bits.into_iter(),
                )?;
                total_c = total_c.add(
                    &mut cs.ns(|| format!("total_c_plus_c_times_randomizer_{}", i)),
                    &c_times_randomizer,
                )?;
                total_w = total_w.add(
                    &mut cs.ns(|| format!("total_w_plus_w_times_randomizer_{}", i)),
                    &w_times_randomizer,
                )?;
            }

            // Prepare each input to the pairing.
            let (prepared_total_w, prepared_beta_h, prepared_total_c, prepared_h) = {
                let g_multiplier_reduced = g_multiplier.reduce(&mut cs.ns(|| "g_multiplier_reduced"))?;
                let g_multiplier_bits = g_multiplier_reduced.to_bits_le(cs.ns(|| "g_multiplier_reduced_to_bits_le"))?;

                let g_times_mul = verification_key.g.mul_bits(
                    cs.ns(|| "g_times_mul_mul_bits"),
                    &zero,
                    g_multiplier_bits.into_iter(),
                )?;
                total_c = total_c.sub(&mut cs.ns(|| "total_c_minus_g_times_mul"), &g_times_mul)?;
                total_w = total_w.negate(cs.ns(|| "total_w_negate"))?;

                let prepared_total_w = PG::prepare_g1(cs.ns(|| "prepared_total_w"), total_w)?;
                let prepared_beta_h = PG::prepare_g2(cs.ns(|| "prepared_beta_h"), verification_key.beta_h.clone())?;
                let prepared_total_c = PG::prepare_g1(cs.ns(|| "prepared_total_c"), total_c.clone())?;
                let prepared_h = PG::prepare_g2(cs.ns(|| "prepared_h"), verification_key.h.clone())?;

                (prepared_total_w, prepared_beta_h, prepared_total_c, prepared_h)
            };

            let lhs = PG::product_of_pairings(cs.ns(|| "lhs"), &[prepared_total_w, prepared_total_c], &[
                prepared_beta_h,
                prepared_h,
            ])?;

            let rhs = &PG::GTGadget::one(cs.ns(|| "rhs"))?;

            lhs.is_eq(cs.ns(|| "lhs_is_eq_rhs"), &rhs)
        }
    }

    #[allow(clippy::type_complexity)]
    fn prepared_check_combinations<CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>>(
        mut cs: CS,
        prepared_verification_key: &Self::PreparedVerifierKeyVar,
        linear_combinations: &[LinearCombinationVar<
            <TargetCurve as PairingEngine>::Fr,
            <BaseCurve as PairingEngine>::Fr,
        >],
        prepared_commitments: &[Self::PreparedLabeledCommitmentVar],
        query_set: &QuerySetVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
        evaluations: &EvaluationsVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
        proof: &Self::BatchLCProofVar,
        rand_data: &PCCheckRandomDataVar<<TargetCurve as PairingEngine>::Fr, <BaseCurve as PairingEngine>::Fr>,
    ) -> Result<Boolean, SynthesisError> {
        let BatchLCProofVar { proofs, .. } = proof;

        let label_comm_map = prepared_commitments
            .iter()
            .map(|c| (c.label.clone(), c))
            .collect::<BTreeMap<_, _>>();

        let mut lc_info = Vec::new();
        let mut evaluations = evaluations.clone();

        // For each linear combination, we sum up the relevant commitments, multiplied
        // with their corresponding coefficients; these combined commitments are then
        // the inputs to the normal batch check.
        for (i, lc) in linear_combinations.iter().enumerate() {
            let lc_label = lc.label.clone();
            let num_polys = lc.terms.len();

            let mut coeffs_and_comms = Vec::new();

            for (j, (coeff, label)) in lc.terms.iter().enumerate() {
                if label.is_one() {
                    for (label, ref mut eval) in evaluations.0.iter_mut() {
                        if label.name == lc_label {
                            match coeff.clone() {
                                LinearCombinationCoeffVar::One => {
                                    let one = NonNativeFieldVar::one(cs.ns(|| format!("coeff_one_{}_{}", i, j)))?;
                                    **eval = (**eval).sub(cs.ns(|| format!("eval_minus_one_{}_{}", i, j)), &one)?;
                                }
                                LinearCombinationCoeffVar::MinusOne => {
                                    let one = NonNativeFieldVar::one(cs.ns(|| format!("coeff_one_{}_{}", i, j)))?;
                                    **eval = (**eval).add(cs.ns(|| format!("eval_add_one_{}_{}", i, j)), &one)?;
                                }
                                LinearCombinationCoeffVar::Var(variable) => {
                                    **eval =
                                        (**eval).sub(cs.ns(|| format!("eval_minus_variable_{}_{}", i, j)), &variable)?
                                }
                            };
                        }
                    }
                } else {
                    let label: &String = label.try_into().unwrap();
                    let &cur_comm = label_comm_map.get(label).unwrap();
                    let negate = match coeff {
                        LinearCombinationCoeffVar::One | LinearCombinationCoeffVar::Var(_) => false,
                        LinearCombinationCoeffVar::MinusOne => true,
                    };

                    if num_polys == 1 && cur_comm.degree_bound.is_some() {
                        assert!(!negate);
                    }

                    let coeff = match coeff {
                        LinearCombinationCoeffVar::One => None,
                        LinearCombinationCoeffVar::MinusOne => None,
                        LinearCombinationCoeffVar::Var(variable) => Some(variable.clone()),
                    };

                    coeffs_and_comms.push((
                        coeff.clone(),
                        cur_comm.degree_bound.clone(),
                        cur_comm.prepared_commitment.clone(),
                        negate,
                    ));
                }
            }

            lc_info.push((lc_label, coeffs_and_comms));
        }

        Self::prepared_batch_check_evaluations(
            cs,
            prepared_verification_key,
            lc_info.as_slice(),
            &query_set,
            &evaluations,
            proofs,
            &rand_data.opening_challenges,
            &rand_data.opening_challenges_bits,
            &rand_data.batching_rands,
            &rand_data.batching_rands_bits,
        )
    }

    fn create_labeled_commitment(
        label: String,
        commitment: Self::CommitmentVar,
        degree_bound: Option<FpGadget<<BaseCurve as PairingEngine>::Fr>>,
    ) -> Self::LabeledCommitmentVar {
        Self::LabeledCommitmentVar {
            label,
            commitment,
            degree_bound,
        }
    }

    fn create_prepared_labeled_commitment(
        label: String,
        prepared_commitment: Self::PreparedCommitmentVar,
        degree_bound: Option<FpGadget<<BaseCurve as PairingEngine>::Fr>>,
    ) -> Self::PreparedLabeledCommitmentVar {
        Self::PreparedLabeledCommitmentVar {
            label,
            prepared_commitment,
            degree_bound,
        }
    }
}
