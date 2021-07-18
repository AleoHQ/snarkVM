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

use core::marker::PhantomData;

use hashbrown::{HashMap, HashSet};

use snarkvm_algorithms::{crypto_hash::PoseidonDefaultParametersField, fft::EvaluationDomain};
use snarkvm_fields::PrimeField;
use snarkvm_gadgets::{
    bits::{Boolean, ToBitsLEGadget},
    fields::FpGadget,
    nonnative::{params::OptimizationType, NonNativeFieldVar},
    traits::{
        alloc::AllocGadget,
        eq::{EqGadget, NEqGadget},
        fields::{FieldGadget, ToConstraintFieldGadget},
        snark::PrepareGadget,
    },
};
use snarkvm_polycommit::{
    EvaluationsVar,
    LCTerm,
    LabeledPointVar,
    LinearCombinationCoeffVar,
    LinearCombinationVar,
    PCCheckVar,
    QuerySetVar,
};
use snarkvm_r1cs::ConstraintSystem;

use crate::{
    constraints::{
        lagrange_interpolation::LagrangeInterpolationVar,
        polynomial::AlgebraForAHP,
        proof::ProofVar,
        verifier_key::PreparedCircuitVerifyingKeyVar,
    },
    AHPError,
    FiatShamirRng,
    FiatShamirRngVar,
    PolynomialCommitment,
};

/// The Marlin verifier round state gadget used to output the state of each round.
#[derive(Clone)]
pub struct VerifierStateVar<TargetField: PrimeField, BaseField: PrimeField> {
    domain_h_size: u64,
    domain_k_size: u64,

    first_round_msg: Option<VerifierFirstMsgVar<TargetField, BaseField>>,
    second_round_msg: Option<VerifierSecondMsgVar<TargetField, BaseField>>,

    gamma: Option<NonNativeFieldVar<TargetField, BaseField>>,
}

/// The Marlin verifier first round message gadget.
#[derive(Clone)]
pub struct VerifierFirstMsgVar<TargetField: PrimeField, BaseField: PrimeField> {
    /// Alpha
    pub alpha: NonNativeFieldVar<TargetField, BaseField>,
    /// Eta a
    pub eta_a: NonNativeFieldVar<TargetField, BaseField>,
    /// Eta b
    pub eta_b: NonNativeFieldVar<TargetField, BaseField>,
    /// Eta c
    pub eta_c: NonNativeFieldVar<TargetField, BaseField>,
}

/// The Marlin verifier second round message gadget.
#[derive(Clone)]
pub struct VerifierSecondMsgVar<TargetField: PrimeField, BaseField: PrimeField> {
    /// Beta
    pub beta: NonNativeFieldVar<TargetField, BaseField>,
}

/// The Marlin verifier third round message gadget.
#[derive(Clone)]
pub struct VerifierThirdMsgVar<TargetField: PrimeField, BaseField: PrimeField> {
    /// Gamma
    pub gamma: NonNativeFieldVar<TargetField, BaseField>,
}

/// The AHP gadget.
pub struct AHPForR1CS<
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> where
    PCG::VerifierKeyVar: ToConstraintFieldGadget<BaseField>,
    PCG::CommitmentVar: ToConstraintFieldGadget<BaseField>,
{
    field: PhantomData<TargetField>,
    constraint_field: PhantomData<BaseField>,
    polynomial_commitment: PhantomData<PC>,
    pc_check: PhantomData<PCG>,
}

impl<
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> AHPForR1CS<TargetField, BaseField, PC, PCG>
where
    PCG::VerifierKeyVar: ToConstraintFieldGadget<BaseField>,
    PCG::CommitmentVar: ToConstraintFieldGadget<BaseField>,
{
    /// Returns the first message and next round state.
    #[allow(clippy::type_complexity)]
    pub fn verifier_first_round<
        CS: ConstraintSystem<BaseField>,
        CommitmentVar: ToConstraintFieldGadget<BaseField>,
        PR: FiatShamirRng<TargetField, BaseField>,
        R: FiatShamirRngVar<TargetField, BaseField, PR>,
    >(
        mut cs: CS,
        domain_h_size: u64,
        domain_k_size: u64,
        fs_rng: &mut R,
        comms: &[CommitmentVar],
        message: &[NonNativeFieldVar<TargetField, BaseField>],
    ) -> Result<
        (
            VerifierFirstMsgVar<TargetField, BaseField>,
            VerifierStateVar<TargetField, BaseField>,
        ),
        AHPError,
    > {
        // absorb the first commitments and messages
        {
            let mut elems = Vec::<FpGadget<BaseField>>::new();
            comms.iter().enumerate().for_each(|(i, comm)| {
                elems.append(
                    &mut comm
                        .to_constraint_field(cs.ns(|| format!("comm_to_constraint_field_{}", i)))
                        .unwrap(),
                );
            });
            fs_rng.absorb_native_field_elements(cs.ns(|| "absorb_native_field_elements"), &elems)?;

            if !message.is_empty() {
                fs_rng.absorb_nonnative_field_elements(
                    cs.ns(|| "absorb_nonnative_field_elements"),
                    &message,
                    OptimizationType::Weight,
                )?;
            }
        }

        // obtain four elements from the sponge
        let elems = fs_rng.squeeze_field_elements(cs.ns(|| "squeeze_field_elements"), 4)?;
        let alpha = elems[0].clone();
        let eta_a = elems[1].clone();
        let eta_b = elems[2].clone();
        let eta_c = elems[3].clone();

        let msg = VerifierFirstMsgVar {
            alpha,
            eta_a,
            eta_b,
            eta_c,
        };

        let new_state = VerifierStateVar {
            domain_h_size,
            domain_k_size,
            first_round_msg: Some(msg.clone()),
            second_round_msg: None,
            gamma: None,
        };

        Ok((msg, new_state))
    }

    /// Returns the second message and next round state.
    #[allow(clippy::type_complexity)]
    pub fn verifier_second_round<
        CS: ConstraintSystem<BaseField>,
        CommitmentVar: ToConstraintFieldGadget<BaseField>,
        PR: FiatShamirRng<TargetField, BaseField>,
        R: FiatShamirRngVar<TargetField, BaseField, PR>,
    >(
        mut cs: CS,
        state: VerifierStateVar<TargetField, BaseField>,
        fs_rng: &mut R,
        comms: &[CommitmentVar],
        message: &[NonNativeFieldVar<TargetField, BaseField>],
    ) -> Result<
        (
            VerifierSecondMsgVar<TargetField, BaseField>,
            VerifierStateVar<TargetField, BaseField>,
        ),
        AHPError,
    > {
        let VerifierStateVar {
            domain_h_size,
            domain_k_size,
            first_round_msg,
            ..
        } = state;

        // absorb the second commitments and messages
        {
            let mut elems = Vec::<FpGadget<BaseField>>::new();
            comms.iter().enumerate().for_each(|(i, comm)| {
                elems.append(
                    &mut comm
                        .to_constraint_field(cs.ns(|| format!("comm_to_constraint_field_{}", i)))
                        .unwrap(),
                );
            });

            fs_rng.absorb_native_field_elements(cs.ns(|| "absorb_native_field_elements"), &elems)?;
            if !message.is_empty() {
                fs_rng.absorb_nonnative_field_elements(
                    cs.ns(|| "absorb_nonnative_field_elements"),
                    &message,
                    OptimizationType::Weight,
                )?;
            }
        }

        // obtain one element from the sponge
        let elems = fs_rng.squeeze_field_elements(cs.ns(|| "squeeze_field_elements"), 1)?;
        let beta = elems[0].clone();

        let msg = VerifierSecondMsgVar { beta };

        let new_state = VerifierStateVar {
            domain_h_size,
            domain_k_size,
            first_round_msg,
            second_round_msg: Some(msg.clone()),
            gamma: None,
        };

        Ok((msg, new_state))
    }

    /// Returns the third message and next round state.
    pub fn verifier_third_round<
        CS: ConstraintSystem<BaseField>,
        CommitmentVar: ToConstraintFieldGadget<BaseField>,
        PR: FiatShamirRng<TargetField, BaseField>,
        R: FiatShamirRngVar<TargetField, BaseField, PR>,
    >(
        mut cs: CS,
        state: VerifierStateVar<TargetField, BaseField>,
        fs_rng: &mut R,
        comms: &[CommitmentVar],
        message: &[NonNativeFieldVar<TargetField, BaseField>],
    ) -> Result<VerifierStateVar<TargetField, BaseField>, AHPError> {
        let VerifierStateVar {
            domain_h_size,
            domain_k_size,
            first_round_msg,
            second_round_msg,
            ..
        } = state;

        // absorb the third commitments and messages
        {
            let mut elems = Vec::<FpGadget<BaseField>>::new();
            comms.iter().enumerate().for_each(|(i, comm)| {
                elems.append(
                    &mut comm
                        .to_constraint_field(cs.ns(|| format!("comm_to_constraint_field_{}", i)))
                        .unwrap(),
                );
            });
            fs_rng.absorb_native_field_elements(cs.ns(|| "absorb_native_field_elements"), &elems)?;
            if !message.is_empty() {
                fs_rng.absorb_nonnative_field_elements(
                    cs.ns(|| "absorb_nonnative_field_elements"),
                    &message,
                    OptimizationType::Weight,
                )?;
            }
        }

        // obtain one element from the sponge
        let elems = fs_rng.squeeze_field_elements(cs.ns(|| "squeeze_field_elements"), 1)?;
        let gamma = elems[0].clone();

        let new_state = VerifierStateVar {
            domain_h_size,
            domain_k_size,
            first_round_msg,
            second_round_msg,
            gamma: Some(gamma),
        };

        Ok(new_state)
    }

    /// Returns a vector of linear combination gadgets.
    pub fn verifier_decision<CS: ConstraintSystem<BaseField>>(
        mut cs: CS,
        public_input: &[NonNativeFieldVar<TargetField, BaseField>],
        evals: &HashMap<String, NonNativeFieldVar<TargetField, BaseField>>,
        state: VerifierStateVar<TargetField, BaseField>,
        domain_k_size_in_vk: &FpGadget<BaseField>,
    ) -> Result<Vec<LinearCombinationVar<TargetField, BaseField>>, AHPError> {
        let VerifierStateVar {
            domain_k_size,
            first_round_msg,
            second_round_msg,
            gamma,
            ..
        } = state;

        let first_round_msg =
            first_round_msg.expect("VerifierState should include first_round_msg when verifier_decision is called");
        let second_round_msg =
            second_round_msg.expect("VerifierState should include second_round_msg when verifier_decision is called");

        let zero = NonNativeFieldVar::<TargetField, BaseField>::zero(cs.ns(|| "nonnative_zero"))?;

        let VerifierFirstMsgVar {
            alpha,
            eta_a,
            eta_b,
            eta_c,
        } = first_round_msg;
        let beta: NonNativeFieldVar<TargetField, BaseField> = second_round_msg.beta;

        let v_h_at_alpha = evals
            .get("vanishing_poly_h_alpha")
            .ok_or_else(|| AHPError::MissingEval("vanishing_poly_h_alpha".to_string()))?;

        v_h_at_alpha.enforce_not_equal(cs.ns(|| "v_h_at_alpha_enforce_not_zero"), &zero)?;

        let v_h_at_beta = evals
            .get("vanishing_poly_h_beta")
            .ok_or_else(|| AHPError::MissingEval("vanishing_poly_h_beta".to_string()))?;
        v_h_at_beta.enforce_not_equal(cs.ns(|| "v_h_at_beta_enforce_not_zero"), &zero)?;

        let gamma: NonNativeFieldVar<TargetField, BaseField> =
            gamma.expect("VerifierState should include gamma when verifier_decision is called");

        let t_at_beta = evals.get("t").ok_or_else(|| AHPError::MissingEval("t".to_string()))?;

        let v_k_at_gamma = evals
            .get("vanishing_poly_k_gamma")
            .ok_or_else(|| AHPError::MissingEval("vanishing_poly_k_gamma".to_string()))?;

        let r_alpha_at_beta = AlgebraForAHP::prepared_eval_bivariable_vanishing_polynomial(
            cs.ns(|| "prepared_eval_bivariable_vanishing_polynomial"),
            &alpha,
            &beta,
            &v_h_at_alpha,
            &v_h_at_beta,
        )?;

        let z_b_at_beta = evals
            .get("z_b")
            .ok_or_else(|| AHPError::MissingEval("z_b".to_string()))?;

        let x_padded_len = public_input.len().next_power_of_two() as u64;

        let mut interpolation_gadget = LagrangeInterpolationVar::<TargetField, BaseField>::new(
            EvaluationDomain::<TargetField>::new(x_padded_len as usize)
                .unwrap()
                .group_gen, // TODO (raychu86): Check reference impl that uses `F::get_root_of_unity(x_padded_len)`
            x_padded_len,
            public_input,
        );

        let f_x_at_beta = interpolation_gadget.interpolate_constraints(cs.ns(|| "interpolate_constraints"), &beta)?;

        let g_1_at_beta = evals
            .get("g_1")
            .ok_or_else(|| AHPError::MissingEval("g_1".to_string()))?;

        // Compute linear combinations
        let mut linear_combinations = Vec::new();

        // Only compute for linear combination optimization.
        let pow_x_at_beta = AlgebraForAHP::prepare(cs.ns(|| "prepare"), &beta, x_padded_len)?;
        let v_x_at_beta = AlgebraForAHP::prepared_eval_vanishing_polynomial(
            cs.ns(|| "prepared_eval_vanishing_polynomial"),
            &pow_x_at_beta,
        )?;

        // Outer sumcheck
        let z_b_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "z_b".to_string(),
            terms: vec![(LinearCombinationCoeffVar::One, "z_b".into())],
        };

        let g_1_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "g_1".to_string(),
            terms: vec![(LinearCombinationCoeffVar::One, "g_1".into())],
        };

        let t_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "t".to_string(),
            terms: vec![(LinearCombinationCoeffVar::One, "t".into())],
        };

        let eta_c_mul_z_b_at_beta = eta_c.mul(cs.ns(|| "eta_c_mul_z_b_at_beta"), &z_b_at_beta)?;
        let eta_a_add_above = eta_a.add(cs.ns(|| "eta_a_add_eta_c"), &eta_c_mul_z_b_at_beta)?;

        let outer_sumcheck_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "outer_sumcheck".to_string(),
            terms: vec![
                (LinearCombinationCoeffVar::One, "mask_poly".into()),
                (
                    LinearCombinationCoeffVar::Var(
                        r_alpha_at_beta.mul(cs.ns(|| "r_alpha_mul_eta_a"), &eta_a_add_above)?,
                    ),
                    "z_a".into(),
                ),
                (
                    LinearCombinationCoeffVar::Var(
                        r_alpha_at_beta
                            .mul(cs.ns(|| "r_alpha_at_beta_mul_eta_b"), &eta_b)?
                            .mul(cs.ns(|| "r_alpha_at_beta_mul_eta_b_mul_z_b_at_beta"), &z_b_at_beta)?,
                    ),
                    LCTerm::One,
                ),
                (
                    LinearCombinationCoeffVar::Var(
                        t_at_beta
                            .mul(cs.ns(|| "t_at_beta_mul_v_x_at_beta"), &v_x_at_beta)?
                            .negate(cs.ns(|| "negate_t_v"))?,
                    ),
                    "w".into(),
                ),
                (
                    LinearCombinationCoeffVar::Var(
                        t_at_beta
                            .mul(cs.ns(|| "t_at_beta_mul_f_x_at_beta"), &f_x_at_beta)?
                            .negate(cs.ns(|| "negate_t_f"))?,
                    ),
                    LCTerm::One,
                ),
                (
                    LinearCombinationCoeffVar::Var(v_h_at_beta.negate(cs.ns(|| "negate_v_h"))?),
                    "h_1".into(),
                ),
                (
                    LinearCombinationCoeffVar::Var(
                        (beta.mul(cs.ns(|| "beta_mul_g_1_at_beta"), &g_1_at_beta))?
                            .negate(cs.ns(|| "negate_beta_g1"))?,
                    ),
                    LCTerm::One,
                ),
            ],
        };

        linear_combinations.push(g_1_lc_gadget);
        linear_combinations.push(z_b_lc_gadget);
        linear_combinations.push(t_lc_gadget);
        linear_combinations.push(outer_sumcheck_lc_gadget);

        // Inner sumcheck
        let g_2_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "g_2".to_string(),
            terms: vec![(LinearCombinationCoeffVar::One, "g_2".into())],
        };

        let beta_alpha = beta.mul(cs.ns(|| "beta_mul_alpha"), &alpha)?;

        let a_denom_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "a_denom".to_string(),
            terms: vec![
                (LinearCombinationCoeffVar::Var(beta_alpha.clone()), LCTerm::One),
                (
                    LinearCombinationCoeffVar::Var(alpha.negate(cs.ns(|| "a_alpha"))?),
                    "a_row".into(),
                ),
                (
                    LinearCombinationCoeffVar::Var(beta.negate(cs.ns(|| "a_beta"))?),
                    "a_col".into(),
                ),
                (LinearCombinationCoeffVar::One, "a_row_col".into()),
            ],
        };

        let b_denom_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "b_denom".to_string(),
            terms: vec![
                (LinearCombinationCoeffVar::Var(beta_alpha.clone()), LCTerm::One),
                (
                    LinearCombinationCoeffVar::Var(alpha.negate(cs.ns(|| "b_alpha"))?),
                    "b_row".into(),
                ),
                (
                    LinearCombinationCoeffVar::Var(beta.negate(cs.ns(|| "b_beta"))?),
                    "b_col".into(),
                ),
                (LinearCombinationCoeffVar::One, "b_row_col".into()),
            ],
        };

        let c_denom_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "c_denom".to_string(),
            terms: vec![
                (LinearCombinationCoeffVar::Var(beta_alpha.clone()), LCTerm::One),
                (
                    LinearCombinationCoeffVar::Var(alpha.negate(cs.ns(|| "c_alpha"))?),
                    "c_row".into(),
                ),
                (
                    LinearCombinationCoeffVar::Var(beta.negate(cs.ns(|| "c_beta"))?),
                    "c_col".into(),
                ),
                (LinearCombinationCoeffVar::One, "c_row_col".into()),
            ],
        };

        let a_denom_at_gamma = evals.get(&a_denom_lc_gadget.label).unwrap();
        let b_denom_at_gamma = evals.get(&b_denom_lc_gadget.label).unwrap();
        let c_denom_at_gamma = evals.get(&c_denom_lc_gadget.label).unwrap();
        let g_2_at_gamma = evals.get(&g_2_lc_gadget.label).unwrap();

        let v_h_at_alpha_beta = v_h_at_alpha.mul(cs.ns(|| "v_h_alpha_mul_v_h_beta"), &v_h_at_beta)?;

        let domain_k_size_gadget =
            NonNativeFieldVar::<TargetField, BaseField>::alloc(cs.ns(|| "domain_k_size"), || {
                Ok(TargetField::from(domain_k_size as u128))
            })?;
        let inv_domain_k_size_gadget = domain_k_size_gadget.inverse(cs.ns(|| "domain_k_inverse"))?;

        let domain_k_size_bit_decomposition =
            domain_k_size_gadget.to_bits_le(cs.ns(|| "domain_k_gadget_to_bits_le"))?;

        let domain_k_size_in_vk_bit_decomposition =
            domain_k_size_in_vk.to_bits_le(cs.ns(|| "domain_k_size_in_vk_to_bits_le"))?;

        // This is not the most efficient implementation; an alternative is to check if the last limb of domain_k_size_gadget
        // can be bit composed by the bits in domain_k_size_in_vk, which would save a lot of constraints.
        // Nevertheless, doing so is using the nonnative field gadget in a non-black-box manner and is somehow not encouraged.
        for (i, (left, right)) in domain_k_size_bit_decomposition
            .iter()
            .take(32)
            .zip(domain_k_size_in_vk_bit_decomposition.iter())
            .enumerate()
        {
            left.enforce_equal(cs.ns(|| format!("domain_k_enforce_equal_{}", i)), &right)?;
        }

        for (i, bit) in domain_k_size_bit_decomposition.iter().skip(32).enumerate() {
            bit.enforce_equal(
                cs.ns(|| format!("domain_k_enforce_false_{}", i)),
                &Boolean::constant(false),
            )?;
        }

        let gamma_mul_g_2 = gamma.mul(cs.ns(|| "gamma_mul_g_2"), &g_2_at_gamma)?;
        let t_div_domain_k = t_at_beta.mul(cs.ns(|| "t_div_domain_k"), &inv_domain_k_size_gadget)?;
        let b_expr_at_gamma_last_term = gamma_mul_g_2.add(cs.ns(|| "b_expr_at_gamma_last_term"), &t_div_domain_k)?;
        let ab_denom_at_gamma = a_denom_at_gamma.mul(cs.ns(|| "ab_denom_at_gamma"), &b_denom_at_gamma)?;

        let inner_sumcheck_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "inner_sumcheck".to_string(),
            terms: vec![
                (
                    LinearCombinationCoeffVar::Var(
                        eta_a
                            .mul(cs.ns(|| "eta_a_mul_b_denom"), &b_denom_at_gamma)?
                            .mul(cs.ns(|| "eta_a_mul_b_denom_mul_c_denom"), &c_denom_at_gamma)?
                            .mul(cs.ns(|| "eta_a_mul_b_denom_mul_c_denom_mul_v_h"), &v_h_at_alpha_beta)?,
                    ),
                    "a_val".into(),
                ),
                (
                    LinearCombinationCoeffVar::Var(
                        eta_b
                            .mul(cs.ns(|| "eta_b_mul_a_denom"), &a_denom_at_gamma)?
                            .mul(cs.ns(|| "eta_b_mul_a_denom_mul_c_denom"), &c_denom_at_gamma)?
                            .mul(cs.ns(|| "eta_b_mul_a_denom_mul_c_denom_mul_v_h"), &v_h_at_alpha_beta)?,
                    ),
                    "b_val".into(),
                ),
                (
                    LinearCombinationCoeffVar::Var(
                        eta_c
                            .mul(cs.ns(|| "eta_c_mul_ab_denom"), &ab_denom_at_gamma)?
                            .mul(cs.ns(|| "eta_c_mul_ab_denom_mul_v_h"), &v_h_at_alpha_beta)?,
                    ),
                    "c_val".into(),
                ),
                (
                    LinearCombinationCoeffVar::Var(
                        ab_denom_at_gamma
                            .mul(cs.ns(|| "ab_denom_mul_c_denom"), &c_denom_at_gamma)?
                            .mul(cs.ns(|| "ab_denom_mul_c_denom_mul_b_last"), &b_expr_at_gamma_last_term)?
                            .negate(cs.ns(|| "ab_c_b_negate"))?,
                    ),
                    LCTerm::One,
                ),
                (
                    LinearCombinationCoeffVar::Var(v_k_at_gamma.negate(cs.ns(|| "v_k_negate"))?),
                    "h_2".into(),
                ),
            ],
        };

        linear_combinations.push(g_2_lc_gadget);
        linear_combinations.push(a_denom_lc_gadget);
        linear_combinations.push(b_denom_lc_gadget);
        linear_combinations.push(c_denom_lc_gadget);
        linear_combinations.push(inner_sumcheck_lc_gadget);

        let vanishing_poly_h_alpha_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "vanishing_poly_h_alpha".to_string(),
            terms: vec![(LinearCombinationCoeffVar::One, "vanishing_poly_h".into())],
        };
        let vanishing_poly_h_beta_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "vanishing_poly_h_beta".to_string(),
            terms: vec![(LinearCombinationCoeffVar::One, "vanishing_poly_h".into())],
        };
        let vanishing_poly_k_gamma_lc_gadget = LinearCombinationVar::<TargetField, BaseField> {
            label: "vanishing_poly_k_gamma".to_string(),
            terms: vec![(LinearCombinationCoeffVar::One, "vanishing_poly_k".into())],
        };
        linear_combinations.push(vanishing_poly_h_alpha_lc_gadget);
        linear_combinations.push(vanishing_poly_h_beta_lc_gadget);
        linear_combinations.push(vanishing_poly_k_gamma_lc_gadget);

        linear_combinations.sort_by(|a, b| a.label.cmp(&b.label));

        Ok(linear_combinations)
    }

    /// Verifier commitment query set and evaluations.
    #[allow(clippy::type_complexity)]
    pub fn verifier_comm_query_eval_set<
        CS: ConstraintSystem<BaseField>,
        PR: FiatShamirRng<TargetField, BaseField>,
        R: FiatShamirRngVar<TargetField, BaseField, PR>,
    >(
        mut cs: CS,
        index_pvk: &PreparedCircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG, PR, R>,
        proof: &ProofVar<TargetField, BaseField, PC, PCG>,
        state: &VerifierStateVar<TargetField, BaseField>,
    ) -> Result<
        (
            usize,
            usize,
            Vec<PCG::PreparedLabeledCommitmentVar>,
            QuerySetVar<TargetField, BaseField>,
            EvaluationsVar<TargetField, BaseField>,
        ),
        AHPError,
    > {
        let VerifierStateVar {
            first_round_msg,
            second_round_msg,
            gamma,
            ..
        } = state;

        let first_round_msg = first_round_msg
            .as_ref()
            .expect("VerifierState should include first_round_msg when verifier_query_set is called");

        let second_round_msg = second_round_msg
            .as_ref()
            .expect("VerifierState should include second_round_msg when verifier_query_set is called");

        let alpha = first_round_msg.alpha.clone();

        let beta = second_round_msg.beta.clone();

        let gamma_ref = gamma
            .as_ref()
            .expect("VerifierState should include gamma when verifier_query_set is called")
            .clone();

        let gamma = gamma_ref;

        let mut query_set_gadget = QuerySetVar::<TargetField, BaseField> { 0: HashSet::new() };

        query_set_gadget.0.insert(("g_1".to_string(), LabeledPointVar {
            name: "beta".to_string(),
            value: beta.clone(),
        }));
        query_set_gadget.0.insert(("z_b".to_string(), LabeledPointVar {
            name: "beta".to_string(),
            value: beta.clone(),
        }));
        query_set_gadget.0.insert(("t".to_string(), LabeledPointVar {
            name: "beta".to_string(),
            value: beta.clone(),
        }));
        query_set_gadget
            .0
            .insert(("outer_sumcheck".to_string(), LabeledPointVar {
                name: "beta".to_string(),
                value: beta.clone(),
            }));
        query_set_gadget.0.insert(("g_2".to_string(), LabeledPointVar {
            name: "gamma".to_string(),
            value: gamma.clone(),
        }));
        query_set_gadget.0.insert(("a_denom".to_string(), LabeledPointVar {
            name: "gamma".to_string(),
            value: gamma.clone(),
        }));
        query_set_gadget.0.insert(("b_denom".to_string(), LabeledPointVar {
            name: "gamma".to_string(),
            value: gamma.clone(),
        }));
        query_set_gadget.0.insert(("c_denom".to_string(), LabeledPointVar {
            name: "gamma".to_string(),
            value: gamma.clone(),
        }));
        query_set_gadget
            .0
            .insert(("inner_sumcheck".to_string(), LabeledPointVar {
                name: "gamma".to_string(),
                value: gamma.clone(),
            }));
        query_set_gadget
            .0
            .insert(("vanishing_poly_h_alpha".to_string(), LabeledPointVar {
                name: "alpha".to_string(),
                value: alpha.clone(),
            }));
        query_set_gadget
            .0
            .insert(("vanishing_poly_h_beta".to_string(), LabeledPointVar {
                name: "beta".to_string(),
                value: beta.clone(),
            }));
        query_set_gadget
            .0
            .insert(("vanishing_poly_k_gamma".to_string(), LabeledPointVar {
                name: "gamma".to_string(),
                value: gamma.clone(),
            }));

        let mut evaluations_gadget = EvaluationsVar::<TargetField, BaseField> { 0: HashMap::new() };

        let zero = NonNativeFieldVar::<TargetField, BaseField>::zero(cs.ns(|| "nonnative_zero"))?;

        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "g_1".to_string(),
                value: beta.clone(),
            },
            (*proof.evaluations.get("g_1").unwrap()).clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "z_b".to_string(),
                value: beta.clone(),
            },
            (*proof.evaluations.get("z_b").unwrap()).clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "t".to_string(),
                value: beta.clone(),
            },
            (*proof.evaluations.get("t").unwrap()).clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "outer_sumcheck".to_string(),
                value: beta.clone(),
            },
            zero.clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "g_2".to_string(),
                value: gamma.clone(),
            },
            (*proof.evaluations.get("g_2").unwrap()).clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "a_denom".to_string(),
                value: gamma.clone(),
            },
            (*proof.evaluations.get("a_denom").unwrap()).clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "b_denom".to_string(),
                value: gamma.clone(),
            },
            (*proof.evaluations.get("b_denom").unwrap()).clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "c_denom".to_string(),
                value: gamma.clone(),
            },
            (*proof.evaluations.get("c_denom").unwrap()).clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "inner_sumcheck".to_string(),
                value: gamma.clone(),
            },
            zero,
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "vanishing_poly_h_alpha".to_string(),
                value: alpha.clone(),
            },
            (*proof.evaluations.get("vanishing_poly_h_alpha").unwrap()).clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "vanishing_poly_h_beta".to_string(),
                value: beta.clone(),
            },
            (*proof.evaluations.get("vanishing_poly_h_beta").unwrap()).clone(),
        );
        evaluations_gadget.0.insert(
            LabeledPointVar {
                name: "vanishing_poly_k_gamma".to_string(),
                value: gamma.clone(),
            },
            (*proof.evaluations.get("vanishing_poly_k_gamma").unwrap()).clone(),
        );

        let mut comms = vec![];

        const INDEX_LABELS: [&str; 14] = [
            "a_row",
            "a_col",
            "a_val",
            "a_row_col",
            "b_row",
            "b_col",
            "b_val",
            "b_row_col",
            "c_row",
            "c_col",
            "c_val",
            "c_row_col",
            "vanishing_poly_h",
            "vanishing_poly_k",
        ];

        // 14 comms for gamma from the index_vk
        for (comm, label) in index_pvk.prepared_index_comms.iter().zip(INDEX_LABELS.iter()) {
            comms.push(PCG::create_prepared_labeled_commitment(
                label.to_string(),
                comm.clone(),
                None,
            ));
        }

        // 4 comms for beta from the round 1
        const PROOF_1_LABELS: [&str; 4] = ["w", "z_a", "z_b", "mask_poly"];
        for (i, (comm, label)) in proof.commitments[0].iter().zip(PROOF_1_LABELS.iter()).enumerate() {
            let prepared_comm = comm.prepare(cs.ns(|| format!("prepare_1_{}", i)))?;
            comms.push(PCG::create_prepared_labeled_commitment(
                label.to_string(),
                prepared_comm,
                None,
            ));
        }

        let h_minus_2 = index_pvk
            .domain_h_size_gadget
            .clone()
            .sub_constant(cs.ns(|| "domain_h_minus_2"), &BaseField::from(2u128))?;

        // 3 comms for beta from the round 2
        const PROOF_2_LABELS: [&str; 3] = ["t", "g_1", "h_1"];
        let proof_2_bounds = [None, Some(h_minus_2), None];
        for (i, ((comm, label), bound)) in proof.commitments[1]
            .iter()
            .zip(PROOF_2_LABELS.iter())
            .zip(proof_2_bounds.iter())
            .enumerate()
        {
            let prepared_comm = comm.prepare(cs.ns(|| format!("prepare_2_{}", i)))?;
            comms.push(PCG::create_prepared_labeled_commitment(
                label.to_string(),
                prepared_comm,
                (*bound).clone(),
            ));
        }

        let k_minus_2 = index_pvk
            .domain_k_size_gadget
            .sub_constant(cs.ns(|| "domain_k_minus_2"), &BaseField::from(2u128))?;

        // 2 comms for gamma from the round 3
        const PROOF_3_LABELS: [&str; 2] = ["g_2", "h_2"];
        let proof_3_bounds = [Some(k_minus_2), None];
        for (i, ((comm, label), bound)) in proof.commitments[2]
            .iter()
            .zip(PROOF_3_LABELS.iter())
            .zip(proof_3_bounds.iter())
            .enumerate()
        {
            let prepared_comm = comm.prepare(cs.ns(|| format!("prepare_3_{}", i)))?;
            comms.push(PCG::create_prepared_labeled_commitment(
                label.to_string(),
                prepared_comm,
                bound.clone(),
            ));
        }

        // For commitments; and combined commitments (degree bounds); and combined commitments again.
        let num_opening_challenges = 7;

        // Combined commitments.
        let num_batching_rands = 2;

        Ok((
            num_opening_challenges,
            num_batching_rands,
            comms,
            query_set_gadget,
            evaluations_gadget,
        ))
    }
}

#[cfg(test)]
mod test {
    use core::ops::MulAssign;

    use snarkvm_curves::{
        bls12_377::{Bls12_377, Fq, Fr},
        bw6_761::BW6_761,
    };
    use snarkvm_fields::{Field, Zero};
    use snarkvm_gadgets::{curves::bls12_377::PairingGadget as Bls12_377PairingGadget, traits::eq::EqGadget};
    use snarkvm_polycommit::{
        marlin_pc::{
            commitment::{commitment::CommitmentVar, labeled_commitment::LabeledCommitmentVar},
            marlin_kzg10::MarlinKZG10Gadget,
            MarlinKZG10,
        },
        Evaluations,
        LabeledCommitment,
    };
    use snarkvm_r1cs::{ConstraintSynthesizer, SynthesisError, TestConstraintSystem};
    use snarkvm_utilities::{test_rng, to_bytes_le, ToBytes, UniformRand};

    use crate::{
        ahp::AHPForR1CS as AHPForR1CSNative,
        marlin::{
            compute_vk_hash,
            CircuitProvingKey,
            CircuitVerifyingKey,
            MarlinMode,
            MarlinRecursiveMode,
            MarlinSNARK,
            Proof,
        },
        FiatShamirAlgebraicSpongeRng,
        FiatShamirAlgebraicSpongeRngVar,
        PoseidonSponge,
        PoseidonSpongeVar,
    };

    use super::*;
    use crate::constraints::verifier_key::CircuitVerifyingKeyVar;
    use snarkvm_algorithms::Prepare;

    type MultiPC = MarlinKZG10<Bls12_377>;
    type MarlinInst = MarlinSNARK<Fr, Fq, MultiPC, FS, MarlinRecursiveMode>;

    type MultiPCVar = MarlinKZG10Gadget<Bls12_377, BW6_761, Bls12_377PairingGadget>;

    type FS = FiatShamirAlgebraicSpongeRng<Fr, Fq, PoseidonSponge<Fq>>;
    type FSG = FiatShamirAlgebraicSpongeRngVar<Fr, Fq, PoseidonSponge<Fq>, PoseidonSpongeVar<Fq>>;

    #[derive(Copy, Clone)]
    struct Circuit<F: Field> {
        a: Option<F>,
        b: Option<F>,
        num_constraints: usize,
        num_variables: usize,
    }

    impl<F: Field> ConstraintSynthesizer<F> for Circuit<F> {
        fn generate_constraints<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
            let a = cs.alloc(|| "a", || self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.alloc(|| "b", || self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.alloc_input(
                || "c",
                || {
                    let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    a.mul_assign(&b);
                    Ok(a)
                },
            )?;

            for i in 0..(self.num_variables - 3) {
                let _ = cs.alloc(
                    || format!("var {}", i),
                    || self.a.ok_or(SynthesisError::AssignmentMissing),
                )?;
            }

            for i in 0..self.num_constraints {
                cs.enforce(|| format!("constraint {}", i), |lc| lc + a, |lc| lc + b, |lc| lc + c);
            }

            Ok(())
        }
    }

    fn construct_circuit_parameters(
        num_variables: usize,
        num_constraints: usize,
    ) -> (
        CircuitProvingKey<Fr, MultiPC>,
        CircuitVerifyingKey<Fr, MultiPC>,
        Proof<Fr, MultiPC>,
        Vec<Fr>,
    ) {
        let rng = &mut test_rng();

        let universal_srs = MarlinInst::universal_setup(100, 25, 100, rng).unwrap();

        // Construct circuit keys.

        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        let mut c = a;
        c.mul_assign(&b);

        let circ = Circuit {
            a: Some(a),
            b: Some(b),
            num_constraints,
            num_variables,
        };

        let (circuit_pk, circuit_vk) = MarlinInst::circuit_setup(&universal_srs, &circ).unwrap();

        let public_input = [c];

        // Construct a proof.
        let proof = MarlinInst::prove(&circuit_pk, &circ, rng).unwrap();

        let verification = MarlinInst::verify(&circuit_vk, &public_input, &proof).unwrap();

        assert_eq!(verification, true);

        (circuit_pk, circuit_vk, proof, public_input.to_vec())
    }

    #[test]
    fn test_verifier_first_round() {
        let cs = &mut TestConstraintSystem::<Fq>::new();

        let num_variables = 25;
        let num_constraints = 25;

        let (circuit_pk, circuit_vk, proof, public_input) =
            construct_circuit_parameters(num_variables, num_constraints);

        let prepared_circuit_vk = circuit_vk.prepare();

        // Attempt verification.

        let public_input = {
            let domain_x = EvaluationDomain::<Fr>::new(public_input.len() + 1).unwrap();

            let mut unpadded_input = public_input.to_vec();
            unpadded_input.resize(core::cmp::max(public_input.len(), domain_x.size() - 1), Fr::zero());

            unpadded_input
        };

        let is_recursion = MarlinRecursiveMode::RECURSION;
        let fs_rng = &mut FS::new();

        if is_recursion {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME].unwrap());
            fs_rng.absorb_native_field_elements(&compute_vk_hash::<Fr, Fq, MultiPC, FS>(&circuit_vk).unwrap());
            fs_rng.absorb_nonnative_field_elements(&public_input, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME, &circuit_vk, &public_input].unwrap());
        }

        // Start first round.

        let first_commitments = &proof.commitments[0];

        // Construct the gadget components
        let fs_rng_gadget = &mut FSG::constant(cs.ns(|| "alloc_rng"), &fs_rng);

        let mut comm_gadgets = Vec::new();
        let mut message_gadgets = Vec::new();

        for (i, comm) in first_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[0].field_elements.iter().enumerate() {
            let msg_gadget = NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_msg_{}", i)), || Ok(msg)).unwrap();
            message_gadgets.push(msg_gadget);
        }

        // Construct the native verifier first round inputs.

        // Insert randomness.
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
        // Execute the verifier first round.
        let (first_round_message, first_round_state) =
            AHPForR1CSNative::verifier_first_round(circuit_pk.circuit.index_info.clone(), fs_rng).unwrap();

        // Execute the verifier first round gadget.
        let (first_round_message_gadget, first_round_state_gadget) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_first_round(
                cs.ns(|| "verifier_first_round"),
                prepared_circuit_vk.domain_h_size,
                prepared_circuit_vk.domain_k_size,
                fs_rng_gadget,
                &comm_gadgets,
                &message_gadgets,
            )
            .unwrap();

        // Enforce that the native and gadget verifier first round message is equivalent.

        let expected_alpha = NonNativeFieldVar::alloc(cs.ns(|| "alpha"), || Ok(first_round_message.alpha)).unwrap();
        let expected_eta_a = NonNativeFieldVar::alloc(cs.ns(|| "eta_a"), || Ok(first_round_message.eta_a)).unwrap();
        let expected_eta_b = NonNativeFieldVar::alloc(cs.ns(|| "eta_b"), || Ok(first_round_message.eta_b)).unwrap();
        let expected_eta_c = NonNativeFieldVar::alloc(cs.ns(|| "eta_c"), || Ok(first_round_message.eta_c)).unwrap();

        expected_alpha
            .enforce_equal(cs.ns(|| "enforce_equal_alpha"), &first_round_message_gadget.alpha)
            .unwrap();
        expected_eta_a
            .enforce_equal(cs.ns(|| "enforce_equal_eta_a"), &first_round_message_gadget.eta_a)
            .unwrap();
        expected_eta_b
            .enforce_equal(cs.ns(|| "enforce_equal_eta_b"), &first_round_message_gadget.eta_b)
            .unwrap();
        expected_eta_c
            .enforce_equal(cs.ns(|| "enforce_equal_eta_c"), &first_round_message_gadget.eta_c)
            .unwrap();

        // Enforce that the native and gadget verifier first round state is equivalent.

        assert_eq!(first_round_state.domain_h.size, first_round_state_gadget.domain_h_size);
        assert_eq!(first_round_state.domain_k.size, first_round_state_gadget.domain_k_size);
        assert_eq!(
            first_round_state.first_round_message.is_some(),
            first_round_state_gadget.first_round_msg.is_some()
        );
        assert_eq!(
            first_round_state.second_round_message.is_none(),
            first_round_state_gadget.second_round_msg.is_none()
        );
        assert_eq!(
            first_round_state.gamma.is_none(),
            first_round_state_gadget.gamma.is_none()
        );

        if !cs.is_satisfied() {
            println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_verifier_second_round() {
        let cs = &mut TestConstraintSystem::<Fq>::new();

        let num_variables = 25;
        let num_constraints = 25;

        let (circuit_pk, circuit_vk, proof, public_input) =
            construct_circuit_parameters(num_variables, num_constraints);

        let prepared_circuit_vk = circuit_vk.prepare();

        // Attempt verification.

        let public_input = {
            let domain_x = EvaluationDomain::<Fr>::new(public_input.len() + 1).unwrap();

            let mut unpadded_input = public_input.to_vec();
            unpadded_input.resize(core::cmp::max(public_input.len(), domain_x.size() - 1), Fr::zero());

            unpadded_input
        };

        let is_recursion = MarlinRecursiveMode::RECURSION;
        let fs_rng = &mut FS::new();

        if is_recursion {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME].unwrap());
            fs_rng.absorb_native_field_elements(&compute_vk_hash::<Fr, Fq, MultiPC, FS>(&circuit_vk).unwrap());
            fs_rng.absorb_nonnative_field_elements(&public_input, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME, &circuit_vk, &public_input].unwrap());
        }

        // Start first round.

        let first_commitments = &proof.commitments[0];

        // Construct the gadget components
        let fs_rng_gadget = &mut FSG::constant(cs.ns(|| "alloc_rng"), &fs_rng);

        let mut comm_gadgets = Vec::new();
        let mut message_gadgets = Vec::new();

        for (i, comm) in first_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[0].field_elements.iter().enumerate() {
            let msg_gadget = NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_msg_{}", i)), || Ok(msg)).unwrap();
            message_gadgets.push(msg_gadget);
        }

        // Insert randomness.
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
        // Execute the verifier first round.
        let (_first_round_message, first_round_state) =
            AHPForR1CSNative::verifier_first_round(circuit_pk.circuit.index_info.clone(), fs_rng).unwrap();

        // Execute the verifier first round gadget.
        let (_first_round_message_gadget, first_round_state_gadget) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_first_round(
                cs.ns(|| "verifier_first_round"),
                prepared_circuit_vk.domain_h_size,
                prepared_circuit_vk.domain_k_size,
                fs_rng_gadget,
                &comm_gadgets,
                &message_gadgets,
            )
            .unwrap();

        // Start the second round.

        let second_commitments = &proof.commitments[1];

        // Construct the gadget components for the second round

        let mut second_round_comm_gadgets = Vec::new();
        let mut second_round_message_gadgets = Vec::new();

        for (i, comm) in second_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_second_round_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            second_round_comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[1].field_elements.iter().enumerate() {
            let msg_gadget =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_second_round_msg_{}", i)), || Ok(msg)).unwrap();
            second_round_message_gadgets.push(msg_gadget);
        }

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

        // Execute the verifier second round.
        let (second_round_message, second_round_state) =
            AHPForR1CSNative::verifier_second_round(first_round_state, fs_rng).unwrap();

        // Execute the verifier second round gadget.
        let (second_round_message_gadget, second_round_state_gadget) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_second_round(
                cs.ns(|| "verifier_second_round"),
                first_round_state_gadget,
                fs_rng_gadget,
                &second_round_comm_gadgets,
                &second_round_message_gadgets,
            )
            .unwrap();

        // Enforce that the native and gadget verifier second round message is equivalent.

        let expected_beta = NonNativeFieldVar::alloc(cs.ns(|| "beta"), || Ok(second_round_message.beta)).unwrap();

        expected_beta
            .enforce_equal(cs.ns(|| "enforce_equal_beta"), &second_round_message_gadget.beta)
            .unwrap();

        // Enforce that the native and gadget verifier first round state is equivalent.

        assert_eq!(
            second_round_state.first_round_message.is_some(),
            second_round_state_gadget.first_round_msg.is_some()
        );
        assert_eq!(
            second_round_state.second_round_message.is_some(),
            second_round_state_gadget.second_round_msg.is_some()
        );
        assert_eq!(
            second_round_state.gamma.is_none(),
            second_round_state_gadget.gamma.is_none()
        );

        if !cs.is_satisfied() {
            println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_verifier_third_round() {
        let cs = &mut TestConstraintSystem::<Fq>::new();

        let num_variables = 25;
        let num_constraints = 25;

        let (circuit_pk, circuit_vk, proof, public_input) =
            construct_circuit_parameters(num_variables, num_constraints);

        let prepared_circuit_vk = circuit_vk.prepare();

        // Attempt verification.

        let public_input = {
            let domain_x = EvaluationDomain::<Fr>::new(public_input.len() + 1).unwrap();

            let mut unpadded_input = public_input.to_vec();
            unpadded_input.resize(core::cmp::max(public_input.len(), domain_x.size() - 1), Fr::zero());

            unpadded_input
        };

        let is_recursion = MarlinRecursiveMode::RECURSION;
        let fs_rng = &mut FS::new();

        if is_recursion {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME].unwrap());
            fs_rng.absorb_native_field_elements(&compute_vk_hash::<Fr, Fq, MultiPC, FS>(&circuit_vk).unwrap());
            fs_rng.absorb_nonnative_field_elements(&public_input, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME, &circuit_vk, &public_input].unwrap());
        }

        // Start first round.

        let first_commitments = &proof.commitments[0];

        // Construct the gadget components
        let fs_rng_gadget = &mut FSG::constant(cs.ns(|| "alloc_rng"), &fs_rng);

        let mut comm_gadgets = Vec::new();
        let mut message_gadgets = Vec::new();

        for (i, comm) in first_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[0].field_elements.iter().enumerate() {
            let msg_gadget = NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_msg_{}", i)), || Ok(msg)).unwrap();
            message_gadgets.push(msg_gadget);
        }

        // Insert randomness.
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
        // Execute the verifier first round.
        let (_first_round_message, first_round_state) =
            AHPForR1CSNative::verifier_first_round(circuit_pk.circuit.index_info.clone(), fs_rng).unwrap();

        // Execute the verifier first round gadget.
        let (_first_round_message_gadget, first_round_state_gadget) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_first_round(
                cs.ns(|| "verifier_first_round"),
                prepared_circuit_vk.domain_h_size,
                prepared_circuit_vk.domain_k_size,
                fs_rng_gadget,
                &comm_gadgets,
                &message_gadgets,
            )
            .unwrap();

        // Start the second round.

        let second_commitments = &proof.commitments[1];

        // Construct the gadget components for the second round

        let mut second_round_comm_gadgets = Vec::new();
        let mut second_round_message_gadgets = Vec::new();

        for (i, comm) in second_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_second_round_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            second_round_comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[1].field_elements.iter().enumerate() {
            let msg_gadget =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_second_round_msg_{}", i)), || Ok(msg)).unwrap();
            second_round_message_gadgets.push(msg_gadget);
        }

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

        // Execute the verifier second round.
        let (_second_round_message, second_round_state) =
            AHPForR1CSNative::verifier_second_round(first_round_state, fs_rng).unwrap();

        // Execute the verifier second round gadget.
        let (_second_round_message_gadget, second_round_state_gadget) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_second_round(
                cs.ns(|| "verifier_second_round"),
                first_round_state_gadget,
                fs_rng_gadget,
                &second_round_comm_gadgets,
                &second_round_message_gadgets,
            )
            .unwrap();

        // Start third round.

        let third_commitments = &proof.commitments[2];

        // Construct the gadget components for the third round

        let mut third_round_comm_gadgets = Vec::new();
        let mut third_round_message_gadgets = Vec::new();

        for (i, comm) in third_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_third_round_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            third_round_comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[2].field_elements.iter().enumerate() {
            let msg_gadget =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_third_round_msg_{}", i)), || Ok(msg)).unwrap();
            third_round_message_gadgets.push(msg_gadget);
        }

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

        // Execute the verifier third round.
        let third_round_state = AHPForR1CSNative::verifier_third_round(second_round_state, fs_rng).unwrap();

        // Execute the verifier third round gadget.
        let third_round_state_gadget = AHPForR1CS::<_, _, _, MultiPCVar>::verifier_third_round(
            cs.ns(|| "verifier_third_round"),
            second_round_state_gadget,
            fs_rng_gadget,
            &third_round_comm_gadgets,
            &third_round_message_gadgets,
        )
        .unwrap();

        // Enforce that the native and gadget verifier third round message is equivalent.

        let expected_gamma =
            NonNativeFieldVar::alloc(cs.ns(|| "gamma"), || Ok(third_round_state.gamma.unwrap())).unwrap();

        expected_gamma
            .enforce_equal(
                cs.ns(|| "enforce_equal_gamma"),
                &third_round_state_gadget.gamma.clone().unwrap(),
            )
            .unwrap();

        // Enforce that the native and gadget verifier first round state is equivalent.

        assert_eq!(
            third_round_state.first_round_message.is_some(),
            third_round_state_gadget.first_round_msg.is_some()
        );
        assert_eq!(
            third_round_state.second_round_message.is_some(),
            third_round_state_gadget.second_round_msg.is_some()
        );
        assert_eq!(
            third_round_state.gamma.is_some(),
            third_round_state_gadget.gamma.is_some()
        );

        if !cs.is_satisfied() {
            println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_verifier_decision() {
        let cs = &mut TestConstraintSystem::<Fq>::new();

        let num_variables = 25;
        let num_constraints = 25;

        let (circuit_pk, circuit_vk, proof, public_input) =
            construct_circuit_parameters(num_variables, num_constraints);

        // Attempt verification.

        let public_input = {
            let domain_x = EvaluationDomain::<Fr>::new(public_input.len() + 1).unwrap();

            let mut unpadded_input = public_input.to_vec();
            unpadded_input.resize(core::cmp::max(public_input.len(), domain_x.size() - 1), Fr::zero());

            unpadded_input
        };

        let is_recursion = MarlinRecursiveMode::RECURSION;
        let fs_rng = &mut FS::new();

        if is_recursion {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME].unwrap());
            fs_rng.absorb_native_field_elements(&compute_vk_hash::<Fr, Fq, MultiPC, FS>(&circuit_vk).unwrap());
            fs_rng.absorb_nonnative_field_elements(&public_input, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME, &circuit_vk, &public_input].unwrap());
        }

        // Start first round.

        let first_commitments = &proof.commitments[0];

        // Construct the gadget components
        let fs_rng_gadget = &mut FSG::constant(cs.ns(|| "alloc_rng"), &fs_rng);

        let mut comm_gadgets = Vec::new();
        let mut message_gadgets = Vec::new();

        for (i, comm) in first_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[0].field_elements.iter().enumerate() {
            let msg_gadget = NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_msg_{}", i)), || Ok(msg)).unwrap();
            message_gadgets.push(msg_gadget);
        }

        // Insert randomness.
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
        // Execute the verifier first round.
        let (_first_round_message, first_round_state) =
            AHPForR1CSNative::verifier_first_round(circuit_pk.circuit.index_info.clone(), fs_rng).unwrap();

        let (domain_h_size, domain_k_size) = {
            let domain_h = EvaluationDomain::<Fr>::new(circuit_vk.circuit_info.num_constraints)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)
                .unwrap();
            let domain_k = EvaluationDomain::<Fr>::new(circuit_vk.circuit_info.num_non_zero)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)
                .unwrap();

            (domain_h.size(), domain_k.size())
        };

        // Execute the verifier first round gadget.
        let (_first_round_message_gadget, first_round_state_gadget) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_first_round(
                cs.ns(|| "verifier_first_round"),
                domain_h_size as u64,
                domain_k_size as u64,
                fs_rng_gadget,
                &comm_gadgets,
                &message_gadgets,
            )
            .unwrap();

        // Start the second round.

        let second_commitments = &proof.commitments[1];

        // Construct the gadget components for the second round

        let mut second_round_comm_gadgets = Vec::new();
        let mut second_round_message_gadgets = Vec::new();

        for (i, comm) in second_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_second_round_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            second_round_comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[1].field_elements.iter().enumerate() {
            let msg_gadget =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_second_round_msg_{}", i)), || Ok(msg)).unwrap();
            second_round_message_gadgets.push(msg_gadget);
        }

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

        // Execute the verifier second round.
        let (_second_round_message, second_round_state) =
            AHPForR1CSNative::verifier_second_round(first_round_state, fs_rng).unwrap();

        // Execute the verifier second round gadget.
        let (_second_round_message_gadget, second_round_state_gadget) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_second_round(
                cs.ns(|| "verifier_second_round"),
                first_round_state_gadget,
                fs_rng_gadget,
                &second_round_comm_gadgets,
                &second_round_message_gadgets,
            )
            .unwrap();

        // Start third round.

        let third_commitments = &proof.commitments[2];

        // Construct the gadget components for the third round

        let mut third_round_comm_gadgets = Vec::new();
        let mut third_round_message_gadgets = Vec::new();

        for (i, comm) in third_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_third_round_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            third_round_comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[2].field_elements.iter().enumerate() {
            let msg_gadget =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_third_round_msg_{}", i)), || Ok(msg)).unwrap();
            third_round_message_gadgets.push(msg_gadget);
        }

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

        // Execute the verifier third round.
        let third_round_state = AHPForR1CSNative::verifier_third_round(second_round_state, fs_rng).unwrap();

        // Execute the verifier third round gadget.
        let third_round_state_gadget = AHPForR1CS::<_, _, _, MultiPCVar>::verifier_third_round(
            cs.ns(|| "verifier_third_round"),
            second_round_state_gadget,
            fs_rng_gadget,
            &third_round_comm_gadgets,
            &third_round_message_gadgets,
        )
        .unwrap();

        // --------- Native verifier lc

        // Collect degree bounds for commitments. Indexed polynomials have *no*
        // degree bounds because we know the committed index polynomial has the
        // correct degree.
        let (query_set, verifier_state) = AHPForR1CSNative::verifier_query_set(third_round_state, fs_rng, is_recursion);

        if is_recursion {
            fs_rng.absorb_nonnative_field_elements(&proof.evaluations, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&proof.evaluations].unwrap());
        }

        let mut evaluations = Evaluations::new();

        let mut evaluation_labels = Vec::<(String, Fr)>::new();

        for (label, (_point_name, q)) in query_set.iter().cloned() {
            if AHPForR1CSNative::<Fr>::LC_WITH_ZERO_EVAL.contains(&label.as_ref()) {
                evaluations.insert((label, q), Fr::zero());
            } else {
                evaluation_labels.push((label, q));
            }
        }
        evaluation_labels.sort_by(|a, b| a.0.cmp(&b.0));
        for (q, eval) in evaluation_labels.into_iter().zip(&proof.evaluations) {
            evaluations.insert(q, *eval);
        }

        let lc_s =
            AHPForR1CSNative::construct_linear_combinations(&public_input, &evaluations, &verifier_state, is_recursion)
                .unwrap();

        // ---------

        // Construct the final construction of the verifier linear combination.

        // Construct the public input

        let mut public_input_gadget = vec![];

        for (i, input) in public_input.iter().enumerate() {
            let input = NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_input_{}", i)), || Ok(input)).unwrap();

            public_input_gadget.push(input);
        }

        let mut formatted_public_input = vec![NonNativeFieldVar::one(cs.ns(|| "nonnative_one")).unwrap()];
        for elem in public_input_gadget.iter().cloned() {
            formatted_public_input.push(elem);
        }

        let vk_gadget =
            CircuitVerifyingKeyVar::<_, _, _, MultiPCVar>::alloc(cs.ns(|| "alloc_prepared_vk"), || Ok(circuit_vk))
                .unwrap();

        let proof_gadget =
            ProofVar::<_, _, _, MultiPCVar>::alloc(cs.ns(|| "proof_gadget"), || Ok(proof.clone())).unwrap();

        let lc_gadgets = AHPForR1CS::<_, _, _, MultiPCVar>::verifier_decision(
            cs.ns(|| "verifier_decision"),
            &formatted_public_input,
            &proof_gadget.evaluations,
            third_round_state_gadget.clone(),
            &vk_gadget.domain_k_size_gadget,
        )
        .unwrap();

        // Check that the native and gadget linear combination is equivalent

        for (i, (native_lc, lc)) in lc_s.iter().zip(lc_gadgets).enumerate() {
            let expected_lc =
                LinearCombinationVar::alloc(cs.ns(|| format!("alloc_lc_{}", i)), || Ok(native_lc)).unwrap();

            assert_eq!(expected_lc.label, lc.label);

            for (j, ((expected_lc_coeff, expected_lc_term), (lc_coeff, lc_term))) in
                expected_lc.terms.iter().zip(lc.terms).enumerate()
            {
                assert_eq!(expected_lc_term, &lc_term);

                match (expected_lc_coeff, &lc_coeff) {
                    (LinearCombinationCoeffVar::MinusOne, LinearCombinationCoeffVar::MinusOne) => {}
                    (LinearCombinationCoeffVar::One, LinearCombinationCoeffVar::One) => {}
                    (LinearCombinationCoeffVar::Var(expected_coeff), LinearCombinationCoeffVar::Var(coeff)) => {
                        expected_coeff
                            .enforce_equal(cs.ns(|| format!("enforce_eq_coeff_{}_{}", i, j)), &coeff)
                            .unwrap();
                    }
                    (LinearCombinationCoeffVar::Var(expected_coeff), LinearCombinationCoeffVar::One) => {
                        let one = NonNativeFieldVar::one(cs.ns(|| format!("testing_{}_{}", i, j))).unwrap();
                        expected_coeff
                            .enforce_equal(cs.ns(|| format!("enforce_eq_coeff_one_{}_{}", i, j)), &one)
                            .unwrap();
                    }
                    (_, _) => {
                        println!(
                            "Mismatched linear combination coeff_{}_{} \n{:?} \n{:?}",
                            i, j, expected_lc_coeff, lc_coeff
                        );
                        assert_eq!(0, 1);
                    }
                }
            }
        }

        if !cs.is_satisfied() {
            println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_verifier_comm_query_eval_set() {
        let cs = &mut TestConstraintSystem::<Fq>::new();

        let num_variables = 25;
        let num_constraints = 25;

        let (circuit_pk, circuit_vk, proof, public_input) =
            construct_circuit_parameters(num_variables, num_constraints);

        // Attempt verification.

        let public_input = {
            let domain_x = EvaluationDomain::<Fr>::new(public_input.len() + 1).unwrap();

            let mut unpadded_input = public_input.to_vec();
            unpadded_input.resize(core::cmp::max(public_input.len(), domain_x.size() - 1), Fr::zero());

            unpadded_input
        };

        let is_recursion = MarlinRecursiveMode::RECURSION;
        let fs_rng = &mut FS::new();

        if is_recursion {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME].unwrap());
            fs_rng.absorb_native_field_elements(&compute_vk_hash::<Fr, Fq, MultiPC, FS>(&circuit_vk).unwrap());
            fs_rng.absorb_nonnative_field_elements(&public_input, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&MarlinInst::PROTOCOL_NAME, &circuit_vk, &public_input].unwrap());
        }

        // Start first round.

        let first_commitments = &proof.commitments[0];

        // Construct the gadget components
        let fs_rng_gadget = &mut FSG::constant(cs.ns(|| "alloc_rng"), &fs_rng);

        let mut comm_gadgets = Vec::new();
        let mut message_gadgets = Vec::new();

        for (i, comm) in first_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[0].field_elements.iter().enumerate() {
            let msg_gadget = NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_msg_{}", i)), || Ok(msg)).unwrap();
            message_gadgets.push(msg_gadget);
        }

        // Insert randomness.
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
        // Execute the verifier first round.
        let (_first_round_message, first_round_state) =
            AHPForR1CSNative::verifier_first_round(circuit_pk.circuit.index_info.clone(), fs_rng).unwrap();

        let (domain_h_size, domain_k_size) = {
            let domain_h = EvaluationDomain::<Fr>::new(circuit_vk.circuit_info.num_constraints)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)
                .unwrap();
            let domain_k = EvaluationDomain::<Fr>::new(circuit_vk.circuit_info.num_non_zero)
                .ok_or(SynthesisError::PolynomialDegreeTooLarge)
                .unwrap();

            (domain_h.size(), domain_k.size())
        };

        // Execute the verifier first round gadget.
        let (_first_round_message_gadget, first_round_state_gadget) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_first_round(
                cs.ns(|| "verifier_first_round"),
                domain_h_size as u64,
                domain_k_size as u64,
                fs_rng_gadget,
                &comm_gadgets,
                &message_gadgets,
            )
            .unwrap();

        // Start the second round.

        let second_commitments = &proof.commitments[1];

        // Construct the gadget components for the second round

        let mut second_round_comm_gadgets = Vec::new();
        let mut second_round_message_gadgets = Vec::new();

        for (i, comm) in second_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_second_round_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            second_round_comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[1].field_elements.iter().enumerate() {
            let msg_gadget =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_second_round_msg_{}", i)), || Ok(msg)).unwrap();
            second_round_message_gadgets.push(msg_gadget);
        }

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

        // Execute the verifier second round.
        let (_second_round_message, second_round_state) =
            AHPForR1CSNative::verifier_second_round(first_round_state, fs_rng).unwrap();

        // Execute the verifier second round gadget.
        let (_second_round_message_gadget, second_round_state_gadget) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_second_round(
                cs.ns(|| "verifier_second_round"),
                first_round_state_gadget,
                fs_rng_gadget,
                &second_round_comm_gadgets,
                &second_round_message_gadgets,
            )
            .unwrap();

        // Start third round.

        let third_commitments = &proof.commitments[2];

        // Construct the gadget components for the third round

        let mut third_round_comm_gadgets = Vec::new();
        let mut third_round_message_gadgets = Vec::new();

        for (i, comm) in third_commitments.iter().enumerate() {
            let commitment_gagdet = CommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_third_round_comm_{}", i)),
                || Ok(comm.clone()),
            )
            .unwrap();
            third_round_comm_gadgets.push(commitment_gagdet);
        }

        for (i, msg) in proof.prover_messages[2].field_elements.iter().enumerate() {
            let msg_gadget =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_third_round_msg_{}", i)), || Ok(msg)).unwrap();
            third_round_message_gadgets.push(msg_gadget);
        }

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

        // Execute the verifier third round.
        let third_round_state = AHPForR1CSNative::verifier_third_round(second_round_state, fs_rng).unwrap();

        // Execute the verifier third round gadget.
        let third_round_state_gadget = AHPForR1CS::<_, _, _, MultiPCVar>::verifier_third_round(
            cs.ns(|| "verifier_third_round"),
            second_round_state_gadget,
            fs_rng_gadget,
            &third_round_comm_gadgets,
            &third_round_message_gadgets,
        )
        .unwrap();

        // --------- Native verifier lc

        // Collect degree bounds for commitments. Indexed polynomials have *no*
        // degree bounds because we know the committed index polynomial has the
        // correct degree.
        let (query_set, verifier_state) = AHPForR1CSNative::verifier_query_set(third_round_state, fs_rng, is_recursion);

        if is_recursion {
            fs_rng.absorb_nonnative_field_elements(&proof.evaluations, OptimizationType::Weight);
        } else {
            fs_rng.absorb_bytes(&to_bytes_le![&proof.evaluations].unwrap());
        }

        let mut evaluations = Evaluations::new();

        let mut evaluation_labels = Vec::<(String, Fr)>::new();

        for (label, (_point_name, q)) in query_set.iter().cloned() {
            if AHPForR1CSNative::<Fr>::LC_WITH_ZERO_EVAL.contains(&label.as_ref()) {
                evaluations.insert((label, q), Fr::zero());
            } else {
                evaluation_labels.push((label, q));
            }
        }
        evaluation_labels.sort_by(|a, b| a.0.cmp(&b.0));
        for (q, eval) in evaluation_labels.into_iter().zip(&proof.evaluations) {
            evaluations.insert(q, *eval);
        }

        let vk_gadget =
            CircuitVerifyingKeyVar::<_, _, _, MultiPCVar>::alloc(cs.ns(|| "alloc_vk"), || Ok(circuit_vk.clone()))
                .unwrap();

        let prepared_vk_gadget: PreparedCircuitVerifyingKeyVar<_, _, _, _, FS, FSG> =
            vk_gadget.prepare(cs.ns(|| "prepare_vk")).unwrap();

        let proof_gadget =
            ProofVar::<_, _, _, MultiPCVar>::alloc(cs.ns(|| "proof_gadget"), || Ok(proof.clone())).unwrap();

        // Test verifier_comm_query_eval_set.

        // Construct native commitments

        // Collect degree bounds for commitments. Indexed polynomials have *no*
        // degree bounds because we know the committed index polynomial has the
        // correct degree.
        let index_info = circuit_vk.circuit_info;
        let degree_bounds = vec![None; circuit_vk.circuit_commitments.len()]
            .into_iter()
            .chain(AHPForR1CSNative::prover_first_round_degree_bounds(&index_info))
            .chain(AHPForR1CSNative::prover_second_round_degree_bounds(&index_info))
            .chain(AHPForR1CSNative::prover_third_round_degree_bounds(&index_info));

        let polynomial_labels: Vec<String> = if is_recursion {
            AHPForR1CSNative::<Fr>::polynomial_labels_with_vanishing().collect()
        } else {
            AHPForR1CSNative::<Fr>::polynomial_labels().collect()
        };

        // Gather commitments in one vector.
        let commitments: Vec<_> = circuit_vk
            .iter()
            .chain(first_commitments)
            .chain(second_commitments)
            .chain(third_commitments)
            .cloned()
            .zip(polynomial_labels)
            .zip(degree_bounds)
            .map(|((c, l), d)| LabeledCommitment::new(l, c, d))
            .collect();

        let (num_opening_challenges, num_batching_rands, comm_gadgets, query_set_gadgets, evaluation_gadgets) =
            AHPForR1CS::<_, _, _, MultiPCVar>::verifier_comm_query_eval_set(
                cs.ns(|| "verifier_comm_query_eval_set"),
                &prepared_vk_gadget,
                &proof_gadget,
                &third_round_state_gadget,
            )
            .unwrap();

        assert_eq!(num_opening_challenges, 7);
        assert_eq!(num_batching_rands, 2);

        let (query_set_native, _verifier_state_native) =
            AHPForR1CSNative::<Fr>::verifier_query_set(verifier_state, fs_rng, true);

        // Check that the query sets are equivalent

        let mut sorted_query_set_gadgets: Vec<_> = query_set_gadgets.0.iter().collect();
        sorted_query_set_gadgets.sort_by(|a, b| a.0.cmp(&b.0));

        for (i, ((label, (_query_point_name, query_native)), query_gadget)) in
            query_set_native.iter().zip(sorted_query_set_gadgets).enumerate()
        {
            assert_eq!(label.clone(), query_gadget.0);

            let expected_query =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_query{}", i)), || Ok(query_native)).unwrap();

            expected_query
                .enforce_equal(cs.ns(|| format!("enforce_eq_query_{}", i)), &query_gadget.1.value)
                .unwrap();
        }

        // Check that the commitments are equivalent

        // let mut sorted_query_set_gadgets: Vec<_> = query_set_gadgets.0.iter().collect();
        // sorted_query_set_gadgets.sort_by(|a, b| a.0.cmp(&b.0));

        for (i, (commitment_native, commitment_gadget)) in commitments.iter().zip(comm_gadgets).enumerate() {
            // Check the label

            assert_eq!(commitment_native.label(), &commitment_gadget.label);

            // Check the commitment values
            let expected_commitment = LabeledCommitmentVar::<Bls12_377, BW6_761, Bls12_377PairingGadget>::alloc(
                cs.ns(|| format!("alloc_commitment_{}", i)),
                || Ok(commitment_native),
            )
            .unwrap();

            let expected_prepared_commitment = expected_commitment
                .commitment
                .prepare(cs.ns(|| format!("prepare_comm_{}", i)))
                .unwrap();

            expected_prepared_commitment
                .prepared_comm
                .enforce_equal(
                    cs.ns(|| format!("enforce_eq_commitment_comm{}", i)),
                    &commitment_gadget.prepared_commitment.prepared_comm,
                )
                .unwrap();

            assert_eq!(
                expected_prepared_commitment.shifted_comm.is_some(),
                commitment_gadget.prepared_commitment.shifted_comm.is_some()
            );

            if let (Some(expected_shifted_comm), Some(shifted_comm)) = (
                expected_prepared_commitment.shifted_comm,
                commitment_gadget.prepared_commitment.shifted_comm,
            ) {
                expected_shifted_comm
                    .enforce_equal(
                        cs.ns(|| format!("enforce_eq_commitment_shifted_comm{}", i)),
                        &shifted_comm,
                    )
                    .unwrap();
            }

            // Check degree bound.

            assert_eq!(
                expected_commitment.degree_bound.is_some(),
                commitment_gadget.degree_bound.is_some()
            );

            if let (Some(expected_degree_bound), Some(degree_bound_gadget)) =
                (expected_commitment.degree_bound, commitment_gadget.degree_bound)
            {
                expected_degree_bound
                    .enforce_equal(
                        cs.ns(|| format!("degree_bound_enforce_equal_{}", i)),
                        &degree_bound_gadget,
                    )
                    .unwrap();
            }
        }

        // Check that the evaluations are equivalent

        let mut sorted_evaluation_gadgets: Vec<_> = evaluation_gadgets.0.iter().collect();
        sorted_evaluation_gadgets.sort_by(|a, b| a.0.name.cmp(&b.0.name));

        for (i, (evaluation_native, evaluation_gadget)) in evaluations.iter().zip(sorted_evaluation_gadgets).enumerate()
        {
            assert_eq!(evaluation_native.0.0, evaluation_gadget.0.name);

            let expected_eval_key =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_eval_key_{}", i)), || Ok(evaluation_native.0.1))
                    .unwrap();

            let expected_eval_value =
                NonNativeFieldVar::alloc(cs.ns(|| format!("alloc_eval_value_{}", i)), || Ok(evaluation_native.1))
                    .unwrap();

            expected_eval_key
                .enforce_equal(
                    cs.ns(|| format!("enforce_eq_eval_key_{}", i)),
                    &evaluation_gadget.0.value,
                )
                .unwrap();

            expected_eval_value
                .enforce_equal(cs.ns(|| format!("enforce_eq_eval_value_{}", i)), &evaluation_gadget.1)
                .unwrap();
        }

        if !cs.is_satisfied() {
            println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
        }

        assert!(cs.is_satisfied());
    }
}
