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

use super::{r1cs_to_sap::R1CStoSAP, ProvingKey, VerifyingKey};
use crate::{fft::EvaluationDomain, msm::FixedBaseMSM};
use snarkvm_curves::traits::{PairingEngine, ProjectiveCurve};
use snarkvm_fields::{Field, One, PrimeField, Zero};
use snarkvm_r1cs::{
    errors::SynthesisError,
    ConstraintSynthesizer,
    ConstraintSystem,
    Index,
    LinearCombination,
    OptimizationGoal,
    Variable,
};
use snarkvm_utilities::rand::UniformRand;

use core::ops::Mul;
use rand::Rng;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Generates a random common reference string for a circuit.
pub fn generate_random_parameters<E, C, R>(circuit: &C, rng: &mut R) -> Result<ProvingKey<E>, SynthesisError>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
{
    let alpha = E::Fr::rand(rng);
    let beta = E::Fr::rand(rng);
    let gamma = E::Fr::one();
    let g = E::G1Projective::rand(rng);
    let h = E::G2Projective::rand(rng);

    generate_parameters::<E, C, R>(circuit, alpha, beta, gamma, g, h, rng)
}

/// This is our assembly structure that we'll use to synthesize the
/// circuit into a SAP.
pub struct KeypairAssembly<E: PairingEngine> {
    pub num_public_variables: usize,
    pub num_private_variables: usize,
    pub num_constraints: usize,
    pub at: Vec<Vec<(E::Fr, Index)>>,
    pub bt: Vec<Vec<(E::Fr, Index)>>,
    pub ct: Vec<Vec<(E::Fr, Index)>>,
    pub optimization_goal: OptimizationGoal,
}

impl<E: PairingEngine> ConstraintSystem<E::Fr> for KeypairAssembly<E> {
    type Root = Self;

    #[inline]
    fn alloc<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        // There is no assignment, so we don't invoke the
        // function for obtaining one.

        let index = self.num_private_variables;
        self.num_private_variables += 1;

        Ok(Variable::new_unchecked(Index::Private(index)))
    }

    #[inline]
    fn alloc_input<F, A, AR>(&mut self, _: A, _: F) -> Result<Variable, SynthesisError>
    where
        F: FnOnce() -> Result<E::Fr, SynthesisError>,
        A: FnOnce() -> AR,
        AR: AsRef<str>,
    {
        // There is no assignment, so we don't invoke the
        // function for obtaining one.

        let index = self.num_public_variables;
        self.num_public_variables += 1;

        Ok(Variable::new_unchecked(Index::Public(index)))
    }

    fn enforce<A, AR, LA, LB, LC>(&mut self, _: A, a: LA, b: LB, c: LC)
    where
        A: FnOnce() -> AR,
        AR: AsRef<str>,
        LA: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LB: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
        LC: FnOnce(LinearCombination<E::Fr>) -> LinearCombination<E::Fr>,
    {
        fn eval<E: PairingEngine>(
            l: LinearCombination<E::Fr>,
            constraints: &mut [Vec<(E::Fr, Index)>],
            this_constraint: usize,
        ) {
            for (var, coeff) in l.as_ref() {
                match var.get_unchecked() {
                    Index::Public(i) => constraints[this_constraint].push((*coeff, Index::Public(i))),
                    Index::Private(i) => constraints[this_constraint].push((*coeff, Index::Private(i))),
                }
            }
        }

        self.at.push(vec![]);
        self.bt.push(vec![]);
        self.ct.push(vec![]);

        eval::<E>(a(LinearCombination::zero()), &mut self.at, self.num_constraints);
        eval::<E>(b(LinearCombination::zero()), &mut self.bt, self.num_constraints);
        eval::<E>(c(LinearCombination::zero()), &mut self.ct, self.num_constraints);

        self.num_constraints += 1;
    }

    fn push_namespace<NR, N>(&mut self, _: N)
    where
        NR: AsRef<str>,
        N: FnOnce() -> NR,
    {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn pop_namespace(&mut self) {
        // Do nothing; we don't care about namespaces in this context.
    }

    fn get_root(&mut self) -> &mut Self::Root {
        self
    }

    fn num_constraints(&self) -> usize {
        self.num_constraints
    }

    fn num_public_variables(&self) -> usize {
        self.num_public_variables
    }

    fn num_private_variables(&self) -> usize {
        self.num_private_variables
    }

    fn optimization_goal(&self) -> OptimizationGoal {
        self.optimization_goal.clone()
    }

    fn set_optimization_goal(&mut self, goal: OptimizationGoal) {
        // `set_optimization_type` should only be executed before any constraint or value is created.
        assert_eq!(self.num_public_variables(), 0);
        assert_eq!(self.num_private_variables(), 0);
        assert_eq!(self.num_constraints(), 0);

        self.optimization_goal = goal;
    }
}

/// Create parameters for a circuit, given some toxic waste.
#[allow(clippy::many_single_char_names)]
pub fn generate_parameters<E, C, R>(
    circuit: &C,
    alpha: E::Fr,
    beta: E::Fr,
    gamma: E::Fr,
    g: E::G1Projective,
    h: E::G2Projective,
    rng: &mut R,
) -> Result<ProvingKey<E>, SynthesisError>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    R: Rng,
{
    let mut assembly = KeypairAssembly {
        num_public_variables: 0,
        num_private_variables: 0,
        num_constraints: 0,
        at: vec![],
        bt: vec![],
        ct: vec![],
        optimization_goal: OptimizationGoal::Constraints,
    };

    // Allocate the "one" input variable
    assembly.alloc_input(|| "", || Ok(E::Fr::one()))?;

    // Synthesize the circuit.
    let synthesis_time = start_timer!(|| "Constraint synthesis");
    circuit.generate_constraints(&mut assembly)?;
    end_timer!(synthesis_time);

    ///////////////////////////////////////////////////////////////////////////
    let domain_time = start_timer!(|| "Constructing evaluation domain");

    let domain_size = 2 * assembly.num_constraints + 2 * assembly.num_public_variables - 1;
    let domain = EvaluationDomain::<E::Fr>::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
    let t = domain.sample_element_outside_domain(rng);

    end_timer!(domain_time);
    ///////////////////////////////////////////////////////////////////////////

    let reduction_time = start_timer!(|| "R1CS to SAP Instance Map with Evaluation");
    let (a, c, zt, sap_num_variables, m_raw) = R1CStoSAP::instance_map_with_evaluation::<E>(&assembly, &t)?;
    end_timer!(reduction_time);

    // Compute query densities
    let non_zero_a = cfg_into_iter!(0..sap_num_variables)
        .map(|i| (!a[i].is_zero()) as usize)
        .sum();
    let scalar_bits = E::Fr::size_in_bits();

    // Compute G window table
    let g_window_time = start_timer!(|| "Compute G window table");
    let g_window = FixedBaseMSM::get_mul_window_size(
        // Verifier query
        assembly.num_public_variables
        // A query
        + non_zero_a
        // C query 1
        + (sap_num_variables - (assembly.num_public_variables - 1))
        // C query 2
        + sap_num_variables + 1
        // G gamma2 Z t
        + m_raw + 1,
    );
    let g_table = FixedBaseMSM::get_window_table::<E::G1Projective>(scalar_bits, g_window, g);
    end_timer!(g_window_time);

    // Generate the R1CS proving key
    let proving_key_time = start_timer!(|| "Generate the R1CS proving key");

    // Compute the A-query
    let a_time = start_timer!(|| "Calculate A");
    let mut a_query = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
        scalar_bits,
        g_window,
        &g_table,
        &cfg_iter!(a).map(|a| *a * gamma).collect::<Vec<_>>(),
    );
    end_timer!(a_time);

    // Compute the G_gamma-query
    let g_gamma_time = start_timer!(|| "Calculate G gamma");
    let gamma_z = zt * gamma;
    let alpha_beta = alpha + beta;
    let ab_gamma_z = alpha_beta * gamma * zt;
    let g_gamma = g.into_affine().mul(gamma);
    let g_gamma_z = g.into_affine().mul(gamma_z);
    let h_gamma = h.into_affine().mul(gamma);
    let h_gamma_z = h_gamma.mul(zt);
    let g_ab_gamma_z = g.into_affine().mul(ab_gamma_z);
    let g_gamma2_z2 = g.into_affine().mul(gamma_z.square());

    // Compute the vector G_gamma2_z_t := Z(t) * t^i * gamma^2 * G
    let gamma2_z_t = gamma_z * gamma;
    let mut g_gamma2_z_t = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
        scalar_bits,
        g_window,
        &g_table,
        &cfg_into_iter!(0..m_raw + 1)
            .map(|i| gamma2_z_t * (t.pow([i as u64])))
            .collect::<Vec<_>>(),
    );
    end_timer!(g_gamma_time);

    // Compute the C_1-query
    let c1_time = start_timer!(|| "Calculate C1");
    let mut result = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
        scalar_bits,
        g_window,
        &g_table,
        &cfg_into_iter!(0..sap_num_variables + 1)
            .map(|i| c[i] * gamma + (a[i] * alpha_beta))
            .collect::<Vec<_>>(),
    );
    let (verifier_query, c_query_1) = result.split_at_mut(assembly.num_public_variables);
    end_timer!(c1_time);

    // Compute the C_2-query
    let c2_time = start_timer!(|| "Calculate C2");
    let double_gamma2_z = (zt * gamma.square()).double();
    let mut c_query_2 = FixedBaseMSM::multi_scalar_mul::<E::G1Projective>(
        scalar_bits,
        g_window,
        &g_table,
        &cfg_into_iter!(0..sap_num_variables + 1)
            .map(|i| a[i] * double_gamma2_z)
            .collect::<Vec<_>>(),
    );
    drop(g_table);
    end_timer!(c2_time);

    // Compute H_gamma window table
    let h_gamma_time = start_timer!(|| "Compute H table");
    let h_gamma_window = FixedBaseMSM::get_mul_window_size(non_zero_a);
    let h_gamma_table = FixedBaseMSM::get_window_table::<E::G2Projective>(scalar_bits, h_gamma_window, h_gamma.into());
    end_timer!(h_gamma_time);

    // Compute the B-query
    let b_time = start_timer!(|| "Calculate B");
    let mut b_query =
        FixedBaseMSM::multi_scalar_mul::<E::G2Projective>(scalar_bits, h_gamma_window, &h_gamma_table, &a);
    end_timer!(b_time);

    end_timer!(proving_key_time);

    // Generate R1CS verification key
    let verifying_key_time = start_timer!(|| "Generate the R1CS verifying key");
    let g_alpha = g.into_affine().mul(alpha);
    let h_beta = h.into_affine().mul(beta);
    end_timer!(verifying_key_time);

    let vk = VerifyingKey::<E> {
        h_g2: h.into_affine(),
        g_alpha_g1: g_alpha,
        h_beta_g2: h_beta,
        g_gamma_g1: g_gamma,
        h_gamma_g2: h_gamma,
        query: cfg_into_iter!(verifier_query).map(|e| e.into_affine()).collect(),
    };

    let batch_normalization_time = start_timer!(|| "Convert proving key elements to affine");
    E::G1Projective::batch_normalization(a_query.as_mut_slice());
    E::G2Projective::batch_normalization(b_query.as_mut_slice());
    E::G1Projective::batch_normalization(c_query_1);
    E::G1Projective::batch_normalization(c_query_2.as_mut_slice());
    E::G1Projective::batch_normalization(g_gamma2_z_t.as_mut_slice());
    end_timer!(batch_normalization_time);

    Ok(ProvingKey {
        vk,
        a_query: a_query.into_iter().map(Into::into).collect(),
        b_query: b_query.into_iter().map(Into::into).collect(),
        c_query_1: c_query_1.iter().copied().map(Into::into).collect(),
        c_query_2: c_query_2.into_iter().map(Into::into).collect(),
        g_gamma_z,
        h_gamma_z,
        g_ab_gamma_z,
        g_gamma2_z2,
        g_gamma2_z_t: g_gamma2_z_t.into_iter().map(Into::into).collect(),
    })
}
