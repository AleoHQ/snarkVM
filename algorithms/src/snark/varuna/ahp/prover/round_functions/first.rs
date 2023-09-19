// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeMap;

use crate::{
    fft::{
        domain::{FFTPrecomputation, IFFTPrecomputation},
        DensePolynomial,
        EvaluationDomain,
        Evaluations as EvaluationsOnDomain,
        SparsePolynomial,
    },
    polycommit::sonic_pc::{LabeledPolynomial, PolynomialInfo, PolynomialLabel},
    snark::varuna::{ahp::AHPError, prover, verifier, witness_label, AHPForR1CS, CircuitId, CircuitInfo, SNARKMode},
    AlgebraicSponge,
};
use itertools::Itertools;
use rand_core::RngCore;
use snarkvm_fields::PrimeField;
use snarkvm_utilities::cfg_into_iter;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

impl<F: PrimeField, MM: SNARKMode> AHPForR1CS<F, MM> {
    /// Output the number of oracles sent by the prover in the first round.
    pub fn num_first_round_oracles(total_batch_size: usize) -> usize {
        total_batch_size + (MM::ZK as usize)
    }

    /// Output the degree bounds of oracles in the first round.
    pub fn first_round_polynomial_info<'a>(
        circuits: impl Iterator<Item = (&'a CircuitId, &'a usize)>,
    ) -> BTreeMap<PolynomialLabel, PolynomialInfo> {
        let mut polynomials = circuits
            .flat_map(|(&circuit_id, &batch_size)| {
                (0..batch_size)
                    .flat_map(move |i| [PolynomialInfo::new(witness_label(circuit_id, "w", i), None, Self::zk_bound())])
            })
            .collect::<Vec<_>>();
        if MM::ZK {
            polynomials.push(PolynomialInfo::new("mask_poly".to_string(), None, None));
        }
        polynomials.into_iter().map(|info| (info.label().into(), info)).collect()
    }
}

impl<'a, F: PrimeField, MM: SNARKMode> prover::State<'a, F, MM> {
    pub fn first_round<R: RngCore>(&mut self, rng: &mut R) -> Result<(), AHPError> {
        let round_time = start_timer!(|| "AHP::Prover::FirstRound");
        let fft_precomp = self.fft_precomputation;
        let ifft_precomp = self.ifft_precomputation;
        let mut job_pool = snarkvm_utilities::ExecutionPool::with_capacity(self.total_instances);
        for (circuit, circuit_state) in self.circuit_specific_states.iter_mut() {
            let batch_size = circuit_state.batch_size;

            let private_variables = core::mem::take(&mut circuit_state.private_variables);
            let x_polys = circuit_state.x_polys.clone();
            assert_eq!(private_variables.len(), batch_size);
            assert_eq!(x_polys.len(), batch_size);

            let v_domain = circuit_state.variable_domain;
            let i_domain = circuit_state.input_domain;

            for (j, (private_vars, x_poly)) in itertools::izip!(private_variables, x_polys).enumerate() {
                let w_label = witness_label(circuit.id, "w", j);
                job_pool.add_job(move || {
                    Self::calculate_w(w_label, private_vars, x_poly, v_domain, i_domain, fft_precomp, ifft_precomp)
                });
            }
        }
        let mut batches =
            job_pool.execute_all().into_iter().map(|w_poly| prover::WitnessPoly(w_poly)).collect::<Vec<_>>();
        assert_eq!(batches.len(), self.total_instances);

        let mut circuit_specific_batches = BTreeMap::new();
        for (circuit, state) in self.circuit_specific_states.iter_mut() {
            let batches = batches.drain(0..state.batch_size).collect_vec();
            circuit_specific_batches.insert(circuit.id, batches);
            end_timer!(round_time);
        }
        let mask_poly = MM::ZK.then(|| Self::calculate_mask_poly(self.max_variable_domain, rng));
        let oracles = prover::FirstOracles { batches: circuit_specific_batches, mask_poly };
        assert!(oracles.matches_info(&AHPForR1CS::<F, MM>::first_round_polynomial_info(
            self.circuit_specific_states.iter().map(|(c, s)| (&c.id, &s.batch_size))
        )));
        self.first_round_oracles = Some(oracles);
        Ok(())
    }

    fn calculate_mask_poly<R: RngCore>(variable_domain: EvaluationDomain<F>, rng: &mut R) -> LabeledPolynomial<F> {
        assert!(MM::ZK);
        let mask_poly_time = start_timer!(|| "Computing mask polynomial");
        // We'll use the masking technique from Lunar (https://eprint.iacr.org/2020/1069.pdf, pgs 20-22).
        let h_1_mask = DensePolynomial::rand(3, rng).coeffs; // selected arbitrarily.
        let h_1_mask = SparsePolynomial::from_coefficients(h_1_mask.into_iter().enumerate())
            .mul(&variable_domain.vanishing_polynomial());
        assert_eq!(h_1_mask.degree(), variable_domain.size() + 3);
        // multiply g_1_mask by X
        let mut g_1_mask = DensePolynomial::rand(5, rng);
        g_1_mask.coeffs[0] = F::zero();
        let g_1_mask = SparsePolynomial::from_coefficients(
            g_1_mask.coeffs.into_iter().enumerate().filter(|(_, coeff)| !coeff.is_zero()),
        );

        let mut mask_poly = h_1_mask;
        mask_poly += &g_1_mask;
        debug_assert!(variable_domain.elements().map(|z| mask_poly.evaluate(z)).sum::<F>().is_zero());
        assert_eq!(mask_poly.degree(), variable_domain.size() + 3);
        assert!(mask_poly.degree() <= 2 * variable_domain.size() + 2 * Self::zk_bound().unwrap() - 3);

        end_timer!(mask_poly_time);
        LabeledPolynomial::new("mask_poly".to_string(), mask_poly, None, None)
    }

    fn calculate_w(
        label: String,
        private_variables: Vec<F>,
        x_poly: DensePolynomial<F>,
        variable_domain: EvaluationDomain<F>,
        input_domain: EvaluationDomain<F>,
        fft_precomp: &'a FFTPrecomputation<F>,
        ifft_precomp: &'a IFFTPrecomputation<F>,
    ) -> Witness<F> {
        let mut w_extended = private_variables;
        let ratio = variable_domain.size() / input_domain.size();
        w_extended.resize(variable_domain.size() - input_domain.size(), F::zero());

        let x_evals = {
            let mut coeffs = x_poly.coeffs;
            coeffs.resize(variable_domain.size(), F::zero());
            variable_domain.in_order_fft_in_place_with_pc(&mut coeffs, fft_precomp);
            coeffs
        };

        let w_poly_time = start_timer!(|| "Computing w polynomial");
        let w_poly_evals = cfg_into_iter!(0..variable_domain.size())
            .map(|k| match k % ratio {
                0 => F::zero(),
                _ => w_extended[k - (k / ratio) - 1] - x_evals[k],
            })
            .collect();
        let w_poly =
            EvaluationsOnDomain::from_vec_and_domain(w_poly_evals, variable_domain).interpolate_with_pc(ifft_precomp);
        let (w_poly, remainder) = w_poly.divide_by_vanishing_poly(input_domain).unwrap();
        assert!(remainder.is_zero());

        assert!(w_poly.degree() < variable_domain.size() - input_domain.size());
        end_timer!(w_poly_time);
        LabeledPolynomial::new(label, w_poly, None, Self::zk_bound())
    }

    pub fn verifier_first_round<Fq: PrimeField, R: AlgebraicSponge<Fq, 2>>(
        &mut self,
        batch_sizes: &BTreeMap<CircuitId, usize>,
        circuit_infos: &BTreeMap<CircuitId, &CircuitInfo>,
        max_constraint_domain: EvaluationDomain<F>,
        max_variable_domain: EvaluationDomain<F>,
        max_non_zero_domain: EvaluationDomain<F>,
        fs_rng: &mut R,
    ) -> Result<(), AHPError> {
        let mut verifier_state = verifier::State::<F, MM>::new(
            batch_sizes,
            circuit_infos,
            max_constraint_domain,
            max_variable_domain,
            max_non_zero_domain,
        )?;
        verifier_state.first_round(fs_rng)?;
        self.verifier_state = Some(verifier_state);
        Ok(())
    }
}

pub type Witness<F> = LabeledPolynomial<F>;
