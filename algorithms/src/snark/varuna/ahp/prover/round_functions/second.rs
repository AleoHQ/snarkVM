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
        domain::IFFTPrecomputation,
        polynomial::PolyMultiplier,
        DensePolynomial,
        EvaluationDomain,
        Evaluations as EvaluationsOnDomain,
    },
    polycommit::sonic_pc::{LabeledPolynomial, PolynomialInfo, PolynomialLabel},
    snark::varuna::{ahp::verifier, prover, witness_label, AHPError, AHPForR1CS, SNARKMode},
    AlgebraicSponge,
};
use anyhow::{anyhow, Result};
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{cfg_into_iter, cfg_iter_mut, cfg_reduce, ExecutionPool};

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

impl<F: PrimeField, MM: SNARKMode> AHPForR1CS<F, MM> {
    /// Output the number of oracles sent by the prover in the second round.
    pub const fn num_second_round_oracles() -> usize {
        1
    }

    /// Output the degree bounds of oracles in the second round.
    pub fn second_round_polynomial_info() -> BTreeMap<PolynomialLabel, PolynomialInfo> {
        [PolynomialInfo::new("h_0".into(), None, None)].into_iter().map(|info| (info.label().into(), info)).collect()
    }
}

impl<'a, F: PrimeField, MM: SNARKMode> prover::State<'a, F, MM> {
    pub fn second_round(&mut self) -> Result<prover::SecondOracles<F>> {
        let round_time = start_timer!(|| "AHP::Prover::SecondRound");

        let zk_bound = Self::zk_bound();

        let max_constraint_domain = self.max_constraint_domain;

        let h_0 = self.calculate_rowcheck_witness()?;

        assert!(h_0.degree() <= 2 * max_constraint_domain.size() + 2 * zk_bound.unwrap_or(0) - 2);

        let oracles = prover::SecondOracles { h_0: LabeledPolynomial::new("h_0", h_0, None, None) };
        assert!(oracles.matches_info(&AHPForR1CS::<F, MM>::second_round_polynomial_info()));

        end_timer!(round_time);

        Ok(oracles)
    }

    fn calculate_rowcheck_witness(&mut self) -> Result<DensePolynomial<F>> {
        let verifier_state = self.verifier_state.as_ref().ok_or(anyhow!("missing verifier state"))?;
        let verifier::FirstMessage { batch_combiners, .. } =
            verifier_state.first_round_message.as_ref().ok_or(anyhow!("missing verifier message"))?;

        let fft_precomp = &self.fft_precomputation;
        let ifft_precomp = &self.ifft_precomputation;

        let mut job_pool = ExecutionPool::with_capacity(self.circuit_specific_states.len());
        let max_constraint_domain = self.max_constraint_domain;

        for (circuit, circuit_specific_state) in self.circuit_specific_states.iter_mut() {
            let z_a = circuit_specific_state.z_a.take().unwrap();
            let z_b = circuit_specific_state.z_b.take().unwrap();
            let z_c = circuit_specific_state.z_c.take().unwrap();

            let circuit_combiner = batch_combiners[&circuit.id].circuit_combiner;
            let instance_combiners = batch_combiners[&circuit.id].instance_combiners.clone();
            let constraint_domain = circuit_specific_state.constraint_domain;

            let _circuit_id = &circuit.id; // seems like a compiler bug marks this as unused

            for (j, (instance_combiner, z_a, z_b, z_c)) in
                itertools::izip!(instance_combiners, z_a, z_b, z_c).enumerate()
            {
                job_pool.add_job(move || {
                    let mut instance_lhs = DensePolynomial::zero();
                    let za_label = witness_label(circuit.id, "z_a", j);
                    let zb_label = witness_label(circuit.id, "z_b", j);
                    let zc_label = witness_label(circuit.id, "z_c", j);
                    let z_a = Self::calculate_z_m(za_label, z_a, constraint_domain, ifft_precomp);
                    let z_b = Self::calculate_z_m(zb_label, z_b, constraint_domain, ifft_precomp);
                    let z_c = Self::calculate_z_m(zc_label, z_c, constraint_domain, ifft_precomp);
                    let mut multiplier_2 = PolyMultiplier::new();
                    multiplier_2.add_precomputation(fft_precomp, ifft_precomp);
                    multiplier_2.add_polynomial(z_a, "z_a");
                    multiplier_2.add_polynomial(z_b, "z_b");
                    let mut rowcheck = multiplier_2.multiply().unwrap();
                    cfg_iter_mut!(rowcheck.coeffs).zip(&z_c.coeffs).for_each(|(ab, c)| *ab -= c);

                    instance_lhs += &(&rowcheck * instance_combiner);

                    let (h_0_i, remainder) = Self::apply_randomized_selector(
                        &mut instance_lhs,
                        circuit_combiner,
                        &max_constraint_domain,
                        &constraint_domain,
                        false,
                    )?;
                    assert!(remainder.is_none());
                    Ok::<_, anyhow::Error>(h_0_i)
                });
            }
        }

        let h_sum_time = start_timer!(|| "AHP::Prover::SecondRound h_sum");
        let h_sum: DensePolynomial<F> =
            cfg_reduce!(cfg_into_iter!(job_pool.execute_all()), || Ok(DensePolynomial::zero()), |a, b| {
                a.and_then(|a| {
                    b.map(|mut b| {
                        b += &a;
                        b
                    })
                })
            })?;
        end_timer!(h_sum_time);

        Ok(h_sum)
    }

    fn calculate_z_m(
        label: impl ToString,
        evaluations: Vec<F>,
        constraint_domain: EvaluationDomain<F>,
        ifft_precomp: &IFFTPrecomputation<F>,
    ) -> DensePolynomial<F> {
        let label = label.to_string();
        let poly_time = start_timer!(|| format!("Computing {label}"));

        let evals = EvaluationsOnDomain::from_vec_and_domain(evaluations, constraint_domain);
        let poly = evals.interpolate_with_pc_by_ref(ifft_precomp);

        debug_assert!(
            poly.evaluate_over_domain_by_ref(constraint_domain)
                .evaluations
                .into_iter()
                .zip(&evals.evaluations)
                .all(|(z, e)| *e == z),
            "Label: {label}\n1: {:#?}\n2: {:#?}",
            poly.evaluate_over_domain_by_ref(constraint_domain).evaluations,
            &evals.evaluations,
        );

        end_timer!(poly_time);

        poly
    }

    pub fn verifier_second_round<Fq: PrimeField, R: AlgebraicSponge<Fq, 2>>(
        &mut self,
        fs_rng: &mut R,
    ) -> Result<(), AHPError> {
        self.verifier_state.as_mut().unwrap().second_round(fs_rng)?;
        Ok(())
    }
}
