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

use std::{collections::BTreeMap, sync::Arc};

use crate::{
    fft::{DensePolynomial, EvaluationDomain, Evaluations as EvaluationsOnDomain},
    r1cs::{SynthesisError, SynthesisResult},
    snark::marlin::{AHPError, AHPForR1CS, Circuit, MarlinMode},
};
use itertools::Itertools;
use snarkvm_fields::PrimeField;

/// Circuit Specific State of the Prover
pub struct CircuitSpecificState<F: PrimeField> {
    pub(super) input_domain: EvaluationDomain<F>,
    pub(super) variable_domain: EvaluationDomain<F>,
    pub(super) constraint_domain: EvaluationDomain<F>,
    pub(super) non_zero_a_domain: EvaluationDomain<F>,
    pub(super) non_zero_b_domain: EvaluationDomain<F>,
    pub(super) non_zero_c_domain: EvaluationDomain<F>,

    /// The number of instances being proved in this batch.
    pub(in crate::snark) batch_size: usize,

    /// The list of public inputs for each instance in the batch.
    /// The length of this list must be equal to the batch size.
    pub(super) padded_public_variables: Vec<Vec<F>>,

    /// The list of private variables for each instance in the batch.
    /// The length of this list must be equal to the batch size.
    pub(super) private_variables: Vec<Vec<F>>,

    /// The list of Az vectors for each instance in the batch.
    /// The length of this list must be equal to the batch size.
    pub(super) z_a: Option<Vec<Vec<F>>>,

    /// The list of Bz vectors for each instance in the batch.
    /// The length of this list must be equal to the batch size.
    pub(super) z_b: Option<Vec<Vec<F>>>,

    /// The list of Cz vectors for each instance in the batch.
    /// The length of this list must be equal to the batch size.
    pub(super) z_c: Option<Vec<Vec<F>>>,

    /// Randomizers for the multiplicities.
    /// The length of this list must be equal to the batch size.
    pub(super) multiplicity_randomizer: Option<Vec<F>>,

    /// A list of polynomials corresponding to the interpolation of the public input.
    /// The length of this list must be equal to the batch size.
    pub(super) x_polys: Vec<DensePolynomial<F>>,

    /// Polynomials involved in the holographic sumcheck.
    pub(super) h_polynomials: Option<[DensePolynomial<F>; 3]>,

    /// Polynomials involved in the lookup sumcheck.
    pub(super) lookup_h_polynomials: Option<Vec<DensePolynomial<F>>>,

    /// How often is each table entry used in a lookup
    pub(super) m_evals: Option<Vec<Vec<F>>>,
}

/// State for the AHP prover.
pub struct State<'a, F: PrimeField, MM: MarlinMode> {
    /// The state for each circuit in the batch.
    pub(super) circuit_specific_states: BTreeMap<&'a Circuit<F, MM>, CircuitSpecificState<F>>,
    /// The first round oracles sent by the prover.
    /// The length of this list must be equal to the batch size.
    pub(in crate::snark) first_round_oracles: Option<Arc<super::FirstOracles<F>>>,
    /// The second round oracles sent by the prover.
    /// The length of this list must be equal to the batch size.
    pub(in crate::snark) second_round_oracles: Option<Arc<super::SecondOracles<F>>>,
    /// The largest non_zero domain of all circuits in the batch.
    pub(in crate::snark) max_non_zero_domain: EvaluationDomain<F>,
    /// The largest constraint domain of all circuits in the batch.
    pub(in crate::snark) max_constraint_domain: EvaluationDomain<F>,
    /// The largest variable domain of all circuits in the batch.
    pub(in crate::snark) max_variable_domain: EvaluationDomain<F>,
    // The total number of instances which use a lookup.
    pub(in crate::snark) total_lookup_instances: usize,
    /// The total number of instances we're proving in the batch.
    pub(in crate::snark) total_instances: usize,
}

/// The public inputs for a single instance.
type PaddedPubInputs<F> = Vec<F>;
/// The private inputs for a single instance.
type PrivateInputs<F> = Vec<F>;
/// The z_i_j*A_i vector for a single instance.
type Za<F> = Vec<F>;
/// The z_i_j*B_i vector for a single instance.
type Zb<F> = Vec<F>;
/// The z_i_j*C_i vector for a single instance.
type Zc<F> = Vec<F>;
/// Assignments for a single instance.
pub(super) struct Assignments<F>(
    pub(super) PaddedPubInputs<F>,
    pub(super) PrivateInputs<F>,
    pub(super) Za<F>,
    pub(super) Zb<F>,
    pub(super) Zc<F>,
    pub(super) BTreeMap<(usize, usize), F>,
);

impl<'a, F: PrimeField, MM: MarlinMode> State<'a, F, MM> {
    pub(super) fn initialize(
        indices_and_assignments: BTreeMap<&'a Circuit<F, MM>, Vec<Assignments<F>>>,
    ) -> Result<Self, AHPError> {
        let mut max_non_zero_domain: Option<EvaluationDomain<F>> = None;
        let mut max_num_constraints = 0;
        let mut max_num_variables = 0;
        let mut total_instances = 0;
        let mut total_lookup_instances = 0;

        // We need to compute the cumulative table sizes in order to easily compute the multiplicity lookup poly
        let mut cumulative_table_sizes = Vec::with_capacity(indices_and_assignments.len());
        for circuit in indices_and_assignments.keys() {
            if circuit.table_info.is_some() {
                let mut table_sizes = vec![0usize];
                circuit
                    .table_info
                    .as_ref()
                    .unwrap()
                    .lookup_tables
                    .iter()
                    .enumerate()
                    .for_each(|(i, table)| table_sizes.push(table_sizes[i] + table.table.len()));
                cumulative_table_sizes.push(Some(table_sizes));
            } else {
                cumulative_table_sizes.push(None);
            }
        }

        let circuit_specific_states = indices_and_assignments
            .into_iter()
            .zip_eq(cumulative_table_sizes)
            .map(|((circuit, variable_assignments), cum_table_sizes)| {
                let index_info = &circuit.index_info;

                let constraint_domain = EvaluationDomain::new(index_info.num_constraints)
                    .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
                max_num_constraints = max_num_constraints.max(index_info.num_constraints);

                let variable_domain =
                    EvaluationDomain::new(index_info.num_variables).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
                max_num_variables = max_num_variables.max(index_info.num_variables);

                let non_zero_domains = AHPForR1CS::<_, MM>::cmp_non_zero_domains(index_info, max_non_zero_domain)?;
                max_non_zero_domain = non_zero_domains.max_non_zero_domain;

                let first_padded_public_inputs = &variable_assignments[0].0;
                let input_domain = EvaluationDomain::new(first_padded_public_inputs.len()).unwrap();
                let batch_size = variable_assignments.len();
                total_instances += batch_size;
                let mut z_as = Vec::with_capacity(batch_size);
                let mut z_bs = Vec::with_capacity(batch_size);
                let mut z_cs = Vec::with_capacity(batch_size);
                let mut x_polys = Vec::with_capacity(batch_size);
                let mut padded_public_variables = Vec::with_capacity(batch_size);
                let mut private_variables = Vec::with_capacity(batch_size);

                let lookups_used = circuit.table_info.is_some();
                let mut m_evals = lookups_used.then(|| Vec::with_capacity(batch_size));

                for Assignments(padded_public_input, private_input, z_a, z_b, z_c, table_indices_used_j) in
                    variable_assignments
                {
                    let num_constraints = z_a.len();
                    z_as.push(z_a);
                    z_bs.push(z_b);
                    z_cs.push(z_c);
                    let x_poly = EvaluationsOnDomain::from_vec_and_domain(padded_public_input.clone(), input_domain)
                        .interpolate();
                    x_polys.push(x_poly);
                    padded_public_variables.push(padded_public_input);
                    private_variables.push(private_input);
                    if let Some(cum_table_sizes) = cum_table_sizes.as_ref() {
                        let mut m_evals_j = vec![F::zero(); num_constraints];
                        // m_i_j_k is the number of times element t_i_j_k appears in f_i_j
                        table_indices_used_j.iter().for_each(|((table_index, table_entry_index), num_times_used)| {
                            m_evals_j[cum_table_sizes[*table_index] + table_entry_index] = *num_times_used;
                        });
                        m_evals.as_mut().unwrap().push(m_evals_j);
                        total_lookup_instances += 1;
                    }
                }

                let state = CircuitSpecificState {
                    input_domain,
                    variable_domain,
                    constraint_domain,
                    non_zero_a_domain: non_zero_domains.domain_a,
                    non_zero_b_domain: non_zero_domains.domain_b,
                    non_zero_c_domain: non_zero_domains.domain_c,
                    batch_size,
                    padded_public_variables,
                    x_polys,
                    private_variables,
                    z_a: Some(z_as),
                    z_b: Some(z_bs),
                    z_c: Some(z_cs),
                    multiplicity_randomizer: None,
                    h_polynomials: None,
                    lookup_h_polynomials: None,
                    m_evals,
                };
                Ok((circuit, state))
            })
            .collect::<SynthesisResult<BTreeMap<_, _>>>()?;

        let max_non_zero_domain = max_non_zero_domain.ok_or(AHPError::BatchSizeIsZero)?;
        let max_constraint_domain =
            EvaluationDomain::new(max_num_constraints).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let max_variable_domain =
            EvaluationDomain::new(max_num_variables).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        Ok(Self {
            max_constraint_domain,
            max_variable_domain,
            max_non_zero_domain,
            circuit_specific_states,
            first_round_oracles: None,
            second_round_oracles: None,
            total_lookup_instances,
            total_instances,
        })
    }

    /// Get the batch size for a given circuit.
    pub fn batch_size(&self, circuit: &Circuit<F, MM>) -> Option<usize> {
        self.circuit_specific_states.get(circuit).map(|s| s.batch_size)
    }

    /// Get the public inputs for the entire batch.
    pub fn public_inputs(&self, circuit: &Circuit<F, MM>) -> Option<Vec<Vec<F>>> {
        // We need to export inputs as they live longer than prover_state
        self.circuit_specific_states.get(circuit).map(|s| {
            s.padded_public_variables.iter().map(|v| super::ConstraintSystem::unformat_public_input(v)).collect()
        })
    }

    /// Get the padded public inputs for the entire batch.
    pub fn padded_public_inputs(&self, circuit: &Circuit<F, MM>) -> Option<&[Vec<F>]> {
        self.circuit_specific_states.get(circuit).map(|s| s.padded_public_variables.as_slice())
    }

    /// Iterate over the lhs_polynomials
    pub fn h_polys_into_iter(self) -> impl Iterator<Item = DensePolynomial<F>> + 'a {
        self.circuit_specific_states.into_values().flat_map(|s| s.h_polynomials.unwrap().into_iter())
    }
}
