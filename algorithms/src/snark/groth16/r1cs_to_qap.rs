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

use super::{generator::KeypairAssembly, prover::ProvingAssignment, InternedField, Vec};
use crate::{cfg_iter, cfg_iter_mut, fft::EvaluationDomain};
use snarkvm_curves::traits::PairingEngine;
use snarkvm_fields::Zero;
use snarkvm_r1cs::{
    errors::{SynthesisError, SynthesisResult},
    ConstraintSystem,
    Index,
};

use indexmap::IndexSet;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

fn evaluate_constraint<E: PairingEngine>(
    terms: &[(InternedField, Index)],
    interned_fields: &IndexSet<E::Fr>,
    public_variables: &[InternedField],
    private_variables: &[InternedField],
) -> E::Fr {
    let mut acc = E::Fr::zero();
    for &(interned_coeff, index) in terms {
        let interned_val = match index {
            Index::Public(i) => public_variables[i],
            Index::Private(i) => private_variables[i],
        };
        let coeff = interned_fields.get_index(interned_coeff).unwrap();
        let val = *interned_fields.get_index(interned_val).unwrap();
        acc += &(val * &coeff);
    }
    acc
}

pub(crate) struct R1CStoQAP;

impl R1CStoQAP {
    #[inline]
    #[allow(clippy::many_single_char_names)]
    #[allow(clippy::type_complexity)]
    pub(crate) fn instance_map_with_evaluation<E: PairingEngine>(
        assembly: KeypairAssembly<E>,
        t: &E::Fr,
    ) -> SynthesisResult<(Vec<E::Fr>, Vec<E::Fr>, Vec<E::Fr>, E::Fr, usize, usize)> {
        let KeypairAssembly {
            num_public_variables,
            num_private_variables,
            constraints,
            interned_fields,
        } = assembly;
        let num_constraints = constraints.len();

        let domain_size = num_constraints + (num_public_variables - 1) + 1;
        let domain = EvaluationDomain::<E::Fr>::new(domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let zt = domain.evaluate_vanishing_polynomial(*t);

        // Evaluate all Lagrange polynomials
        let coefficients_time = start_timer!(|| "Evaluate Lagrange coefficients");
        let u = domain.evaluate_all_lagrange_coefficients(*t);
        end_timer!(coefficients_time);

        let qap_num_variables = (num_public_variables - 1) + num_private_variables;

        let mut a = vec![E::Fr::zero(); qap_num_variables + 1];
        let mut b = vec![E::Fr::zero(); qap_num_variables + 1];
        let mut c = vec![E::Fr::zero(); qap_num_variables + 1];

        for i in 0..num_public_variables {
            a[i] = u[num_constraints + i];
        }

        for (cstr, x) in constraints.iter().zip(u.iter()) {
            for &(interned_coeff, index) in cstr.at.iter() {
                let index = match index {
                    Index::Public(i) => i,
                    Index::Private(i) => num_public_variables + i,
                };

                let coeff = interned_fields.get_index(interned_coeff).unwrap();
                a[index] += &(*x * coeff);
            }
            for &(interned_coeff, index) in cstr.bt.iter() {
                let index = match index {
                    Index::Public(i) => i,
                    Index::Private(i) => num_public_variables + i,
                };

                let coeff = interned_fields.get_index(interned_coeff).unwrap();
                b[index] += &(*x * coeff);
            }
            for &(interned_coeff, index) in cstr.ct.iter() {
                let index = match index {
                    Index::Public(i) => i,
                    Index::Private(i) => num_public_variables + i,
                };

                let coeff = interned_fields.get_index(interned_coeff).unwrap();
                c[index] += &(*x * coeff);
            }
        }

        Ok((a, b, c, zt, qap_num_variables, domain_size))
    }

    #[inline]
    pub(crate) fn witness_map<E: PairingEngine>(prover: &ProvingAssignment<E>) -> SynthesisResult<Vec<E::Fr>> {
        let zero = E::Fr::zero();
        let num_inputs = prover.public_variables.len();
        let num_constraints = prover.num_constraints();

        let domain = EvaluationDomain::<E::Fr>::new(num_constraints + num_inputs)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];

        cfg_iter_mut!(a[..num_constraints])
            .zip(cfg_iter_mut!(b[..num_constraints]))
            .zip(cfg_iter!(&prover.constraints))
            .for_each(|((a, b), cstr)| {
                *a = evaluate_constraint::<E>(
                    &cstr.at,
                    &prover.interned_fields,
                    &prover.public_variables,
                    &prover.private_variables,
                );
                *b = evaluate_constraint::<E>(
                    &cstr.bt,
                    &prover.interned_fields,
                    &prover.public_variables,
                    &prover.private_variables,
                );
            });

        a[num_constraints..][..num_inputs].clone_from_slice(
            prover
                .public_variables
                .iter()
                .map(|v| *prover.interned_fields.get_index(*v).unwrap())
                .collect::<Vec<_>>()
                .as_slice(),
        );

        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);

        domain.coset_fft_in_place(&mut a);
        domain.coset_fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        let mut c = vec![zero; domain_size];

        cfg_iter_mut!(c[..num_constraints])
            .zip(cfg_iter!(&prover.constraints))
            .for_each(|(c, cstr)| {
                *c = evaluate_constraint::<E>(
                    &cstr.ct,
                    &prover.interned_fields,
                    &prover.public_variables,
                    &prover.private_variables,
                );
            });

        domain.ifft_in_place(&mut c);
        domain.coset_fft_in_place(&mut c);

        cfg_iter_mut!(ab).zip(c).for_each(|(ab_i, c_i)| *ab_i -= &c_i);

        domain.divide_by_vanishing_poly_on_coset_in_place(&mut ab);
        domain.coset_ifft_in_place(&mut ab);

        Ok(ab)
    }
}
