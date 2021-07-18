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

#![cfg_attr(not(feature = "std"), no_std)]
//! A crate for polynomial commitment schemes.
#![deny(unused_import_braces, trivial_casts, bare_trait_objects)]
#![deny(unused_qualifications, variant_size_differences, stable_features)]
#![deny(non_shorthand_field_patterns, unused_attributes)]
#![deny(renamed_and_removed_lints, unused_allocation, unused_comparisons)]
#![deny(const_err, unused_must_use, unused_mut, private_in_public)]
#![deny(unused_extern_crates, trivial_numeric_casts)]
#![forbid(unsafe_code)]

#[macro_use]
extern crate derivative;

#[macro_use]
extern crate snarkvm_profiler;

pub use snarkvm_algorithms::fft::DensePolynomial as Polynomial;
use snarkvm_fields::Field;
use snarkvm_utilities::{error as error_fn, errors::SerializationError, serialize::*, FromBytes, ToBytes};

use core::fmt::Debug;
use rand_core::RngCore;

#[cfg(not(feature = "std"))]
#[macro_use]
extern crate alloc;

#[rustfmt::skip]
#[cfg(not(feature = "std"))]
use alloc::{
    borrow::{Cow, ToOwned},
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

#[rustfmt::skip]
#[cfg(feature = "std")]
use std::{
    borrow::{Cow, ToOwned},
    collections::{BTreeMap, BTreeSet},
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

/// Data structures used by a polynomial commitment scheme.
pub mod data_structures;
pub use data_structures::*;

/// R1CS constraints for polynomial constraints.
mod constraints;
pub use constraints::*;

/// Errors pertaining to query sets.
pub mod error;
pub use error::*;
use snarkvm_algorithms::Prepare;

/// A random number generator that bypasses some limitations of the Rust borrow
/// checker.
pub mod optional_rng;

#[cfg(not(feature = "std"))]
macro_rules! eprintln {
    () => {};
    ($($arg: tt)*) => {};
}

/// The core [[KZG10]][kzg] construction.
///
/// [kzg]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf
pub mod kzg10;

/// Polynomial commitment scheme from [[KZG10]][kzg] that enforces
/// strict degree bounds and (optionally) enables hiding commitments by
/// following the approach outlined in [[CHMMVW20, "Marlin"]][marlin].
///
/// [kzg]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf
/// [marlin]: https://eprint.iacr.org/2019/1047
pub mod marlin_pc;

/// Polynomial commitment scheme based on the construction in [[KZG10]][kzg],
/// modified to obtain batching and to enforce strict
/// degree bounds by following the approach outlined in [[MBKM19,
/// “Sonic”]][sonic] (more precisely, via the variant in
/// [[Gabizon19, “AuroraLight”]][al] that avoids negative G1 powers).
///
/// [kzg]: http://cacr.uwaterloo.ca/techreports/2010/cacr2010-10.pdf
/// [sonic]: https://eprint.iacr.org/2019/099
/// [al]: https://eprint.iacr.org/2019/601
/// [marlin]: https://eprint.iacr.org/2019/1047
pub mod sonic_pc;

/// `QuerySet` is the set of queries that are to be made to a set of labeled polynomials/equations
/// `p` that have previously been committed to. Each element of a `QuerySet` is a `(label, query)`
/// pair, where `label` is the label of a polynomial in `p`, and `query` is the field element
/// that `p[label]` is to be queried at.
///
/// Added the third field: the point name.
pub type QuerySet<'a, T> = BTreeSet<(String, (String, T))>;

/// `Evaluations` is the result of querying a set of labeled polynomials or equations
/// `p` at a `QuerySet` `Q`. It maps each element of `Q` to the resulting evaluation.
/// That is, if `(label, query)` is an element of `Q`, then `evaluation.get((label, query))`
/// should equal `p[label].evaluate(query)`.
pub type Evaluations<'a, F> = BTreeMap<(String, F), F>;

/// A proof of satisfaction of linear combinations.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct BatchLCProof<F: Field, PC: PolynomialCommitment<F>> {
    /// Evaluation proof.
    pub proof: PC::BatchProof,
    /// Evaluations required to verify the proof.
    pub evaluations: Option<Vec<F>>,
}

impl<F: Field, PC: PolynomialCommitment<F>> FromBytes for BatchLCProof<F, PC> {
    fn read_le<R: Read>(mut reader: R) -> io::Result<Self> {
        CanonicalDeserialize::deserialize(&mut reader).map_err(|_| error_fn("could not deserialize struct"))
    }
}

impl<F: Field, PC: PolynomialCommitment<F>> ToBytes for BatchLCProof<F, PC> {
    fn write_le<W: Write>(&self, mut writer: W) -> io::Result<()> {
        CanonicalSerialize::serialize(self, &mut writer).map_err(|_| error_fn("could not serialize struct"))
    }
}

/// Describes the interface for a polynomial commitment scheme that allows
/// a sender to commit to multiple polynomials and later provide a succinct proof
/// of evaluation for the corresponding commitments at a query set `Q`, while
/// enforcing per-polynomial degree bounds.
pub trait PolynomialCommitment<F: Field>: Sized + Clone + Debug {
    /// The universal parameters for the commitment scheme. These are "trimmed"
    /// down to `Self::CommitterKey` and `Self::VerifierKey` by `Self::trim`.
    type UniversalParams: PCUniversalParams + Clone;
    /// The committer key for the scheme; used to commit to a polynomial and then
    /// open the commitment to produce an evaluation proof.
    type CommitterKey: PCCommitterKey + Clone;
    /// The verifier key for the scheme; used to check an evaluation proof.
    type VerifierKey: PCVerifierKey + Prepare<Self::PreparedVerifierKey> + Clone;
    /// The prepared verifier key for the scheme; used to check an evaluation proof.
    type PreparedVerifierKey: Clone;
    /// The commitment to a polynomial.
    type Commitment: PCCommitment + Prepare<Self::PreparedCommitment> + Clone;
    /// The prepared commitment to a polynomial.
    type PreparedCommitment: Clone;
    /// The commitment randomness.
    type Randomness: PCRandomness + Clone;
    /// The evaluation proof for a single point.
    type Proof: PCProof + Clone;
    /// The evaluation proof for a query set.
    type BatchProof: CanonicalSerialize
        + CanonicalDeserialize
        + Clone
        + From<Vec<Self::Proof>>
        + Into<Vec<Self::Proof>>
        + Debug;
    /// The error type for the scheme.
    type Error: snarkvm_utilities::error::Error + From<Error>;

    /// Constructs public parameters when given as input the maximum degree `degree`
    /// for the polynomial commitment scheme.
    fn setup<R: RngCore>(max_degree: usize, rng: &mut R) -> Result<Self::UniversalParams, Self::Error>;

    /// Specializes the public parameters for polynomials up to the given `supported_degree`
    /// and for enforcing degree bounds in the range `1..=supported_degree`.
    fn trim(
        parameters: &Self::UniversalParams,
        supported_degree: usize,
        supported_hiding_bound: usize,
        enforced_degree_bounds: Option<&[usize]>,
    ) -> Result<(Self::CommitterKey, Self::VerifierKey), Self::Error>;

    /// Outputs a commitments to `polynomials`. If `polynomials[i].is_hiding()`,
    /// then the `i`-th commitment is hiding up to `polynomials.hiding_bound()` queries.
    /// `rng` should not be `None` if `polynomials[i].is_hiding() == true` for any `i`.
    ///
    /// If for some `i`, `polynomials[i].is_hiding() == false`, then the
    /// corresponding randomness is `Self::Randomness::empty()`.
    ///
    /// If for some `i`, `polynomials[i].degree_bound().is_some()`, then that
    /// polynomial will have the corresponding degree bound enforced.
    #[allow(clippy::type_complexity)]
    fn commit<'a>(
        ck: &Self::CommitterKey,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<F>>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<(Vec<LabeledCommitment<Self::Commitment>>, Vec<Self::Randomness>), Self::Error>;

    /// On input a list of labeled polynomials and a query point, `open` outputs a proof of evaluation
    /// of the polynomials at the query point.
    fn open<'a>(
        ck: &Self::CommitterKey,
        labeled_polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<F>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        point: F,
        opening_challenge: F,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<Self::Proof, Self::Error>
    where
        Self::Randomness: 'a,
        Self::Commitment: 'a;

    /// On input a list of labeled polynomials and a query set, `open` outputs a proof of evaluation
    /// of the polynomials at the points in the query set.
    fn batch_open<'a>(
        ck: &Self::CommitterKey,
        labeled_polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<F>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<F>,
        opening_challenge: F,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<Self::BatchProof, Self::Error>
    where
        Self::Randomness: 'a,
        Self::Commitment: 'a,
    {
        let rng = &mut crate::optional_rng::OptionalRng(rng);
        let poly_rand_comm: BTreeMap<_, _> = labeled_polynomials
            .into_iter()
            .zip(rands)
            .zip(commitments.into_iter())
            .map(|((poly, r), comm)| (poly.label(), (poly, r, comm)))
            .collect();

        let open_time = start_timer!(|| format!(
            "Opening {} polynomials at query set of size {}",
            poly_rand_comm.len(),
            query_set.len(),
        ));

        let mut query_to_labels_map = BTreeMap::new();

        for (label, (point_name, point)) in query_set.iter() {
            let labels = query_to_labels_map
                .entry(point_name)
                .or_insert((point, BTreeSet::new()));
            labels.1.insert(label);
        }

        let mut proofs = Vec::with_capacity(query_to_labels_map.len());
        for (_point_name, (query, labels)) in query_to_labels_map.into_iter() {
            let mut query_polys = Vec::with_capacity(labels.len());
            let mut query_rands = Vec::with_capacity(labels.len());
            let mut query_comms = Vec::with_capacity(labels.len());

            for label in labels {
                let (polynomial, rand, comm) = poly_rand_comm.get(label).ok_or(Error::MissingPolynomial {
                    label: label.to_string(),
                })?;

                query_polys.push(*polynomial);
                query_rands.push(*rand);
                query_comms.push(*comm);
            }

            let proof_time = start_timer!(|| "Creating proof");
            let proof = Self::open(
                ck,
                query_polys,
                query_comms,
                *query,
                opening_challenge,
                query_rands,
                Some(rng),
            )?;

            end_timer!(proof_time);

            proofs.push(proof);
        }
        end_timer!(open_time);

        Ok(proofs.into())
    }

    /// Verifies that `values` are the evaluations at `point` of the polynomials
    /// committed inside `commitments`.
    fn check<'a, R: RngCore>(
        vk: &Self::VerifierKey,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        point: F,
        values: impl IntoIterator<Item = F>,
        proof: &Self::Proof,
        opening_challenge: F,
        rng: &mut R,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a;

    /// Checks that `values` are the true evaluations at `query_set` of the polynomials
    /// committed in `labeled_commitments`.
    fn batch_check<'a, R: RngCore>(
        vk: &Self::VerifierKey,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<F>,
        evaluations: &Evaluations<F>,
        proof: &Self::BatchProof,
        opening_challenge: F,
        rng: &mut R,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a,
    {
        let commitments: BTreeMap<_, _> = commitments.into_iter().map(|c| (c.label(), c)).collect();
        let mut query_to_labels_map = BTreeMap::new();
        for (label, (point_name, point)) in query_set.iter() {
            let labels = query_to_labels_map
                .entry(point_name)
                .or_insert((point, BTreeSet::new()));
            labels.1.insert(label);
        }

        // Implicit assumption: proofs are order in same manner as queries in
        // `query_to_labels_map`.
        let proofs: Vec<_> = proof.clone().into();
        assert_eq!(proofs.len(), query_to_labels_map.len());

        let mut result = true;
        for ((_point_name, (query, labels)), proof) in query_to_labels_map.into_iter().zip(proofs) {
            let mut comms: Vec<&'_ LabeledCommitment<_>> = Vec::with_capacity(labels.len());
            let mut values = Vec::with_capacity(labels.len());
            for label in labels.into_iter() {
                let commitment = commitments.get(label).ok_or(Error::MissingPolynomial {
                    label: label.to_string(),
                })?;

                let v_i = evaluations
                    .get(&(label.clone(), *query))
                    .ok_or(Error::MissingEvaluation {
                        label: label.to_string(),
                    })?;

                comms.push(commitment);
                values.push(*v_i);
            }

            let proof_time = start_timer!(|| "Checking per-query proof");
            result &= Self::check(vk, comms, *query, values, &proof, opening_challenge, rng)?;
            end_timer!(proof_time);
        }
        Ok(result)
    }

    /// On input a list of polynomials, linear combinations of those polynomials,
    /// and a query set, `open_combination` outputs a proof of evaluation of
    /// the combinations at the points in the query set.
    #[allow(clippy::too_many_arguments)]
    fn open_combinations<'a>(
        ck: &Self::CommitterKey,
        linear_combinations: impl IntoIterator<Item = &'a LinearCombination<F>>,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<F>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<F>,
        opening_challenge: F,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
        rng: Option<&mut dyn RngCore>,
    ) -> Result<BatchLCProof<F, Self>, Self::Error>
    where
        Self::Randomness: 'a,
        Self::Commitment: 'a,
    {
        let linear_combinations: Vec<_> = linear_combinations.into_iter().collect();
        let polynomials: Vec<_> = polynomials.into_iter().collect();
        let poly_query_set = lc_query_set_to_poly_query_set(linear_combinations.iter().copied(), query_set);
        let poly_evals = evaluate_query_set(polynomials.iter().copied(), &poly_query_set);
        let proof = Self::batch_open(
            ck,
            polynomials,
            commitments,
            &poly_query_set,
            opening_challenge,
            rands,
            rng,
        )?;
        Ok(BatchLCProof {
            proof,
            evaluations: Some(poly_evals.values().copied().collect()),
        })
    }

    /// Checks that `evaluations` are the true evaluations at `query_set` of the
    /// linear combinations of polynomials committed in `commitments`.
    #[allow(clippy::too_many_arguments)]
    fn check_combinations<'a, R: RngCore>(
        vk: &Self::VerifierKey,
        linear_combinations: impl IntoIterator<Item = &'a LinearCombination<F>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        eqn_query_set: &QuerySet<F>,
        eqn_evaluations: &Evaluations<F>,
        proof: &BatchLCProof<F, Self>,
        opening_challenge: F,
        rng: &mut R,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a,
    {
        let BatchLCProof {
            proof,
            evaluations: evals,
        } = proof;

        let lc_s: BTreeMap<_, _> = linear_combinations.into_iter().map(|lc| (lc.label(), lc)).collect();

        let poly_query_set = lc_query_set_to_poly_query_set(lc_s.values().copied(), eqn_query_set);
        let poly_evals: Evaluations<_> = poly_query_set
            .iter()
            .map(|(_, point)| point)
            .cloned()
            .zip(evals.clone().unwrap())
            .collect();

        for &(ref lc_label, (_, point)) in eqn_query_set {
            if let Some(lc) = lc_s.get(lc_label) {
                let claimed_rhs = *eqn_evaluations
                    .get(&(lc_label.clone(), point))
                    .ok_or(Error::MissingEvaluation {
                        label: lc_label.to_string(),
                    })?;

                let mut actual_rhs = F::zero();

                for (coeff, label) in lc.iter() {
                    let eval = match label {
                        LCTerm::One => F::one(),
                        LCTerm::PolyLabel(l) => *poly_evals
                            .get(&(l.clone(), point))
                            .ok_or(Error::MissingEvaluation { label: l.clone() })?,
                    };

                    actual_rhs += &(*coeff * eval);
                }
                if claimed_rhs != actual_rhs {
                    eprintln!("Claimed evaluation of {} is incorrect", lc.label());
                    return Ok(false);
                }
            }
        }

        let pc_result = Self::batch_check(
            vk,
            commitments,
            &poly_query_set,
            &poly_evals,
            proof,
            opening_challenge,
            rng,
        )?;
        if !pc_result {
            eprintln!("Evaluation proofs failed to verify");
            return Ok(false);
        }

        Ok(true)
    }

    /// On input a list of polynomials, linear combinations of those polynomials,
    /// and a query set, `open_combination` outputs a proof of evaluation of
    /// the combinations at the points in the query set.
    fn open_combinations_individual_opening_challenges<'a>(
        ck: &Self::CommitterKey,
        linear_combinations: impl IntoIterator<Item = &'a LinearCombination<F>>,
        polynomials: impl IntoIterator<Item = &'a LabeledPolynomial<F>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        query_set: &QuerySet<F>,
        opening_challenges: &dyn Fn(u64) -> F,
        rands: impl IntoIterator<Item = &'a Self::Randomness>,
    ) -> Result<BatchLCProof<F, Self>, Self::Error>
    where
        Self::Randomness: 'a,
        Self::Commitment: 'a;

    /// Check combinations with individual challenges.
    fn check_combinations_individual_opening_challenges<'a, R: RngCore>(
        vk: &Self::VerifierKey,
        linear_combinations: impl IntoIterator<Item = &'a LinearCombination<F>>,
        commitments: impl IntoIterator<Item = &'a LabeledCommitment<Self::Commitment>>,
        eqn_query_set: &QuerySet<F>,
        eqn_evaluations: &Evaluations<F>,
        proof: &BatchLCProof<F, Self>,
        opening_challenges: &dyn Fn(u64) -> F,
        rng: &mut R,
    ) -> Result<bool, Self::Error>
    where
        Self::Commitment: 'a;
}

/// Evaluate the given polynomials at `query_set`.
pub fn evaluate_query_set<'a, F: Field>(
    polys: impl IntoIterator<Item = &'a LabeledPolynomial<F>>,
    query_set: &QuerySet<'a, F>,
) -> Evaluations<'a, F> {
    let polys: BTreeMap<_, _> = polys.into_iter().map(|p| (p.label(), p)).collect();
    let mut evaluations = Evaluations::new();
    for (label, (_point_name, point)) in query_set {
        let poly = polys.get(label).expect("polynomial in evaluated lc is not found");
        let eval = poly.evaluate(*point);
        evaluations.insert((label.clone(), *point), eval);
    }
    evaluations
}

fn lc_query_set_to_poly_query_set<'a, F: 'a + Field>(
    linear_combinations: impl IntoIterator<Item = &'a LinearCombination<F>>,
    query_set: &QuerySet<F>,
) -> QuerySet<'a, F> {
    let mut poly_query_set = QuerySet::new();
    let lc_s = linear_combinations.into_iter().map(|lc| (lc.label(), lc));
    let linear_combinations: BTreeMap<_, _> = lc_s.collect();
    for (lc_label, (point_name, point)) in query_set {
        if let Some(lc) = linear_combinations.get(lc_label) {
            for (_, poly_label) in lc.iter().filter(|(_, l)| !l.is_one()) {
                if let LCTerm::PolyLabel(l) = poly_label {
                    poly_query_set.insert((l.into(), (point_name.clone(), *point)));
                }
            }
        }
    }
    poly_query_set
}

#[cfg(test)]
pub mod tests {
    use crate::*;
    use rand::{distributions::Distribution, Rng};
    use snarkvm_fields::Field;
    use snarkvm_utilities::rand::test_rng;

    #[derive(Default)]
    struct TestInfo {
        num_iters: usize,
        max_degree: Option<usize>,
        supported_degree: Option<usize>,
        num_polynomials: usize,
        enforce_degree_bounds: bool,
        max_num_queries: usize,
        num_equations: Option<usize>,
    }

    pub struct TestComponents<F: Field, PC: PolynomialCommitment<F>> {
        pub verification_key: PC::VerifierKey,
        pub commitments: Vec<LabeledCommitment<PC::Commitment>>,
        pub query_set: QuerySet<'static, F>,
        pub evaluations: Evaluations<'static, F>,
        pub batch_lc_proof: Option<BatchLCProof<F, PC>>,
        pub batch_proof: Option<PC::BatchProof>,
        pub opening_challenge: F,
        pub randomness: Vec<PC::Randomness>,
    }

    pub fn bad_degree_bound_test<F, PC>() -> Result<(), PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let rng = &mut test_rng();
        let max_degree = 100;
        let pp = PC::setup(max_degree, rng)?;

        for _ in 0..10 {
            let supported_degree = rand::distributions::Uniform::from(1..=max_degree).sample(rng);
            assert!(max_degree >= supported_degree, "max_degree < supported_degree");

            let mut labels = Vec::new();
            let mut polynomials = Vec::new();
            let mut degree_bounds = Vec::new();

            for i in 0..10 {
                let label = format!("Test{}", i);
                labels.push(label.clone());
                let poly = Polynomial::rand(supported_degree, rng);

                let degree_bound = 1usize;
                let hiding_bound = Some(1);
                degree_bounds.push(degree_bound);

                polynomials.push(LabeledPolynomial::new(label, poly, Some(degree_bound), hiding_bound))
            }

            println!("supported degree: {:?}", supported_degree);
            let (ck, vk) = PC::trim(&pp, supported_degree, supported_degree, Some(degree_bounds.as_slice()))?;
            println!("Trimmed");

            let (comms, rands) = PC::commit(&ck, &polynomials, Some(rng))?;

            let mut query_set = QuerySet::new();
            let mut values = Evaluations::new();
            let point = F::rand(rng);
            for (i, label) in labels.iter().enumerate() {
                query_set.insert((label.clone(), ("rand".into(), point)));
                let value = polynomials[i].evaluate(point);
                values.insert((label.clone(), point), value);
            }
            println!("Generated query set");

            let opening_challenge = F::rand(rng);
            let proof = PC::batch_open(
                &ck,
                &polynomials,
                &comms,
                &query_set,
                opening_challenge,
                &rands,
                Some(rng),
            )?;
            let result = PC::batch_check(&vk, &comms, &query_set, &values, &proof, opening_challenge, rng)?;
            assert!(result, "proof was incorrect, Query set: {:#?}", query_set);
        }
        Ok(())
    }

    fn test_template<F, PC>(info: TestInfo) -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let TestInfo {
            num_iters,
            max_degree,
            supported_degree,
            num_polynomials,
            enforce_degree_bounds,
            max_num_queries,
            ..
        } = info;

        let mut test_components = Vec::new();

        let rng = &mut test_rng();
        let max_degree = max_degree.unwrap_or_else(|| rand::distributions::Uniform::from(2..=64).sample(rng));
        let pp = PC::setup(max_degree, rng)?;

        for _ in 0..num_iters {
            let supported_degree =
                supported_degree.unwrap_or_else(|| rand::distributions::Uniform::from(1..=max_degree).sample(rng));
            assert!(max_degree >= supported_degree, "max_degree < supported_degree");
            let mut polynomials = Vec::new();
            let mut degree_bounds = if enforce_degree_bounds { Some(Vec::new()) } else { None };

            let mut labels = Vec::new();
            println!("Sampled supported degree");

            // Generate polynomials
            let num_points_in_query_set = rand::distributions::Uniform::from(1..=max_num_queries).sample(rng);
            for i in 0..num_polynomials {
                let label = format!("Test{}", i);
                labels.push(label.clone());
                let degree = rand::distributions::Uniform::from(1..=supported_degree).sample(rng);
                let poly = Polynomial::rand(degree, rng);

                let degree_bound = if let Some(degree_bounds) = &mut degree_bounds {
                    let range = rand::distributions::Uniform::from(degree..=supported_degree);
                    let degree_bound = range.sample(rng);
                    degree_bounds.push(degree_bound);
                    Some(degree_bound)
                } else {
                    None
                };

                let hiding_bound = if num_points_in_query_set >= degree {
                    Some(degree)
                } else {
                    Some(num_points_in_query_set)
                };
                println!("Hiding bound: {:?}", hiding_bound);

                polynomials.push(LabeledPolynomial::new(label, poly, degree_bound, hiding_bound))
            }
            let supported_hiding_bound = polynomials
                .iter()
                .map(|p| p.hiding_bound().unwrap_or(0))
                .max()
                .unwrap_or(0);
            println!("supported degree: {:?}", supported_degree);
            println!("supported hiding bound: {:?}", supported_hiding_bound);
            println!("num_points_in_query_set: {:?}", num_points_in_query_set);
            let (ck, vk) = PC::trim(&pp, supported_degree, supported_hiding_bound, degree_bounds.as_deref())?;
            println!("Trimmed");

            let (comms, rands) = PC::commit(&ck, &polynomials, Some(rng))?;

            // Construct query set
            let mut query_set = QuerySet::new();
            let mut values = Evaluations::new();
            // let mut point = F::one();
            for point_id in 0..num_points_in_query_set {
                let point = F::rand(rng);
                for (i, label) in labels.iter().enumerate() {
                    query_set.insert((label.clone(), (format!("rand_{}", point_id), point)));
                    let value = polynomials[i].evaluate(point);
                    values.insert((label.clone(), point), value);
                }
            }
            println!("Generated query set");

            let opening_challenge = F::rand(rng);
            let proof = PC::batch_open(
                &ck,
                &polynomials,
                &comms,
                &query_set,
                opening_challenge,
                &rands,
                Some(rng),
            )?;
            let result = PC::batch_check(&vk, &comms, &query_set, &values, &proof, opening_challenge, rng)?;
            if !result {
                println!(
                    "Failed with {} polynomials, num_points_in_query_set: {:?}",
                    num_polynomials, num_points_in_query_set
                );
                println!("Degree of polynomials:",);
                for poly in polynomials {
                    println!("Degree: {:?}", poly.degree());
                }
            }
            assert!(result, "proof was incorrect, Query set: {:#?}", query_set);

            test_components.push(TestComponents {
                verification_key: vk,
                commitments: comms,
                query_set,
                evaluations: values,
                batch_lc_proof: None,
                batch_proof: Some(proof),
                opening_challenge,
                randomness: rands,
            });
        }
        Ok(test_components)
    }

    fn equation_test_template<F, PC>(info: TestInfo) -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let TestInfo {
            num_iters,
            max_degree,
            supported_degree,
            num_polynomials,
            enforce_degree_bounds,
            max_num_queries,
            num_equations,
        } = info;

        let mut test_components = Vec::new();

        let rng = &mut test_rng();
        let max_degree = max_degree.unwrap_or_else(|| rand::distributions::Uniform::from(2..=64).sample(rng));
        let pp = PC::setup(max_degree, rng)?;

        for _ in 0..num_iters {
            let supported_degree =
                supported_degree.unwrap_or_else(|| rand::distributions::Uniform::from(1..=max_degree).sample(rng));
            assert!(max_degree >= supported_degree, "max_degree < supported_degree");
            let mut polynomials = Vec::new();
            let mut degree_bounds = if enforce_degree_bounds { Some(Vec::new()) } else { None };

            let mut labels = Vec::new();
            println!("Sampled supported degree");

            // Generate polynomials
            let num_points_in_query_set = rand::distributions::Uniform::from(1..=max_num_queries).sample(rng);
            for i in 0..num_polynomials {
                let label = format!("Test{}", i);
                labels.push(label.clone());
                let degree = rand::distributions::Uniform::from(1..=supported_degree).sample(rng);
                let poly = Polynomial::rand(degree, rng);

                let degree_bound = if let Some(degree_bounds) = &mut degree_bounds {
                    if rng.gen() {
                        let range = rand::distributions::Uniform::from(degree..=supported_degree);
                        let degree_bound = range.sample(rng);
                        degree_bounds.push(degree_bound);
                        Some(degree_bound)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let hiding_bound = if num_points_in_query_set >= degree {
                    Some(degree)
                } else {
                    Some(num_points_in_query_set)
                };
                println!("Hiding bound: {:?}", hiding_bound);

                polynomials.push(LabeledPolynomial::new(label, poly, degree_bound, hiding_bound))
            }
            let supported_hiding_bound = polynomials
                .iter()
                .map(|p| p.hiding_bound().unwrap_or(0))
                .max()
                .unwrap_or(0);
            println!("supported degree: {:?}", supported_degree);
            println!("supported hiding bound: {:?}", supported_hiding_bound);
            println!("num_points_in_query_set: {:?}", num_points_in_query_set);
            println!("{:?}", degree_bounds);
            println!("{}", num_polynomials);
            println!("{}", enforce_degree_bounds);

            let (ck, vk) = PC::trim(&pp, supported_degree, supported_hiding_bound, degree_bounds.as_deref())?;
            println!("Trimmed");

            let (comms, rands) = PC::commit(&ck, &polynomials, Some(rng))?;

            // Let's construct our equations
            let mut linear_combinations = Vec::new();
            let mut query_set = QuerySet::new();
            let mut values = Evaluations::new();
            for i in 0..num_points_in_query_set {
                let point = F::rand(rng);
                for j in 0..num_equations.unwrap() {
                    let label = format!("query {} eqn {}", i, j);
                    let mut lc = LinearCombination::empty(label.clone());

                    let mut value = F::zero();
                    let should_have_degree_bounds: bool = rng.gen();
                    for (k, label) in labels.iter().enumerate() {
                        if should_have_degree_bounds {
                            value += &polynomials[k].evaluate(point);
                            lc.push((F::one(), label.to_string().into()));
                            break;
                        } else {
                            let poly = &polynomials[k];
                            if poly.degree_bound().is_some() {
                                continue;
                            } else {
                                assert!(poly.degree_bound().is_none());
                                let coeff = F::rand(rng);
                                value += &(coeff * poly.evaluate(point));
                                lc.push((coeff, label.to_string().into()));
                            }
                        }
                    }
                    values.insert((label.clone(), point), value);
                    if !lc.is_empty() {
                        linear_combinations.push(lc);
                        // Insert query
                        query_set.insert((label.clone(), (format!("rand_{}", i), point)));
                    }
                }
            }
            if linear_combinations.is_empty() {
                continue;
            }
            println!("Generated query set");
            println!("Linear combinations: {:?}", linear_combinations);

            let opening_challenge = F::rand(rng);
            let proof = PC::open_combinations(
                &ck,
                &linear_combinations,
                &polynomials,
                &comms,
                &query_set,
                opening_challenge,
                &rands,
                Some(rng),
            )?;
            println!("Generated proof");
            let result = PC::check_combinations(
                &vk,
                &linear_combinations,
                &comms,
                &query_set,
                &values,
                &proof,
                opening_challenge,
                rng,
            )?;
            if !result {
                println!(
                    "Failed with {} polynomials, num_points_in_query_set: {:?}",
                    num_polynomials, num_points_in_query_set
                );
                println!("Degree of polynomials:",);
                for poly in polynomials {
                    println!("Degree: {:?}", poly.degree());
                }
            }
            assert!(result, "proof was incorrect, equations: {:#?}", linear_combinations);

            test_components.push(TestComponents {
                verification_key: vk,
                commitments: comms,
                query_set,
                evaluations: values,
                batch_lc_proof: Some(proof),
                batch_proof: None,
                opening_challenge,
                randomness: rands,
            });
        }
        Ok(test_components)
    }

    pub fn single_poly_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: None,
            supported_degree: None,
            num_polynomials: 1,
            enforce_degree_bounds: false,
            max_num_queries: 1,
            ..Default::default()
        };
        test_template::<F, PC>(info)
    }

    pub fn linear_poly_degree_bound_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: Some(2),
            supported_degree: Some(1),
            num_polynomials: 1,
            enforce_degree_bounds: true,
            max_num_queries: 1,
            ..Default::default()
        };
        test_template::<F, PC>(info)
    }

    pub fn single_poly_degree_bound_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: None,
            supported_degree: None,
            num_polynomials: 1,
            enforce_degree_bounds: true,
            max_num_queries: 1,
            ..Default::default()
        };
        test_template::<F, PC>(info)
    }

    pub fn quadratic_poly_degree_bound_multiple_queries_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: Some(3),
            supported_degree: Some(2),
            num_polynomials: 1,
            enforce_degree_bounds: true,
            max_num_queries: 2,
            ..Default::default()
        };
        test_template::<F, PC>(info)
    }

    pub fn single_poly_degree_bound_multiple_queries_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: None,
            supported_degree: None,
            num_polynomials: 1,
            enforce_degree_bounds: true,
            max_num_queries: 2,
            ..Default::default()
        };
        test_template::<F, PC>(info)
    }

    pub fn two_polys_degree_bound_single_query_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: None,
            supported_degree: None,
            num_polynomials: 2,
            enforce_degree_bounds: true,
            max_num_queries: 1,
            ..Default::default()
        };
        test_template::<F, PC>(info)
    }

    pub fn full_end_to_end_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: None,
            supported_degree: None,
            num_polynomials: 10,
            enforce_degree_bounds: true,
            max_num_queries: 5,
            ..Default::default()
        };
        test_template::<F, PC>(info)
    }

    pub fn full_end_to_end_equation_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: None,
            supported_degree: None,
            num_polynomials: 10,
            enforce_degree_bounds: true,
            max_num_queries: 5,
            num_equations: Some(10),
        };
        equation_test_template::<F, PC>(info)
    }

    pub fn single_equation_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: None,
            supported_degree: None,
            num_polynomials: 1,
            enforce_degree_bounds: false,
            max_num_queries: 1,
            num_equations: Some(1),
        };
        equation_test_template::<F, PC>(info)
    }

    pub fn two_equation_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: None,
            supported_degree: None,
            num_polynomials: 2,
            enforce_degree_bounds: false,
            max_num_queries: 1,
            num_equations: Some(2),
        };
        equation_test_template::<F, PC>(info)
    }

    pub fn two_equation_degree_bound_test<F, PC>() -> Result<Vec<TestComponents<F, PC>>, PC::Error>
    where
        F: Field,
        PC: PolynomialCommitment<F>,
    {
        let info = TestInfo {
            num_iters: 100,
            max_degree: None,
            supported_degree: None,
            num_polynomials: 2,
            enforce_degree_bounds: true,
            max_num_queries: 1,
            num_equations: Some(2),
        };
        equation_test_template::<F, PC>(info)
    }
}
