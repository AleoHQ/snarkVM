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

use crate::{impl_bytes, PCCommitment, PCCommitterKey, PCRandomness, PCVerifierKey, Vec};
use snarkvm_curves::{traits::PairingEngine, Group};
use snarkvm_fields::{ConstraintFieldError, PrimeField, ToConstraintField};
use snarkvm_utilities::{error, errors::SerializationError, serialize::*, FromBytes, ToBytes};

use core::ops::{Add, AddAssign};
use rand_core::RngCore;

use crate::kzg10;
use snarkvm_algorithms::Prepare;

/// `UniversalParams` are the universal parameters for the KZG10 scheme.
pub type UniversalParams<E> = kzg10::UniversalParams<E>;

/// `CommitterKey` is used to commit to and create evaluation proofs for a given
/// polynomial.
#[derive(Derivative)]
#[derivative(Default(bound = ""), Hash(bound = ""), Clone(bound = ""), Debug(bound = ""))]
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct CommitterKey<E: PairingEngine> {
    /// The key used to commit to polynomials.
    pub powers: Vec<E::G1Affine>,

    /// The key used to commit to shifted polynomials.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub shifted_powers: Option<Vec<E::G1Affine>>,

    /// The key used to commit to hiding polynomials.
    pub powers_of_gamma_g: Vec<E::G1Affine>,

    /// The degree bounds that are supported by `self`.
    /// In ascending order from smallest to largest.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub enforced_degree_bounds: Option<Vec<usize>>,
    /// The maximum degree supported by the `UniversalParams` `self` was derived
    /// from.
    pub max_degree: usize,
}
impl_bytes!(CommitterKey);

impl<E: PairingEngine> CommitterKey<E> {
    /// Obtain powers for the underlying KZG10 construction
    pub fn powers(&self) -> kzg10::Powers<'_, E> {
        kzg10::Powers {
            powers_of_g: self.powers.as_slice().into(),
            powers_of_gamma_g: self.powers_of_gamma_g.as_slice().into(),
        }
    }

    /// Obtain powers for committing to shifted polynomials.
    pub fn shifted_powers(&self, degree_bound: impl Into<Option<usize>>) -> Option<kzg10::Powers<'_, E>> {
        self.shifted_powers.as_ref().map(|shifted_powers| {
            let powers_range = if let Some(degree_bound) = degree_bound.into() {
                assert!(self.enforced_degree_bounds.as_ref().unwrap().contains(&degree_bound));
                let max_bound = self.enforced_degree_bounds.as_ref().unwrap().last().unwrap();
                (max_bound - degree_bound)..
            } else {
                0..
            };
            let ck = kzg10::Powers {
                powers_of_g: (&shifted_powers[powers_range]).into(),
                powers_of_gamma_g: self.powers_of_gamma_g.as_slice().into(),
            };
            ck
        })
    }
}

impl<E: PairingEngine> PCCommitterKey for CommitterKey<E> {
    fn max_degree(&self) -> usize {
        self.max_degree
    }

    fn supported_degree(&self) -> usize {
        self.powers.len()
    }
}

/// `VerifierKey` is used to check evaluation proofs for a given commitment.
#[derive(Derivative)]
#[derivative(Default(bound = ""), Clone(bound = ""), Debug(bound = ""))]
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct VerifierKey<E: PairingEngine> {
    /// The verification key for the underlying KZG10 scheme.
    pub vk: kzg10::VerifierKey<E>,
    /// Information required to enforce degree bounds. Each pair
    /// is of the form `(degree_bound, shifting_advice)`.
    /// The vector is sorted in ascending order of `degree_bound`.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub degree_bounds_and_shift_powers: Option<Vec<(usize, E::G1Affine)>>,
    /// The maximum degree supported by the `UniversalParams` `self` was derived
    /// from.
    pub max_degree: usize,
    /// The maximum degree supported by the trimmed parameters that `self` is
    /// a part of.
    pub supported_degree: usize,
}
impl_bytes!(VerifierKey);

impl<E: PairingEngine> VerifierKey<E> {
    /// Find the appropriate shift for the degree bound.
    pub fn get_shift_power(&self, bound: usize) -> Option<E::G1Affine> {
        self.degree_bounds_and_shift_powers
            .as_ref()
            .and_then(|v| v.binary_search_by(|(d, _)| d.cmp(&bound)).ok().map(|i| v[i].1))
    }
}

impl<E: PairingEngine> PCVerifierKey for VerifierKey<E> {
    fn max_degree(&self) -> usize {
        self.max_degree
    }

    fn supported_degree(&self) -> usize {
        self.supported_degree
    }
}

impl<E: PairingEngine> ToConstraintField<E::Fq> for VerifierKey<E>
where
    E::G1Affine: ToConstraintField<E::Fq>,
    E::G2Affine: ToConstraintField<E::Fq>,
{
    fn to_field_elements(&self) -> Result<Vec<E::Fq>, ConstraintFieldError> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.vk.to_field_elements()?);

        if let Some(degree_bounds_and_shift_powers) = &self.degree_bounds_and_shift_powers {
            for (d, shift_power) in degree_bounds_and_shift_powers.iter() {
                let d_elem: E::Fq = (*d as u64).into();

                res.push(d_elem);
                res.extend_from_slice(&shift_power.to_field_elements()?);
            }
        }

        Ok(res)
    }
}

/// `PreparedVerifierKey` is used to check evaluation proofs for a given commitment.
#[derive(Derivative)]
#[derivative(Clone(bound = ""), Debug(bound = ""))]
pub struct PreparedVerifierKey<E: PairingEngine> {
    /// The verification key for the underlying KZG10 scheme.
    pub prepared_vk: kzg10::PreparedVerifierKey<E>,
    /// Information required to enforce degree bounds. Each pair
    /// is of the form `(degree_bound, shifting_advice)`.
    /// This is `None` if `self` does not support enforcing any degree bounds.
    pub prepared_degree_bounds_and_shift_powers: Option<Vec<(usize, Vec<E::G1Affine>)>>,
    /// The maximum degree supported by the `UniversalParams` `self` was derived
    /// from.
    pub max_degree: usize,
    /// The maximum degree supported by the trimmed parameters that `self` is
    /// a part of.
    pub supported_degree: usize,
}

impl<E: PairingEngine> Prepare<PreparedVerifierKey<E>> for VerifierKey<E> {
    /// prepare `PreparedVerifierKey` from `VerifierKey`
    fn prepare(&self) -> PreparedVerifierKey<E> {
        let prepared_vk = kzg10::PreparedVerifierKey::<E>::prepare(&self.vk);

        let supported_bits = E::Fr::size_in_bits();

        let prepared_degree_bounds_and_shift_powers: Option<Vec<(usize, Vec<E::G1Affine>)>> =
            if self.degree_bounds_and_shift_powers.is_some() {
                let mut res = Vec::<(usize, Vec<E::G1Affine>)>::new();

                let degree_bounds_and_shift_powers = self.degree_bounds_and_shift_powers.as_ref().unwrap();

                for (d, shift_power) in degree_bounds_and_shift_powers {
                    let mut prepared_shift_power = Vec::<E::G1Affine>::new();

                    let mut cur = E::G1Projective::from(shift_power.clone());
                    for _ in 0..supported_bits {
                        prepared_shift_power.push(cur.clone().into());
                        cur.double_in_place();
                    }

                    res.push((d.clone(), prepared_shift_power));
                }

                Some(res)
            } else {
                None
            };

        PreparedVerifierKey::<E> {
            prepared_vk,
            prepared_degree_bounds_and_shift_powers,
            max_degree: self.max_degree,
            supported_degree: self.supported_degree,
        }
    }
}

/// Commitment to a polynomial that optionally enforces a degree bound.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Copy(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Commitment<E: PairingEngine> {
    pub(crate) comm: kzg10::Commitment<E>,
    pub(crate) shifted_comm: Option<kzg10::Commitment<E>>,
}
impl_bytes!(Commitment);

impl<E: PairingEngine> PCCommitment for Commitment<E> {
    #[inline]
    fn empty() -> Self {
        Self {
            comm: kzg10::Commitment::empty(),
            shifted_comm: Some(kzg10::Commitment::empty()),
        }
    }

    fn has_degree_bound(&self) -> bool {
        self.shifted_comm.is_some()
    }

    fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool {
        self.comm.is_in_correct_subgroup_assuming_on_curve()
            && if let Some(ref comm) = self.shifted_comm {
                comm.is_in_correct_subgroup_assuming_on_curve()
            } else {
                true
            }
    }
}

impl<E: PairingEngine> ToConstraintField<E::Fq> for Commitment<E>
where
    E::G1Affine: ToConstraintField<E::Fq>,
{
    fn to_field_elements(&self) -> Result<Vec<E::Fq>, ConstraintFieldError> {
        let mut res = Vec::new();
        res.extend_from_slice(&self.comm.to_field_elements()?);

        if let Some(shifted_comm) = &self.shifted_comm {
            res.extend_from_slice(&shifted_comm.to_field_elements()?);
        }

        Ok(res)
    }
}

/// Prepared commitment to a polynomial that optionally enforces a degree bound.
#[derive(Derivative)]
#[derivative(
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
pub struct PreparedCommitment<E: PairingEngine> {
    pub(crate) prepared_comm: kzg10::PreparedCommitment<E>,
    pub(crate) shifted_comm: Option<kzg10::Commitment<E>>,
}

impl<E: PairingEngine> Prepare<PreparedCommitment<E>> for Commitment<E> {
    /// Prepare commitment to a polynomial that optionally enforces a degree bound.
    fn prepare(&self) -> PreparedCommitment<E> {
        let prepared_commitment = kzg10::PreparedCommitment::<E>::prepare(&self.comm);

        let shifted_commitment = self.shifted_comm.clone();

        PreparedCommitment::<E> {
            prepared_comm: prepared_commitment,
            shifted_comm: shifted_commitment,
        }
    }
}

/// `Randomness` hides the polynomial inside a commitment. It is output by `KZG10::commit`.
#[derive(Derivative)]
#[derivative(
    Default(bound = ""),
    Hash(bound = ""),
    Clone(bound = ""),
    Debug(bound = ""),
    PartialEq(bound = ""),
    Eq(bound = "")
)]
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct Randomness<E: PairingEngine> {
    pub(crate) rand: kzg10::Randomness<E>,
    pub(crate) shifted_rand: Option<kzg10::Randomness<E>>,
}
impl_bytes!(Randomness);

impl<'a, E: PairingEngine> Add<&'a Self> for Randomness<E> {
    type Output = Self;

    fn add(mut self, other: &'a Self) -> Self {
        self += other;
        self
    }
}

impl<'a, E: PairingEngine> AddAssign<&'a Self> for Randomness<E> {
    #[inline]
    fn add_assign(&mut self, other: &'a Self) {
        self.rand += &other.rand;
        if let Some(r1) = &mut self.shifted_rand {
            *r1 += other.shifted_rand.as_ref().unwrap_or(&kzg10::Randomness::empty());
        } else {
            self.shifted_rand = other.shifted_rand.clone();
        }
    }
}

impl<'a, E: PairingEngine> Add<(E::Fr, &'a Randomness<E>)> for Randomness<E> {
    type Output = Self;

    #[inline]
    fn add(mut self, other: (E::Fr, &'a Randomness<E>)) -> Self {
        self += other;
        self
    }
}

impl<'a, E: PairingEngine> AddAssign<(E::Fr, &'a Randomness<E>)> for Randomness<E> {
    #[inline]
    fn add_assign(&mut self, (f, other): (E::Fr, &'a Randomness<E>)) {
        self.rand += (f, &other.rand);
        let empty = kzg10::Randomness::empty();
        if let Some(r1) = &mut self.shifted_rand {
            *r1 += (f, other.shifted_rand.as_ref().unwrap_or(&empty));
        } else {
            self.shifted_rand = other.shifted_rand.as_ref().map(|r| empty + (f, r));
        }
    }
}

impl<E: PairingEngine> PCRandomness for Randomness<E> {
    fn empty() -> Self {
        Self {
            rand: kzg10::Randomness::empty(),
            shifted_rand: None,
        }
    }

    fn rand<R: RngCore>(hiding_bound: usize, has_degree_bound: bool, rng: &mut R) -> Self {
        let shifted_rand = if has_degree_bound {
            Some(kzg10::Randomness::rand(hiding_bound, false, rng))
        } else {
            None
        };
        Self {
            rand: kzg10::Randomness::rand(hiding_bound, false, rng),
            shifted_rand,
        }
    }
}
