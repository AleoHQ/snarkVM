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

use crate::traits::Group;
use snarkvm_fields::{Field, PrimeField, SquareRootField, ToConstraintField};
use snarkvm_utilities::{biginteger::BigInteger, serialize::*, BitIteratorBE, ToBytes};

use std::{fmt::Debug, iter};

pub trait PairingEngine: Sized + 'static + Copy + Debug + Sync + Send {
    /// This is the scalar field of the G1/G2 groups.
    type Fr: PrimeField + SquareRootField + Into<<Self::Fr as PrimeField>::BigInteger>;

    /// The projective representation of an element in G1.
    type G1Projective: ProjectiveCurve<BaseField = Self::Fq, ScalarField = Self::Fr, Affine = Self::G1Affine>
        + From<Self::G1Affine>;

    /// The affine representation of an element in G1.
    type G1Affine: AffineCurve<BaseField = Self::Fq, ScalarField = Self::Fr, Projective = Self::G1Projective>
        + PairingCurve<PairWith = Self::G2Affine, PairingResult = Self::Fqk>
        + From<Self::G1Projective>
        + ToConstraintField<Self::Fq>;

    /// The projective representation of an element in G2.
    type G2Projective: ProjectiveCurve<BaseField = Self::Fqe, ScalarField = Self::Fr, Affine = Self::G2Affine>
        + From<Self::G2Affine>;

    /// The affine representation of an element in G2.
    type G2Affine: AffineCurve<BaseField = Self::Fqe, ScalarField = Self::Fr, Projective = Self::G2Projective>
        + PairingCurve<PairWith = Self::G1Affine, PairingResult = Self::Fqk>
        + From<Self::G2Projective>
        + ToConstraintField<Self::Fq>;

    /// The base field that hosts G1.
    type Fq: PrimeField + SquareRootField;

    /// The extension field that hosts G2.
    type Fqe: SquareRootField;

    /// The extension field that hosts the target group of the pairing.
    type Fqk: Field;

    /// Perform a miller loop with some number of (G1, G2) pairs.
    #[must_use]
    fn miller_loop<'a, I>(i: I) -> Self::Fqk
    where
        I: Iterator<
            Item = (
                &'a <Self::G1Affine as PairingCurve>::Prepared,
                &'a <Self::G2Affine as PairingCurve>::Prepared,
            ),
        >;

    /// Perform final exponentiation of the result of a miller loop.
    #[must_use]
    fn final_exponentiation(_: &Self::Fqk) -> Option<Self::Fqk>;

    /// Computes a product of pairings.
    #[must_use]
    fn product_of_pairings<'a, I>(i: I) -> Self::Fqk
    where
        I: Iterator<
            Item = (
                &'a <Self::G1Affine as PairingCurve>::Prepared,
                &'a <Self::G2Affine as PairingCurve>::Prepared,
            ),
        >,
    {
        Self::final_exponentiation(&Self::miller_loop(i)).unwrap()
    }

    /// Performs multiple pairing operations
    #[must_use]
    fn pairing<G1, G2>(p: G1, q: G2) -> Self::Fqk
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        Self::final_exponentiation(&Self::miller_loop(iter::once((
            &p.into().prepare(),
            &q.into().prepare(),
        ))))
        .unwrap()
    }
}

/// Projective representation of an elliptic curve point guaranteed to be
/// in the correct prime order subgroup.
pub trait ProjectiveCurve:
    Group
    + Sized
    + CanonicalSerialize
    + ConstantSerializedSize
    + CanonicalDeserialize
    + From<<Self as ProjectiveCurve>::Affine>
{
    type BaseField: Field;
    type Affine: AffineCurve<Projective = Self, ScalarField = Self::ScalarField> + From<Self> + Into<Self>;

    /// Returns a fixed generator of unknown exponent.
    #[must_use]
    fn prime_subgroup_generator() -> Self;

    /// Normalizes a slice of projective elements so that
    /// conversion to affine is cheap.
    fn batch_normalization(v: &mut [Self]);

    /// Normalizes a slice of projective elements and outputs a vector
    /// containing the affine equivalents.
    fn batch_normalization_into_affine(mut v: Vec<Self>) -> Vec<Self::Affine> {
        Self::batch_normalization(&mut v);
        v.into_iter().map(|v| v.into()).collect()
    }

    /// Checks if the point is already "normalized" so that
    /// cheap affine conversion is possible.
    #[must_use]
    fn is_normalized(&self) -> bool;

    /// Adds an affine element to this element.
    fn add_assign_mixed(&mut self, other: &Self::Affine);

    /// Converts this element into its affine representation.
    #[must_use]
    #[allow(clippy::wrong_self_convention)]
    fn into_affine(&self) -> Self::Affine;

    /// Recommends a wNAF window table size given a scalar. Always returns a
    /// number between 2 and 22, inclusive.
    #[must_use]
    fn recommended_wnaf_for_scalar(scalar: <Self::ScalarField as PrimeField>::BigInteger) -> usize;

    /// Recommends a wNAF window size given the number of scalars you intend to
    /// multiply a base by. Always returns a number between 2 and 22,
    /// inclusive.
    #[must_use]
    fn recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize;
}

/// Affine representation of an elliptic curve point guaranteed to be
/// in the correct prime order subgroup.
#[allow(clippy::wrong_self_convention)]
pub trait AffineCurve:
    Group
    + Sized
    + CanonicalSerialize
    + ConstantSerializedSize
    + CanonicalDeserialize
    + From<<Self as AffineCurve>::Projective>
{
    type BaseField: Field;
    type Projective: ProjectiveCurve<Affine = Self, ScalarField = Self::ScalarField> + From<Self> + Into<Self>;

    /// Returns a fixed generator of unknown exponent.
    #[must_use]
    fn prime_subgroup_generator() -> Self;

    /// Attempts to construct an affine point given an x-coordinate. The
    /// point is not guaranteed to be in the prime order subgroup.
    ///
    /// If and only if `greatest` is set will the lexicographically
    /// largest y-coordinate be selected.
    fn from_x_coordinate(x: Self::BaseField, greatest: bool) -> Option<Self>;

    /// Attempts to construct an affine point given a y-coordinate. The
    /// point is not guaranteed to be in the prime order subgroup.
    ///
    /// If and only if `greatest` is set will the lexicographically
    /// largest y-coordinate be selected.
    fn from_y_coordinate(y: Self::BaseField, greatest: bool) -> Option<Self>;

    /// Multiply this element by the cofactor and output the
    /// resulting projective element.
    #[must_use]
    fn mul_by_cofactor_to_projective(&self) -> Self::Projective;

    /// Converts this element into its projective representation.
    #[must_use]
    fn into_projective(&self) -> Self::Projective;

    /// Returns a group element if the set of bytes forms a valid group element,
    /// otherwise returns None. This function is primarily intended for sampling
    /// random group elements from a hash-function or RNG output.
    fn from_random_bytes(bytes: &[u8]) -> Option<Self>;

    /// Multiply this element by a scalar field element in BigInteger form.
    fn mul_bits<S: AsRef<[u64]>>(&self, bits: BitIteratorBE<S>) -> Self::Projective;

    /// Multiply this element by the cofactor.
    #[must_use]
    fn mul_by_cofactor(&self) -> Self {
        self.mul_by_cofactor_to_projective().into()
    }

    /// Multiply this element by the inverse of the cofactor modulo the size of
    /// `Self::ScalarField`.
    #[must_use]
    fn mul_by_cofactor_inv(&self) -> Self;

    /// Checks that the point is in the prime order subgroup given the point on the curve.
    #[must_use]
    fn is_in_correct_subgroup_assuming_on_curve(&self) -> bool;

    /// Returns the x-coordinate of the point.
    #[must_use]
    fn to_x_coordinate(&self) -> Self::BaseField;

    /// Returns the y-coordinate of the point.
    #[must_use]
    fn to_y_coordinate(&self) -> Self::BaseField;

    /// Checks that the current point is on the elliptic curve.
    fn is_on_curve(&self) -> bool;
}

pub trait PairingCurve: AffineCurve {
    type Engine: PairingEngine<Fr = Self::ScalarField>;
    type Prepared: CanonicalSerialize + CanonicalDeserialize + ToBytes + Default + Clone + Send + Sync + Debug + 'static;
    type PairWith: PairingCurve<PairWith = Self>;
    type PairingResult: Field;

    /// Prepares this element for pairing purposes.
    #[must_use]
    fn prepare(&self) -> Self::Prepared;

    /// Perform a pairing
    #[must_use]
    fn pairing_with(&self, other: &Self::PairWith) -> Self::PairingResult;
}

pub trait ModelParameters: Send + Sync + 'static {
    type BaseField: Field + SquareRootField;
    type ScalarField: PrimeField + SquareRootField + Into<<Self::ScalarField as PrimeField>::BigInteger>;
}

pub trait ShortWeierstrassParameters: ModelParameters {
    const COEFF_A: Self::BaseField;
    const COEFF_B: Self::BaseField;
    const COFACTOR: &'static [u64];
    const COFACTOR_INV: Self::ScalarField;
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField);

    #[inline(always)]
    fn mul_by_a(elem: &Self::BaseField) -> Self::BaseField {
        let mut copy = *elem;
        copy *= &Self::COEFF_A;
        copy
    }

    #[inline(always)]
    fn add_b(elem: &Self::BaseField) -> Self::BaseField {
        let mut copy = *elem;
        copy += &Self::COEFF_B;
        copy
    }

    #[inline(always)]
    fn empirical_recommended_wnaf_for_scalar(scalar: <Self::ScalarField as PrimeField>::BigInteger) -> usize {
        let num_bits = scalar.num_bits() as usize;

        if num_bits >= 103 {
            4
        } else if num_bits >= 37 {
            3
        } else {
            2
        }
    }

    #[inline(always)]
    fn empirical_recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
        const RECOMMENDATIONS: [usize; 11] = [1, 3, 8, 20, 47, 126, 260, 826, 1501, 4555, 84071];

        let mut result = 4;
        for r in &RECOMMENDATIONS {
            match num_scalars > *r {
                true => result += 1,
                false => break,
            }
        }
        result
    }
}

pub trait TwistedEdwardsParameters: ModelParameters {
    const COEFF_A: Self::BaseField;
    const COEFF_D: Self::BaseField;
    const COFACTOR: &'static [u64];
    const COFACTOR_INV: Self::ScalarField;
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField);

    type MontgomeryParameters: MontgomeryParameters<BaseField = Self::BaseField>;

    #[inline(always)]
    fn mul_by_a(elem: &Self::BaseField) -> Self::BaseField {
        let mut copy = *elem;
        copy *= &Self::COEFF_A;
        copy
    }

    #[inline(always)]
    fn empirical_recommended_wnaf_for_scalar(scalar: <Self::ScalarField as PrimeField>::BigInteger) -> usize {
        let num_bits = scalar.num_bits() as usize;

        if num_bits >= 130 {
            4
        } else if num_bits >= 34 {
            3
        } else {
            2
        }
    }

    #[inline(always)]
    fn empirical_recommended_wnaf_for_num_scalars(num_scalars: usize) -> usize {
        const RECOMMENDATIONS: [usize; 12] = [1, 3, 7, 20, 43, 120, 273, 563, 1630, 3128, 7933, 62569];

        let mut ret = 4;
        for r in &RECOMMENDATIONS {
            if num_scalars > *r {
                ret += 1;
            } else {
                break;
            }
        }

        ret
    }
}

pub trait MontgomeryParameters: ModelParameters {
    const COEFF_A: Self::BaseField;
    const COEFF_B: Self::BaseField;

    type TwistedEdwardsParameters: TwistedEdwardsParameters<BaseField = Self::BaseField>;
}
