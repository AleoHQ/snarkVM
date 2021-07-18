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

use snarkvm_fields::{field, Zero};
use snarkvm_utilities::biginteger::{BigInteger256, BigInteger384};

use crate::{
    bls12_377::{Fq, Fr},
    traits::{ModelParameters, ShortWeierstrassParameters},
};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Bls12_377G1Parameters;

impl ModelParameters for Bls12_377G1Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;
}

impl ShortWeierstrassParameters for Bls12_377G1Parameters {
    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) = (G1_GENERATOR_X, G1_GENERATOR_Y);
    /// COEFF_A = 0
    const COEFF_A: Fq = field!(Fq, BigInteger384([0x0, 0x0, 0x0, 0x0, 0x0, 0x0]));
    /// COEFF_B = 1
    const COEFF_B: Fq = field!(
        Fq,
        BigInteger384([
            0x2cdffffffffff68,
            0x51409f837fffffb1,
            0x9f7db3a98a7d3ff2,
            0x7b4e97b76e7c6305,
            0x4cf495bf803c84e8,
            0x8d6661e2fdf49a,
        ])
    );
    /// COFACTOR = (x - 1)^2 / 3  = 30631250834960419227450344600217059328
    const COFACTOR: &'static [u64] = &[0x0, 0x170b5d4430000000];
    /// COFACTOR_INV = COFACTOR^{-1} mod r
    /// = 5285428838741532253824584287042945485047145357130994810877
    const COFACTOR_INV: Fr = field!(
        Fr,
        BigInteger256([
            2013239619100046060,
            4201184776506987597,
            2526766393982337036,
            1114629510922847535,
        ])
    );

    #[inline(always)]
    fn mul_by_a(_: &Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

///
/// G1_GENERATOR_X =
/// 89363714989903307245735717098563574705733591463163614225748337416674727625843187853442697973404985688481508350822
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bls12_377` for tests.
///
pub const G1_GENERATOR_X: Fq = field!(
    Fq,
    BigInteger384::new([
        1171681672315280277,
        6528257384425852712,
        7514971432460253787,
        2032708395764262463,
        12876543207309632302,
        107509843840671767
    ])
);

///
/// G1_GENERATOR_Y =
/// 3702177272937190650578065972808860481433820514072818216637796320125658674906330993856598323293086021583822603349
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bls12_377` for tests.
///
pub const G1_GENERATOR_Y: Fq = field!(
    Fq,
    BigInteger384::new([
        13572190014569192121,
        15344828677741220784,
        17067903700058808083,
        10342263224753415805,
        1083990386877464092,
        21335464879237822
    ])
);
