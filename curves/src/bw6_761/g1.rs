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
use snarkvm_utilities::biginteger::{BigInteger384, BigInteger768};

use crate::{
    bw6_761::{Fq, Fr},
    traits::{ModelParameters, ShortWeierstrassParameters},
};

#[derive(Clone, Default, PartialEq, Eq)]
pub struct BW6_761G1Parameters;

impl ModelParameters for BW6_761G1Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;
}

impl ShortWeierstrassParameters for BW6_761G1Parameters {
    /// AFFINE_GENERATOR_COEFFS = (G1_GENERATOR_X, G1_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) = (G1_GENERATOR_X, G1_GENERATOR_Y);
    /// COEFF_A = 0
    const COEFF_A: Fq = field!(Fq, BigInteger768([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    /// COEFF_B = -1
    const COEFF_B: Fq = field!(
        Fq,
        BigInteger768([
            0xf29a000000007ab6,
            0x8c391832e000739b,
            0x77738a6b6870f959,
            0xbe36179047832b03,
            0x84f3089e56574722,
            0xc5a3614ac0b1d984,
            0x5c81153f4906e9fe,
            0x4d28be3a9f55c815,
            0xd72c1d6f77d5f5c5,
            0x73a18e069ac04458,
            0xf9dfaa846595555f,
            0xd0f0a60a5be58c,
        ])
    );
    /// COFACTOR =
    /// 26642435879335816683987677701488073867751118270052650655942102502312977592501693353047140953112195348280268661194876
    const COFACTOR: &'static [u64] = &[
        0x3de580000000007c,
        0x832ba4061000003b,
        0xc61c554757551c0c,
        0xc856a0853c9db94c,
        0x2c77d5ac34cb12ef,
        0xad1972339049ce76,
    ];
    /// COFACTOR^(-1) mod r =
    /// 91141326767669940707819291241958318717982251277713150053234367522357946997763584490607453720072232540829942217804
    const COFACTOR_INV: Fr = field!(
        Fr,
        BigInteger384([
            489703175600125849,
            3883341943836920852,
            1678256062427438196,
            5848789333018172718,
            7127967896440782320,
            71512347676739162,
        ])
    );

    #[inline(always)]
    fn mul_by_a(_elem: &Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

///
/// G1_GENERATOR_X =
/// 3475636518786498766590810745250126945968740010631847578009395853050342820108308881971249946821118240925527322852779996711186385119856316194209542863985484661252056926060250383124450299173357715156750061459909058938784631925098185
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bw6_761` for tests.
///
pub const G1_GENERATOR_X: Fq = field!(
    Fq,
    BigInteger768::new([
        12877523079922362788,
        7752575235482070428,
        10011652029515665100,
        15977973268104179781,
        6650682096433390709,
        7089159491550934343,
        12402656740034927996,
        16078622859415237779,
        6176729449605897675,
        13861293628711269015,
        10247809388267527780,
        10528928568506906
    ])
);

///
/// G1_GENERATOR_Y =
/// 6386045741560615474115286751221519546327665724453260780636948036691066354033553926136039329128245771826622081935656169693501570527441758504134165160161290809285880130747815459138453114895109629685668115497335848801906309831854449
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bw6_761` for tests.
///
pub const G1_GENERATOR_Y: Fq = field!(
    Fq,
    BigInteger768::new([
        2946353734925236977,
        16176025292777111085,
        5461526384304579835,
        9030519021371797121,
        392712970462636053,
        16933452782188291054,
        15151082028748062197,
        11724317612978406850,
        9469657462524899792,
        403488069705763791,
        14811030666200823776,
        39400888622938101
    ])
);
