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
pub struct Bls12_377G2Parameters;

impl ModelParameters for Bls12_377G2Parameters {
    type BaseField = Fq;
    type ScalarField = Fr;
}

impl ShortWeierstrassParameters for Bls12_377G2Parameters {
    /// AFFINE_GENERATOR_COEFFS = (G2_GENERATOR_X, G2_GENERATOR_Y)
    const AFFINE_GENERATOR_COEFFS: (Self::BaseField, Self::BaseField) = (G2_GENERATOR_X, G2_GENERATOR_Y);
    /// COEFF_A = 0
    const COEFF_A: Fq = field!(Fq, BigInteger768([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]));
    /// COEFF_B = 4
    const COEFF_B: Fq = field!(
        Fq,
        BigInteger768([
            0x136efffffffe16c9,
            0x82cf5a6dcffe3319,
            0x6458c05f1f0e0741,
            0xd10ae605e52a4eda,
            0x41ca591c0266e100,
            0x7d0fd59c3626929f,
            0x9967dc004d00c112,
            0x1ccff9c033379af5,
            0x9ad6ec10a23f63af,
            0x5cec11251a72c235,
            0x8d18b1ae789ba83e,
            10403402007434220,
        ])
    );
    /// COFACTOR =
    /// 26642435879335816683987677701488073867751118270052650655942102502312977592501693353047140953112195348280268661194869
    const COFACTOR: &'static [u64] = &[
        0x3de5800000000075,
        0x832ba4061000003b,
        0xc61c554757551c0c,
        0xc856a0853c9db94c,
        0x2c77d5ac34cb12ef,
        0xad1972339049ce76,
    ];
    /// COFACTOR^(-1) mod r =
    /// 214911522365886453591244899095480747723790054550866810551297776298664428889000553861210287833206024638187939842124
    const COFACTOR_INV: Fr = field!(
        Fr,
        BigInteger384([
            14378295991815829998,
            14586153992421458638,
            9788477762582722914,
            12654821707953664524,
            15185631607604703397,
            26723985783783076,
        ])
    );

    #[inline(always)]
    fn mul_by_a(_elem: &Self::BaseField) -> Self::BaseField {
        Self::BaseField::zero()
    }
}

///
/// G2_GENERATOR_X =
///  927956984471615468124472746554543101337527312348662621347440770917496233677004806656401789322295154757803076219469766862850983203848259151794917476784348647741097824043386936111698873760942854285698387656381822040687217598671475
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bw6_761` for tests.
///
pub const G2_GENERATOR_X: Fq = field!(
    Fq,
    BigInteger768::new([
        10634505283823758248,
        12474260491383229975,
        15569041147122342465,
        229589451343854593,
        17809542510990719370,
        7141848535003467854,
        12291544884903833552,
        10318678898116314991,
        10135148888583310199,
        7938758716343420664,
        12876992257746654479,
        28134550160207396
    ])
);

///
/// G2_GENERATOR_Y =
/// 608205995591379252593575348853717734690994487823225986322386812170777664697317078928599401333750023327415326429631777048153067399834460761103119533693592159593385004303526978878263449123862579622710147286865775614857922338717660
///
/// See `snarkvm_algorithms::hash_to_curve::tests::bw6_761` for tests.
///
pub const G2_GENERATOR_Y: Fq = field!(
    Fq,
    BigInteger768::new([
        13646097242432658323,
        4850665909724646326,
        7360412517677089449,
        12865608907432106429,
        4102018624610352121,
        17837689763279414164,
        1465321240991937963,
        14363746691071914467,
        9255969020966565367,
        8837836703783055843,
        8516967617461466404,
        41650228197102562
    ])
);
