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

use snarkvm_fields::{
    FftParameters,
    FieldParameters,
    Fp256,
    Fp256Parameters,
    PoseidonDefaultParameters,
    PoseidonDefaultParametersEntry,
};
use snarkvm_utilities::biginteger::BigInteger256 as BigInteger;

pub type Fr = Fp256<FrParameters>;

pub struct FrParameters;

impl Fp256Parameters for FrParameters {}

impl FftParameters for FrParameters {
    type BigInteger = BigInteger;

    const TWO_ADICITY: u32 = 1;
    #[rustfmt::skip]
    const TWO_ADIC_ROOT_OF_UNITY: BigInteger = BigInteger([
        15170730761708361161u64,
        13670723686578117817u64,
        12803492266614043665u64,
        50861023252832611u64,
    ]);
}

impl FieldParameters for FrParameters {
    #[rustfmt::skip]
    const CAPACITY: u32 = Self::MODULUS_BITS - 1;
    /// 70865795004005329077606947863872807680085016823885970091001235374859923341923
    #[rustfmt::skip]
    const GENERATOR: BigInteger = BigInteger([
        11289572479685143826u64,
        11383637369941080925u64,
        2288212753973340071u64,
        82014976407880291u64,
    ]);
    #[rustfmt::skip]
    const INV: u64 = 9659935179256617473u64;
    /// MODULUS = 2111115437357092606062206234695386632838870926408408195193685246394721360383
    #[rustfmt::skip]
    const MODULUS: BigInteger = BigInteger([
        13356249993388743167u64,
        5950279507993463550u64,
        10965441865914903552u64,
        336320092672043349u64,
    ]);
    #[rustfmt::skip]
    const MODULUS_BITS: u32 = 251;
    #[rustfmt::skip]
    const MODULUS_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        6678124996694371583u64,
        2975139753996731775u64,
        14706092969812227584u64,
        168160046336021674u64,
    ]);
    #[rustfmt::skip]
    const R: BigInteger = BigInteger([
        16632263305389933622u64,
        10726299895124897348u64,
        16608693673010411502u64,
        285459069419210737u64,
    ]);
    #[rustfmt::skip]
    const R2: BigInteger = BigInteger([
        3987543627614508126u64,
        17742427666091596403u64,
        14557327917022607905u64,
        322810149704226881u64,
    ]);
    #[rustfmt::skip]
    const REPR_SHAVE_BITS: u32 = 5;
    #[rustfmt::skip]
    const T: BigInteger = BigInteger([
        6678124996694371583,
        2975139753996731775,
        14706092969812227584,
        168160046336021674
    ]);
    #[rustfmt::skip]
    const T_MINUS_ONE_DIV_TWO: BigInteger = BigInteger([
        12562434535201961599,
        1487569876998365887,
        7353046484906113792,
        84080023168010837
    ]);
}

impl PoseidonDefaultParameters for FrParameters {
    const PARAMS_OPT_FOR_CONSTRAINTS: [PoseidonDefaultParametersEntry; 7] = [
        PoseidonDefaultParametersEntry::new(2, 17, 8, 31, 0),
        PoseidonDefaultParametersEntry::new(3, 5, 8, 56, 0),
        PoseidonDefaultParametersEntry::new(4, 5, 8, 56, 0),
        PoseidonDefaultParametersEntry::new(5, 5, 8, 57, 0),
        PoseidonDefaultParametersEntry::new(6, 3, 8, 84, 0),
        PoseidonDefaultParametersEntry::new(7, 3, 8, 84, 0),
        PoseidonDefaultParametersEntry::new(8, 3, 8, 84, 0),
    ];
    const PARAMS_OPT_FOR_WEIGHTS: [PoseidonDefaultParametersEntry; 7] = [
        PoseidonDefaultParametersEntry::new(2, 257, 8, 13, 0),
        PoseidonDefaultParametersEntry::new(3, 257, 8, 13, 0),
        PoseidonDefaultParametersEntry::new(4, 257, 8, 13, 0),
        PoseidonDefaultParametersEntry::new(5, 257, 8, 13, 0),
        PoseidonDefaultParametersEntry::new(6, 257, 8, 13, 0),
        PoseidonDefaultParametersEntry::new(7, 257, 8, 13, 0),
        PoseidonDefaultParametersEntry::new(8, 257, 8, 13, 0),
    ];
}
