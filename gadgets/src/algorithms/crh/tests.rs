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

use rand::{thread_rng, Rng};

use snarkvm_algorithms::{
    crh::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenCompressedCRH, PedersenCRH, PedersenCompressedCRH},
    CRH,
};
use snarkvm_curves::{bls12_377::Fr, edwards_bls12::EdwardsProjective};
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};

use crate::{
    algorithms::crh::{
        BoweHopwoodPedersenCRHGadget,
        BoweHopwoodPedersenCompressedCRHGadget,
        PedersenCRHGadget,
        PedersenCompressedCRHGadget,
    },
    curves::edwards_bls12::EdwardsBls12Gadget,
    integers::uint::UInt8,
    traits::{
        algorithms::{CRHGadget, MaskedCRHGadget},
        alloc::AllocGadget,
        eq::EqGadget,
    },
};

const PEDERSEN_NUM_WINDOWS: usize = 8;
const PEDERSEN_WINDOW_SIZE: usize = 128;

const BHP_NUM_WINDOWS: usize = 32;
const BHP_WINDOW_SIZE: usize = 48;

const PEDERSEN_HASH_CONSTRAINTS: usize = 5632;
const BOWE_HOPWOOD_HASH_CONSTRAINTS: usize = 3974;

fn generate_input<F: PrimeField, CS: ConstraintSystem<F>, R: Rng>(
    mut cs: CS,
    rng: &mut R,
) -> ([u8; 128], Vec<UInt8>, Vec<UInt8>) {
    let mut input = [1u8; 128];
    rng.fill_bytes(&mut input);
    let mut mask = [1u8; 128];
    rng.fill_bytes(&mut mask);

    let mut input_bytes = vec![];
    let mut mask_bytes = vec![];
    for (byte_i, (input_byte, mask_byte)) in input.iter().zip(mask.iter()).enumerate() {
        let cs_input = cs.ns(|| format!("input_byte_gadget_{}", byte_i));
        input_bytes.push(UInt8::alloc(cs_input, || Ok(*input_byte)).unwrap());
        // The mask will later on be extended to be double the size, so we only need half the bits
        // as the input.
        if byte_i % 2 == 0 {
            let cs_mask = cs.ns(|| format!("mask_byte_gadget_{}", byte_i));
            mask_bytes.push(UInt8::alloc(cs_mask, || Ok(*mask_byte)).unwrap());
        }
    }
    (input, input_bytes, mask_bytes)
}

fn primitive_crh_gadget_test<F: PrimeField, H: CRH, CG: CRHGadget<H, F>>(hash_constraints: usize) {
    let rng = &mut thread_rng();
    let mut cs = TestConstraintSystem::<F>::new();

    let (input, input_bytes, _mask_bytes) = generate_input(&mut cs, rng);
    assert_eq!(cs.num_constraints(), 1536);

    let crh = H::setup("primitive_crh_gadget_test");
    let native_result = crh.hash(&input).unwrap();

    let crh_gadget = CG::alloc(&mut cs.ns(|| "gadget_parameters"), || Ok(crh)).unwrap();
    assert_eq!(cs.num_constraints(), 1536);

    let output_gadget = crh_gadget
        .check_evaluation_gadget(&mut cs.ns(|| "gadget_evaluation"), input_bytes)
        .unwrap();
    assert_eq!(cs.num_constraints(), hash_constraints);

    let native_result_gadget =
        <CG as CRHGadget<_, _>>::OutputGadget::alloc(&mut cs.ns(|| "native_result"), || Ok(&native_result)).unwrap();

    output_gadget
        .enforce_equal(
            &mut cs.ns(|| "Check that computed crh matches provided output"),
            &native_result_gadget,
        )
        .unwrap();

    assert!(cs.is_satisfied());
}

fn masked_crh_gadget_test<F: PrimeField, H: CRH, CG: MaskedCRHGadget<H, F>>() {
    let rng = &mut thread_rng();
    let mut cs = TestConstraintSystem::<F>::new();

    let (input, input_bytes, mask_bytes) = generate_input(&mut cs, rng);
    assert_eq!(cs.num_constraints(), 1536);

    let crh = H::setup("masked_crh_gadget_test_0");
    let mask_parameters = H::setup("masked_crh_gadget_test_1");
    let native_result = crh.hash(&input).unwrap();

    let crh_gadget = CG::alloc(&mut cs.ns(|| "gadget_parameters"), || Ok(crh)).unwrap();
    assert_eq!(cs.num_constraints(), 1536);

    let mask_parameters_gadget =
        CG::MaskParametersGadget::alloc(&mut cs.ns(|| "gadget_mask_parameters"), || Ok(mask_parameters)).unwrap();
    assert_eq!(cs.num_constraints(), 1536);

    let masked_output_gadget = <CG as MaskedCRHGadget<_, _>>::check_evaluation_gadget_masked(
        &crh_gadget,
        &mut cs.ns(|| "masked_gadget_evaluation"),
        input_bytes,
        &mask_parameters_gadget,
        mask_bytes,
    )
    .unwrap();
    assert_eq!(cs.num_constraints(), 17932);

    let native_result_gadget =
        <CG as CRHGadget<_, _>>::OutputGadget::alloc(&mut cs.ns(|| "native_result"), || Ok(&native_result)).unwrap();

    masked_output_gadget
        .enforce_equal(
            &mut cs.ns(|| "Check that computed crh matches provided output"),
            &native_result_gadget,
        )
        .unwrap();

    assert!(cs.is_satisfied());
}

mod pedersen_crh_gadget_on_projective {
    use super::*;

    type TestCRH = PedersenCRH<EdwardsProjective, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>;
    type TestCRHGadget =
        PedersenCRHGadget<EdwardsProjective, Fr, EdwardsBls12Gadget, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>;

    #[test]
    fn primitive_gadget_test() {
        primitive_crh_gadget_test::<Fr, TestCRH, TestCRHGadget>(PEDERSEN_HASH_CONSTRAINTS)
    }

    #[test]
    fn masked_gadget_test() {
        masked_crh_gadget_test::<Fr, TestCRH, TestCRHGadget>()
    }
}

mod pedersen_compressed_crh_gadget_on_projective {
    use super::*;

    type TestCRH = PedersenCompressedCRH<EdwardsProjective, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>;
    type TestCRHGadget = PedersenCompressedCRHGadget<
        EdwardsProjective,
        Fr,
        EdwardsBls12Gadget,
        PEDERSEN_NUM_WINDOWS,
        PEDERSEN_WINDOW_SIZE,
    >;

    #[test]
    fn primitive_gadget_test() {
        primitive_crh_gadget_test::<Fr, TestCRH, TestCRHGadget>(PEDERSEN_HASH_CONSTRAINTS)
    }

    #[test]
    fn masked_gadget_test() {
        masked_crh_gadget_test::<Fr, TestCRH, TestCRHGadget>()
    }
}

// Note: Bowe-Hopwood CRH Gadget currently does not support affine curves or masked crh

mod bowe_hopwood_pedersen_crh_gadget_on_projective {
    use super::*;

    type TestCRH = BoweHopwoodPedersenCRH<EdwardsProjective, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>;
    type TestCRHGadget =
        BoweHopwoodPedersenCRHGadget<EdwardsProjective, Fr, EdwardsBls12Gadget, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>;

    #[test]
    fn primitive_gadget_test() {
        primitive_crh_gadget_test::<Fr, TestCRH, TestCRHGadget>(BOWE_HOPWOOD_HASH_CONSTRAINTS)
    }
}

mod bowe_hopwood_pedersen_compressed_crh_gadget_on_projective {
    use super::*;

    type TestCRH = BoweHopwoodPedersenCompressedCRH<EdwardsProjective, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>;
    type TestCRHGadget = BoweHopwoodPedersenCompressedCRHGadget<
        EdwardsProjective,
        Fr,
        EdwardsBls12Gadget,
        BHP_NUM_WINDOWS,
        BHP_WINDOW_SIZE,
    >;

    #[test]
    fn primitive_gadget_test() {
        primitive_crh_gadget_test::<Fr, TestCRH, TestCRHGadget>(BOWE_HOPWOOD_HASH_CONSTRAINTS)
    }
}
