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

use super::*;
use crate::{
    curves::edwards_bls12::EdwardsBls12Gadget,
    integers::uint::UInt8,
    traits::{algorithms::CommitmentGadget, alloc::AllocGadget, FieldGadget},
};
use snarkvm_algorithms::{
    commitment::{Blake2sCommitment, PedersenCommitment},
    traits::CommitmentScheme,
};
use snarkvm_curves::edwards_bls12::{EdwardsProjective, Fq, Fr};
use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};
use snarkvm_utilities::rand::UniformRand;

use rand::{thread_rng, Rng};

#[test]
fn blake2s_commitment_gadget_test() {
    let mut cs = TestConstraintSystem::<Fr>::new();
    let rng = &mut thread_rng();

    let input = [1u8; 32];

    let mut randomness = [0u8; 32];
    rng.fill(&mut randomness);

    let commitment = Blake2sCommitment::setup("blake2s_commitment_gadget_test");
    let native_result = commitment.commit(&input, &randomness).unwrap();

    let mut input_bytes = vec![];
    for (byte_i, input_byte) in input.iter().enumerate() {
        let cs = cs.ns(|| format!("input_byte_gadget_{}", byte_i));
        input_bytes.push(UInt8::alloc(cs, || Ok(*input_byte)).unwrap());
    }

    let mut randomness_bytes = vec![];
    for (byte_i, random_byte) in randomness.iter().enumerate() {
        let cs = cs.ns(|| format!("randomness_byte_gadget_{}", byte_i));
        randomness_bytes.push(UInt8::alloc(cs, || Ok(*random_byte)).unwrap());
    }
    let randomness_bytes = Blake2sRandomnessGadget(randomness_bytes);

    let blake2s_gadget =
        Blake2sCommitmentGadget::alloc(&mut cs.ns(|| "gadget_parameters"), || Ok(&commitment)).unwrap();
    let gadget_result = blake2s_gadget
        .check_commitment_gadget(&mut cs.ns(|| "gadget_evaluation"), &input_bytes, &randomness_bytes)
        .unwrap();

    for (i, nr) in native_result.iter().enumerate() {
        assert_eq!(*nr, gadget_result.0[i].value.unwrap());
    }
    assert!(cs.is_satisfied());
}

#[test]
fn pedersen_commitment_gadget_test() {
    let mut cs = TestConstraintSystem::<Fq>::new();

    const NUM_WINDOWS: usize = 8;
    const WINDOW_SIZE: usize = 4;

    type TestCommitment = PedersenCommitment<EdwardsProjective, NUM_WINDOWS, WINDOW_SIZE>;
    type TestCommitmentGadget =
        PedersenCommitmentGadget<EdwardsProjective, Fq, EdwardsBls12Gadget, NUM_WINDOWS, WINDOW_SIZE>;

    let rng = &mut thread_rng();

    let input = [1u8; 4];
    let randomness = Fr::rand(rng);
    let commitment = TestCommitment::setup("pedersen_commitment_gadget_test");
    let native_output = commitment.commit(&input, &randomness).unwrap();

    let mut input_bytes = vec![];
    for (byte_i, input_byte) in input.iter().enumerate() {
        let cs = cs.ns(|| format!("input_byte_gadget_{}", byte_i));
        input_bytes.push(UInt8::alloc(cs, || Ok(*input_byte)).unwrap());
    }

    let randomness_gadget = <TestCommitmentGadget as CommitmentGadget<TestCommitment, Fq>>::RandomnessGadget::alloc(
        &mut cs.ns(|| "randomness_gadget"),
        || Ok(&randomness),
    )
    .unwrap();
    let commitment_gadget =
        TestCommitmentGadget::alloc(&mut cs.ns(|| "parameters_gadget"), || Ok(&commitment)).unwrap();
    let output_gadget = commitment_gadget
        .check_commitment_gadget(&mut cs.ns(|| "commitment_gadget"), &input_bytes, &randomness_gadget)
        .unwrap();

    let native_output = native_output;
    assert_eq!(native_output.x, output_gadget.x.get_value().unwrap());
    assert_eq!(native_output.y, output_gadget.y.get_value().unwrap());
    assert!(cs.is_satisfied());
}
