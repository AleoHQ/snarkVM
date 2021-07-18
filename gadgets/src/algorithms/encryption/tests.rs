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

use crate::{
    algorithms::encryption::*,
    curves::edwards_bls12::EdwardsBls12Gadget,
    traits::{algorithms::EncryptionGadget, alloc::AllocGadget, eq::EqGadget},
};
use snarkvm_algorithms::{encryption::GroupEncryption, traits::EncryptionScheme};
use snarkvm_curves::{bls12_377::Fr, edwards_bls12::EdwardsProjective, traits::ProjectiveCurve};
use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};

use rand::{CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

type TestEncryptionScheme = GroupEncryption<EdwardsProjective>;
type TestEncryptionSchemeGadget = GroupEncryptionGadget<EdwardsProjective, Fr, EdwardsBls12Gadget>;

fn generate_input<G: ProjectiveCurve, R: Rng + CryptoRng>(input_size: usize, rng: &mut R) -> Vec<G> {
    let mut input = vec![];
    for _ in 0..input_size {
        input.push(G::rand(rng))
    }

    input
}

#[test]
fn test_group_encryption_public_key_gadget() {
    let mut cs = TestConstraintSystem::<Fr>::new();
    let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);

    let encryption_scheme = TestEncryptionScheme::setup("test_group_encryption_public_key_gadget");

    let private_key = encryption_scheme.generate_private_key(rng);
    let public_key = encryption_scheme.generate_public_key(&private_key).unwrap();

    let encryption =
        TestEncryptionSchemeGadget::alloc(&mut cs.ns(|| "parameters_gadget"), || Ok(&encryption_scheme)).unwrap();
    let private_key_gadget =
        <TestEncryptionSchemeGadget as EncryptionGadget<TestEncryptionScheme, _>>::PrivateKeyGadget::alloc(
            &mut cs.ns(|| "private_key_gadget"),
            || Ok(&private_key),
        )
        .unwrap();
    let expected_public_key_gadget =
        <TestEncryptionSchemeGadget as EncryptionGadget<TestEncryptionScheme, _>>::PublicKeyGadget::alloc(
            &mut cs.ns(|| "public_key_gadget"),
            || Ok(&public_key),
        )
        .unwrap();

    println!("number of constraints for inputs: {}", cs.num_constraints());

    let public_key_gadget = encryption
        .check_public_key_gadget(&mut cs.ns(|| "public_key_gadget_evaluation"), &private_key_gadget)
        .unwrap();

    expected_public_key_gadget
        .enforce_equal(
            cs.ns(|| "Check that declared and computed public keys are equal"),
            &public_key_gadget,
        )
        .unwrap();

    println!("number of constraints total: {}", cs.num_constraints());

    if !cs.is_satisfied() {
        println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
    }
    assert!(cs.is_satisfied());
}

#[test]
fn test_group_encryption_gadget() {
    let mut cs = TestConstraintSystem::<Fr>::new();
    let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);

    let encryption_scheme = TestEncryptionScheme::setup("test_group_encryption_gadget");

    let private_key = encryption_scheme.generate_private_key(rng);
    let public_key = encryption_scheme.generate_public_key(&private_key).unwrap();

    let randomness = encryption_scheme.generate_randomness(&public_key, rng).unwrap();
    let message = generate_input(10, rng);
    let blinding_exponents = encryption_scheme
        .generate_blinding_exponents(&public_key, &randomness, message.len())
        .unwrap();
    let ciphertext = encryption_scheme.encrypt(&public_key, &randomness, &message).unwrap();

    // Alloc parameters, public key, plaintext, randomness, and blinding exponents
    let encryption =
        TestEncryptionSchemeGadget::alloc(&mut cs.ns(|| "parameters_gadget"), || Ok(&encryption_scheme)).unwrap();
    let public_key_gadget =
        <TestEncryptionSchemeGadget as EncryptionGadget<TestEncryptionScheme, _>>::PublicKeyGadget::alloc(
            &mut cs.ns(|| "public_key_gadget"),
            || Ok(&public_key),
        )
        .unwrap();
    let plaintext_gadget =
        <TestEncryptionSchemeGadget as EncryptionGadget<TestEncryptionScheme, _>>::PlaintextGadget::alloc(
            &mut cs.ns(|| "plaintext_gadget"),
            || Ok(&message),
        )
        .unwrap();
    let randomness_gadget =
        <TestEncryptionSchemeGadget as EncryptionGadget<TestEncryptionScheme, _>>::RandomnessGadget::alloc(
            &mut cs.ns(|| "randomness_gadget"),
            || Ok(&randomness),
        )
        .unwrap();
    let blinding_exponents_gadget =
        <TestEncryptionSchemeGadget as EncryptionGadget<TestEncryptionScheme, _>>::BlindingExponentGadget::alloc(
            &mut cs.ns(|| "blinding_exponents_gadget"),
            || Ok(&blinding_exponents),
        )
        .unwrap();

    // Expected ciphertext gadget
    let expected_ciphertext_gadget =
        <TestEncryptionSchemeGadget as EncryptionGadget<TestEncryptionScheme, _>>::CiphertextGadget::alloc(
            &mut cs.ns(|| "ciphertext_gadget"),
            || Ok(&ciphertext),
        )
        .unwrap();

    println!("number of constraints for inputs: {}", cs.num_constraints());

    let ciphertext_gadget = encryption
        .check_encryption_gadget(
            &mut cs.ns(|| "ciphertext_gadget_evaluation"),
            &randomness_gadget,
            &public_key_gadget,
            &plaintext_gadget,
            &blinding_exponents_gadget,
        )
        .unwrap();

    expected_ciphertext_gadget
        .enforce_equal(
            cs.ns(|| "Check that declared and computed ciphertexts are equal"),
            &ciphertext_gadget,
        )
        .unwrap();

    println!("number of constraints total: {}", cs.num_constraints());

    if !cs.is_satisfied() {
        println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
    }
    assert!(cs.is_satisfied());
}
