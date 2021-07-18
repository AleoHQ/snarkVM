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
    algorithms::signature::{SchnorrGadget, SchnorrPublicKeyGadget},
    curves::edwards_bls12::EdwardsBls12Gadget,
    integers::uint::UInt8,
    traits::{algorithms::SignatureGadget, alloc::AllocGadget, eq::EqGadget},
    Boolean,
};
use snarkvm_algorithms::{signature::Schnorr, traits::SignatureScheme};
use snarkvm_curves::{bls12_377::Fr, edwards_bls12::EdwardsProjective};
use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};
use snarkvm_utilities::ToBytes;

use rand::{thread_rng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;

type SchnorrScheme = Schnorr<EdwardsProjective>;
type TestSignature = Schnorr<EdwardsProjective>;
type TestSignatureGadget = SchnorrGadget<EdwardsProjective, Fr, EdwardsBls12Gadget>;

#[test]
fn test_schnorr_signature_randomize_public_key_gadget() {
    // Setup environment
    let mut cs = TestConstraintSystem::<Fr>::new();
    let rng = &mut thread_rng();

    // Native Schnorr message
    let message: [u8; 32] = rng.gen();

    // Native Schnorr signing
    let schnorr = SchnorrScheme::setup("test_schnorr_signature_randomize_public_key_gadget");
    let private_key = schnorr.generate_private_key(rng).unwrap();
    let public_key = schnorr.generate_public_key(&private_key).unwrap();
    let signature = schnorr.sign(&private_key, &message, rng).unwrap();
    assert!(schnorr.verify(&public_key, &message, &signature).unwrap());

    // Native Schnorr randomization
    let randomizer: [u8; 32] = rng.gen();
    let randomized_private_key = schnorr.randomize_private_key(&private_key, &randomizer).unwrap();
    let randomized_public_key = schnorr.randomize_public_key(&public_key, &randomizer).unwrap();
    let randomized_signature = schnorr.sign_randomized(&randomized_private_key, &message, rng).unwrap();
    assert!(signature != randomized_signature);
    assert!(
        schnorr
            .verify(&randomized_public_key, &message, &randomized_signature)
            .unwrap()
    );

    // Circuit Schnorr randomized public key (candidate)
    let schnorr_gadget = TestSignatureGadget::alloc_input(&mut cs.ns(|| "schnorr_gadget"), || Ok(schnorr)).unwrap();
    let candidate_public_key = SchnorrPublicKeyGadget::<EdwardsProjective, Fr, EdwardsBls12Gadget>::alloc(
        &mut cs.ns(|| "candidate_public_key"),
        || Ok(&public_key),
    )
    .unwrap();
    let candidate_randomizer = UInt8::alloc_vec(
        &mut cs.ns(|| "candidate_randomizer"),
        &randomizer.to_bytes_le().unwrap(),
    )
    .unwrap();
    let candidate_randomized_public_key = schnorr_gadget
        .randomize_public_key(
            &mut cs.ns(|| "candidate_randomized_public_key"),
            &candidate_public_key,
            &candidate_randomizer,
        )
        .unwrap();

    // Circuit Schnorr randomized public key (given)
    let given_randomized_public_key = SchnorrPublicKeyGadget::<EdwardsProjective, Fr, EdwardsBls12Gadget>::alloc_input(
        &mut cs.ns(|| "given_randomized_public_key"),
        || Ok(randomized_public_key),
    )
    .unwrap();

    candidate_randomized_public_key
        .enforce_equal(&mut cs.ns(|| "enforce_equal"), &given_randomized_public_key)
        .unwrap();

    if !cs.is_satisfied() {
        println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
    }
    assert!(cs.is_satisfied());
}

#[test]
fn schnorr_signature_verification_test() {
    let message = "Hi, I am a Schnorr signature!".as_bytes();
    let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);

    let schnorr = TestSignature::setup("schnorr_signature_verification_test");
    let private_key = schnorr.generate_private_key(rng).unwrap();
    let public_key = schnorr.generate_public_key(&private_key).unwrap();
    let signature = schnorr.sign(&private_key, &message, rng).unwrap();
    assert!(schnorr.verify(&public_key, &message, &signature).unwrap());

    let mut cs = TestConstraintSystem::<Fr>::new();

    let schnorr_gadget = TestSignatureGadget::alloc_input(&mut cs.ns(|| "schnorr_gadget"), || Ok(schnorr)).unwrap();

    assert_eq!(cs.num_constraints(), 0);

    let public_key_gadget = <TestSignatureGadget as SignatureGadget<SchnorrScheme, Fr>>::PublicKeyGadget::alloc(
        cs.ns(|| "alloc_public_key"),
        || Ok(public_key),
    )
    .unwrap();

    assert_eq!(cs.num_constraints(), 13);

    let message_gadget = UInt8::alloc_vec(cs.ns(|| "alloc_message"), message).unwrap();

    assert_eq!(cs.num_constraints(), 245);

    let signature_gadget = <TestSignatureGadget as SignatureGadget<SchnorrScheme, Fr>>::SignatureGadget::alloc(
        cs.ns(|| "alloc_signature"),
        || Ok(signature),
    )
    .unwrap();

    assert_eq!(cs.num_constraints(), 245);

    let verification = schnorr_gadget
        .verify(
            cs.ns(|| "verify"),
            &public_key_gadget,
            &message_gadget,
            &signature_gadget,
        )
        .unwrap();

    assert_eq!(cs.num_constraints(), 6582);

    verification
        .enforce_equal(cs.ns(|| "check_verification"), &Boolean::constant(true))
        .unwrap();

    if !cs.is_satisfied() {
        println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
    }
    assert!(cs.is_satisfied());
}

#[test]
fn failed_schnorr_signature_verification_test() {
    let message = "Hi, I am a Schnorr signature!".as_bytes();
    let bad_message = "Bad Message".as_bytes();
    let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);

    let schnorr = TestSignature::setup("failed_schnorr_signature_verification_test");
    let private_key = schnorr.generate_private_key(rng).unwrap();
    let public_key = schnorr.generate_public_key(&private_key).unwrap();
    let signature = schnorr.sign(&private_key, &message, rng).unwrap();

    assert!(schnorr.verify(&public_key, &message, &signature).unwrap());
    assert!(!schnorr.verify(&public_key, &bad_message, &signature).unwrap());

    let mut cs = TestConstraintSystem::<Fr>::new();

    let schnorr_gadget = TestSignatureGadget::alloc_input(&mut cs.ns(|| "schnorr_gadget"), || Ok(schnorr)).unwrap();

    let public_key_gadget = <TestSignatureGadget as SignatureGadget<SchnorrScheme, Fr>>::PublicKeyGadget::alloc(
        cs.ns(|| "alloc_public_key"),
        || Ok(public_key),
    )
    .unwrap();

    let bad_message_gadget = UInt8::alloc_vec(cs.ns(|| "alloc_message"), bad_message).unwrap();

    let signature_gadget = <TestSignatureGadget as SignatureGadget<SchnorrScheme, Fr>>::SignatureGadget::alloc(
        cs.ns(|| "alloc_signature"),
        || Ok(signature),
    )
    .unwrap();

    let verification = schnorr_gadget
        .verify(
            cs.ns(|| "verify"),
            &public_key_gadget,
            &bad_message_gadget,
            &signature_gadget,
        )
        .unwrap();

    verification
        .enforce_equal(cs.ns(|| "check_verification"), &Boolean::constant(false))
        .unwrap();

    if !cs.is_satisfied() {
        println!("which is unsatisfied: {:?}", cs.which_is_unsatisfied().unwrap());
    }
    assert!(cs.is_satisfied());
}
