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

use crate::{signature::Schnorr, SignatureScheme};
use snarkvm_curves::{
    edwards_bls12::EdwardsProjective as EdwardsBls12,
    edwards_bw6::EdwardsProjective as EdwardsBW6,
    Group,
};
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{FromBytes, UniformRand};

use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

fn sign_and_verify<S: SignatureScheme>(message: &[u8]) {
    let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);
    let schnorr = S::setup("sign_and_verify");

    let private_key = schnorr.generate_private_key(rng).unwrap();
    let public_key = schnorr.generate_public_key(&private_key).unwrap();
    let signature = schnorr.sign(&private_key, message, rng).unwrap();
    assert!(schnorr.verify(&public_key, &message, &signature).unwrap());
}

fn failed_verification<S: SignatureScheme>(message: &[u8], bad_message: &[u8]) {
    let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);
    let schnorr = S::setup("failed_verification");

    let private_key = schnorr.generate_private_key(rng).unwrap();
    let public_key = schnorr.generate_public_key(&private_key).unwrap();
    let signature = schnorr.sign(&private_key, message, rng).unwrap();
    assert!(!schnorr.verify(&public_key, bad_message, &signature).unwrap());
}

fn randomize_and_verify<S: SignatureScheme<Randomizer = [u8; 32]>>(message: &[u8], randomizer: [u8; 32]) {
    let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);
    let schnorr = S::setup("randomize_and_verify");

    let private_key = schnorr.generate_private_key(rng).unwrap();
    let public_key = schnorr.generate_public_key(&private_key).unwrap();
    let signature = schnorr.sign(&private_key, message, rng).unwrap();
    assert!(schnorr.verify(&public_key, message, &signature).unwrap());

    let randomized_private_key = schnorr.randomize_private_key(&private_key, &randomizer).unwrap();
    let randomized_public_key = schnorr.randomize_public_key(&public_key, &randomizer).unwrap();
    assert_eq!(
        randomized_public_key,
        schnorr
            .generate_public_key(&randomized_private_key.clone().into())
            .unwrap()
    );

    let randomized_signature = schnorr.sign_randomized(&randomized_private_key, message, rng).unwrap();
    assert!(signature != randomized_signature);
    assert!(
        schnorr
            .verify(&randomized_public_key, &message, &randomized_signature)
            .unwrap()
    );
}

fn signature_scheme_serialization<S: SignatureScheme>() {
    let signature_scheme = S::setup("signature_scheme_serialization");
    let recovered_signature_scheme: S = FromBytes::read_le(&signature_scheme.to_bytes_le().unwrap()[..]).unwrap();
    assert_eq!(signature_scheme, recovered_signature_scheme);
}

#[test]
fn test_schnorr_signature_on_edwards_bls12_377() {
    type TestSignature = Schnorr<EdwardsBls12>;

    let message = "Hi, I am a Schnorr signature!";
    sign_and_verify::<TestSignature>(message.as_bytes());
    failed_verification::<TestSignature>(message.as_bytes(), b"Bad message");

    let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);
    let randomizer: [u8; 32] = rng.gen();
    randomize_and_verify::<TestSignature>(message.as_bytes(), randomizer);
}

#[test]
fn test_schnorr_signature_on_edwards_bw6() {
    type TestSignature = Schnorr<EdwardsBW6>;

    let message = "Hi, I am a Schnorr signature!";
    sign_and_verify::<TestSignature>(message.as_bytes());
    failed_verification::<TestSignature>(message.as_bytes(), b"Bad message");

    let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);
    let randomizer: [u8; 32] = rng.gen();
    randomize_and_verify::<TestSignature>(message.as_bytes(), randomizer);
}

#[test]
fn schnorr_signature_scheme_serialization() {
    signature_scheme_serialization::<Schnorr<EdwardsBls12>>();
    signature_scheme_serialization::<Schnorr<EdwardsBW6>>();
}
