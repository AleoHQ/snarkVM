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

use crate::{encryption::GroupEncryption, signature::Schnorr, traits::SignatureScheme};
use snarkvm_curves::{
    edwards_bls12::{EdwardsAffine, EdwardsProjective},
    edwards_bw6::EdwardsAffine as Edwards,
    traits::Group,
};
use snarkvm_utilities::{rand::UniformRand, to_bytes_le, FromBytes, ToBytes};

use blake2::Blake2s;
use rand::SeedableRng;
use rand_xorshift::XorShiftRng;

type TestSignature = Schnorr<Edwards, Blake2s>;
type TestGroupEncryptionSignature = GroupEncryption<EdwardsProjective, EdwardsAffine, Blake2s>;

fn sign_and_verify<S: SignatureScheme>(message: &[u8]) {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);
    let schnorr_signature = S::setup::<_>(rng).unwrap();
    let private_key = schnorr_signature.generate_private_key(rng).unwrap();
    let public_key = schnorr_signature.generate_public_key(&private_key).unwrap();
    let signature = schnorr_signature.sign(&private_key, message, rng).unwrap();
    assert!(schnorr_signature.verify(&public_key, &message, &signature).unwrap());
}

fn failed_verification<S: SignatureScheme>(message: &[u8], bad_message: &[u8]) {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);
    let schnorr_signature = S::setup::<_>(rng).unwrap();
    let private_key = schnorr_signature.generate_private_key(rng).unwrap();
    let public_key = schnorr_signature.generate_public_key(&private_key).unwrap();
    let signature = schnorr_signature.sign(&private_key, message, rng).unwrap();
    assert!(!schnorr_signature.verify(&public_key, bad_message, &signature).unwrap());
}

fn randomize_and_verify<S: SignatureScheme>(message: &[u8], randomness: &[u8]) {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);
    let schnorr_signature = S::setup::<_>(rng).unwrap();
    let private_key = schnorr_signature.generate_private_key(rng).unwrap();
    let public_key = schnorr_signature.generate_public_key(&private_key).unwrap();
    let signature = schnorr_signature.sign(&private_key, message, rng).unwrap();
    assert!(schnorr_signature.verify(&public_key, message, &signature).unwrap());

    let randomized_public_key = schnorr_signature.randomize_public_key(&public_key, randomness).unwrap();
    let randomized_signature = schnorr_signature.randomize_signature(&signature, randomness).unwrap();
    assert!(schnorr_signature
        .verify(&randomized_public_key, &message, &randomized_signature)
        .unwrap());
}

fn signature_scheme_parameter_serialization<S: SignatureScheme>() {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);

    let signature_scheme = S::setup(rng).unwrap();
    let signature_scheme_parameters = signature_scheme.parameters();

    let signature_scheme_parameters_bytes = to_bytes_le![signature_scheme_parameters].unwrap();
    let recovered_signature_scheme_parameters: <S as SignatureScheme>::Parameters =
        FromBytes::read_le(&signature_scheme_parameters_bytes[..]).unwrap();

    assert_eq!(signature_scheme_parameters, &recovered_signature_scheme_parameters);
}

#[test]
fn schnorr_signature_test() {
    let message = "Hi, I am a Schnorr signature!";
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);
    sign_and_verify::<TestSignature>(message.as_bytes());
    failed_verification::<TestSignature>(message.as_bytes(), b"Bad message");
    let random_scalar = to_bytes_le!(<Edwards as Group>::ScalarField::rand(rng)).unwrap();
    randomize_and_verify::<TestSignature>(message.as_bytes(), &random_scalar.as_slice());
}

#[test]
fn schnorr_signature_scheme_parameters_serialization() {
    signature_scheme_parameter_serialization::<TestSignature>();
}

#[test]
fn group_encryption_signature_test() {
    // Test the encryption scheme's Schnorr signature implementation, excluding randomized signatures
    let message = "Hi, I am a Group Encryption signature!";
    sign_and_verify::<TestGroupEncryptionSignature>(message.as_bytes());
    failed_verification::<TestGroupEncryptionSignature>(message.as_bytes(), "Bad message".as_bytes());
}

#[test]
fn group_encryption_signature_scheme_parameters_serialization() {
    signature_scheme_parameter_serialization::<TestGroupEncryptionSignature>();
}
