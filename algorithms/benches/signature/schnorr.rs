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

#[macro_use]
extern crate criterion;

use snarkvm_algorithms::{signature::schnorr::Schnorr as SchnorrSignature, traits::SignatureScheme};
use snarkvm_curves::{edwards_bls12::EdwardsProjective, Group};
use snarkvm_utilities::UniformRand;

use criterion::Criterion;
use rand::{self, thread_rng, Rng};

type Schnorr = SchnorrSignature<EdwardsProjective>;

fn schnorr_signature_setup(c: &mut Criterion) {
    c.bench_function("Schnorr Signature Setup", move |b| {
        b.iter(|| Schnorr::setup("schnorr_signature_setup"))
    });
}

fn schnorr_signature_generate_private_key(c: &mut Criterion) {
    let rng = &mut thread_rng();
    let parameters = Schnorr::setup("schnorr_signature_generate_private_key");

    c.bench_function("Schnorr Signature Generate Private Key", move |b| {
        b.iter(|| Schnorr::generate_private_key(&parameters, rng).unwrap())
    });
}

fn schnorr_signature_generate_public_key(c: &mut Criterion) {
    let rng = &mut thread_rng();
    let parameters = Schnorr::setup("schnorr_signature_generate_public_key");
    let private_key = Schnorr::generate_private_key(&parameters, rng).unwrap();

    c.bench_function("Schnorr Signature Generate Public Key", move |b| {
        b.iter(|| Schnorr::generate_public_key(&parameters, &private_key).unwrap())
    });
}

fn schnorr_signature_sign(c: &mut Criterion) {
    let rng = &mut thread_rng();
    let parameters = Schnorr::setup("schnorr_signature_sign");
    let private_key = Schnorr::generate_private_key(&parameters, rng).unwrap();
    let message = [100u8; 128];

    c.bench_function("Schnorr Signature Sign", move |b| {
        b.iter(|| Schnorr::sign(&parameters, &private_key, &message, rng).unwrap())
    });
}

fn schnorr_signature_verify(c: &mut Criterion) {
    let rng = &mut thread_rng();
    let parameters = Schnorr::setup("schnorr_signature_verify");
    let private_key = Schnorr::generate_private_key(&parameters, rng).unwrap();
    let public_key = Schnorr::generate_public_key(&parameters, &private_key).unwrap();
    let message = [100u8; 128];
    let signature = Schnorr::sign(&parameters, &private_key, &message, rng).unwrap();

    c.bench_function("Schnorr Signature Verify", move |b| {
        b.iter(|| Schnorr::verify(&parameters, &public_key, &message, &signature).unwrap())
    });
}

fn schnorr_signature_randomize_public_key(c: &mut Criterion) {
    let mut rng = &mut thread_rng();
    let parameters = Schnorr::setup("schnorr_signature_randomize_public_key");
    let private_key = Schnorr::generate_private_key(&parameters, rng).unwrap();
    let public_key = Schnorr::generate_public_key(&parameters, &private_key).unwrap();
    let randomizer: [u8; 32] = rng.gen();

    c.bench_function("Schnorr Signature Randomize Public Key", move |b| {
        b.iter(|| Schnorr::randomize_public_key(&parameters, &public_key, &randomizer).unwrap())
    });
}

fn schnorr_signature_randomize_signature(c: &mut Criterion) {
    let mut rng = &mut thread_rng();
    let parameters = Schnorr::setup("schnorr_signature_randomize_signature");
    let private_key = Schnorr::generate_private_key(&parameters, rng).unwrap();
    let message = [100u8; 128];

    let randomizer: [u8; 32] = rng.gen();
    let randomized_private_key = Schnorr::randomize_private_key(&parameters, &private_key, &randomizer).unwrap();

    c.bench_function("Schnorr Signature Randomize Signature", move |b| {
        b.iter(|| Schnorr::sign_randomized(&parameters, &randomized_private_key, &message, &mut rng).unwrap())
    });
}
criterion_group! {
    name = schnorr_signature;
    config = Criterion::default().sample_size(20);
    targets = schnorr_signature_setup,
                schnorr_signature_generate_private_key,
                schnorr_signature_generate_public_key,
                schnorr_signature_sign,
                schnorr_signature_verify,
                schnorr_signature_randomize_public_key,
                schnorr_signature_randomize_signature
}
criterion_main!(schnorr_signature);
