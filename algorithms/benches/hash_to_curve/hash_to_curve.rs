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

use criterion::Criterion;

use snarkvm_algorithms::hash_to_curve::{hash_to_curve, try_hash_to_curve};
use snarkvm_curves::bls12_377::{G1Affine, G2Affine};

use rand::{distributions::Alphanumeric, thread_rng, Rng};

#[macro_use]
extern crate criterion;

fn hash_to_g1_on_bls12_377(c: &mut Criterion) {
    let message: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    c.bench_function("try_hash_to_g1_on_bls12_377", move |b| {
        b.iter(|| {
            let _ = hash_to_curve::<G1Affine>(&message);
        })
    });
}

fn try_hash_to_g1_on_bls12_377(c: &mut Criterion) {
    let message: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    c.bench_function("one_step_of_hash_to_g1_on_bls12_377", move |b| {
        b.iter(|| {
            let _ = try_hash_to_curve::<G1Affine>(&message);
        })
    });
}

fn hash_to_g2_on_bls12_377(c: &mut Criterion) {
    let message: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    c.bench_function("try_hash_to_g1_on_bls12_377", move |b| {
        b.iter(|| {
            let _ = hash_to_curve::<G2Affine>(&message);
        })
    });
}

fn try_hash_to_g2_on_bls12_377(c: &mut Criterion) {
    let message: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(30)
        .map(char::from)
        .collect();

    c.bench_function("one_step_of_hash_to_g2_on_bls12_377", move |b| {
        b.iter(|| {
            let _ = try_hash_to_curve::<G2Affine>(&message);
        })
    });
}

criterion_group! {
    name = hash_to_curve_group;
    config = Criterion::default().sample_size(10);
    targets = hash_to_g1_on_bls12_377, try_hash_to_g1_on_bls12_377, hash_to_g2_on_bls12_377, try_hash_to_g2_on_bls12_377
}

criterion_main!(hash_to_curve_group);
