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

use snarkvm_algorithms::{crh::pedersen::PedersenCRH, traits::CRH};
use snarkvm_curves::edwards_bls12::EdwardsProjective;

use criterion::Criterion;

const NUM_WINDOWS: usize = 8;
const WINDOW_SIZE: usize = 32;

fn pedersen_crh_setup(c: &mut Criterion) {
    c.bench_function("Pedersen CRH Setup", move |b| {
        b.iter(|| <PedersenCRH<EdwardsProjective, NUM_WINDOWS, WINDOW_SIZE> as CRH>::setup("pedersen_crh_benchmark"))
    });
}

fn pedersen_crh_hash(c: &mut Criterion) {
    let crh = <PedersenCRH<EdwardsProjective, NUM_WINDOWS, WINDOW_SIZE> as CRH>::setup("pedersen_crh_benchmark");
    let input = vec![127u8; 32];

    c.bench_function("Pedersen CRH Evaluation", move |b| b.iter(|| crh.hash(&input).unwrap()));
}

criterion_group! {
    name = crh_setup;
    config = Criterion::default().sample_size(50);
    targets = pedersen_crh_setup
}

criterion_group! {
    name = crh_hash;
    config = Criterion::default().sample_size(50);
    targets = pedersen_crh_hash
}

criterion_main!(crh_setup, crh_hash);
