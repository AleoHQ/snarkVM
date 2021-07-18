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

use snarkvm_dpc::{
    prelude::*,
    testnet2::{instantiated::Components, NoopProgram},
};

use criterion::Criterion;
use rand::thread_rng;

fn noop_program_setup(c: &mut Criterion) {
    c.bench_function("NoopProgram::setup", move |b| {
        b.iter(|| {
            let _noop_program = NoopProgram::<Components>::setup(&mut thread_rng()).unwrap();
        })
    });
}

fn noop_program_load(c: &mut Criterion) {
    c.bench_function("NoopProgram::load", move |b| {
        b.iter(|| {
            let _noop_program = NoopProgram::<Components>::load().unwrap();
        })
    });
}

criterion_group! {
    name = noop_program;
    config = Criterion::default().sample_size(10);
    targets = noop_program_setup, noop_program_load
}

criterion_main!(noop_program);
