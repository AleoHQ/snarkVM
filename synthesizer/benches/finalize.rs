// Copyright (C) 2019-2023 Aleo Systems Inc.
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

#![cfg(feature = "testing")]

#[macro_use]
extern crate criterion;

mod benchmarks;
use benchmarks::*;

mod utilities;
use utilities::*;

use console::network::Testnet3;
use snarkvm_synthesizer::ConsensusStorage;

use criterion::{BatchSize, Criterion};
use std::fmt::Display;

// Note: The number of commands that can be included in a finalize block must be within the range [1, 255].
const NUM_COMMANDS: &[usize] = &[1, 2, 4, 8, 16, 32, 64, 128, 255];
const NUM_EXECUTIONS: &[usize] = &[2, 4, 8, 16, 32, 64];
const NUM_PROGRAMS: &[usize] = &[2, 4, 8, 16, 32, 64];

/// A helper function for benchmarking `VM::finalize`.
pub fn bench_finalize<C: ConsensusStorage<Testnet3>>(c: &mut Criterion, header: impl Display, mut workload: Workload) {
    // Setup the workload.
    let (vm, _, benchmark_transactions, _) = workload.setup::<C>();

    // Benchmark each of the programs.
    for (name, transactions) in benchmark_transactions {
        if transactions.is_empty() {
            println!("Skipping benchmark {} because it has no transactions.", name);
            continue;
        }

        let mut num_transactions = 0f64;
        let mut num_rejected = 0f64;

        // Benchmark speculation.
        c.bench_function(&format!("{header}/{name}/finalize"), |b| {
            b.iter_batched(
                || {
                    let transactions = vm.speculate(transactions.iter()).unwrap();
                    num_transactions += transactions.iter().count() as f64;
                    num_rejected += transactions.iter().filter(|t| t.is_rejected()).count() as f64;
                    transactions
                },
                |transactions| vm.finalize(&transactions).unwrap(),
                BatchSize::PerIteration,
            )
        });
        println!(
            "| {header}/{name}/add_next_block | Transactions: {} | Rejected: {} | Percent Rejected: {}",
            num_transactions,
            num_rejected,
            (num_rejected / num_transactions) * 100.0
        );
    }
}

fn bench_one_operation(c: &mut Criterion) {
    // Initialize the workload.
    let workload = one_execution_workload(NUM_COMMANDS);

    #[cfg(not(any(feature = "rocks")))]
    bench_finalize::<ConsensusMemory<Testnet3>>(c, "memory", workload);
    #[cfg(any(feature = "rocks"))]
    bench_finalize::<snarkvm_synthesizer::helpers::rocksdb::ConsensusDB<Testnet3>>(c, "db", workload);
}

fn bench_multiple_operations(c: &mut Criterion) {
    // Initialize the workload.
    let workload = multiple_executions_workload(NUM_EXECUTIONS, *NUM_COMMANDS.last().unwrap());

    #[cfg(not(any(feature = "rocks")))]
    bench_finalize::<ConsensusMemory<Testnet3>>(c, "memory", workload);
    #[cfg(any(feature = "rocks"))]
    bench_finalize::<snarkvm_synthesizer::helpers::rocksdb::ConsensusDB<Testnet3>>(c, "db", workload);
}

fn bench_multiple_operations_with_multiple_programs(c: &mut Criterion) {
    // Initialize the workload.
    let workload = multiple_executions_multiple_programs_workload(
        NUM_PROGRAMS,
        *NUM_COMMANDS.last().unwrap(),
        *NUM_EXECUTIONS.last().unwrap(),
    );

    #[cfg(not(any(feature = "rocks")))]
    bench_finalize::<ConsensusMemory<Testnet3>>(c, "memory", workload);
    #[cfg(any(feature = "rocks"))]
    bench_finalize::<snarkvm_synthesizer::helpers::rocksdb::ConsensusDB<Testnet3>>(c, "db", workload);
}

criterion_group! {
    name = benchmarks;
    config = Criterion::default().sample_size(10);
    targets = bench_one_operation, bench_multiple_operations
}
criterion_group! {
    name = long_benchmarks;
    config = Criterion::default().sample_size(10);
    targets = bench_multiple_operations_with_multiple_programs
}
#[cfg(all(feature = "testing", feature = "long-benchmarks"))]
criterion_main!(long_benchmarks);
#[cfg(all(feature = "testing", not(any(feature = "long-benchmarks"))))]
criterion_main!(benchmarks);
