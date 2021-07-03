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

extern crate criterion;

use snarkvm_algorithms::fft::{DensePolynomial, EvaluationDomain};
use snarkvm_curves::bls12_377::Fr as Bls12_377_Fr;
use snarkvm_fields::PrimeField;

use criterion::{criterion_group, criterion_main, Bencher, BenchmarkId, Criterion};
use rand::{self, thread_rng};
use std::cmp::min;

/// Degree bounds to benchmark on
/// e.g. degree bound of 2^{15}, means we do an FFT for a degree (2^{15} - 1) polynomial
const BENCHMARK_MIN_DEGREE: usize = 1 << 16;
const BENCHMARK_MAX_DEGREE: usize = 1 << 20;
const BENCHMARK_LOG_INTERVAL_DEGREE: usize = 1;

/// Utility function for getting a vector of degrees to benchmark on.
/// Returns vec![2^{min}, 2^{min + interval}, ..., 2^{max}], where:
/// interval = log_interval
/// min      = ceil(log_2(min_degree))
/// max      = ceil(log_2(max_degree))
pub fn size_range(log_interval: usize, min_degree: usize, max_degree: usize) -> Vec<usize> {
    let mut to_ret = vec![min_degree.next_power_of_two()];
    let interval = 1 << log_interval;

    while *to_ret.last().unwrap() < max_degree {
        let next_elem = min(max_degree, interval * to_ret.last().unwrap());
        to_ret.push(next_elem);
    }

    to_ret
}

/// Returns vec![2^{min}, 2^{min + interval}, ..., 2^{max}], where:
/// interval = BENCHMARK_LOG_INTERVAL_DEGREE
/// min      = ceil(log_2(BENCHMARK_MIN_DEGREE))
/// max      = ceil(log_2(BENCHMARK_MAX_DEGREE))
fn default_size_range() -> Vec<usize> {
    size_range(
        BENCHMARK_LOG_INTERVAL_DEGREE,
        BENCHMARK_MIN_DEGREE,
        BENCHMARK_MAX_DEGREE,
    )
}

fn setup_bench(c: &mut Criterion, name: &str, bench_fn: fn(&mut Bencher, &usize)) {
    let mut group = c.benchmark_group(name);
    for degree in default_size_range().iter() {
        group.bench_with_input(BenchmarkId::from_parameter(degree), degree, bench_fn);
    }
    group.finish();
}

fn create_evaluation_domain<F: PrimeField>(degree: usize) -> (EvaluationDomain<F>, Vec<F>) {
    let domain = EvaluationDomain::new(degree).unwrap();
    let a = DensePolynomial::<F>::rand(degree - 1, &mut thread_rng())
        .coeffs()
        .to_vec();
    (domain, a)
}

fn bench_fft_in_place<F: PrimeField>(b: &mut Bencher, degree: &usize) {
    let (domain, mut a) = create_evaluation_domain::<F>(*degree);

    b.iter(|| {
        domain.fft_in_place(&mut a);
    });
}

fn bench_ifft_in_place<F: PrimeField>(b: &mut Bencher, degree: &usize) {
    let (domain, mut a) = create_evaluation_domain::<F>(*degree);

    b.iter(|| {
        domain.ifft_in_place(&mut a);
    });
}

fn bench_coset_fft_in_place<F: PrimeField>(b: &mut Bencher, degree: &usize) {
    let (domain, mut a) = create_evaluation_domain::<F>(*degree);

    b.iter(|| {
        domain.coset_fft_in_place(&mut a);
    });
}

fn bench_coset_ifft_in_place<F: PrimeField>(b: &mut Bencher, degree: &usize) {
    let (domain, mut a) = create_evaluation_domain::<F>(*degree);

    b.iter(|| {
        domain.coset_ifft_in_place(&mut a);
    });
}

fn fft_benches<F: PrimeField>(c: &mut Criterion, name: &str) {
    let description = format!("{:?} - subgroup_fft_in_place", name);
    setup_bench(c, &description, bench_fft_in_place::<F>);
    let description = format!("{:?} - subgroup_ifft_in_place", name);
    setup_bench(c, &description, bench_ifft_in_place::<F>);
    let description = format!("{:?} - coset_fft_in_place", name);
    setup_bench(c, &description, bench_coset_fft_in_place::<F>);
    let description = format!("{:?} - coset_ifft_in_place", name);
    setup_bench(c, &description, bench_coset_ifft_in_place::<F>);
}

fn bench_bls12_377(c: &mut Criterion) {
    fft_benches::<Bls12_377_Fr>(c, "BLS12-377 - radix-2");
}

criterion_group!(benches, bench_bls12_377);
criterion_main!(benches);
