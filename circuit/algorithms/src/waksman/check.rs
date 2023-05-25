// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

impl<E: Environment> ASWaksman<E> {
    /// Returns `true` if `first` is a permutation of `second`, given the `selectors` for the switches in the network.
    pub fn check_permutation(&self, first: &[Field<E>], second: &[Field<E>], selectors: &[Boolean<E>]) -> Boolean<E> {
        // Check that the two sequences are the same length.
        if first.len() != second.len() {
            return E::halt("The two sequences must be the same length.");
        }

        // Run the network on the first sequence, using the given selectors.
        let output = self.run(first, selectors);

        // Check that the output of the network is element-wise equal to the second sequence.
        output.iter().zip_eq(second).fold(Boolean::constant(true), |acc, (a, b)| acc & a.is_equal(b))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use snarkvm_circuit_types::environment::Circuit;
    use snarkvm_utilities::{TestRng, Uniform};

    use rand::seq::SliceRandom;
    use std::iter;

    const ITERATIONS: usize = 10;

    type CurrentEnvironment = Circuit;

    #[test]
    fn test_check_permutation() {
        // A helper function to check that `check_permutation` returns the expected result.
        fn run_test(n: usize, iterations: usize, rng: &mut TestRng) {
            for mode in [Mode::Constant, Mode::Public, Mode::Private] {
                for i in 0..iterations {
                    // Sample a random permutation.
                    let mut permutation: Vec<usize> = (0..n).collect();
                    permutation.shuffle(rng);
                    // Compute the inverse permutation.
                    let inverse_permutation = permutation
                        .iter()
                        .enumerate()
                        .map(|(i, &j)| (j, i))
                        .sorted()
                        .map(|(_, i)| i)
                        .collect::<Vec<_>>();
                    // Sample a random sequence of inputs.
                    let inputs: Vec<console::Field<<CurrentEnvironment as Environment>::Network>> =
                        iter::repeat_with(|| Uniform::rand(rng)).take(n).collect();
                    // Instantiate the Waksman network.
                    let network = console::ASWaksman::<_>::new(n);
                    // Compute the selectors.
                    let selectors = network.assign_selectors(&permutation);
                    assert_eq!(selectors.len(), network.num_selectors());
                    // Apply the permutation to the inputs.
                    let mut outputs = Vec::with_capacity(n);
                    for i in 0..inputs.len() {
                        outputs.push(inputs[inverse_permutation[i]]);
                    }
                    // Check the permutation.
                    assert!(*network.check_permutation(&inputs, &outputs, &selectors));

                    // Inject the inputs.
                    let inputs = inputs
                        .into_iter()
                        .map(|input| Field::<CurrentEnvironment>::new(mode, input))
                        .collect::<Vec<_>>();
                    // Inject the selectors.
                    let selectors = selectors
                        .into_iter()
                        .map(|selector| Boolean::<CurrentEnvironment>::new(mode, *selector))
                        .collect::<Vec<_>>();
                    // Inject the outputs.
                    let outputs = outputs
                        .into_iter()
                        .map(|output| Field::<CurrentEnvironment>::new(mode, output))
                        .collect::<Vec<_>>();
                    // Initialize the network.
                    let network = ASWaksman::<_>::new(n);
                    CurrentEnvironment::scope(format!("TestCheckPermutation(Mode: {mode}, Iteration: {i})"), || {
                        let is_satisfied = network.check_permutation(&inputs, &outputs, &selectors);
                        assert!(is_satisfied.eject_value());
                        assert!(Circuit::is_satisfied());
                    });
                    Circuit::reset();
                }
            }
        }

        let mut rng = TestRng::default();

        run_test(1, ITERATIONS, &mut rng);
        run_test(2, ITERATIONS, &mut rng);
        run_test(3, ITERATIONS, &mut rng);
        run_test(4, ITERATIONS, &mut rng);
        run_test(5, ITERATIONS, &mut rng);
        run_test(6, ITERATIONS, &mut rng);
        run_test(7, ITERATIONS, &mut rng);
        run_test(8, ITERATIONS, &mut rng);
        run_test(9, ITERATIONS, &mut rng);
        run_test(10, ITERATIONS, &mut rng);
        run_test(11, ITERATIONS, &mut rng);
        run_test(12, ITERATIONS, &mut rng);
        run_test(13, ITERATIONS, &mut rng);
        run_test(14, ITERATIONS, &mut rng);
        run_test(15, ITERATIONS, &mut rng);
        run_test(16, ITERATIONS, &mut rng);
        run_test(17, ITERATIONS, &mut rng);
        run_test(32, ITERATIONS, &mut rng);
        run_test(33, ITERATIONS, &mut rng);
        run_test(64, ITERATIONS, &mut rng);
        run_test(65, ITERATIONS, &mut rng);
        run_test(128, ITERATIONS, &mut rng);
        run_test(129, ITERATIONS, &mut rng);
        run_test(256, ITERATIONS, &mut rng);
        run_test(257, ITERATIONS, &mut rng);
        run_test(512, ITERATIONS, &mut rng);
        run_test(513, ITERATIONS, &mut rng);
        run_test(1024, ITERATIONS, &mut rng);
        run_test(1025, ITERATIONS, &mut rng);
        run_test(2048, ITERATIONS, &mut rng);
        run_test(2049, ITERATIONS, &mut rng);
        run_test(4096, ITERATIONS, &mut rng);
        run_test(4097, ITERATIONS, &mut rng);
    }
}
