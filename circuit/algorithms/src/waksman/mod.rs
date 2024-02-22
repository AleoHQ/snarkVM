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

mod check;
mod switch;

use snarkvm_circuit_types::prelude::*;

use core::marker::PhantomData;

/// An arbitrary-size Waksman network.
/// See "On Arbitrary Waksman Networks and their Vulnerability" - https://hal.inria.fr/inria-00072871/document
pub struct ASWaksman<E: Environment> {
    /// The number of inputs to the network.
    num_inputs: usize,
    _phantom: PhantomData<E>,
}

impl<E: Environment> ASWaksman<E> {
    /// Initializes a new `ASWaksman` network with the given number of inputs.
    pub fn new(num_inputs: usize) -> Self {
        match num_inputs != 0 {
            true => Self { num_inputs, _phantom: Default::default() },
            false => E::halt("A Waksman network must have at least one input."),
        }
    }

    /// Runs the network on the given sequence of `inputs` using the given `selectors`.
    pub fn run(&self, inputs: &[Field<E>], selectors: &[Boolean<E>]) -> Vec<Field<E>> {
        // Check that the number of inputs is correct.
        if inputs.len() != self.num_inputs {
            return E::halt(format!("The number of inputs must be exactly {}.", self.num_inputs));
        }

        // Check that the number of selectors is correct.
        if selectors.len() != self.num_selectors() {
            return E::halt(format!("The number of selectors must be exactly {}.", self.num_selectors()));
        }

        match self.num_inputs {
            // Base Case #1: The network has exactly one input.
            // In this case, the network is a single wire.
            1 => vec![inputs[0].clone()],
            // Base Case #2: The network has exactly two inputs.
            // In this case, the network is a single switch.
            2 => {
                let result = Self::switch(&selectors[0], &inputs[0], &inputs[1]);
                vec![result.0, result.1]
            }
            _ => {
                // Initialize a counter for the selector bit.
                let mut selector_counter = 0;

                // Calculate the number of inputs to the upper subnetwork.
                let upper_num_inputs = self.num_inputs / 2;
                // Calculate the number of inputs to the lower subnetwork.
                let lower_num_inputs = self.num_inputs - upper_num_inputs;

                // Initialize the upper subnetwork.
                let upper_network = Self::new(upper_num_inputs);
                // Initialize the lower subnetwork.
                let lower_network = Self::new(lower_num_inputs);

                // Calculate the number of input switches.
                let num_input_switches = self.num_inputs / 2;
                // Calculate the number of output switches.
                let num_output_switches = match self.num_inputs % 2 == 0 {
                    true => self.num_inputs / 2 - 1,
                    false => (self.num_inputs - 1) / 2,
                };
                // Check that the number of switches matches the number of selectors.
                if num_input_switches
                    + num_output_switches
                    + upper_network.num_selectors()
                    + lower_network.num_selectors()
                    != self.num_selectors()
                {
                    return E::halt("The number of switches does not match the number of selectors.");
                }

                // Run each pair of inputs through a switch.
                // Arrange the writes into the inputs for the upper and lower subnetworks.
                // Note that if the number of inputs is odd, the last input is not paired with anything.
                let (upper_inputs, lower_inputs) = {
                    // Initialize a vector for the upper subnetwork.
                    let mut upper_inputs = Vec::with_capacity(upper_num_inputs);
                    // Initialize a vector for the lower subnetwork.
                    let mut lower_inputs = Vec::with_capacity(lower_num_inputs);
                    // Initialize a counter to track where we are in the input vector.
                    let mut input_counter = 0;
                    // Run each pair of inputs through a switch, and write the outputs to the appropriate subnetwork.
                    while input_counter < self.num_inputs {
                        if input_counter == self.num_inputs - 1 {
                            // If we are at the last input, write it to the lower subnetwork.
                            lower_inputs.push(inputs[input_counter].clone());
                            break;
                        } else {
                            let first = &inputs[input_counter];
                            let second = &inputs[input_counter + 1];
                            let (upper, lower) = Self::switch(&selectors[selector_counter], first, second);
                            upper_inputs.push(upper);
                            lower_inputs.push(lower);
                            selector_counter += 1;
                            input_counter += 2;
                        }
                    }
                    (upper_inputs, lower_inputs)
                };

                // Run the upper subnetwork.
                let mut upper_outputs = upper_network.run(
                    &upper_inputs,
                    &selectors[num_input_switches..(num_input_switches + upper_network.num_selectors())],
                );

                // Run the lower subnetwork.
                let mut lower_outputs = lower_network.run(
                    &lower_inputs,
                    &selectors[(num_input_switches + upper_network.num_selectors())
                        ..(num_input_switches + upper_network.num_selectors() + lower_network.num_selectors())],
                );

                // Combine the outputs of the subnetworks.
                let (pairs, additional) = {
                    // Note that the unwraps are safe since, since there are at least 3 inputs to the network, which implies that there is at
                    // least one input/output in each of the subnetworks.
                    match self.num_inputs % 2 == 0 {
                        true => {
                            let second_to_last = upper_outputs.pop().unwrap();
                            let last = lower_outputs.pop().unwrap();
                            let pairs = upper_outputs.into_iter().zip_eq(lower_outputs.into_iter()).collect::<Vec<_>>();
                            (pairs, vec![second_to_last, last])
                        }
                        false => {
                            let last = lower_outputs.pop().unwrap();
                            let pairs = upper_outputs.into_iter().zip_eq(lower_outputs.into_iter()).collect::<Vec<_>>();
                            (pairs, vec![last])
                        }
                    }
                };

                // Run each pair through a switch.
                let mut outputs = {
                    // Set the selector counter.
                    selector_counter =
                        num_input_switches + upper_network.num_selectors() + lower_network.num_selectors();
                    let mut outputs = Vec::with_capacity(self.num_inputs);
                    for (first, second) in pairs {
                        let (upper, lower) = Self::switch(&selectors[selector_counter], &first, &second);
                        outputs.push(upper);
                        outputs.push(lower);
                        selector_counter += 1;
                    }
                    outputs
                };

                // Add the additional output(s).
                outputs.extend(additional);

                outputs
            }
        }
    }

    /// Returns the exact number of selector bits required to program the network.
    pub fn num_selectors(&self) -> usize {
        (1..=self.num_inputs).map(|i| i.next_power_of_two().ilog2() as usize).sum()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use snarkvm_circuit_types::environment::{assert_scope, Circuit};
    use snarkvm_utilities::{TestRng, Uniform};

    use std::iter;

    const ITERATIONS: usize = 10;

    type CurrentEnvironment = Circuit;

    #[test]
    #[should_panic]
    fn test_zero_size_network_fails() {
        ASWaksman::<CurrentEnvironment>::new(0);
    }

    #[test]
    fn test_identity_network() {
        fn run_test(num_inputs: usize, rng: &mut TestRng) {
            for mode in [Mode::Constant, Mode::Public, Mode::Public] {
                for i in 0..ITERATIONS {
                    let network = ASWaksman::new(num_inputs);

                    let inputs = iter::repeat_with(|| Field::<CurrentEnvironment>::new(mode, Uniform::rand(rng)))
                        .take(num_inputs)
                        .collect::<Vec<_>>();

                    let selectors = vec![Boolean::new(mode, false); network.num_selectors()];

                    let name = format!("ASWaksman({}, {}, {})", mode, num_inputs, i);

                    CurrentEnvironment::scope(name, || {
                        let outputs = network.run(&inputs, &selectors);
                        for (input, output) in inputs.iter().zip_eq(outputs.iter()) {
                            assert_eq!(input.eject_value(), output.eject_value());
                        }
                        match mode {
                            Mode::Constant => assert_scope!(0, 0, 0, 0),
                            _ => assert_scope!(
                                0,
                                0,
                                2 * network.num_selectors() as u64,
                                2 * network.num_selectors() as u64
                            ),
                        }
                    });
                }
            }
        }

        let mut rng = TestRng::default();

        run_test(1, &mut rng);
        run_test(2, &mut rng);
        run_test(3, &mut rng);
        run_test(4, &mut rng);
        run_test(5, &mut rng);
        run_test(6, &mut rng);
        run_test(7, &mut rng);
        run_test(8, &mut rng);
        run_test(9, &mut rng);
        run_test(10, &mut rng);
        run_test(11, &mut rng);
        run_test(12, &mut rng);
        run_test(13, &mut rng);
        run_test(14, &mut rng);
        run_test(15, &mut rng);
        run_test(16, &mut rng);
        run_test(17, &mut rng);
        run_test(32, &mut rng);
        run_test(33, &mut rng);
        run_test(64, &mut rng);
        run_test(65, &mut rng);
        run_test(128, &mut rng);
        run_test(129, &mut rng);
        run_test(256, &mut rng);
        run_test(257, &mut rng);
        run_test(512, &mut rng);
        run_test(513, &mut rng);
        run_test(1024, &mut rng);
        run_test(1025, &mut rng);
        run_test(2048, &mut rng);
        run_test(2049, &mut rng);
        run_test(4096, &mut rng);
        run_test(4097, &mut rng);
    }

    #[test]
    fn test_reverse_network() {
        fn compute_selectors(mode: Mode, num_inputs: usize) -> Vec<Boolean<CurrentEnvironment>> {
            match num_inputs {
                0 => panic!("num_inputs must be greater than 0"),
                1 => vec![],
                2 => vec![Boolean::new(mode, true)],
                _ => {
                    let mut input_selectors = vec![Boolean::new(mode, true); num_inputs / 2];
                    let upper_selectors = compute_selectors(mode, num_inputs / 2);
                    let lower_selectors = compute_selectors(mode, num_inputs - num_inputs / 2);
                    let output_selectors = match num_inputs % 2 == 0 {
                        true => vec![Boolean::new(mode, false); num_inputs / 2 - 1],
                        false => vec![Boolean::new(mode, true); (num_inputs - 1) / 2],
                    };
                    input_selectors.extend(upper_selectors);
                    input_selectors.extend(lower_selectors);
                    input_selectors.extend(output_selectors);
                    input_selectors
                }
            }
        }

        fn run_test(num_inputs: usize, rng: &mut TestRng) {
            for mode in [Mode::Constant, Mode::Public, Mode::Public] {
                for i in 0..ITERATIONS {
                    let network = ASWaksman::new(num_inputs);

                    let inputs = iter::repeat_with(|| Field::<CurrentEnvironment>::new(mode, Uniform::rand(rng)))
                        .take(num_inputs)
                        .collect::<Vec<_>>();
                    let selectors = compute_selectors(mode, num_inputs);

                    let name = format!("ASWaksman({}, {}, {})", mode, num_inputs, i);

                    CurrentEnvironment::scope(name, || {
                        let outputs = network.run(&inputs, &selectors);
                        for (input, output) in inputs.iter().zip_eq(outputs.iter().rev()) {
                            assert_eq!(input.eject_value(), output.eject_value());
                        }
                        match mode {
                            Mode::Constant => assert_scope!(0, 0, 0, 0),
                            _ => assert_scope!(
                                0,
                                0,
                                2 * network.num_selectors() as u64,
                                2 * network.num_selectors() as u64
                            ),
                        }
                    });
                }
            }
        }

        let mut rng = TestRng::default();

        run_test(1, &mut rng);
        run_test(2, &mut rng);
        run_test(3, &mut rng);
        run_test(4, &mut rng);
        run_test(5, &mut rng);
        run_test(6, &mut rng);
        run_test(7, &mut rng);
        run_test(8, &mut rng);
        run_test(9, &mut rng);
        run_test(10, &mut rng);
        run_test(11, &mut rng);
        run_test(12, &mut rng);
        run_test(13, &mut rng);
        run_test(14, &mut rng);
        run_test(15, &mut rng);
        run_test(16, &mut rng);
        run_test(17, &mut rng);
        run_test(32, &mut rng);
        run_test(33, &mut rng);
        run_test(64, &mut rng);
        run_test(65, &mut rng);
        run_test(128, &mut rng);
        run_test(129, &mut rng);
        run_test(256, &mut rng);
        run_test(257, &mut rng);
        run_test(512, &mut rng);
        run_test(513, &mut rng);
        run_test(1024, &mut rng);
        run_test(1025, &mut rng);
        run_test(2048, &mut rng);
        run_test(2049, &mut rng);
        run_test(4096, &mut rng);
        run_test(4097, &mut rng);
    }
}
