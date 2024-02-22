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
    /// A function to construct a switch in the network.
    /// The switch takes two inputs, `first` and `second`, and returns a pair of outputs.
    /// The output pair is determined by the `selector` bit.
    /// If the selector is `true`, the first output is `second` and the second output is `first`.
    /// If the selector is `false`, the first output is `first` and the second output is `second`.
    pub fn switch(selector: &Boolean<E>, first: &Field<E>, second: &Field<E>) -> (Field<E>, Field<E>) {
        (Field::ternary(selector, second, first), Field::ternary(selector, first, second))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use snarkvm_circuit_types::environment::{assert_scope, Circuit};
    use snarkvm_utilities::{TestRng, Uniform};

    const ITERATIONS: usize = 100;

    type CurrentEnvironment = Circuit;

    fn check_switch(
        name: &str,
        expected: (
            console::Field<<CurrentEnvironment as Environment>::Network>,
            console::Field<<CurrentEnvironment as Environment>::Network>,
        ),
        selector: Boolean<CurrentEnvironment>,
        a: &Field<CurrentEnvironment>,
        b: &Field<CurrentEnvironment>,
    ) {
        CurrentEnvironment::scope(name, || {
            let case = format!("switch({}, {}, {})", selector.eject_value(), a.eject_value(), b.eject_value());
            let candidate = ASWaksman::switch(&selector, a, b);
            assert_eq!(expected.0, candidate.0.eject_value(), "Unexpected first output for {}", case);
            assert_eq!(expected.1, candidate.1.eject_value(), "Unexpected second output for {}", case);
            match (selector.eject_mode(), a.eject_mode(), b.eject_mode()) {
                (Mode::Constant, _, _)
                | (Mode::Public, Mode::Constant, Mode::Constant)
                | (Mode::Private, Mode::Constant, Mode::Constant) => assert_scope!(0, 0, 0, 0),
                _ => assert_scope!(0, 0, 2, 2),
            }
        });
    }

    #[test]
    fn test_switch() {
        let mut rng = TestRng::default();
        let modes = &[Mode::Constant, Mode::Public, Mode::Private];
        for _ in 0..ITERATIONS {
            for condition_mode in modes {
                for first_mode in modes {
                    for second_mode in modes {
                        let first = Uniform::rand(&mut rng);
                        let second = Uniform::rand(&mut rng);

                        let a = Field::<CurrentEnvironment>::new(*first_mode, first);
                        let b = Field::<CurrentEnvironment>::new(*second_mode, second);

                        // Test false case.
                        let expected = (first, second);
                        let condition = Boolean::<CurrentEnvironment>::new(*condition_mode, false);
                        check_switch(
                            &format!("switch(false, {condition_mode}, {first_mode}, {second_mode})"),
                            expected,
                            condition,
                            &a,
                            &b,
                        );

                        // Test true case.
                        let expected = (second, first);
                        let condition = Boolean::<CurrentEnvironment>::new(*condition_mode, true);
                        check_switch(
                            &format!("switch(true, {condition_mode}, {first_mode}, {second_mode})"),
                            expected,
                            condition,
                            &a,
                            &b,
                        );
                    }
                }
            }
        }
    }
}
