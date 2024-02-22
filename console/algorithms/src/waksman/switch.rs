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

    use snarkvm_utilities::{TestRng, Uniform};

    type CurrentEnvironment = Console;

    const ITERATIONS: usize = 100;

    fn check_switch(
        expected: (<CurrentEnvironment as Environment>::Field, <CurrentEnvironment as Environment>::Field),
        selector: Boolean<CurrentEnvironment>,
        a: &Field<CurrentEnvironment>,
        b: &Field<CurrentEnvironment>,
    ) {
        let case = format!("switch({}, {}, {})", selector, a, b);
        let candidate = ASWaksman::switch(&selector, a, b);
        assert_eq!(expected.0, *candidate.0, "Unexpected first output for {}", case);
        assert_eq!(expected.1, *candidate.1, "Unexpected second output for {}", case);
    }

    #[test]
    fn test_switch() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            let first = Uniform::rand(&mut rng);
            let second = Uniform::rand(&mut rng);

            let a = Field::<CurrentEnvironment>::new(first);
            let b = Field::<CurrentEnvironment>::new(second);

            // switch(false)
            let expected = (first, second);
            let condition = Boolean::<CurrentEnvironment>::new(false);
            check_switch(expected, condition, &a, &b);

            // switch(true)
            let expected = (second, first);
            let condition = Boolean::<CurrentEnvironment>::new(true);
            check_switch(expected, condition, &a, &b);
        }
    }
}
