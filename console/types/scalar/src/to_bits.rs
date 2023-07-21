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

use snarkvm_utilities::ToBitsInto;

impl<E: Environment> ToBitsInto for Scalar<E> {
    /// Outputs the little-endian bit representation of `self` *without* trailing zeros.
    fn to_bits_le_into(&self, vec: &mut Vec<bool>) {
        (**self).to_bits_le_into(vec);
    }

    /// Outputs the big-endian bit representation of `self` *without* leading zeros.
    fn to_bits_be_into(&self, vec: &mut Vec<bool>) {
        (**self).to_bits_be_into(vec);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network_environment::Console;

    type CurrentEnvironment = Console;

    const ITERATIONS: u64 = 10_000;

    #[test]
    fn test_to_bits_le() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a random value.
            let scalar: Scalar<CurrentEnvironment> = Uniform::rand(&mut rng);

            let candidate = scalar.to_bits_le();
            assert_eq!(Scalar::<CurrentEnvironment>::size_in_bits(), candidate.len());

            for (expected, candidate) in (*scalar).to_bits_le().iter().zip_eq(&candidate) {
                assert_eq!(expected, candidate);
            }
        }
    }

    #[test]
    fn test_to_bits_be() {
        let mut rng = TestRng::default();

        for _ in 0..ITERATIONS {
            // Sample a random value.
            let scalar: Scalar<CurrentEnvironment> = Uniform::rand(&mut rng);

            let candidate = scalar.to_bits_be();
            assert_eq!(Scalar::<CurrentEnvironment>::size_in_bits(), candidate.len());

            for (expected, candidate) in (*scalar).to_bits_be().iter().zip_eq(&candidate) {
                assert_eq!(expected, candidate);
            }
        }
    }
}
