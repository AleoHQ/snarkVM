// Copyright (C) 2019-2022 Aleo Systems Inc.
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

use super::*;
use crate::BaseField;
// use snarkvm_utilities::{from_bits_le_to_bytes_le, FromBytes};

impl<E: Environment> FromBits for Scalar<E> {
    type Boolean = Boolean<E>;

    /// Initializes a new scalar field element from a list of little-endian bits *without* trailing zeros.
    fn from_bits_le(mode: Mode, bits_le: &[Self::Boolean]) -> Self {
        // Initialize the new little-endian boolean vector.
        let mut bits_le = bits_le.to_vec();
        let num_bits = bits_le.len();

        // TODO (howardwu): Contemplate how to handle the CAPACITY vs. BITS case.
        // Ensure the list of booleans is within the allowed capacity.
        let size_in_bits = E::ScalarField::size_in_bits();
        match num_bits <= size_in_bits {
            true => bits_le.resize(size_in_bits, Boolean::new(Mode::Constant, false)),
            false => E::halt(format!("Attempted to instantiate a {size_in_bits}-bit scalar with {num_bits} bits")),
        }

        // Construct the candidate scalar field element.
        let candidate = Scalar { bits_le };

        // Ensure the mode in the given bits are consistent with the desired mode.
        // If they do not match, proceed to construct a new scalar, and check that it is well-formed.
        let output = match candidate.eject_mode() == mode {
            true => candidate,
            false => {
                // Construct a new integer as a witness.
                let output = Scalar::new(mode, candidate.eject_value());
                // Ensure `output` == `candidate`.
                E::assert_eq(&output, &candidate);
                // Return the new integer.
                output
            }
        };

        // Initialize the scalar field modulus as a constant base field variable.
        //
        // Note: We are reconstituting the scalar field into a base field here in order to check
        // that the scalar was synthesized correctly. This is safe as the scalar field modulus
        // is less that the base field modulus, and thus will always fit in a base field element.
        let modulus = BaseField::new(Mode::Constant, match E::ScalarField::modulus().to_bytes_le() {
            Ok(modulus_bytes) => match E::BaseField::from_bytes_le(&modulus_bytes) {
                Ok(modulus) => modulus,
                Err(error) => {
                    E::halt(format!("Failed to initialize the scalar modulus as a constant variable: {error}"))
                }
            },
            Err(error) => E::halt(format!("Failed to retrieve the scalar modulus as bytes: {error}")),
        });

        // Ensure `output` is less than `E::ScalarField::modulus()`.
        E::assert(output.to_field().is_less_than(&modulus));

        output
    }

    /// Initializes a new scalar field element from a list of big-endian bits *without* leading zeros.
    fn from_bits_be(mode: Mode, bits_be: &[Self::Boolean]) -> Self {
        // Reverse the given bits from big-endian into little-endian.
        // Note: This is safe as the bit representation is consistent (there are no leading zeros).
        let mut bits_le = bits_be.to_vec();
        bits_le.reverse();

        Self::from_bits_le(mode, &bits_le)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{assert_circuit, Circuit};
    use snarkvm_utilities::UniformRand;

    use rand::thread_rng;

    const ITERATIONS: usize = 100;

    fn check_from_bits_le(
        mode: Mode,
        num_constants: usize,
        num_public: usize,
        num_private: usize,
        num_constraints: usize,
    ) {
        for i in 0..ITERATIONS {
            // Sample a random element.
            let expected: <Circuit as Environment>::ScalarField = UniformRand::rand(&mut thread_rng());
            let candidate = Scalar::<Circuit>::new(mode, expected).to_bits_le();

            Circuit::scoped(&format!("{} {}", mode, i), || {
                let candidate = Scalar::<Circuit>::from_bits_le(mode, &candidate);
                assert_eq!(expected, candidate.eject_value());
                assert_circuit!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
    }

    fn check_from_bits_be(
        mode: Mode,
        num_constants: usize,
        num_public: usize,
        num_private: usize,
        num_constraints: usize,
    ) {
        for i in 0..ITERATIONS {
            // Sample a random element.
            let expected: <Circuit as Environment>::ScalarField = UniformRand::rand(&mut thread_rng());
            let candidate = Scalar::<Circuit>::new(mode, expected).to_bits_be();

            Circuit::scoped(&format!("{} {}", mode, i), || {
                let candidate = Scalar::<Circuit>::from_bits_be(mode, &candidate);
                assert_eq!(expected, candidate.eject_value());
                assert_circuit!(num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
    }

    #[test]
    fn test_from_bits_le_constant() {
        check_from_bits_le(Mode::Constant, 510, 0, 0, 0);
    }

    #[test]
    fn test_from_bits_le_public() {
        check_from_bits_le(Mode::Public, 257, 0, 769, 771);
    }

    #[test]
    fn test_from_bits_le_private() {
        check_from_bits_le(Mode::Private, 257, 0, 769, 771);
    }

    #[test]
    fn test_from_bits_be_constant() {
        check_from_bits_be(Mode::Constant, 510, 0, 0, 0);
    }

    #[test]
    fn test_from_bits_be_public() {
        check_from_bits_be(Mode::Public, 257, 0, 769, 771);
    }

    #[test]
    fn test_from_bits_be_private() {
        check_from_bits_be(Mode::Private, 257, 0, 769, 771);
    }
}
