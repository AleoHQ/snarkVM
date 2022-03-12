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

impl<E: Environment> Equal<Self> for Affine<E> {
    type Boolean = Boolean<E>;

    ///
    /// Returns `true` if `self` and `other` are equal.
    ///
    /// This method costs 8 constraints.
    ///
    fn is_equal(&self, other: &Self) -> Self::Boolean {
        let is_x_eq = self.x.is_equal(&other.x);
        let is_y_eq = self.y.is_equal(&other.y);
        is_x_eq & is_y_eq
    }

    ///
    /// Returns `true` if `self` and `other` are *not* equal.
    ///
    /// This method constructs a boolean that indicates if
    /// `self` and `other ` are *not* equal to each other.
    ///
    /// This method costs 8 constraints.
    ///
    fn is_not_equal(&self, other: &Self) -> Self::Boolean {
        !self.is_equal(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{assert_circuit, Circuit};
    use snarkvm_utilities::UniformRand;

    use rand::thread_rng;

    const ITERATIONS: usize = 100;

    #[test]
    fn test_is_equal() {
        // Constant == Constant
        for i in 0..ITERATIONS {
            // Sample two random elements.
            let a: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());
            let b: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());

            let a = Affine::<Circuit>::new(Mode::Constant, (a.to_x_coordinate(), Some(a.to_y_coordinate())));
            let b = Affine::<Circuit>::new(Mode::Constant, (b.to_x_coordinate(), Some(b.to_y_coordinate())));

            Circuit::scoped(&format!("Constant Equals {}", i), || {
                let equals = a.is_equal(&b);
                assert!(!equals.eject_value());
                assert_circuit!(2, 0, 0, 0);
            });
            Circuit::reset();

            Circuit::scoped(&format!("Constant Not Equals {}", i), || {
                let equals = a.is_not_equal(&b);
                assert!(equals.eject_value());
                assert_circuit!(2, 0, 0, 0);
            });
            Circuit::reset();
        }

        // Constant == Public
        for i in 0..ITERATIONS {
            // Sample two random elements.
            let a: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());
            let b: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());

            let a = Affine::<Circuit>::new(Mode::Constant, (a.to_x_coordinate(), Some(a.to_y_coordinate())));
            let b = Affine::<Circuit>::new(Mode::Public, (b.to_x_coordinate(), Some(b.to_y_coordinate())));

            Circuit::scoped(&format!("Constant and Public Equals {}", i), || {
                let equals = a.is_equal(&b);
                assert!(!equals.eject_value());
                assert_circuit!(0, 0, 5, 7);
            });
            Circuit::reset();

            Circuit::scoped(&format!("Constant and Public Not Equals {}", i), || {
                let equals = a.is_not_equal(&b);
                assert!(equals.eject_value());
                assert_circuit!(0, 0, 5, 7);
            });
            Circuit::reset();
        }

        // Public == Constant
        for i in 0..ITERATIONS {
            // Sample two random elements.
            let a: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());
            let b: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());

            let a = Affine::<Circuit>::new(Mode::Public, (a.to_x_coordinate(), Some(a.to_y_coordinate())));
            let b = Affine::<Circuit>::new(Mode::Constant, (b.to_x_coordinate(), Some(b.to_y_coordinate())));

            Circuit::scoped(&format!("Public and Constant Equals {}", i), || {
                let equals = a.is_equal(&b);
                assert!(!equals.eject_value());
                assert_circuit!(0, 0, 5, 7);
            });
            Circuit::reset();

            Circuit::scoped(&format!("Public and Constant Not Equals {}", i), || {
                let equals = a.is_not_equal(&b);
                assert!(equals.eject_value());
                assert_circuit!(0, 0, 5, 7);
            });
            Circuit::reset();
        }

        // Public == Public
        for i in 0..ITERATIONS {
            // Sample two random elements.
            let a: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());
            let b: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());

            let a = Affine::<Circuit>::new(Mode::Public, (a.to_x_coordinate(), Some(a.to_y_coordinate())));
            let b = Affine::<Circuit>::new(Mode::Public, (b.to_x_coordinate(), Some(b.to_y_coordinate())));

            Circuit::scoped(&format!("Public Equals {}", i), || {
                let equals = a.is_equal(&b);
                assert!(!equals.eject_value());
                assert_circuit!(0, 0, 5, 7);
            });
            Circuit::reset();

            Circuit::scoped(&format!("Public Not Equals {}", i), || {
                let equals = a.is_not_equal(&b);
                assert!(equals.eject_value());
                assert_circuit!(0, 0, 5, 7);
            });
            Circuit::reset();
        }

        // Private == Private
        for i in 0..ITERATIONS {
            // Sample two random elements.
            let a: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());
            let b: <Circuit as Environment>::Affine = UniformRand::rand(&mut thread_rng());

            let a = Affine::<Circuit>::new(Mode::Private, (a.to_x_coordinate(), Some(a.to_y_coordinate())));
            let b = Affine::<Circuit>::new(Mode::Private, (b.to_x_coordinate(), Some(b.to_y_coordinate())));

            Circuit::scoped(&format!("Private Equals {}", i), || {
                let equals = a.is_equal(&b);
                assert!(!equals.eject_value());
                assert_circuit!(0, 0, 5, 7);
            });
            Circuit::reset();

            Circuit::scoped(&format!("Private Not Equals {}", i), || {
                let equals = a.is_not_equal(&b);
                assert!(equals.eject_value());
                assert_circuit!(0, 0, 5, 7);
            });
            Circuit::reset();
        }
    }
}
