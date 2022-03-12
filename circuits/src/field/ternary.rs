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

impl<E: Environment> Ternary for BaseField<E> {
    type Boolean = Boolean<E>;
    type Output = Self;

    /// Returns `first` if `condition` is `true`, otherwise returns `second`.
    fn ternary(condition: &Self::Boolean, first: &Self, second: &Self) -> Self::Output {
        // Constant `condition`
        if condition.is_constant() {
            match condition.eject_value() {
                true => first.clone(),
                false => second.clone(),
            }
        }
        // Constant `first` and `second`
        else if first.is_constant() && second.is_constant() {
            let not_condition = BaseField::from(&!condition);
            let condition = BaseField::from(condition);
            (condition * first) + (not_condition * second)
        }
        // Variables
        else {
            // Initialize the witness.
            let witness = BaseField::new(Mode::Private, match condition.eject_value() {
                true => first.eject_value(),
                false => second.eject_value(),
            });

            //
            // Ternary Enforcement
            // -------------------------------------------------------
            //    witness = condition * a + (1 - condition) * b
            // => witness = b + condition * (a - b)
            // => condition * (a - b) = witness - b
            //
            //
            // Assumption
            // -------------------------------------------------------
            // If a == b, either values suffices as a valid witness,
            // and we may forgo the cases below. Else, we consider
            // the following four cases.
            //
            //
            // Case 1: condition = 0 AND witness = a (dishonest)
            // -------------------------------------------------------
            // 0 * (a - b) = a - b
            //           0 = a - b
            // => if a != b, as LHS != RHS, the witness is incorrect.
            //
            //
            // Case 2: condition = 0 AND witness = b (honest)
            // -------------------------------------------------------
            // 0 * (a - b) = b - b
            //           0 = 0
            // => as LHS == RHS, the witness is correct.
            //
            //
            // Case 3: condition = 1 AND witness = a (honest)
            // -------------------------------------------------------
            // 1 * (a - b) = a - b
            //       a - b = a - b
            // => as LHS == RHS, the witness is correct.
            //
            //
            // Case 4: condition = 1 AND witness = b (dishonest)
            // -------------------------------------------------------
            // 1 * (a - b) = b - b
            //       a - b = 0
            // => if a != b, as LHS != RHS, the witness is incorrect.
            //
            E::enforce(|| (condition, (first - second), (&witness.0 - &second.0)));

            witness
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{assert_circuit, Circuit};
    use snarkvm_utilities::UniformRand;

    use rand::thread_rng;

    #[test]
    fn test_ternary() {
        // Constant ? Constant : Constant
        {
            let a = BaseField::<Circuit>::new(Mode::Constant, UniformRand::rand(&mut thread_rng()));
            let b = BaseField::<Circuit>::new(Mode::Constant, UniformRand::rand(&mut thread_rng()));

            let condition = Boolean::new(Mode::Constant, true);
            Circuit::scoped("Constant(true) ? Constant : Constant", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 0, 0);

                assert!(output.is_equal(&a).eject_value());
                assert!(!output.is_equal(&b).eject_value());
            });

            let condition = Boolean::new(Mode::Constant, false);
            Circuit::scoped("Constant(false) ? Constant : Constant", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 0, 0);

                assert!(!output.is_equal(&a).eject_value());
                assert!(output.is_equal(&b).eject_value());
            });
        }

        // Constant ? Public : Private
        {
            let a = BaseField::<Circuit>::new(Mode::Public, UniformRand::rand(&mut thread_rng()));
            let b = BaseField::<Circuit>::new(Mode::Private, UniformRand::rand(&mut thread_rng()));

            let condition = Boolean::new(Mode::Constant, true);
            Circuit::scoped("Constant(true) ? Public : Private", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 0, 0);

                assert!(output.is_equal(&a).eject_value());
                assert!(!output.is_equal(&b).eject_value());
            });

            let condition = Boolean::new(Mode::Constant, false);
            Circuit::scoped("Constant(false) ? Public : Private", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 0, 0);

                assert!(!output.is_equal(&a).eject_value());
                assert!(output.is_equal(&b).eject_value());
            });
        }

        // Public ? Constant : Constant
        {
            let a = BaseField::<Circuit>::new(Mode::Constant, UniformRand::rand(&mut thread_rng()));
            let b = BaseField::<Circuit>::new(Mode::Constant, UniformRand::rand(&mut thread_rng()));

            let condition = Boolean::new(Mode::Public, true);
            Circuit::scoped("Public(true) ? Constant : Constant", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 0, 0);

                assert!(output.is_equal(&a).eject_value());
                assert!(!output.is_equal(&b).eject_value());
            });

            let condition = Boolean::new(Mode::Public, false);
            Circuit::scoped("Public(false) ? Constant : Constant", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 0, 0);

                assert!(!output.is_equal(&a).eject_value());
                assert!(output.is_equal(&b).eject_value());
            });
        }

        // Private ? Constant : Constant
        {
            let a = BaseField::<Circuit>::new(Mode::Constant, UniformRand::rand(&mut thread_rng()));
            let b = BaseField::<Circuit>::new(Mode::Constant, UniformRand::rand(&mut thread_rng()));

            let condition = Boolean::new(Mode::Private, true);
            Circuit::scoped("Private(true) ? Constant : Constant", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 0, 0);

                assert!(output.is_equal(&a).eject_value());
                assert!(!output.is_equal(&b).eject_value());
            });

            let condition = Boolean::new(Mode::Private, false);
            Circuit::scoped("Private(false) ? Constant : Constant", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 0, 0);

                assert!(!output.is_equal(&a).eject_value());
                assert!(output.is_equal(&b).eject_value());
            });
        }

        // Private ? Public : Constant
        {
            let a = BaseField::<Circuit>::new(Mode::Public, UniformRand::rand(&mut thread_rng()));
            let b = BaseField::<Circuit>::new(Mode::Constant, UniformRand::rand(&mut thread_rng()));

            let condition = Boolean::new(Mode::Private, true);
            Circuit::scoped("Private(true) ? Public : Constant", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 1, 1);

                assert!(output.is_equal(&a).eject_value());
                assert!(!output.is_equal(&b).eject_value());
            });

            let condition = Boolean::new(Mode::Private, false);
            Circuit::scoped("Private(false) ? Public : Constant", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 1, 1);

                assert!(!output.is_equal(&a).eject_value());
                assert!(output.is_equal(&b).eject_value());
            });
        }

        // Private ? Constant : Public
        {
            let a = BaseField::<Circuit>::new(Mode::Constant, UniformRand::rand(&mut thread_rng()));
            let b = BaseField::<Circuit>::new(Mode::Public, UniformRand::rand(&mut thread_rng()));

            let condition = Boolean::new(Mode::Private, true);
            Circuit::scoped("Private(true) ? Constant : Public", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 1, 1);

                assert!(output.is_equal(&a).eject_value());
                assert!(!output.is_equal(&b).eject_value());
            });

            let condition = Boolean::new(Mode::Private, false);
            Circuit::scoped("Private(false) ? Constant : Public", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 1, 1);

                assert!(!output.is_equal(&a).eject_value());
                assert!(output.is_equal(&b).eject_value());
            });
        }

        // Private ? Private : Public
        {
            let a = BaseField::<Circuit>::new(Mode::Private, UniformRand::rand(&mut thread_rng()));
            let b = BaseField::<Circuit>::new(Mode::Public, UniformRand::rand(&mut thread_rng()));

            let condition = Boolean::new(Mode::Private, true);
            Circuit::scoped("Private(true) ? Private : Public", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 1, 1);

                assert!(output.is_equal(&a).eject_value());
                assert!(!output.is_equal(&b).eject_value());
            });

            let condition = Boolean::new(Mode::Private, false);
            Circuit::scoped("Private(false) ? Private : Public", || {
                let output = BaseField::ternary(&condition, &a, &b);
                assert_circuit!(0, 0, 1, 1);

                assert!(!output.is_equal(&a).eject_value());
                assert!(output.is_equal(&b).eject_value());
            });
        }
    }
}
