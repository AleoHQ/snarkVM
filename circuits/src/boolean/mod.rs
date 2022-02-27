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

pub mod adder;
pub use adder::*;

pub mod and;
pub use and::*;

pub mod equal;
pub use equal::*;

pub mod nand;
pub use nand::*;

pub mod nor;
pub use nor::*;

pub mod not;
pub use not::*;

pub mod or;
pub use or::*;

pub mod subtractor;
pub use subtractor::*;

pub mod ternary;
pub use ternary::*;

pub mod xor;
pub use xor::*;

use crate::{traits::*, Environment, LinearCombination, Mode, Variable};
use snarkvm_fields::{One as O, Zero as Z};

use core::{
    fmt,
    ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Deref, Not},
};

#[derive(Clone)]
pub struct Boolean<E: Environment>(LinearCombination<E::BaseField>);

impl<E: Environment> BooleanTrait for Boolean<E> {}

impl<E: Environment> Boolean<E> {
    ///
    /// Initializes a new instance of a boolean from a constant boolean value.
    ///
    pub fn new(mode: Mode, value: bool) -> Self {
        let variable = E::new_variable(mode, match value {
            true => E::BaseField::one(),
            false => E::BaseField::zero(),
        });

        // Ensure (1 - a) * a = 0
        // `a` must be either 0 or 1.
        E::enforce(|| (E::one() - variable, variable, E::zero()));

        Self(variable.into())
    }
}

impl<E: Environment> Eject for Boolean<E> {
    type Primitive = bool;

    ///
    /// Ejects the mode of the boolean.
    ///
    fn eject_mode(&self) -> Mode {
        // Perform a software-level safety check that the boolean is well-formed.
        match self.0.is_boolean_type() {
            true => self.0.to_mode(),
            false => E::halt("Boolean variable is not well-formed"),
        }
    }

    ///
    /// Ejects the boolean as a constant boolean value.
    ///
    fn eject_value(&self) -> Self::Primitive {
        let value = self.0.to_value();
        debug_assert!(value.is_zero() || value.is_one());
        value.is_one()
    }
}

impl<E: Environment> Parser for Boolean<E> {
    type Output = Boolean<E>;

    /// Parses a string into a circuit type.
    #[inline]
    fn parse(boolean: &str) -> Self::Output {
        match boolean {
            "true" => Boolean::new(Mode::Constant, true),
            "false" => Boolean::new(Mode::Constant, false),
            "Constant(true)" => Boolean::new(Mode::Constant, true),
            "Constant(false)" => Boolean::new(Mode::Constant, false),
            "Public(true)" => Boolean::new(Mode::Public, true),
            "Public(false)" => Boolean::new(Mode::Public, false),
            "Private(true)" => Boolean::new(Mode::Private, true),
            "Private(false)" => Boolean::new(Mode::Private, false),
            _ => E::halt(format!("Parser failed on 'boolean' type: {}", boolean)),
        }
    }
}

impl<E: Environment> fmt::Debug for Boolean<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.eject_value())
    }
}

impl<E: Environment> fmt::Display for Boolean<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}({})", self.eject_mode(), self.eject_value())
    }
}

impl<E: Environment> Deref for Boolean<E> {
    type Target = LinearCombination<E::BaseField>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<E: Environment> From<Boolean<E>> for LinearCombination<E::BaseField> {
    fn from(boolean: Boolean<E>) -> Self {
        boolean.0
    }
}

impl<E: Environment> From<&Boolean<E>> for LinearCombination<E::BaseField> {
    fn from(boolean: &Boolean<E>) -> Self {
        boolean.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{assert_circuit, Circuit};

    #[test]
    fn test_new_constant() {
        Circuit::scoped("test_new_constant", || {
            let candidate = Boolean::<Circuit>::new(Mode::Constant, false);
            assert!(!candidate.eject_value()); // false
            assert_circuit!(1, 0, 0, 0);

            let candidate = Boolean::<Circuit>::new(Mode::Constant, true);
            assert!(candidate.eject_value()); // true
            assert_circuit!(2, 0, 0, 0);
        });
    }

    #[test]
    fn test_new_public() {
        Circuit::scoped("test_new_public", || {
            let candidate = Boolean::<Circuit>::new(Mode::Public, false);
            assert!(!candidate.eject_value()); // false
            assert_circuit!(0, 1, 0, 1);

            let candidate = Boolean::<Circuit>::new(Mode::Public, true);
            assert!(candidate.eject_value()); // true
            assert_circuit!(0, 2, 0, 2);
        });
    }

    #[test]
    fn test_new_private() {
        Circuit::scoped("test_new_private", || {
            let candidate = Boolean::<Circuit>::new(Mode::Private, false);
            assert!(!candidate.eject_value()); // false
            assert_circuit!(0, 0, 1, 1);

            let candidate = Boolean::<Circuit>::new(Mode::Private, true);
            assert!(candidate.eject_value()); // true
            assert_circuit!(0, 0, 2, 2);
        });
    }

    #[test]
    fn test_new_fail() {
        let one = <Circuit as Environment>::BaseField::one();
        let two = one + one;
        {
            let candidate = Circuit::new_variable(Mode::Constant, two);

            // Ensure `a` is either 0 or 1:
            // (1 - a) * a = 0
            Circuit::enforce(|| (Circuit::one() - candidate, candidate, Circuit::zero()));
            assert_eq!(0, Circuit::num_constraints());

            Circuit::reset();
        }
        {
            let candidate = Circuit::new_variable(Mode::Public, two);

            // Ensure `a` is either 0 or 1:
            // (1 - a) * a = 0
            Circuit::enforce(|| (Circuit::one() - candidate, candidate, Circuit::zero()));
            assert!(!Circuit::is_satisfied());

            Circuit::reset();
        }
        {
            let candidate = Circuit::new_variable(Mode::Private, two);

            // Ensure `a` is either 0 or 1:
            // (1 - a) * a = 0
            Circuit::enforce(|| (Circuit::one() - candidate, candidate, Circuit::zero()));
            assert!(!Circuit::is_satisfied());

            Circuit::reset();
        }
    }

    #[test]
    fn test_parser() {
        let candidate = Boolean::<Circuit>::parse("true");
        assert_eq!(true, candidate.eject_value());
        assert!(candidate.is_constant());

        let candidate = Boolean::<Circuit>::parse("false");
        assert_eq!(false, candidate.eject_value());
        assert!(candidate.is_constant());

        let candidate = Boolean::<Circuit>::parse("Constant(true)");
        assert_eq!(true, candidate.eject_value());
        assert!(candidate.is_constant());

        let candidate = Boolean::<Circuit>::parse("Constant(false)");
        assert_eq!(false, candidate.eject_value());
        assert!(candidate.is_constant());

        let candidate = Boolean::<Circuit>::parse("Public(true)");
        assert_eq!(true, candidate.eject_value());
        assert!(candidate.is_public());

        let candidate = Boolean::<Circuit>::parse("Public(false)");
        assert_eq!(false, candidate.eject_value());
        assert!(candidate.is_public());

        let candidate = Boolean::<Circuit>::parse("Private(true)");
        assert_eq!(true, candidate.eject_value());
        assert!(candidate.is_private());

        let candidate = Boolean::<Circuit>::parse("Private(false)");
        assert_eq!(false, candidate.eject_value());
        assert!(candidate.is_private());
    }

    #[test]
    fn test_debug() {
        let candidate = Boolean::<Circuit>::new(Mode::Constant, false);
        assert_eq!("false", format!("{:?}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Constant, true);
        assert_eq!("true", format!("{:?}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Public, false);
        assert_eq!("false", format!("{:?}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Public, true);
        assert_eq!("true", format!("{:?}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Private, false);
        assert_eq!("false", format!("{:?}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Private, true);
        assert_eq!("true", format!("{:?}", candidate));
    }

    #[test]
    fn test_display() {
        let candidate = Boolean::<Circuit>::new(Mode::Constant, false);
        assert_eq!("Constant(false)", format!("{}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Constant, true);
        assert_eq!("Constant(true)", format!("{}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Public, false);
        assert_eq!("Public(false)", format!("{}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Public, true);
        assert_eq!("Public(true)", format!("{}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Private, false);
        assert_eq!("Private(false)", format!("{}", candidate));

        let candidate = Boolean::<Circuit>::new(Mode::Private, true);
        assert_eq!("Private(true)", format!("{}", candidate));
    }
}
