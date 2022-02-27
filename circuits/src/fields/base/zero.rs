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

impl<E: Environment> Zero for BaseField<E> {
    type Boolean = Boolean<E>;

    #[scope(circuit = "BaseField")]
    fn zero() -> Self {
        BaseField(E::zero())
    }

    fn is_zero(&self) -> Self::Boolean {
        self.is_eq(&BaseField::zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Circuit;

    #[test]
    fn test_zero() {
        let zero = <Circuit as Environment>::BaseField::zero();

        Circuit::scoped("Zero", || {
            assert_eq!(0, Circuit::num_constants());
            assert_eq!(1, Circuit::num_public());
            assert_eq!(0, Circuit::num_private());
            assert_eq!(0, Circuit::num_constraints());

            assert_eq!(0, Circuit::num_constants_in_scope());
            assert_eq!(0, Circuit::num_public_in_scope());
            assert_eq!(0, Circuit::num_private_in_scope());
            assert_eq!(0, Circuit::num_constraints_in_scope());

            let candidate = BaseField::<Circuit>::zero();
            assert_eq!(zero, candidate.eject_value());

            assert_eq!(0, Circuit::num_constants_in_scope());
            assert_eq!(0, Circuit::num_public_in_scope());
            assert_eq!(0, Circuit::num_private_in_scope());
            assert_eq!(0, Circuit::num_constraints_in_scope());

            assert_eq!(0, Circuit::num_constants());
            assert_eq!(1, Circuit::num_public());
            assert_eq!(0, Circuit::num_private());
            assert_eq!(0, Circuit::num_constraints());
        });
    }

    #[test]
    fn test_is_zero() {
        let candidate = BaseField::<Circuit>::zero();

        // Should equal 0.
        assert!(candidate.is_zero().eject_value());

        // Should not equal 1.
        assert!(!candidate.is_one().eject_value());
    }
}
