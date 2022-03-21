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

impl<E: Environment> Add<Field<E>> for Field<E> {
    type Output = Field<E>;

    fn add(self, other: Field<E>) -> Self::Output {
        self + &other
    }
}

impl<E: Environment> Add<Field<E>> for &Field<E> {
    type Output = Field<E>;

    fn add(self, other: Field<E>) -> Self::Output {
        self + &other
    }
}

impl<E: Environment> Add<&Field<E>> for Field<E> {
    type Output = Field<E>;

    fn add(self, other: &Field<E>) -> Self::Output {
        &self + other
    }
}

impl<E: Environment> Add<&Field<E>> for &Field<E> {
    type Output = Field<E>;

    fn add(self, other: &Field<E>) -> Self::Output {
        let mut result = self.clone();
        result += other;
        result
    }
}

impl<E: Environment> AddAssign<Field<E>> for Field<E> {
    fn add_assign(&mut self, other: Field<E>) {
        *self += &other;
    }
}

impl<E: Environment> AddAssign<&Field<E>> for Field<E> {
    fn add_assign(&mut self, other: &Field<E>) {
        *self = (&self.linear_combination + &other.linear_combination).into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_circuits_environment::Circuit;
    use snarkvm_utilities::{test_rng, UniformRand};

    const ITERATIONS: usize = 100_000;

    fn check_add(
        name: &str,
        expected: &<Circuit as Environment>::BaseField,
        a: &Field<Circuit>,
        b: &Field<Circuit>,
        num_constants: usize,
        num_public: usize,
        num_private: usize,
        num_constraints: usize,
    ) {
        Circuit::scope(name, || {
            let candidate = a + b;
            assert_eq!(*expected, candidate.eject_value(), "({} + {})", a.eject_value(), b.eject_value());
            assert_scope!(num_constants, num_public, num_private, num_constraints);
        });
    }

    fn check_add_assign(
        name: &str,
        expected: &<Circuit as Environment>::BaseField,
        a: &Field<Circuit>,
        b: &Field<Circuit>,
        num_constants: usize,
        num_public: usize,
        num_private: usize,
        num_constraints: usize,
    ) {
        Circuit::scope(name, || {
            let mut candidate = a.clone();
            candidate += b;
            assert_eq!(*expected, candidate.eject_value(), "({} + {})", a.eject_value(), b.eject_value());
            assert_scope!(num_constants, num_public, num_private, num_constraints);
        });
    }

    #[test]
    fn test_constant_plus_constant() {
        for i in 0..ITERATIONS {
            let first = UniformRand::rand(&mut test_rng());
            let second = UniformRand::rand(&mut test_rng());

            let expected = first + second;
            let a = Field::<Circuit>::new(Mode::Constant, first);
            let b = Field::<Circuit>::new(Mode::Constant, second);

            let name = format!("Add: a + b {}", i);
            check_add(&name, &expected, &a, &b, 0, 0, 0, 0);
            let name = format!("AddAssign: a + b {}", i);
            check_add_assign(&name, &expected, &a, &b, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_constant_plus_public() {
        for i in 0..ITERATIONS {
            let first = UniformRand::rand(&mut test_rng());
            let second = UniformRand::rand(&mut test_rng());

            let expected = first + second;
            let a = Field::<Circuit>::new(Mode::Constant, first);
            let b = Field::<Circuit>::new(Mode::Public, second);

            let name = format!("Add: a + b {}", i);
            check_add(&name, &expected, &a, &b, 0, 0, 0, 0);
            let name = format!("AddAssign: a + b {}", i);
            check_add_assign(&name, &expected, &a, &b, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_public_plus_constant() {
        for i in 0..ITERATIONS {
            let first = UniformRand::rand(&mut test_rng());
            let second = UniformRand::rand(&mut test_rng());

            let expected = first + second;
            let a = Field::<Circuit>::new(Mode::Public, first);
            let b = Field::<Circuit>::new(Mode::Constant, second);

            let name = format!("Add: a + b {}", i);
            check_add(&name, &expected, &a, &b, 0, 0, 0, 0);
            let name = format!("AddAssign: a + b {}", i);
            check_add_assign(&name, &expected, &a, &b, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_constant_plus_private() {
        for i in 0..ITERATIONS {
            let first = UniformRand::rand(&mut test_rng());
            let second = UniformRand::rand(&mut test_rng());

            let expected = first + second;
            let a = Field::<Circuit>::new(Mode::Constant, first);
            let b = Field::<Circuit>::new(Mode::Private, second);

            let name = format!("Add: a + b {}", i);
            check_add(&name, &expected, &a, &b, 0, 0, 0, 0);
            let name = format!("AddAssign: a + b {}", i);
            check_add_assign(&name, &expected, &a, &b, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_private_plus_constant() {
        for i in 0..ITERATIONS {
            let first = UniformRand::rand(&mut test_rng());
            let second = UniformRand::rand(&mut test_rng());

            let expected = first + second;
            let a = Field::<Circuit>::new(Mode::Private, first);
            let b = Field::<Circuit>::new(Mode::Constant, second);

            let name = format!("Add: a + b {}", i);
            check_add(&name, &expected, &a, &b, 0, 0, 0, 0);
            let name = format!("AddAssign: a + b {}", i);
            check_add_assign(&name, &expected, &a, &b, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_public_plus_public() {
        for i in 0..ITERATIONS {
            let first = UniformRand::rand(&mut test_rng());
            let second = UniformRand::rand(&mut test_rng());

            let expected = first + second;
            let a = Field::<Circuit>::new(Mode::Public, first);
            let b = Field::<Circuit>::new(Mode::Public, second);

            let name = format!("Add: a + b {}", i);
            check_add(&name, &expected, &a, &b, 0, 0, 0, 0);
            let name = format!("AddAssign: a + b {}", i);
            check_add_assign(&name, &expected, &a, &b, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_public_plus_private() {
        for i in 0..ITERATIONS {
            let first = UniformRand::rand(&mut test_rng());
            let second = UniformRand::rand(&mut test_rng());

            let expected = first + second;
            let a = Field::<Circuit>::new(Mode::Public, first);
            let b = Field::<Circuit>::new(Mode::Private, second);

            let name = format!("Add: a + b {}", i);
            check_add(&name, &expected, &a, &b, 0, 0, 0, 0);
            let name = format!("AddAssign: a + b {}", i);
            check_add_assign(&name, &expected, &a, &b, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_private_plus_public() {
        for i in 0..ITERATIONS {
            let first = UniformRand::rand(&mut test_rng());
            let second = UniformRand::rand(&mut test_rng());

            let expected = first + second;
            let a = Field::<Circuit>::new(Mode::Private, first);
            let b = Field::<Circuit>::new(Mode::Public, second);

            let name = format!("Add: a + b {}", i);
            check_add(&name, &expected, &a, &b, 0, 0, 0, 0);
            let name = format!("AddAssign: a + b {}", i);
            check_add_assign(&name, &expected, &a, &b, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_private_plus_private() {
        for i in 0..ITERATIONS {
            let first = UniformRand::rand(&mut test_rng());
            let second = UniformRand::rand(&mut test_rng());

            let expected = first + second;
            let a = Field::<Circuit>::new(Mode::Private, first);
            let b = Field::<Circuit>::new(Mode::Private, second);

            let name = format!("Add: a + b {}", i);
            check_add(&name, &expected, &a, &b, 0, 0, 0, 0);
            let name = format!("AddAssign: a + b {}", i);
            check_add_assign(&name, &expected, &a, &b, 0, 0, 0, 0);
        }
    }

    #[test]
    fn test_0_plus_0() {
        let zero = <Circuit as Environment>::BaseField::zero();

        let candidate = Field::<Circuit>::zero() + Field::zero();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::zero() + &Field::zero();
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, zero) + Field::new(Mode::Public, zero);
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, zero) + Field::new(Mode::Private, zero);
        assert_eq!(zero, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, zero) + Field::new(Mode::Private, zero);
        assert_eq!(zero, candidate.eject_value());
    }

    #[test]
    fn test_0_plus_1() {
        let zero = <Circuit as Environment>::BaseField::zero();
        let one = <Circuit as Environment>::BaseField::one();

        let candidate = Field::<Circuit>::zero() + Field::one();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::zero() + &Field::one();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::one() + Field::zero();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::one() + &Field::zero();
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) + Field::new(Mode::Public, zero);
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) + Field::new(Mode::Private, zero);
        assert_eq!(one, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Private, zero);
        assert_eq!(one, candidate.eject_value());
    }

    #[test]
    fn test_1_plus_1() {
        let one = <Circuit as Environment>::BaseField::one();
        let two = one + one;

        let candidate = Field::<Circuit>::one() + Field::one();
        assert_eq!(two, candidate.eject_value());

        let candidate = Field::<Circuit>::one() + &Field::one();
        assert_eq!(two, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) + Field::new(Mode::Public, one);
        assert_eq!(two, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Public, one);
        assert_eq!(two, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Private, one);
        assert_eq!(two, candidate.eject_value());
    }

    #[test]
    fn test_1_plus_2() {
        let one = <Circuit as Environment>::BaseField::one();
        let two = one + one;
        let three = two + one;

        let candidate_two = Field::<Circuit>::one() + Field::one();
        let candidate = candidate_two + Field::one();
        assert_eq!(three, candidate.eject_value());

        let candidate_two = Field::<Circuit>::one() + &Field::one();
        let candidate = candidate_two + &Field::one();
        assert_eq!(three, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Public, one) + Field::new(Mode::Public, two);
        assert_eq!(three, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Public, two);
        assert_eq!(three, candidate.eject_value());

        let candidate = Field::<Circuit>::new(Mode::Private, one) + Field::new(Mode::Private, two);
        assert_eq!(three, candidate.eject_value());
    }
}
