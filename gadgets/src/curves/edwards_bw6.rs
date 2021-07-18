// Copyright (C) 2019-2021 Aleo Systems Inc.
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

use crate::{curves::templates::twisted_edwards::AffineGadget, fields::FpGadget};
use snarkvm_curves::edwards_bw6::{EdwardsParameters, Fq};

pub type FqGadget = FpGadget<Fq>;

pub type EdwardsBW6Gadget = AffineGadget<EdwardsParameters, Fq, FqGadget>;

#[cfg(test)]
mod test {
    use super::EdwardsBW6Gadget;
    use crate::{
        curves::{
            templates::twisted_edwards::test::{edwards_constraint_costs, edwards_test},
            tests_group::group_test,
        },
        traits::{alloc::AllocGadget, eq::EqGadget},
        Boolean,
    };
    use snarkvm_curves::edwards_bw6::{EdwardsParameters, EdwardsProjective, Fq};
    use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};

    #[test]
    fn edwards_constraint_costs_test() {
        let mut cs = TestConstraintSystem::<Fq>::new();
        edwards_constraint_costs::<_, EdwardsParameters, EdwardsBW6Gadget, _>(&mut cs);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn edwards_bw6_gadget_test() {
        let mut cs = TestConstraintSystem::<Fq>::new();
        edwards_test::<_, EdwardsParameters, EdwardsBW6Gadget, _>(&mut cs);
        assert!(cs.is_satisfied());
    }

    #[test]
    fn edwards_bw6_group_gadgets_test() {
        let mut cs = TestConstraintSystem::<Fq>::new();

        let a: EdwardsProjective = rand::random();
        let b: EdwardsProjective = rand::random();

        let a = EdwardsBW6Gadget::alloc(&mut cs.ns(|| "generate_a"), || Ok(a)).unwrap();
        let b = EdwardsBW6Gadget::alloc(&mut cs.ns(|| "generate_b"), || Ok(b)).unwrap();
        group_test::<_, EdwardsProjective, _, _>(&mut cs.ns(|| "GroupTest(a, b)"), a, b);
    }

    #[test]
    fn edwards_bw6_group_gadgets_is_eq_test() {
        let mut cs = TestConstraintSystem::<Fq>::new();

        let a: EdwardsProjective = rand::random();
        let b: EdwardsProjective = a.clone();
        let c: EdwardsProjective = rand::random();

        let a = EdwardsBW6Gadget::alloc(&mut cs.ns(|| "generate_a"), || Ok(a)).unwrap();
        let b = EdwardsBW6Gadget::alloc(&mut cs.ns(|| "generate_b"), || Ok(b)).unwrap();
        let c = EdwardsBW6Gadget::alloc(&mut cs.ns(|| "generate_c"), || Ok(c)).unwrap();

        let a_is_eq_b = a.is_eq(cs.ns(|| "a_is_eq_b"), &b).unwrap();
        let a_is_eq_c = a.is_eq(cs.ns(|| "a_is_eq_c"), &c).unwrap();

        a_is_eq_b
            .enforce_equal(cs.ns(|| " a_is_eq_b is true"), &Boolean::constant(true))
            .unwrap();
        a_is_eq_c
            .enforce_equal(cs.ns(|| " a_is_eq_c is false"), &Boolean::constant(false))
            .unwrap();

        assert!(cs.is_satisfied());
    }
}
