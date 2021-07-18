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

use crate::{
    curves::templates::bls12::{
        Bls12PairingGadget,
        G1Gadget as Bls12G1Gadget,
        G1PreparedGadget as Bls12G1PreparedGadget,
        G2Gadget as Bls12G2Gadget,
        G2PreparedGadget as Bls12G2PreparedGadget,
    },
    fields::{Fp12Gadget, Fp2Gadget, Fp6Gadget, FpGadget},
};
use snarkvm_curves::bls12_377::{Bls12_377Parameters, Fq, Fq12Parameters, Fq2Parameters, Fq6Parameters};

pub type FqGadget = FpGadget<Fq>;
pub type Fq2Gadget = Fp2Gadget<Fq2Parameters, Fq>;
pub type Fq6Gadget = Fp6Gadget<Fq6Parameters, Fq>;
pub type Fq12Gadget = Fp12Gadget<Fq12Parameters, Fq>;
pub type G1Gadget = Bls12G1Gadget<Bls12_377Parameters>;
pub type G1PreparedGadget = Bls12G1PreparedGadget<Bls12_377Parameters>;
pub type G2Gadget = Bls12G2Gadget<Bls12_377Parameters>;
pub type G2PreparedGadget = Bls12G2PreparedGadget<Bls12_377Parameters>;
pub type PairingGadget = Bls12PairingGadget<Bls12_377Parameters>;

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        bits::boolean::{AllocatedBit, Boolean},
        traits::{
            alloc::AllocGadget,
            curves::GroupGadget,
            eq::EqGadget,
            fields::FieldGadget,
            select::CondSelectGadget,
        },
    };
    use snarkvm_curves::{
        bls12_377::{Fq, Fr, G1Projective as G1, G2Projective as G2},
        traits::ProjectiveCurve,
        Group,
    };
    use snarkvm_fields::PrimeField;
    use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};
    use snarkvm_utilities::{bititerator::BitIteratorBE, rand::UniformRand};

    use core::ops::Mul;
    use rand::{
        SeedableRng,
        {self},
    };
    use rand_xorshift::XorShiftRng;

    #[test]
    fn bls12_g1_constraint_costs() {
        let mut cs = TestConstraintSystem::<Fq>::new();

        let bit = AllocatedBit::alloc(&mut cs.ns(|| "bool"), || Ok(true)).unwrap().into();

        let a: G1 = rand::random();
        let b: G1 = rand::random();
        let gadget_a = G1Gadget::alloc(&mut cs.ns(|| "a"), || Ok(a)).unwrap();
        let gadget_b = G1Gadget::alloc(&mut cs.ns(|| "b"), || Ok(b)).unwrap();
        let alloc_cost = cs.num_constraints();
        let _ = G1Gadget::conditionally_select(&mut cs.ns(|| "cond_select"), &bit, &gadget_a, &gadget_b).unwrap();
        let cond_select_cost = cs.num_constraints() - alloc_cost;

        let _ = gadget_a.add(&mut cs.ns(|| "ab"), &gadget_b).unwrap();
        let add_cost = cs.num_constraints() - cond_select_cost - alloc_cost;

        assert!(cs.is_satisfied());
        assert_eq!(cond_select_cost, <G1Gadget as CondSelectGadget<Fq>>::cost());
        assert_eq!(add_cost, G1Gadget::cost_of_add());
    }

    #[test]
    fn bls12_g2_constraint_costs() {
        let mut cs = TestConstraintSystem::<Fq>::new();

        let bit = AllocatedBit::alloc(&mut cs.ns(|| "bool"), || Ok(true)).unwrap().into();

        let a: G2 = rand::random();
        let b: G2 = rand::random();
        let gadget_a = G2Gadget::alloc(&mut cs.ns(|| "a"), || Ok(a)).unwrap();
        let gadget_b = G2Gadget::alloc(&mut cs.ns(|| "b"), || Ok(b)).unwrap();
        let alloc_cost = cs.num_constraints();
        let _ = G2Gadget::conditionally_select(&mut cs.ns(|| "cond_select"), &bit, &gadget_a, &gadget_b).unwrap();
        let cond_select_cost = cs.num_constraints() - alloc_cost;

        let _ = gadget_a.add(&mut cs.ns(|| "ab"), &gadget_b).unwrap();
        let add_cost = cs.num_constraints() - cond_select_cost - alloc_cost;

        assert!(cs.is_satisfied());
        assert_eq!(cond_select_cost, <G2Gadget as CondSelectGadget<Fq>>::cost());
        assert_eq!(add_cost, G2Gadget::cost_of_add());
    }

    #[test]
    fn bls12_g1_gadget_test() {
        let mut rng = XorShiftRng::seed_from_u64(1231275789u64);

        let mut cs = TestConstraintSystem::<Fq>::new();

        let a = G1::rand(&mut rng);
        let b = G1::rand(&mut rng);
        let a_affine = a.into_affine();
        let b_affine = b.into_affine();
        let mut gadget_a = G1Gadget::alloc(&mut cs.ns(|| "a"), || Ok(a)).unwrap();
        let gadget_b = G1Gadget::alloc(&mut cs.ns(|| "b"), || Ok(b)).unwrap();
        assert_eq!(gadget_a.x.get_value().unwrap(), a_affine.x);
        assert_eq!(gadget_a.y.get_value().unwrap(), a_affine.y);
        assert_eq!(gadget_b.x.get_value().unwrap(), b_affine.x);
        assert_eq!(gadget_b.y.get_value().unwrap(), b_affine.y);

        // Check addition
        let ab = a + b;
        let ab_affine = ab.into_affine();
        let gadget_ab = gadget_a.add(&mut cs.ns(|| "ab"), &gadget_b).unwrap();
        let gadget_ba = gadget_b.add(&mut cs.ns(|| "ba"), &gadget_a).unwrap();
        gadget_ba
            .enforce_equal(&mut cs.ns(|| "b + a == a + b?"), &gadget_ab)
            .unwrap();

        let ab_val = gadget_ab
            .get_value()
            .expect("Doubling should be successful")
            .into_affine();
        assert_eq!(ab_val, ab_affine, "Result of addition is unequal");

        // Check doubling
        let aa = a.double();
        let aa_affine = aa.into_affine();
        gadget_a.double_in_place(&mut cs.ns(|| "2a")).unwrap();
        let aa_val = gadget_a
            .get_value()
            .expect("Doubling should be successful")
            .into_affine();
        assert_eq!(aa_val, aa_affine, "Gadget and native values are unequal after double.");

        // Check mul_bits
        let scalar = Fr::rand(&mut rng);
        let native_result = aa.mul(scalar) + b;
        let native_result = native_result.into_affine();

        let mut scalar: Vec<bool> = BitIteratorBE::new(scalar.to_repr()).collect();
        // Get the scalar bits into little-endian form.
        scalar.reverse();
        let input = Vec::<Boolean>::alloc(cs.ns(|| "Input"), || Ok(scalar)).unwrap();
        let result = gadget_a
            .mul_bits(cs.ns(|| "mul_bits"), &gadget_b, input.into_iter())
            .unwrap();
        let result_val = result.get_value().unwrap().into_affine();
        assert_eq!(
            result_val, native_result,
            "gadget & native values are diff. after scalar mul"
        );

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied().unwrap());
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn bls12_g2_gadget_test() {
        let mut cs = TestConstraintSystem::<Fq>::new();

        let a: G2 = rand::random();
        let b: G2 = rand::random();
        let a_affine = a.into_affine();
        let b_affine = b.into_affine();

        let mut gadget_a = G2Gadget::alloc(&mut cs.ns(|| "a"), || Ok(a)).unwrap();
        let gadget_b = G2Gadget::alloc(&mut cs.ns(|| "b"), || Ok(b)).unwrap();
        assert_eq!(gadget_a.x.get_value().unwrap(), a_affine.x);
        assert_eq!(gadget_a.y.get_value().unwrap(), a_affine.y);
        assert_eq!(gadget_b.x.get_value().unwrap(), b_affine.x);
        assert_eq!(gadget_b.y.get_value().unwrap(), b_affine.y);

        let ab = a + b;
        let ab_affine = ab.into_affine();
        let gadget_ab = gadget_a.add(&mut cs.ns(|| "ab"), &gadget_b).unwrap();
        let gadget_ba = gadget_b.add(&mut cs.ns(|| "ba"), &gadget_a).unwrap();
        gadget_ba
            .enforce_equal(&mut cs.ns(|| "b + a == a + b?"), &gadget_ab)
            .unwrap();
        assert_eq!(gadget_ab.x.get_value().unwrap(), ab_affine.x);
        assert_eq!(gadget_ab.y.get_value().unwrap(), ab_affine.y);

        let aa = a.double();
        let aa_affine = aa.into_affine();
        gadget_a.double_in_place(&mut cs.ns(|| "2a")).unwrap();

        assert_eq!(gadget_a.x.get_value().unwrap(), aa_affine.x);
        assert_eq!(gadget_a.y.get_value().unwrap(), aa_affine.y);

        if !cs.is_satisfied() {
            println!("{:?}", cs.which_is_unsatisfied().unwrap());
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn bls12_g1_gadget_is_eq_test() {
        let mut cs = TestConstraintSystem::<Fq>::new();

        let a: G1 = rand::random();
        let b: G1 = a.clone();
        let c: G1 = rand::random();

        let a = G1Gadget::alloc(&mut cs.ns(|| "generate_a"), || Ok(a)).unwrap();
        let b = G1Gadget::alloc(&mut cs.ns(|| "generate_b"), || Ok(b)).unwrap();
        let c = G1Gadget::alloc(&mut cs.ns(|| "generate_c"), || Ok(c)).unwrap();

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

    #[test]
    fn bls12_g2_gadget_is_eq_test() {
        let mut cs = TestConstraintSystem::<Fq>::new();

        let a: G2 = rand::random();
        let b: G2 = a.clone();
        let c: G2 = rand::random();

        let a = G2Gadget::alloc(&mut cs.ns(|| "generate_a"), || Ok(a)).unwrap();
        let b = G2Gadget::alloc(&mut cs.ns(|| "generate_b"), || Ok(b)).unwrap();
        let c = G2Gadget::alloc(&mut cs.ns(|| "generate_c"), || Ok(c)).unwrap();

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
