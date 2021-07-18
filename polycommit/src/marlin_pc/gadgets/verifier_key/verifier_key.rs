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

use core::borrow::Borrow;

use snarkvm_curves::{AffineCurve, PairingEngine};
use snarkvm_fields::{PrimeField, ToConstraintField};
use snarkvm_gadgets::{
    bits::{Boolean, ToBytesGadget},
    fields::FpGadget,
    integers::uint::UInt8,
    traits::{
        alloc::AllocGadget,
        curves::{GroupGadget, PairingGadget},
        eq::EqGadget,
        fields::{FieldGadget, ToConstraintFieldGadget},
        select::CondSelectGadget,
    },
    PrepareGadget,
};
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};

use crate::{
    kzg10::VerifierKey as KZG10VerifierKey,
    marlin_pc::{data_structures::VerifierKey, gadgets::verifier_key::prepared_verifier_key::PreparedVerifierKeyVar},
    Vec,
};

/// Var for the verification key of the Marlin-KZG10 polynomial commitment scheme.
#[allow(clippy::type_complexity)]
pub struct VerifierKeyVar<
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
> {
    /// Generator of G1.
    pub g: PG::G1Gadget,
    /// The generator of G1 that is used for making a commitment hiding.
    pub gamma_g: PG::G1Gadget,
    /// Generator of G2.
    pub h: PG::G2Gadget,
    /// Generator of G1, times first monomial.
    pub beta_h: PG::G2Gadget,
    /// Used for the shift powers associated with different degree bounds.
    pub degree_bounds_and_shift_powers: Option<Vec<(usize, FpGadget<<BaseCurve as PairingEngine>::Fr>, PG::G1Gadget)>>,
}

impl<TargetCurve, BaseCurve, PG> VerifierKeyVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
{
    /// Find the appropriate shift for the degree bound.
    pub fn get_shift_power<CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>>(
        &self,
        mut cs: CS,
        bound: &FpGadget<<BaseCurve as PairingEngine>::Fr>,
    ) -> Option<PG::G1Gadget> {
        // Search the bound using PIR
        if self.degree_bounds_and_shift_powers.is_none() {
            None
        } else {
            let degree_bounds_and_shift_powers = self.degree_bounds_and_shift_powers.clone().unwrap();

            let mut pir_vector = vec![false; degree_bounds_and_shift_powers.len()];

            let desired_bound_value = bound.get_value().unwrap_or_default();

            for (i, (_, this_bound, _)) in degree_bounds_and_shift_powers.iter().enumerate() {
                if this_bound.get_value().unwrap_or_default().eq(&desired_bound_value) {
                    pir_vector[i] = true;
                    break;
                }
            }

            let mut pir_vector_gadgets = Vec::new();
            for (i, bit) in pir_vector.iter().enumerate() {
                pir_vector_gadgets.push(Boolean::alloc(cs.ns(|| format!("alloc_pir_{}", i)), || Ok(bit)).unwrap());
            }

            // Sum of the PIR values are equal to one
            let mut sum = FpGadget::<<BaseCurve as PairingEngine>::Fr>::zero(cs.ns(|| "zero")).unwrap();
            let one = FpGadget::<<BaseCurve as PairingEngine>::Fr>::one(cs.ns(|| "one")).unwrap();
            for (i, pir_gadget) in pir_vector_gadgets.iter().enumerate() {
                let temp = FpGadget::<<BaseCurve as PairingEngine>::Fr>::from_boolean(
                    cs.ns(|| format!("from_boolean_{}", i)),
                    pir_gadget.clone(),
                )
                .unwrap();

                sum = sum.add(cs.ns(|| format!("sum_add_pir{}", i)), &temp).unwrap();
            }
            sum.enforce_equal(cs.ns(|| "sum_enforce_equal"), &one).unwrap();

            // PIR the value
            let mut found_bound =
                FpGadget::<<BaseCurve as PairingEngine>::Fr>::zero(cs.ns(|| "found_bound_zero")).unwrap();

            let mut found_shift_power = PG::G1Gadget::zero(cs.ns(|| "found_shift_power_zero")).unwrap();

            for (i, (pir_gadget, (_, degree, shift_power))) in pir_vector_gadgets
                .iter()
                .zip(degree_bounds_and_shift_powers.iter())
                .enumerate()
            {
                found_bound = FpGadget::<<BaseCurve as PairingEngine>::Fr>::conditionally_select(
                    cs.ns(|| format!("found_bound_coond_select{}", i)),
                    pir_gadget,
                    degree,
                    &found_bound,
                )
                .unwrap();

                found_shift_power = PG::G1Gadget::conditionally_select(
                    cs.ns(|| format!("found_shift_conditionally_select+{}", i)),
                    pir_gadget,
                    shift_power,
                    &found_shift_power,
                )
                .unwrap();
            }

            found_bound
                .enforce_equal(cs.ns(|| "found_bound_enforce_equal"), &bound)
                .unwrap();

            Some(found_shift_power)
        }
    }
}

impl<TargetCurve, BaseCurve, PG> Clone for VerifierKeyVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            g: self.g.clone(),
            gamma_g: self.gamma_g.clone(),
            h: self.h.clone(),
            beta_h: self.beta_h.clone(),
            degree_bounds_and_shift_powers: self.degree_bounds_and_shift_powers.clone(),
        }
    }
}

impl<TargetCurve, BaseCurve, PG> AllocGadget<VerifierKey<TargetCurve>, <BaseCurve as PairingEngine>::Fr>
    for VerifierKeyVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
{
    fn alloc_constant<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<VerifierKey<TargetCurve>>,
        CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let vk_orig = value_gen()?.borrow().clone();

        let VerifierKey {
            vk,
            degree_bounds_and_shift_powers,
            ..
        } = vk_orig;

        let degree_bounds_and_shift_powers = degree_bounds_and_shift_powers.map(|vec| {
            vec.iter()
                .enumerate()
                .map(|(i, (s, g))| {
                    (
                        *s,
                        FpGadget::<<BaseCurve as PairingEngine>::Fr>::alloc_constant(
                            cs.ns(|| format!("degree bound_{}", i)),
                            || Ok(<<BaseCurve as PairingEngine>::Fr as From<u128>>::from(*s as u128)),
                        )
                        .unwrap(),
                        PG::G1Gadget::alloc_constant(cs.ns(|| format!("pow_{}", i)), || Ok(g.into_projective()))
                            .unwrap(),
                    )
                })
                .collect()
        });

        let KZG10VerifierKey {
            g, gamma_g, h, beta_h, ..
        } = vk;

        let g = PG::G1Gadget::alloc_constant(cs.ns(|| "g"), || Ok(g.into_projective()))?;
        let gamma_g = PG::G1Gadget::alloc_constant(cs.ns(|| "gamma_g"), || Ok(gamma_g.into_projective()))?;
        let h = PG::G2Gadget::alloc_constant(cs.ns(|| "h"), || Ok(h.into_projective()))?;
        let beta_h = PG::G2Gadget::alloc_constant(cs.ns(|| "beta_h"), || Ok(beta_h.into_projective()))?;

        Ok(Self {
            g,
            gamma_g,
            h,
            beta_h,
            degree_bounds_and_shift_powers,
        })
    }

    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<VerifierKey<TargetCurve>>,
        CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let vk_orig = value_gen()?.borrow().clone();

        let VerifierKey {
            vk,
            degree_bounds_and_shift_powers,
            ..
        } = vk_orig;

        let degree_bounds_and_shift_powers = degree_bounds_and_shift_powers.map(|vec| {
            vec.iter()
                .enumerate()
                .map(|(i, (s, g))| {
                    (
                        *s,
                        FpGadget::<<BaseCurve as PairingEngine>::Fr>::alloc(
                            cs.ns(|| format!("degree bound_{}", i)),
                            || Ok(<<BaseCurve as PairingEngine>::Fr as From<u128>>::from(*s as u128)),
                        )
                        .unwrap(),
                        PG::G1Gadget::alloc(cs.ns(|| format!("pow_{}", i)), || Ok(g.into_projective())).unwrap(),
                    )
                })
                .collect()
        });

        let KZG10VerifierKey {
            g, gamma_g, h, beta_h, ..
        } = vk;

        let g = PG::G1Gadget::alloc(cs.ns(|| "g"), || Ok(g.into_projective()))?;
        let gamma_g = PG::G1Gadget::alloc(cs.ns(|| "gamma_g"), || Ok(gamma_g.into_projective()))?;
        let h = PG::G2Gadget::alloc(cs.ns(|| "h"), || Ok(h.into_projective()))?;
        let beta_h = PG::G2Gadget::alloc(cs.ns(|| "beta_h"), || Ok(beta_h.into_projective()))?;

        Ok(Self {
            g,
            gamma_g,
            h,
            beta_h,
            degree_bounds_and_shift_powers,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<VerifierKey<TargetCurve>>,
        CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let vk_orig = value_gen()?.borrow().clone();

        let VerifierKey {
            vk,
            degree_bounds_and_shift_powers,
            ..
        } = vk_orig;

        let degree_bounds_and_shift_powers = degree_bounds_and_shift_powers.map(|vec| {
            vec.iter()
                .enumerate()
                .map(|(i, (s, g))| {
                    (
                        *s,
                        FpGadget::<<BaseCurve as PairingEngine>::Fr>::alloc_input(
                            cs.ns(|| format!("degree bound_{}", i)),
                            || Ok(<<BaseCurve as PairingEngine>::Fr as From<u128>>::from(*s as u128)),
                        )
                        .unwrap(),
                        PG::G1Gadget::alloc_input(cs.ns(|| format!("pow_{}", i)), || Ok(g.into_projective())).unwrap(),
                    )
                })
                .collect()
        });

        let KZG10VerifierKey {
            g, gamma_g, h, beta_h, ..
        } = vk;

        let g = PG::G1Gadget::alloc_input(cs.ns(|| "g"), || Ok(g.into_projective()))?;
        let gamma_g = PG::G1Gadget::alloc_constant(cs.ns(|| "gamma_g"), || Ok(gamma_g.into_projective()))?;
        let h = PG::G2Gadget::alloc_input(cs.ns(|| "h"), || Ok(h.into_projective()))?;
        let beta_h = PG::G2Gadget::alloc_input(cs.ns(|| "beta_h"), || Ok(beta_h.into_projective()))?;

        Ok(Self {
            g,
            gamma_g,
            h,
            beta_h,
            degree_bounds_and_shift_powers,
        })
    }
}

impl<TargetCurve, BaseCurve, PG> ToBytesGadget<<BaseCurve as PairingEngine>::Fr>
    for VerifierKeyVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
{
    fn to_bytes<CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<UInt8>, SynthesisError> {
        let mut bytes = Vec::new();

        bytes.extend_from_slice(&self.g.to_bytes(cs.ns(|| "g_to_bytes"))?);
        bytes.extend_from_slice(&self.gamma_g.to_bytes(cs.ns(|| "gamma_g_to_bytes"))?);
        bytes.extend_from_slice(&self.h.to_bytes(cs.ns(|| "h_to_bytes"))?);
        bytes.extend_from_slice(&self.beta_h.to_bytes(cs.ns(|| "beta_h_to_bytes"))?);

        if self.degree_bounds_and_shift_powers.is_some() {
            let degree_bounds_and_shift_powers = self.degree_bounds_and_shift_powers.as_ref().unwrap();
            for (i, (_, degree_bound, shift_power)) in degree_bounds_and_shift_powers.iter().enumerate() {
                bytes.extend_from_slice(&degree_bound.to_bytes(cs.ns(|| format!("degree_bound_to_bytes_{}", i)))?);
                bytes.extend_from_slice(&shift_power.to_bytes(cs.ns(|| format!("shift_power_to_bytes_{}", i)))?);
            }
        }

        Ok(bytes)
    }

    fn to_bytes_strict<CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>>(
        &self,
        cs: CS,
    ) -> Result<Vec<UInt8>, SynthesisError> {
        self.to_bytes(cs)
    }
}

impl<TargetCurve, BaseCurve, PG>
    PrepareGadget<PreparedVerifierKeyVar<TargetCurve, BaseCurve, PG>, <BaseCurve as PairingEngine>::Fr>
    for VerifierKeyVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    fn prepare<CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>>(
        &self,
        mut cs: CS,
    ) -> Result<PreparedVerifierKeyVar<TargetCurve, BaseCurve, PG>, SynthesisError> {
        let supported_bits = <<TargetCurve as PairingEngine>::Fr as PrimeField>::size_in_bits();
        let mut prepared_g = Vec::<PG::G1Gadget>::new();
        let mut prepared_gamma_g = Vec::<PG::G1Gadget>::new();

        let mut g: PG::G1Gadget = self.g.clone();
        for i in 0..supported_bits {
            prepared_g.push(g.clone());
            g.double_in_place(cs.ns(|| format!("double_in_place_{}", i)))?;
        }

        let mut gamma_g: PG::G1Gadget = self.gamma_g.clone();
        for i in 0..supported_bits {
            prepared_gamma_g.push(gamma_g.clone());
            gamma_g.double_in_place(cs.ns(|| format!("double_in_place_{}_gamma_g", i)))?;
        }

        let prepared_h = PG::prepare_g2(cs.ns(|| "prepared_h"), self.h.clone())?;
        let prepared_beta_h = PG::prepare_g2(cs.ns(|| "prepared_beta_h"), self.beta_h.clone())?;

        let prepared_degree_bounds_and_shift_powers = if self.degree_bounds_and_shift_powers.is_some() {
            let mut res = Vec::<(usize, FpGadget<<BaseCurve as PairingEngine>::Fr>, Vec<PG::G1Gadget>)>::new();

            for (d, d_gadget, shift_power) in self.degree_bounds_and_shift_powers.as_ref().unwrap().iter() {
                res.push((*d, (*d_gadget).clone(), vec![shift_power.clone()]));
            }

            Some(res)
        } else {
            None
        };

        Ok(PreparedVerifierKeyVar::<TargetCurve, BaseCurve, PG> {
            prepared_g,
            prepared_gamma_g,
            prepared_h,
            prepared_beta_h,
            prepared_degree_bounds_and_shift_powers,
            constant_allocation: false,
            origin_vk: Some(self.clone()),
        })
    }
}

impl<TargetCurve, BaseCurve, PG> ToConstraintFieldGadget<<BaseCurve as PairingEngine>::Fr>
    for VerifierKeyVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    <BaseCurve as PairingEngine>::Fr: PrimeField,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    PG::G1Gadget: ToConstraintFieldGadget<<BaseCurve as PairingEngine>::Fr>,
    PG::G2Gadget: ToConstraintFieldGadget<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    fn to_constraint_field<CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<FpGadget<<BaseCurve as PairingEngine>::Fr>>, SynthesisError> {
        let mut res = Vec::new();

        let mut g_gadget = self.g.to_constraint_field(cs.ns(|| "g_to_constraint_field"))?;
        let mut gamma_g_gadget = self
            .gamma_g
            .to_constraint_field(cs.ns(|| "gamma_g_to_constraint_field"))?;
        let mut h_gadget = self.h.to_constraint_field(cs.ns(|| "h_to_constraint_field"))?;
        let mut beta_h_gadget = self
            .beta_h
            .to_constraint_field(cs.ns(|| "beta_h_to_constraint_field"))?;

        res.append(&mut g_gadget);
        res.append(&mut gamma_g_gadget);
        res.append(&mut h_gadget);
        res.append(&mut beta_h_gadget);

        if self.degree_bounds_and_shift_powers.as_ref().is_some() {
            let list = self.degree_bounds_and_shift_powers.as_ref().unwrap();
            for (i, (_, d_gadget, shift_power)) in list.iter().enumerate() {
                let mut d_elems = vec![d_gadget.clone()];
                let mut shift_power_elems =
                    shift_power.to_constraint_field(cs.ns(|| format!("shifted_power_to_constraint_field_{}", i)))?;

                res.append(&mut d_elems);
                res.append(&mut shift_power_elems);
            }
        }

        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;

    use snarkvm_curves::{
        bls12_377::{Bls12_377, Fq},
        bw6_761::BW6_761,
        ProjectiveCurve,
    };
    use snarkvm_fields::PrimeField;
    use snarkvm_gadgets::curves::bls12_377::PairingGadget as Bls12_377PairingGadget;
    use snarkvm_r1cs::TestConstraintSystem;
    use snarkvm_utilities::rand::test_rng;

    use crate::{marlin_pc::MarlinKZG10, PolynomialCommitment};

    use super::*;

    type PC = MarlinKZG10<Bls12_377>;
    type PG = Bls12_377PairingGadget;
    type BaseCurve = BW6_761;

    const MAX_DEGREE: usize = 383;
    const SUPPORTED_DEGREE: usize = 300;
    const SUPPORTED_HIDING_BOUND: usize = 1;

    // TODO (raychu86): Implement `test_to_bytes` and `test_to_constraint_field`.

    #[test]
    fn test_alloc() {
        let rng = &mut test_rng();

        let cs = &mut TestConstraintSystem::<Fq>::new();

        // Construct the universal params.
        let pp = PC::setup(MAX_DEGREE, rng).unwrap();

        // Construct the verifying key.
        let (_committer_key, vk) = PC::trim(&pp, SUPPORTED_DEGREE, SUPPORTED_HIDING_BOUND, None).unwrap();

        // Allocate the vk gadget.
        let vk_gadget = VerifierKeyVar::<_, BaseCurve, PG>::alloc(cs.ns(|| "alloc_vk"), || Ok(vk.clone())).unwrap();

        // Naive value comparison.
        assert_eq!(vk.vk.g, vk_gadget.g.get_value().unwrap().into_affine());
        assert_eq!(vk.vk.h, vk_gadget.h.get_value().unwrap().into_affine());
        assert_eq!(vk.vk.beta_h, vk_gadget.beta_h.get_value().unwrap().into_affine());

        // Gadget enforcement checks.
        let g_gadget =
            <PG as PairingGadget<_, _>>::G1Gadget::alloc(cs.ns(|| "alloc_native_g"), || Ok(vk.vk.g.into_projective()))
                .unwrap();
        let h_gadget =
            <PG as PairingGadget<_, _>>::G2Gadget::alloc(cs.ns(|| "alloc_native_h"), || Ok(vk.vk.h.into_projective()))
                .unwrap();
        let beta_h_gadget = <PG as PairingGadget<_, _>>::G2Gadget::alloc(cs.ns(|| "alloc_native_beta_h"), || {
            Ok(vk.vk.beta_h.into_projective())
        })
        .unwrap();

        g_gadget
            .enforce_equal(cs.ns(|| "enforce_equals_g"), &vk_gadget.g)
            .unwrap();
        h_gadget
            .enforce_equal(cs.ns(|| "enforce_equals_h"), &vk_gadget.h)
            .unwrap();
        beta_h_gadget
            .enforce_equal(cs.ns(|| "enforce_equals_beta_h"), &vk_gadget.beta_h)
            .unwrap();

        // Native check that degree bounds are equivalent.

        assert_eq!(
            vk.degree_bounds_and_shift_powers.is_some(),
            vk_gadget.degree_bounds_and_shift_powers.is_some()
        );

        if let (Some(native), Some(gadget)) = (
            &vk.degree_bounds_and_shift_powers,
            &vk_gadget.degree_bounds_and_shift_powers,
        ) {
            // Check each degree bound and shift power.
            for (i, ((native_degree_bounds, native_shift_power), (degree_bounds, _fp_gadget, shift_power))) in
                native.iter().zip(gadget).enumerate()
            {
                assert_eq!(native_degree_bounds, degree_bounds);
                assert_eq!(native_shift_power, &shift_power.get_value().unwrap().into_affine());

                let shift_power_gadget = <PG as PairingGadget<_, _>>::G1Gadget::alloc(
                    cs.ns(|| format!("alloc_native_shift_power_{}", i)),
                    || Ok(native_shift_power.into_projective()),
                )
                .unwrap();

                shift_power_gadget
                    .enforce_equal(cs.ns(|| format!("enforce_equals_shift_power_{}", i)), &shift_power)
                    .unwrap();
            }
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_get_shift_power() {
        let rng = &mut test_rng();

        let cs = &mut TestConstraintSystem::<Fq>::new();

        // Construct the universal params.
        let pp = PC::setup(MAX_DEGREE, rng).unwrap();

        // Establish the bound
        let bound = rng.gen_range(1..=SUPPORTED_DEGREE);

        let bound_field = <BaseCurve as PairingEngine>::Fr::from_repr(
            <<BaseCurve as PairingEngine>::Fr as PrimeField>::BigInteger::from(bound as u64),
        )
        .unwrap();
        let bound_gadget = FpGadget::alloc(cs.ns(|| "alloc_bound"), || Ok(bound_field)).unwrap();

        // Construct the verifying key.
        let (_committer_key, vk) = PC::trim(&pp, SUPPORTED_DEGREE, SUPPORTED_HIDING_BOUND, Some(&vec![bound])).unwrap();

        // Allocate the vk gadget.
        let vk_gadget = VerifierKeyVar::<_, BaseCurve, PG>::alloc(cs.ns(|| "alloc_vk"), || Ok(vk.clone())).unwrap();

        // Fetch the shift power
        let shift_power = vk.get_shift_power(bound).unwrap();
        let expected_shift_power =
            <PG as PairingGadget<_, _>>::G1Gadget::alloc(cs.ns(|| "alloc_native_shift_power"), || {
                Ok(shift_power.into_projective())
            })
            .unwrap();

        let shift_power_gadget = vk_gadget
            .get_shift_power(cs.ns(|| "get_shift_power"), &bound_gadget)
            .unwrap();

        shift_power_gadget
            .enforce_equal(cs.ns(|| "enforce_equals_shift_power"), &expected_shift_power)
            .unwrap();

        assert!(cs.is_satisfied());
    }

    // #[test]
    // fn test_to_bytes() {
    //     let rng = &mut test_rng();
    //
    //     let cs = &mut TestConstraintSystem::<Fq>::new();
    //
    //     // Construct the universal params.
    //     let pp = PC::setup(MAX_DEGREE, rng).unwrap();
    //
    //     // Construct the verifying key.
    //     let (_committer_key, vk) = PC::trim(&pp, SUPPORTED_DEGREE, SUPPORTED_HIDING_BOUND, None).unwrap();
    //
    //     // Allocate the vk gadget.
    //     let vk_gadget = VerifierKeyVar::<_, BaseCurve, PG>::alloc(cs.ns(|| "alloc_vk"), || Ok(vk.clone())).unwrap();
    //     let _vk_gadget_bytes = vk_gadget.to_bytes(cs.ns(|| "to_bytes")).unwrap();
    //
    //     // TODO (raychu86): Compare with native impl. The native impl serializes the prepared elements as well which the gadgets do not include.
    // }

    // #[test]
    // fn test_to_constraint_field() {
    // let rng = &mut test_rng();
    //
    // let cs = &mut TestConstraintSystem::<Fq>::new();
    //
    // // Construct the universal params.
    // let pp = PC::setup(MAX_DEGREE, rng).unwrap();
    //
    // // Construct the verifying key.
    // let (_committer_key, vk) = PC::trim(&pp, SUPPORTED_DEGREE, SUPPORTED_HIDING_BOUND, None).unwrap();
    //
    // // Allocate the vk gadget.
    // let vk_gadget = VerifierKeyVar::<_, BaseCurve, PG>::alloc(cs.ns(|| "alloc_vk"), || Ok(vk.clone())).unwrap();
    //
    // let vk_field_elements = vk.to_field_elements().unwrap();
    // let vk_field_gadgets = vk_gadget.to_constraint_field().unwrap();

    // TODO (raychu86): Fix `to_constraint_field` execution on the gadget.
    // }
}
