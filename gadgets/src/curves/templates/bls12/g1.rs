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

use std::fmt::Debug;

use snarkvm_curves::{
    templates::bls12::{Bls12Parameters, G1Prepared},
    traits::ProjectiveCurve,
    AffineCurve,
};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use crate::{
    bits::{Boolean, ToBytesGadget},
    curves::templates::bls12::AffineGadget,
    fields::FpGadget,
    integers::uint::UInt8,
    traits::{
        curves::GroupGadget,
        eq::{ConditionalEqGadget, EqGadget},
    },
    AllocGadget,
};
use std::borrow::Borrow;

pub type G1Gadget<P> = AffineGadget<
    <P as Bls12Parameters>::G1Parameters,
    <P as Bls12Parameters>::Fp,
    FpGadget<<P as Bls12Parameters>::Fp>,
>;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "G1Gadget<P>: Clone"),
    Debug(bound = "G1Gadget<P>: Debug"),
    PartialEq(bound = "G1Gadget<P>: Debug"),
    Eq(bound = "G1Gadget<P>: Debug")
)]
pub struct G1PreparedGadget<P: Bls12Parameters>(pub G1Gadget<P>);

impl<P: Bls12Parameters> G1PreparedGadget<P> {
    pub fn get_value(&self) -> Option<G1Prepared<P>> {
        Some(G1Prepared::from_affine(self.0.get_value().unwrap().into_affine()))
    }

    pub fn from_affine<CS: ConstraintSystem<P::Fp>>(_cs: CS, q: G1Gadget<P>) -> Result<Self, SynthesisError> {
        Ok(G1PreparedGadget(q))
    }
}

impl<P: Bls12Parameters> ToBytesGadget<P::Fp> for G1PreparedGadget<P> {
    #[inline]
    fn to_bytes<CS: ConstraintSystem<P::Fp>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        self.0.to_bytes(&mut cs.ns(|| "g_alpha to bytes"))
    }

    fn to_bytes_strict<CS: ConstraintSystem<P::Fp>>(&self, cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        self.to_bytes(cs)
    }
}

impl<P: Bls12Parameters> EqGadget<<P as Bls12Parameters>::Fp> for G1PreparedGadget<P> {}

impl<P: Bls12Parameters> ConditionalEqGadget<<P as Bls12Parameters>::Fp> for G1PreparedGadget<P> {
    fn conditional_enforce_equal<CS: ConstraintSystem<P::Fp>>(
        &self,
        cs: CS,
        other: &Self,
        condition: &Boolean,
    ) -> Result<(), SynthesisError> {
        self.0.conditional_enforce_equal(cs, &other.0, condition)
    }

    fn cost() -> usize {
        2 * <FpGadget<<P as Bls12Parameters>::Fp> as ConditionalEqGadget<<P as Bls12Parameters>::Fp>>::cost()
    }
}

impl<P: Bls12Parameters> AllocGadget<G1Prepared<P>, <P as Bls12Parameters>::Fp> for G1PreparedGadget<P> {
    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<G1Prepared<P>>,
        CS: ConstraintSystem<<P as Bls12Parameters>::Fp>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        value_gen().and_then(|elem| {
            let elem = elem.borrow();
            Ok(Self {
                0: G1Gadget::<P>::alloc(cs, || Ok(elem.0.into_projective()))?,
            })
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<G1Prepared<P>>,
        CS: ConstraintSystem<<P as Bls12Parameters>::Fp>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        value_gen().and_then(|elem| {
            let elem = elem.borrow();
            Ok(Self {
                0: G1Gadget::<P>::alloc_input(cs, || Ok(elem.0.into_projective()))?,
            })
        })
    }
}
