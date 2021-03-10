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
    curves::templates::bls12::AffineGadget,
    fields::Fp2Gadget,
    traits::{
        curves::GroupGadget,
        fields::FieldGadget,
        utilities::{alloc::AllocGadget, eq::NEqGadget, uint::UInt8, ToBytesGadget},
    },
};
use snarkvm_curves::templates::bls12::{Bls12Parameters, G2Prepared, TwistType};
use snarkvm_fields::{batch_inversion, Field, One};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};
use snarkvm_utilities::bititerator::BitIteratorBE;

use std::{borrow::Borrow, fmt::Debug};

pub type G2Gadget<P> = AffineGadget<<P as Bls12Parameters>::G2Parameters, <P as Bls12Parameters>::Fp, Fp2G<P>>;

type Fp2G<P> = Fp2Gadget<<P as Bls12Parameters>::Fp2Params, <P as Bls12Parameters>::Fp>;
type LCoeff<P> = (Fp2G<P>, Fp2G<P>);
#[derive(Derivative)]
#[derivative(
    Clone(bound = "Fp2Gadget<P::Fp2Params, P::Fp>: Clone"),
    Debug(bound = "Fp2Gadget<P::Fp2Params, P::Fp>: Debug")
)]
pub struct G2PreparedGadget<P: Bls12Parameters> {
    pub ell_coeffs: Vec<LCoeff<P>>,
}

impl<P: Bls12Parameters> ToBytesGadget<P::Fp> for G2PreparedGadget<P> {
    #[inline]
    fn to_bytes<CS: ConstraintSystem<P::Fp>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        let mut bytes = Vec::new();
        for (i, coeffs) in self.ell_coeffs.iter().enumerate() {
            let mut cs = cs.ns(|| format!("Iteration {}", i));
            bytes.extend_from_slice(&coeffs.0.to_bytes(&mut cs.ns(|| "c0"))?);
            bytes.extend_from_slice(&coeffs.1.to_bytes(&mut cs.ns(|| "c1"))?);
        }
        Ok(bytes)
    }

    fn to_bytes_strict<CS: ConstraintSystem<P::Fp>>(&self, cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        self.to_bytes(cs)
    }
}

impl<P: Bls12Parameters> G2PreparedGadget<P> {
    pub fn from_affine<CS: ConstraintSystem<P::Fp>>(mut cs: CS, q: G2Gadget<P>) -> Result<Self, SynthesisError> {
        let two_inv = P::Fp::one().double().inverse().unwrap();
        let zero = G2Gadget::<P>::zero(cs.ns(|| "zero"))?;
        q.enforce_not_equal(cs.ns(|| "enforce not zero"), &zero)?;
        let bit_iterator = BitIteratorBE::new(P::X);
        let mut ell_coeffs = Vec::with_capacity(bit_iterator.len());
        let mut r = q.clone();

        for (j, i) in bit_iterator.skip(1).enumerate() {
            let mut cs = cs.ns(|| format!("Iteration {}", j));
            ell_coeffs.push(Self::double(cs.ns(|| "double"), &mut r, &two_inv)?);

            if i {
                ell_coeffs.push(Self::add(cs.ns(|| "add"), &mut r, &q)?);
            }
        }

        Ok(Self { ell_coeffs })
    }

    #[allow(clippy::many_single_char_names)]
    fn double<CS: ConstraintSystem<P::Fp>>(
        mut cs: CS,
        r: &mut G2Gadget<P>,
        two_inv: &P::Fp,
    ) -> Result<LCoeff<P>, SynthesisError> {
        let a = r.y.inverse(cs.ns(|| "Inverse"))?;
        let mut b = r.x.square(cs.ns(|| "square x"))?;
        let b_tmp = b.clone();
        b.mul_by_fp_constant_in_place(cs.ns(|| "mul by two_inv"), two_inv)?;
        b.add_in_place(cs.ns(|| "compute b"), &b_tmp)?;

        let c = a.mul(cs.ns(|| "compute c"), &b)?;
        let d = r.x.double(cs.ns(|| "compute d"))?;
        let x3 = c.square(cs.ns(|| "c^2"))?.sub(cs.ns(|| "sub d"), &d)?;
        let e = c.mul(cs.ns(|| "c*r.x"), &r.x)?.sub(cs.ns(|| "sub r.y"), &r.y)?;
        let c_x3 = c.mul(cs.ns(|| "c*x_3"), &x3)?;
        let y3 = e.sub(cs.ns(|| "e = c * x3"), &c_x3)?;
        let mut f = c;
        f.negate_in_place(cs.ns(|| "c = -c"))?;
        r.x = x3;
        r.y = y3;
        match P::TWIST_TYPE {
            TwistType::M => Ok((e, f)),
            TwistType::D => Ok((f, e)),
        }
    }

    #[allow(clippy::many_single_char_names)]
    fn add<CS: ConstraintSystem<P::Fp>>(
        mut cs: CS,
        r: &mut G2Gadget<P>,
        q: &G2Gadget<P>,
    ) -> Result<LCoeff<P>, SynthesisError> {
        let a = q.x.sub(cs.ns(|| "q.x - r.x"), &r.x)?.inverse(cs.ns(|| "calc a"))?;
        let b = q.y.sub(cs.ns(|| "q.y - r.y"), &r.y)?;
        let c = a.mul(cs.ns(|| "compute c"), &b)?;
        let d = r.x.add(cs.ns(|| "r.x + q.x"), &q.x)?;
        let x3 = c.square(cs.ns(|| "c^2"))?.sub(cs.ns(|| "sub d"), &d)?;

        let e =
            r.x.sub(cs.ns(|| "r.x - x3"), &x3)?
                .mul(cs.ns(|| "c * (r.x - x3)"), &c)?;
        let y3 = e.sub(cs.ns(|| "calc y3"), &r.y)?;
        let g = c.mul(cs.ns(|| "c*r.x"), &r.x)?.sub(cs.ns(|| "calc g"), &r.y)?;
        let mut f = c;
        f.negate_in_place(cs.ns(|| "c = -c"))?;
        r.x = x3;
        r.y = y3;
        match P::TWIST_TYPE {
            TwistType::M => Ok((g, f)),
            TwistType::D => Ok((f, g)),
        }
    }
}

impl<P: Bls12Parameters> AllocGadget<G2Prepared<P>, <P as Bls12Parameters>::Fp> for G2PreparedGadget<P> {
    fn alloc_constant<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<G2Prepared<P>>,
        CS: ConstraintSystem<<P as Bls12Parameters>::Fp>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let g2_prep = value_gen().map(|b| {
            let projective_coeffs = &b.borrow().ell_coeffs;
            let mut z_s = projective_coeffs.iter().map(|(_, _, z)| *z).collect::<Vec<_>>();
            batch_inversion(&mut z_s);
            projective_coeffs
                .iter()
                .zip(z_s)
                .map(|((x, y, _), z_inv)| (*x * &z_inv, *y * &z_inv))
                .collect::<Vec<_>>()
        })?;

        let mut l = Vec::new();
        let mut r = Vec::new();

        for (i, (l_elem, _)) in g2_prep.iter().enumerate() {
            let elem = Fp2G::<P>::alloc_constant(cs.ns(|| format!("l_{}", i)), || Ok(l_elem))?;
            l.push(elem);
        }

        for (i, (_, r_elem)) in g2_prep.iter().enumerate() {
            let elem = Fp2G::<P>::alloc_constant(cs.ns(|| format!("r_{}", i)), || Ok(r_elem))?;
            r.push(elem);
        }

        let ell_coeffs = l.into_iter().zip(r).collect();
        Ok(Self { ell_coeffs })
    }

    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<G2Prepared<P>>,
        CS: ConstraintSystem<<P as Bls12Parameters>::Fp>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let g2_prep = value_gen().map(|b| {
            let projective_coeffs = &b.borrow().ell_coeffs;
            let mut z_s = projective_coeffs.iter().map(|(_, _, z)| *z).collect::<Vec<_>>();
            batch_inversion(&mut z_s);
            projective_coeffs
                .iter()
                .zip(z_s)
                .map(|((x, y, _), z_inv)| (*x * &z_inv, *y * &z_inv))
                .collect::<Vec<_>>()
        })?;

        let mut l = Vec::new();
        let mut r = Vec::new();

        for (i, (l_elem, _)) in g2_prep.iter().enumerate() {
            let elem = Fp2G::<P>::alloc(cs.ns(|| format!("l_{}", i)), || Ok(l_elem))?;
            l.push(elem);
        }

        for (i, (_, r_elem)) in g2_prep.iter().enumerate() {
            let elem = Fp2G::<P>::alloc(cs.ns(|| format!("r_{}", i)), || Ok(r_elem))?;
            r.push(elem);
        }

        let ell_coeffs = l.into_iter().zip(r).collect();
        Ok(Self { ell_coeffs })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<G2Prepared<P>>,
        CS: ConstraintSystem<<P as Bls12Parameters>::Fp>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let g2_prep = value_gen().map(|b| {
            let projective_coeffs = &b.borrow().ell_coeffs;
            let mut z_s = projective_coeffs.iter().map(|(_, _, z)| *z).collect::<Vec<_>>();
            batch_inversion(&mut z_s);
            projective_coeffs
                .iter()
                .zip(z_s)
                .map(|((x, y, _), z_inv)| (*x * &z_inv, *y * &z_inv))
                .collect::<Vec<_>>()
        })?;

        let mut l = Vec::new();
        let mut r = Vec::new();

        for (i, (l_elem, _)) in g2_prep.iter().enumerate() {
            let elem = Fp2G::<P>::alloc_input(cs.ns(|| format!("l_{}", i)), || Ok(l_elem))?;
            l.push(elem);
        }

        for (i, (_, r_elem)) in g2_prep.iter().enumerate() {
            let elem = Fp2G::<P>::alloc_input(cs.ns(|| format!("r_{}", i)), || Ok(r_elem))?;
            r.push(elem);
        }

        let ell_coeffs = l.into_iter().zip(r).collect();
        Ok(Self { ell_coeffs })
    }
}
