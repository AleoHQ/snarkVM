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
    algorithms::crh::PedersenCRHGadget,
    integers::uint::UInt8,
    traits::{
        algorithms::{CRHGadget, MaskedCRHGadget},
        alloc::AllocGadget,
        curves::CompressedGroupGadget,
    },
};
use snarkvm_algorithms::{
    crh::{PedersenCRH, PedersenCompressedCRH},
    CRH,
};
use snarkvm_curves::ProjectiveCurve;
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use std::borrow::Borrow;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenCompressedCRHGadget<
    G: ProjectiveCurve,
    F: PrimeField,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> {
    crh_gadget: PedersenCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>,
}

// TODO (howardwu): This should be only `alloc_constant`. This is unsafe convention.
impl<
    G: ProjectiveCurve,
    F: PrimeField,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> AllocGadget<PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for PedersenCompressedCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE> = value_gen()?.borrow().parameters().clone().into();
        Ok(Self {
            crh_gadget: PedersenCRHGadget::<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>::alloc(cs, || Ok(crh))?,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE> = value_gen()?.borrow().parameters().clone().into();
        Ok(Self {
            crh_gadget: PedersenCRHGadget::<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>::alloc_input(cs, || Ok(crh))?,
        })
    }
}

impl<
    G: ProjectiveCurve,
    F: PrimeField,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> CRHGadget<PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for PedersenCompressedCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    type OutputGadget = GG::BaseFieldGadget;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        input: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let output = self.crh_gadget.check_evaluation_gadget(cs, input)?;
        Ok(output.to_x_coordinate())
    }
}

impl<
    G: ProjectiveCurve,
    F: PrimeField,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> MaskedCRHGadget<PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for PedersenCompressedCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    type MaskParametersGadget = Self;

    fn check_evaluation_gadget_masked<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        input: Vec<UInt8>,
        mask_parameters: &Self::MaskParametersGadget,
        mask: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let output = self
            .crh_gadget
            .check_evaluation_gadget_masked(cs, input, &mask_parameters.crh_gadget, mask)?;
        Ok(output.to_x_coordinate())
    }
}
