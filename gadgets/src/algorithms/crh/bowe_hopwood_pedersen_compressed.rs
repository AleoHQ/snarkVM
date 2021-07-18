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
    algorithms::crh::BoweHopwoodPedersenCRHGadget,
    integers::uint::UInt8,
    traits::{algorithms::CRHGadget, alloc::AllocGadget, curves::CompressedGroupGadget},
};
use snarkvm_algorithms::{
    crh::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenCompressedCRH},
    CRH,
};
use snarkvm_curves::ProjectiveCurve;
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use std::borrow::Borrow;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoweHopwoodPedersenCompressedCRHGadget<
    G: ProjectiveCurve,
    F: PrimeField,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> {
    bhp_gadget: BoweHopwoodPedersenCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>,
}

// TODO (howardwu): This should be only `alloc_constant`. This is unsafe convention.
impl<
    G: ProjectiveCurve,
    F: PrimeField,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> AllocGadget<BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for BoweHopwoodPedersenCompressedCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let bhp: BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE> =
            value_gen()?.borrow().parameters().clone().into();
        Ok(Self {
            bhp_gadget: BoweHopwoodPedersenCRHGadget::alloc(cs, || Ok(bhp))?,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let bhp: BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE> =
            value_gen()?.borrow().parameters().clone().into();
        Ok(Self {
            bhp_gadget: BoweHopwoodPedersenCRHGadget::alloc_input(cs, || Ok(bhp))?,
        })
    }
}

impl<
    F: PrimeField,
    G: ProjectiveCurve,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> CRHGadget<BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for BoweHopwoodPedersenCompressedCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    type OutputGadget = GG::BaseFieldGadget;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        input: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let output = self.bhp_gadget.check_evaluation_gadget(cs, input)?;
        Ok(output.to_x_coordinate())
    }
}
