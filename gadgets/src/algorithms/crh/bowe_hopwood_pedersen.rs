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
    algorithms::crh::pedersen::PedersenCRHGadget,
    bits::Boolean,
    integers::uint::UInt8,
    traits::{algorithms::CRHGadget, alloc::AllocGadget, curves::CurveGadget, integers::Integer},
};
use snarkvm_algorithms::{
    crh::{BoweHopwoodPedersenCRH, PedersenCRH, BOWE_HOPWOOD_CHUNK_SIZE},
    CRH,
};
use snarkvm_curves::ProjectiveCurve;
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use std::borrow::Borrow;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoweHopwoodPedersenCRHGadget<
    G: ProjectiveCurve,
    F: PrimeField,
    GG: CurveGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> {
    crh_gadget: PedersenCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>,
}

// TODO (howardwu): This should be only `alloc_constant`. This is unsafe convention.
impl<G: ProjectiveCurve, F: PrimeField, GG: CurveGadget<G, F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    AllocGadget<BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for BoweHopwoodPedersenCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE> = value_gen()?.borrow().parameters().clone().into();
        Ok(Self {
            crh_gadget: PedersenCRHGadget::alloc(cs, || Ok(crh))?,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE> = value_gen()?.borrow().parameters().clone().into();
        Ok(Self {
            crh_gadget: PedersenCRHGadget::alloc_input(cs, || Ok(crh))?,
        })
    }
}

impl<F: PrimeField, G: ProjectiveCurve, GG: CurveGadget<G, F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    CRHGadget<BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for BoweHopwoodPedersenCRHGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    type OutputGadget = GG;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        input: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        // Pad the input bytes
        let mut padded_input_bytes = input;
        padded_input_bytes.resize(WINDOW_SIZE * NUM_WINDOWS / 8, UInt8::constant(0u8));
        assert_eq!(padded_input_bytes.len() * 8, WINDOW_SIZE * NUM_WINDOWS);

        // Pad the input bits if it is not the current length.
        let mut input_in_bits: Vec<_> = padded_input_bytes
            .into_iter()
            .flat_map(|byte| byte.to_bits_le())
            .collect();
        if (input_in_bits.len()) % BOWE_HOPWOOD_CHUNK_SIZE != 0 {
            let current_length = input_in_bits.len();
            let target_length = current_length + BOWE_HOPWOOD_CHUNK_SIZE - current_length % BOWE_HOPWOOD_CHUNK_SIZE;
            input_in_bits.resize(target_length, Boolean::constant(false));
        }
        assert!(input_in_bits.len() % BOWE_HOPWOOD_CHUNK_SIZE == 0);
        assert_eq!(self.crh_gadget.crh.bases.len(), NUM_WINDOWS);
        for generators in self.crh_gadget.crh.bases.iter() {
            assert_eq!(generators.len(), WINDOW_SIZE);
        }

        // Allocate new variable for the result.
        let input_in_bits = input_in_bits
            .chunks(WINDOW_SIZE * BOWE_HOPWOOD_CHUNK_SIZE)
            .map(|x| x.chunks(BOWE_HOPWOOD_CHUNK_SIZE));

        let result = GG::three_bit_signed_digit_scalar_multiplication(cs, &self.crh_gadget.crh.bases, input_in_bits)?;

        Ok(result)
    }
}
