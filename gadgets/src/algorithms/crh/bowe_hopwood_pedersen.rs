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
    algorithms::crh::pedersen::PedersenCRHParametersGadget,
    bits::Boolean,
    integers::uint::UInt8,
    traits::{
        algorithms::CRHGadget,
        curves::{CompressedGroupGadget, GroupGadget},
        integers::integer::Integer,
    },
};
use snarkvm_algorithms::crh::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenCompressedCRH, BOWE_HOPWOOD_CHUNK_SIZE};
use snarkvm_curves::traits::{Group, ProjectiveCurve};
use snarkvm_fields::Field;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use std::marker::PhantomData;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoweHopwoodPedersenCRHGadget<G: Group, F: Field, GG: GroupGadget<G, F>> {
    _group: PhantomData<*const G>,
    _group_gadget: PhantomData<*const GG>,
    _engine: PhantomData<F>,
}

impl<F: Field, G: Group, GG: GroupGadget<G, F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    CRHGadget<BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F> for BoweHopwoodPedersenCRHGadget<G, F, GG>
{
    type OutputGadget = GG;
    type ParametersGadget = PedersenCRHParametersGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        cs: CS,
        parameters: &Self::ParametersGadget,
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
        assert_eq!(parameters.parameters.bases.len(), NUM_WINDOWS);
        for generators in parameters.parameters.bases.iter() {
            assert_eq!(generators.len(), WINDOW_SIZE);
        }

        // Allocate new variable for the result.
        let input_in_bits = input_in_bits
            .chunks(WINDOW_SIZE * BOWE_HOPWOOD_CHUNK_SIZE)
            .map(|x| x.chunks(BOWE_HOPWOOD_CHUNK_SIZE));

        let result = GG::three_bit_signed_digit_scalar_multiplication(cs, &parameters.parameters.bases, input_in_bits)?;

        Ok(result)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoweHopwoodPedersenCompressedCRHGadget<G: Group + ProjectiveCurve, F: Field, GG: CompressedGroupGadget<G, F>>
{
    _group: PhantomData<*const G>,
    _group_gadget: PhantomData<*const GG>,
    _engine: PhantomData<F>,
}

impl<
        F: Field,
        G: Group + ProjectiveCurve,
        GG: CompressedGroupGadget<G, F>,
        const NUM_WINDOWS: usize,
        const WINDOW_SIZE: usize,
    > CRHGadget<BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for BoweHopwoodPedersenCompressedCRHGadget<G, F, GG>
{
    type OutputGadget = GG::BaseFieldGadget;
    type ParametersGadget = PedersenCRHParametersGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        cs: CS,
        parameters: &Self::ParametersGadget,
        input: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let output = BoweHopwoodPedersenCRHGadget::<G, F, GG>::check_evaluation_gadget(cs, parameters, input)?;
        Ok(output.to_x_coordinate())
    }
}
