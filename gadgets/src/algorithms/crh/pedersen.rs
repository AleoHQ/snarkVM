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

use std::{borrow::Borrow, marker::PhantomData};

use snarkvm_algorithms::crh::{PedersenCRH, PedersenCRHParameters, PedersenCompressedCRH};
use snarkvm_curves::traits::{Group, ProjectiveCurve};
use snarkvm_fields::{Field, PrimeField};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use crate::{
    bits::Boolean,
    integers::uint::UInt8,
    traits::{
        algorithms::{CRHGadget, MaskedCRHGadget},
        alloc::AllocGadget,
        curves::{CompressedGroupGadget, GroupGadget},
        integers::Integer,
    },
};

#[derive(Clone, PartialEq, Eq)]
pub struct PedersenCRHParametersGadget<
    G: Group,
    F: Field,
    GG: GroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> {
    pub(crate) parameters: PedersenCRHParameters<G, NUM_WINDOWS, WINDOW_SIZE>,
    _group: PhantomData<GG>,
    _engine: PhantomData<F>,
}

impl<G: Group, F: Field, GG: GroupGadget<G, F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    AllocGadget<PedersenCRHParameters<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for PedersenCRHParametersGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PedersenCRHParameters<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        _cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(PedersenCRHParametersGadget {
            parameters: value_gen()?.borrow().clone(),
            _group: PhantomData,
            _engine: PhantomData,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PedersenCRHParameters<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        _cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(PedersenCRHParametersGadget {
            parameters: value_gen()?.borrow().clone(),
            _group: PhantomData,
            _engine: PhantomData,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenCRHGadget<G: Group, F: Field, GG: GroupGadget<G, F>> {
    _group: PhantomData<*const G>,
    _group_gadget: PhantomData<*const GG>,
    _engine: PhantomData<F>,
}

impl<F: Field, G: Group, GG: GroupGadget<G, F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    CRHGadget<PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F> for PedersenCRHGadget<G, F, GG>
{
    type OutputGadget = GG;
    type ParametersGadget = PedersenCRHParametersGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        cs: CS,
        parameters: &Self::ParametersGadget,
        input: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        assert_eq!(parameters.parameters.bases.len(), NUM_WINDOWS);
        // Pad the input if it is not the correct length.
        let input_in_bits = pad_input_and_bitify::<NUM_WINDOWS, WINDOW_SIZE>(input);

        GG::multi_scalar_multiplication(cs, &parameters.parameters.bases, input_in_bits.chunks(WINDOW_SIZE))
    }
}

fn pad_input_and_bitify<const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>(input: Vec<UInt8>) -> Vec<Boolean> {
    let mut padded_input = input;
    padded_input.resize(WINDOW_SIZE * NUM_WINDOWS / 8, UInt8::constant(0u8));
    assert_eq!(padded_input.len() * 8, WINDOW_SIZE * NUM_WINDOWS);
    padded_input.into_iter().flat_map(|byte| byte.to_bits_le()).collect()
}

impl<F: PrimeField, G: Group, GG: GroupGadget<G, F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    MaskedCRHGadget<PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F> for PedersenCRHGadget<G, F, GG>
{
    /// Evaluates a masked Pedersen hash on the given `input` using the given `mask`. The algorithm
    /// is based on the description in https://eprint.iacr.org/2020/190.pdf, which relies on the
    /// homomorphic properties of Pedersen hashes. First, the mask is extended to ensure constant
    /// hardness - for each bit, 0 => 01, 1 => 10. Then, denoting input bits as m_i, mask bits
    /// as p_i and bases as h_i, computes sum of
    /// (g_i * 1[p_i = 0] + g_i^{-1} * 1[p_i = 1])^{m_i \xor p_i} for all i. Finally, the hash of
    /// the mask itself, being sum of h_i^{p_i} for all i, is added to the computed sum. This
    /// algorithm ensures that each bit in the hash is affected by the mask and that the
    /// final hash remains the same as if no mask was used.
    fn check_evaluation_gadget_masked<CS: ConstraintSystem<F>>(
        mut cs: CS,
        parameters: &Self::ParametersGadget,
        input: Vec<UInt8>,
        mask_parameters: &Self::ParametersGadget,
        mask: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        // The mask will be extended to ensure constant hardness. This condition
        // ensures the input and the mask sizes match.
        if input.len() != mask.len() * 2 {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mask = <Self as MaskedCRHGadget<PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F>>::extend_mask(
            cs.ns(|| "extend mask"),
            &mask,
        )?;
        // H(p) = sum of g_i^{p_i} for all i.
        let mask_hash = Self::check_evaluation_gadget(cs.ns(|| "evaluate mask"), parameters, mask.clone())?;

        // H_2(p) = sum of h_i^{1-2*p_i} for all i.
        let mask_input_in_bits = pad_input_and_bitify::<NUM_WINDOWS, WINDOW_SIZE>(mask.clone());
        let mask_symmetric_hash = GG::symmetric_multi_scalar_multiplication(
            cs.ns(|| "evaluate mask with mask bases"),
            &mask_parameters.parameters.bases,
            mask_input_in_bits.chunks(WINDOW_SIZE),
        )?;

        assert_eq!(parameters.parameters.bases.len(), NUM_WINDOWS);
        // Pad the input if it is not the correct length.
        let input_in_bits = pad_input_and_bitify::<NUM_WINDOWS, WINDOW_SIZE>(input);
        let mask_in_bits = pad_input_and_bitify::<NUM_WINDOWS, WINDOW_SIZE>(mask);

        let masked_output = GG::masked_multi_scalar_multiplication(
            cs.ns(|| "multiscalar multiplication"),
            &parameters.parameters.bases,
            input_in_bits.chunks(WINDOW_SIZE),
            &mask_parameters.parameters.bases,
            mask_in_bits.chunks(WINDOW_SIZE),
        )?;
        masked_output
            .add(cs.ns(|| "remove mask"), &mask_hash)?
            .add(cs.ns(|| "remove mask with mask bases"), &mask_symmetric_hash)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PedersenCompressedCRHGadget<G: Group + ProjectiveCurve, F: Field, GG: CompressedGroupGadget<G, F>> {
    _group: PhantomData<fn() -> G>,
    _group_gadget: PhantomData<fn() -> GG>,
    _engine: PhantomData<F>,
}

impl<
        F: Field,
        G: Group + ProjectiveCurve,
        GG: CompressedGroupGadget<G, F>,
        const NUM_WINDOWS: usize,
        const WINDOW_SIZE: usize,
    > CRHGadget<PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F> for PedersenCompressedCRHGadget<G, F, GG>
{
    type OutputGadget = GG::BaseFieldGadget;
    type ParametersGadget = PedersenCRHParametersGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        cs: CS,
        parameters: &Self::ParametersGadget,
        input: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let output = PedersenCRHGadget::<G, F, GG>::check_evaluation_gadget(cs, parameters, input)?;
        Ok(output.to_x_coordinate())
    }
}

impl<
        F: PrimeField,
        G: Group + ProjectiveCurve,
        GG: CompressedGroupGadget<G, F>,
        const NUM_WINDOWS: usize,
        const WINDOW_SIZE: usize,
    > MaskedCRHGadget<PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>, F> for PedersenCompressedCRHGadget<G, F, GG>
{
    fn check_evaluation_gadget_masked<CS: ConstraintSystem<F>>(
        cs: CS,
        parameters: &Self::ParametersGadget,
        input: Vec<UInt8>,
        mask_parameters: &Self::ParametersGadget,
        mask: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let output = PedersenCRHGadget::<G, F, GG>::check_evaluation_gadget_masked(
            cs,
            parameters,
            input,
            mask_parameters,
            mask,
        )?;
        Ok(output.to_x_coordinate())
    }
}
