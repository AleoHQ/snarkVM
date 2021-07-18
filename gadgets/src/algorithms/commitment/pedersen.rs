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
    integers::uint::UInt8,
    traits::{algorithms::CommitmentGadget, alloc::AllocGadget, curves::CurveGadget, integers::Integer},
};
use snarkvm_algorithms::commitment::PedersenCommitment;
use snarkvm_curves::ProjectiveCurve;
use snarkvm_fields::{Field, PrimeField};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};
use snarkvm_utilities::{to_bytes_le, ToBytes};

use std::{
    borrow::{Borrow, Cow},
    marker::PhantomData,
};

#[derive(Clone, Debug)]
pub struct PedersenRandomnessGadget<G: ProjectiveCurve>(pub Vec<UInt8>, PhantomData<G>);

impl<G: ProjectiveCurve, F: PrimeField> AllocGadget<G::ScalarField, F> for PedersenRandomnessGadget<G> {
    fn alloc<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<G::ScalarField>, CS: ConstraintSystem<F>>(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let randomness = to_bytes_le![value_gen()?.borrow()].unwrap();
        Ok(PedersenRandomnessGadget(
            UInt8::alloc_vec(cs, &randomness)?,
            PhantomData,
        ))
    }

    fn alloc_input<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<G::ScalarField>, CS: ConstraintSystem<F>>(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let randomness = to_bytes_le![value_gen()?.borrow()].unwrap();
        Ok(PedersenRandomnessGadget(
            UInt8::alloc_input_vec_le(cs, &randomness)?,
            PhantomData,
        ))
    }
}

#[derive(Clone)]
pub struct PedersenCommitmentGadget<
    G: ProjectiveCurve,
    F: Field,
    GG: CurveGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> {
    pub(crate) pedersen: PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>,
    _group_gadget: PhantomData<GG>,
    _field: PhantomData<F>,
}

// TODO (howardwu): This should be only `alloc_constant`. This is unsafe convention.
impl<G: ProjectiveCurve, F: PrimeField, GG: CurveGadget<G, F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    AllocGadget<PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for PedersenCommitmentGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        _cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            pedersen: value_gen()?.borrow().clone(),
            _group_gadget: PhantomData,
            _field: PhantomData,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        _cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            pedersen: value_gen()?.borrow().clone(),
            _group_gadget: PhantomData,
            _field: PhantomData,
        })
    }
}

impl<G: ProjectiveCurve, F: PrimeField, GG: CurveGadget<G, F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    CommitmentGadget<PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for PedersenCommitmentGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    type OutputGadget = GG;
    type RandomnessGadget = PedersenRandomnessGadget<G>;

    fn check_commitment_gadget<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        input: &[UInt8],
        randomness: &Self::RandomnessGadget,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        assert!((input.len() * 8) <= (WINDOW_SIZE * NUM_WINDOWS));

        let mut padded_input = Cow::Borrowed(input);
        // Pad if input length is less than `WINDOW_SIZE * NUM_WINDOWS`.
        if (input.len() * 8) < WINDOW_SIZE * NUM_WINDOWS {
            padded_input
                .to_mut()
                .resize((WINDOW_SIZE * NUM_WINDOWS) / 8, UInt8::constant(0u8))
        }
        assert_eq!(padded_input.len() * 8, WINDOW_SIZE * NUM_WINDOWS);

        let bases = &self.pedersen.crh.bases;
        assert_eq!(bases.len(), NUM_WINDOWS);

        // Allocate new variable for commitment output.
        let input_in_bits: Vec<_> = padded_input.iter().flat_map(|byte| byte.to_bits_le()).collect();
        let input_in_bits = input_in_bits.chunks(WINDOW_SIZE);
        let mut result = GG::multi_scalar_multiplication(cs.ns(|| "msm"), bases, input_in_bits)?;

        // Compute h^r
        let rand_bits = randomness.0.iter().flat_map(|byte| byte.to_bits_le());
        result.scalar_multiplication(cs.ns(|| "randomizer"), rand_bits.zip(&self.pedersen.random_base))?;

        Ok(result)
    }
}
