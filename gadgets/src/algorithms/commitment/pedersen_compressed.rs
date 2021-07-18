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
    algorithms::commitment::{PedersenCommitmentGadget, PedersenRandomnessGadget},
    integers::uint::UInt8,
    traits::{algorithms::CommitmentGadget, alloc::AllocGadget, curves::CompressedGroupGadget},
};
use snarkvm_algorithms::{
    commitment::{PedersenCommitment, PedersenCompressedCommitment},
    CommitmentScheme,
};
use snarkvm_curves::ProjectiveCurve;
use snarkvm_fields::{Field, PrimeField};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use std::borrow::Borrow;

#[derive(Clone)]
pub struct PedersenCompressedCommitmentGadget<
    G: ProjectiveCurve,
    F: Field,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> {
    pedersen: PedersenCommitmentGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>,
}

// TODO (howardwu): This should be only `alloc_constant`. This is unsafe convention.
impl<
    G: ProjectiveCurve,
    F: PrimeField,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> AllocGadget<PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for PedersenCompressedCommitmentGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let commitment: PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE> = value_gen()?.borrow().parameters().into();
        Ok(Self {
            pedersen: PedersenCommitmentGadget::<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>::alloc(cs, || Ok(commitment))?,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>>,
        CS: ConstraintSystem<F>,
    >(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let commitment: PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE> = value_gen()?.borrow().parameters().into();
        Ok(Self {
            pedersen: PedersenCommitmentGadget::<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>::alloc(cs, || Ok(commitment))?,
        })
    }
}

impl<
    G: ProjectiveCurve,
    F: PrimeField,
    GG: CompressedGroupGadget<G, F>,
    const NUM_WINDOWS: usize,
    const WINDOW_SIZE: usize,
> CommitmentGadget<PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>, F>
    for PedersenCompressedCommitmentGadget<G, F, GG, NUM_WINDOWS, WINDOW_SIZE>
{
    type OutputGadget = GG::BaseFieldGadget;
    type RandomnessGadget = PedersenRandomnessGadget<G>;

    fn check_commitment_gadget<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        input: &[UInt8],
        randomness: &Self::RandomnessGadget,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let output = self.pedersen.check_commitment_gadget(cs, input, randomness)?;
        Ok(output.to_x_coordinate())
    }
}
