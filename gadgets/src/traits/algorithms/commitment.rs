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

use snarkvm_algorithms::traits::CommitmentScheme;
use snarkvm_fields::Field;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use crate::{
    bits::ToBytesGadget,
    integers::uint::UInt8,
    traits::{
        alloc::AllocGadget,
        eq::{ConditionalEqGadget, EqGadget},
        select::CondSelectGadget,
    },
};

pub trait CommitmentGadget<C: CommitmentScheme, F: Field>: AllocGadget<C, F> + Clone + Sized {
    type OutputGadget: ConditionalEqGadget<F>
        + CondSelectGadget<F>
        + EqGadget<F>
        + ToBytesGadget<F>
        + AllocGadget<C::Output, F>
        + Clone
        + Sized
        + Debug;
    type RandomnessGadget: AllocGadget<C::Randomness, F> + Clone;

    fn check_commitment_gadget<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        input: &[UInt8],
        r: &Self::RandomnessGadget,
    ) -> Result<Self::OutputGadget, SynthesisError>;
}
