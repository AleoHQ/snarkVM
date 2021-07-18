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
    algorithms::prf::{blake2s_gadget, Blake2sOutputGadget},
    bits::ToBytesGadget,
    integers::uint::UInt8,
    traits::{algorithms::CommitmentGadget, alloc::AllocGadget, integers::integer::Integer},
};
use snarkvm_algorithms::commitment::Blake2sCommitment;
use snarkvm_fields::{Field, PrimeField};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use std::borrow::Borrow;

#[derive(Clone)]
pub struct Blake2sRandomnessGadget(pub Vec<UInt8>);

// TODO (howardwu): Find a better convention than this.
impl<F: PrimeField> AllocGadget<[u8; 32], F> for Blake2sRandomnessGadget {
    #[inline]
    fn alloc<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<[u8; 32]>, CS: ConstraintSystem<F>>(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Blake2sRandomnessGadget(<UInt8>::alloc_vec(cs, &match value_gen() {
            Ok(val) => *(val.borrow()),
            Err(_) => [0u8; 32],
        })?))
    }

    #[inline]
    fn alloc_input<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<[u8; 32]>, CS: ConstraintSystem<F>>(
        cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Blake2sRandomnessGadget(<UInt8>::alloc_input_vec_le(
            cs,
            &match value_gen() {
                Ok(val) => *(val.borrow()),
                Err(_) => [0u8; 32],
            },
        )?))
    }
}

#[derive(Clone)]
pub struct Blake2sCommitmentGadget;

impl<F: Field> AllocGadget<Blake2sCommitment, F> for Blake2sCommitmentGadget {
    fn alloc<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<Blake2sCommitment>, CS: ConstraintSystem<F>>(
        _: CS,
        _: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Self)
    }

    fn alloc_input<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<Blake2sCommitment>, CS: ConstraintSystem<F>>(
        _: CS,
        _: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Self)
    }
}

impl<F: PrimeField> CommitmentGadget<Blake2sCommitment, F> for Blake2sCommitmentGadget {
    type OutputGadget = Blake2sOutputGadget;
    type RandomnessGadget = Blake2sRandomnessGadget;

    fn check_commitment_gadget<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        input: &[UInt8],
        r: &Self::RandomnessGadget,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let mut input_bits = vec![];
        for byte in input.iter().chain(r.0.iter()) {
            input_bits.extend_from_slice(&byte.to_bits_le());
        }

        let mut result = vec![];
        for (i, int) in blake2s_gadget(cs.ns(|| "blake2s_commitment"), &input_bits)?
            .into_iter()
            .enumerate()
        {
            result.extend_from_slice(&int.to_bytes(&mut cs.ns(|| format!("to_bytes_{}", i)))?);
        }
        Ok(Blake2sOutputGadget(result))
    }
}
