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

use snarkvm_algorithms::traits::CRH;
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use crate::{
    bits::ToBytesGadget,
    integers::uint::UInt8,
    traits::{
        alloc::AllocGadget,
        eq::{ConditionalEqGadget, EqGadget},
        integers::Integer,
        select::CondSelectGadget,
    },
    FpGadget,
};

pub trait CRHGadget<H: CRH, F: PrimeField>: AllocGadget<H, F> + Sized + Clone {
    type OutputGadget: ConditionalEqGadget<F>
        + EqGadget<F>
        + ToBytesGadget<F>
        + CondSelectGadget<F>
        + AllocGadget<H::Output, F>
        + Debug
        + Clone
        + Sized;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        input: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError>;

    fn check_evaluation_gadget_on_field_elements<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        input: Vec<FpGadget<F>>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let mut input_bytes = vec![];
        for (i, elem) in input.iter().enumerate() {
            input_bytes.append(&mut elem.to_bytes(cs.ns(|| format!("convert_to_bytes_{}", i)))?);
        }
        self.check_evaluation_gadget(cs.ns(|| "crh"), input_bytes)
    }
}

pub trait MaskedCRHGadget<H: CRH, F: PrimeField>: CRHGadget<H, F> {
    type MaskParametersGadget: AllocGadget<H, F> + Clone;

    fn check_evaluation_gadget_masked<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        input: Vec<UInt8>,
        mask_parameters: &Self::MaskParametersGadget,
        mask: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError>;

    /// Extends the mask such that 0 => 01, 1 => 10.
    fn extend_mask<CS: ConstraintSystem<F>>(_: CS, mask: &[UInt8]) -> Result<Vec<UInt8>, SynthesisError> {
        let extended_mask = mask
            .iter()
            .flat_map(|m| {
                m.to_bits_le()
                    .chunks(4)
                    .map(|c| {
                        let new_byte = c.iter().flat_map(|b| vec![*b, b.not()]).collect::<Vec<_>>();
                        UInt8::from_bits_le(&new_byte)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();

        Ok(extended_mask)
    }
}
