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
    algorithms::crypto_hash::{CryptographicSpongeVar, PoseidonCryptoHashGadget, PoseidonSpongeGadget},
    traits::{integers::Integer, ToConstraintFieldGadget},
    CRHGadget,
    FpGadget,
    UInt8,
};

use snarkvm_algorithms::{
    crypto_hash::{PoseidonCryptoHash, PoseidonDefaultParametersField},
    traits::CRH,
};
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};

impl<F: PrimeField + PoseidonDefaultParametersField, const RATE: usize, const OPTIMIZED_FOR_WEIGHTS: bool>
    CRHGadget<PoseidonCryptoHash<F, RATE, OPTIMIZED_FOR_WEIGHTS>, F>
    for PoseidonCryptoHashGadget<F, RATE, OPTIMIZED_FOR_WEIGHTS>
{
    type OutputGadget = FpGadget<F>;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        input: Vec<UInt8>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let params = F::get_default_poseidon_parameters(RATE, OPTIMIZED_FOR_WEIGHTS).unwrap();

        let mut padded_input_bytes = input;
        padded_input_bytes.resize(
            PoseidonCryptoHash::<F, RATE, OPTIMIZED_FOR_WEIGHTS>::INPUT_SIZE_BITS / 8,
            UInt8::constant(0u8),
        );

        let field_input = &padded_input_bytes.to_constraint_field(cs.ns(|| "convert input into field gadgets"))?;

        let mut sponge = PoseidonSpongeGadget::<F>::new(cs.ns(|| "alloc"), &params);
        sponge.absorb(cs.ns(|| "absorb"), field_input.iter())?;
        let res = sponge.squeeze_field_elements(cs.ns(|| "squeeze"), 1)?;
        Ok(res[0].clone())
    }

    fn check_evaluation_gadget_on_field_elements<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        input: Vec<FpGadget<F>>,
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let params = F::get_default_poseidon_parameters(RATE, OPTIMIZED_FOR_WEIGHTS).unwrap();
        let mut sponge = PoseidonSpongeGadget::<F>::new(cs.ns(|| "alloc"), &params);
        sponge.absorb(cs.ns(|| "absorb"), input.iter())?;
        let res = sponge.squeeze_field_elements(cs.ns(|| "squeeze"), 1)?;
        Ok(res[0].clone())
    }
}
