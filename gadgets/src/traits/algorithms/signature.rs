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

use snarkvm_algorithms::{prf::Blake2s, traits::SignatureScheme};
use snarkvm_fields::Field;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use crate::{
    bits::ToBytesGadget,
    integers::uint::UInt8,
    traits::{alloc::AllocGadget, eq::EqGadget},
    Boolean, PRFGadget,
};

pub trait SignaturePublicKeyRandomizationGadget<S: SignatureScheme, F: Field> {
    type ParametersGadget: AllocGadget<S::Parameters, F>;
    type PublicKeyGadget: ToBytesGadget<F> + EqGadget<F> + AllocGadget<S::PublicKey, F> + Clone;
    type SignatureGadget: ToBytesGadget<F> + EqGadget<F> + AllocGadget<S::Signature, F> + Clone;

    fn check_randomization_gadget<CS: ConstraintSystem<F>>(
        cs: CS,
        parameters: &Self::ParametersGadget,
        public_key: &Self::PublicKeyGadget,
        randomness: &[UInt8],
    ) -> Result<Self::PublicKeyGadget, SynthesisError>;

    fn verify<CS: ConstraintSystem<F>, PG: PRFGadget<Blake2s, F>>(
        cs: CS,
        parameters: &Self::ParametersGadget,
        public_key: &Self::PublicKeyGadget,
        message: &[UInt8],
        signature: &Self::SignatureGadget,
    ) -> Result<Boolean, SynthesisError>;
}
