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

use crate::{AllocGadget, EqGadget, FpGadget, ToBytesGadget};
use snarkvm_algorithms::CryptoHash;
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};
use snarkvm_utilities::fmt::Debug;

pub trait CryptoHashGadget<P: CryptoHash, F: PrimeField> {
    type OutputGadget: EqGadget<F> + ToBytesGadget<F> + AllocGadget<P::Output, F> + Clone + Debug;

    fn check_evaluation_gadget<CS: ConstraintSystem<F>>(
        cs: CS,
        input: &[FpGadget<F>],
    ) -> Result<Self::OutputGadget, SynthesisError>;

    fn check_evaluation_with_len_gadget<CS: ConstraintSystem<F>>(
        cs: CS,
        input: &[FpGadget<F>],
    ) -> Result<Self::OutputGadget, SynthesisError> {
        let mut header = vec![FpGadget::<F>::Constant(F::from(input.len() as u128))];
        header.extend_from_slice(input);
        Self::check_evaluation_gadget(cs, &header)
    }
}
