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

use snarkvm_curves::{traits::PairingEngine, PairingCurve};
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use crate::{
    bits::ToBytesGadget,
    traits::{alloc::AllocGadget, curves::GroupGadget, fields::FieldGadget},
    ToConstraintFieldGadget,
};

pub trait PairingGadget<E: PairingEngine, F: PrimeField = <E as PairingEngine>::Fq> {
    type G1Gadget: GroupGadget<E::G1Projective, F> + ToConstraintFieldGadget<F>;
    type G2Gadget: GroupGadget<E::G2Projective, F> + ToConstraintFieldGadget<F>;
    type G1PreparedGadget: ToBytesGadget<F> + Clone + Debug;
    type G2PreparedGadget: ToBytesGadget<F> + AllocGadget<<E::G2Affine as PairingCurve>::Prepared, F> + Clone + Debug;
    type GTGadget: FieldGadget<E::Fqk, F> + Clone;

    fn miller_loop<CS: ConstraintSystem<F>>(
        cs: CS,
        p: &[Self::G1PreparedGadget],
        q: &[Self::G2PreparedGadget],
    ) -> Result<Self::GTGadget, SynthesisError>;

    fn final_exponentiation<CS: ConstraintSystem<F>>(
        cs: CS,
        p: &Self::GTGadget,
    ) -> Result<Self::GTGadget, SynthesisError>;

    fn pairing<CS: ConstraintSystem<F>>(
        mut cs: CS,
        p: Self::G1PreparedGadget,
        q: Self::G2PreparedGadget,
    ) -> Result<Self::GTGadget, SynthesisError> {
        let tmp = Self::miller_loop(cs.ns(|| "miller loop"), &[p], &[q])?;
        Self::final_exponentiation(cs.ns(|| "final_exp"), &tmp)
    }

    /// Computes a product of pairings.
    fn product_of_pairings<CS: ConstraintSystem<F>>(
        mut cs: CS,
        p: &[Self::G1PreparedGadget],
        q: &[Self::G2PreparedGadget],
    ) -> Result<Self::GTGadget, SynthesisError> {
        let miller_result = Self::miller_loop(&mut cs.ns(|| "Miller loop"), p, q)?;
        Self::final_exponentiation(&mut cs.ns(|| "Final Exp"), &miller_result)
    }

    fn prepare_g1<CS: ConstraintSystem<F>>(cs: CS, q: Self::G1Gadget)
    -> Result<Self::G1PreparedGadget, SynthesisError>;

    fn prepare_g2<CS: ConstraintSystem<F>>(cs: CS, q: Self::G2Gadget)
    -> Result<Self::G2PreparedGadget, SynthesisError>;
}
