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

use crate::testnet2::Testnet2Components;
use snarkvm_algorithms::prelude::*;
use snarkvm_gadgets::prelude::*;
use snarkvm_r1cs::{Assignment, ConstraintSynthesizer, ConstraintSystem, SynthesisError};

/// Always-accept program
pub struct NoopCircuit<C: Testnet2Components> {
    /// Commitment to the program input.
    pub local_data_root: Option<<C::LocalDataCRH as CRH>::Output>,
    /// Record position
    pub position: u8,
}

impl<C: Testnet2Components> NoopCircuit<C> {
    pub fn blank() -> Self {
        Self {
            local_data_root: Some(<C::LocalDataCRH as CRH>::Output::default()),
            position: 0u8,
        }
    }

    pub fn new(local_data_root: &<C::LocalDataCRH as CRH>::Output, position: u8) -> Self {
        Self {
            local_data_root: Some(local_data_root.clone()),
            position,
        }
    }
}

impl<C: Testnet2Components> ConstraintSynthesizer<C::InnerScalarField> for NoopCircuit<C> {
    fn generate_constraints<CS: ConstraintSystem<C::InnerScalarField>>(
        &self,
        cs: &mut CS,
    ) -> Result<(), SynthesisError> {
        let local_data_root = self.local_data_root.get_ref()?;
        let position = self.position;

        let _position = UInt8::alloc_input_vec_le(cs.ns(|| "Alloc position"), &[position])?;

        let _local_data_commitment_parameters_gadget = C::LocalDataCommitmentGadget::alloc_input(
            &mut cs.ns(|| "Declare local data commitment parameters"),
            || Ok(C::local_data_commitment().clone()),
        )?;

        let _local_data_root_gadget = <C::LocalDataCRHGadget as CRHGadget<_, _>>::OutputGadget::alloc_input(
            cs.ns(|| "Allocate local data root"),
            || Ok(local_data_root),
        )?;

        Ok(())
    }
}
