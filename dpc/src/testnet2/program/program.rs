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
use snarkvm_algorithms::{traits::CRH, SNARK};
use snarkvm_fields::{ConstraintFieldError, ToConstraintField};

/// Program verifying key and proof.
#[derive(Derivative)]
#[derivative(Clone(bound = "S: SNARK"))]
pub struct Execution<S: SNARK> {
    pub verifying_key: S::VerifyingKey,
    pub proof: S::Proof,
}

pub struct ProgramLocalData<C: Testnet2Components> {
    pub local_data_root: <C::LocalDataCRH as CRH>::Output,
    pub position: u8,
}

/// Convert each component to bytes and pack into field elements.
impl<C: Testnet2Components> ToConstraintField<C::InnerScalarField> for ProgramLocalData<C>
where
    <C::LocalDataCRH as CRH>::Output: ToConstraintField<C::InnerScalarField>,
{
    fn to_field_elements(&self) -> Result<Vec<C::InnerScalarField>, ConstraintFieldError> {
        let mut v = ToConstraintField::<C::InnerScalarField>::to_field_elements(&[self.position][..])?;
        v.extend_from_slice(&C::local_data_commitment().to_field_elements()?);
        v.extend_from_slice(&self.local_data_root.to_field_elements()?);
        Ok(v)
    }
}
