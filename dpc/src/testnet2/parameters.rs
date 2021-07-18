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

use crate::{testnet2::Testnet2Components, ProgramError};
use snarkvm_fields::ToConstraintField;
use snarkvm_marlin::marlin::{MarlinSNARK, UniversalSRS};
use snarkvm_parameters::{prelude::*, testnet2::*};
use snarkvm_polycommit::PolynomialCommitment;
use snarkvm_utilities::FromBytes;

use rand::{CryptoRng, Rng};
use std::io::Result as IoResult;

#[derive(Derivative)]
#[derivative(Clone(bound = "C: Testnet2Components"))]
pub struct ProgramSNARKUniversalSRS<C: Testnet2Components>(
    pub UniversalSRS<C::InnerScalarField, C::PolynomialCommitment>,
);

impl<C: Testnet2Components> ProgramSNARKUniversalSRS<C>
where
    <C::PolynomialCommitment as PolynomialCommitment<C::InnerScalarField>>::VerifierKey:
        ToConstraintField<C::OuterScalarField>,
    <C::PolynomialCommitment as PolynomialCommitment<C::InnerScalarField>>::Commitment:
        ToConstraintField<C::OuterScalarField>,
{
    pub fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self, ProgramError> {
        // TODO (raychu86): CRITICAL - Specify the `num_constraints`, `num_variables`, and `num_non_zero` variables.
        let num_constraints = 10000;
        let num_variables = 10000;
        let num_non_zero = 10000;

        // TODO (raychu86): Handle this unwrap.
        Ok(Self(
            MarlinSNARK::<
                C::InnerScalarField,
                C::OuterScalarField,
                C::PolynomialCommitment,
                C::FiatShamirRng,
                C::MarlinMode,
            >::universal_setup(num_constraints, num_variables, num_non_zero, rng)
            .unwrap(),
        ))
    }
}

impl<C: Testnet2Components> ProgramSNARKUniversalSRS<C> {
    pub fn load() -> IoResult<Self> {
        Ok(Self(From::from(FromBytes::read_le(
            UniversalSRSParameters::load_bytes()?.as_slice(),
        )?)))
    }
}
