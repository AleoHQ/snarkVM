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

use crate::{commitment::PedersenCommitment, errors::CommitmentError, traits::CommitmentScheme};
use snarkvm_curves::traits::{AffineCurve, Group, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, Field, ToConstraintField};
use snarkvm_utilities::{FromBytes, ToBytes};

use std::io::{Read, Result as IoResult, Write};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PedersenCompressedCommitment<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> {
    pub pedersen: PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>,
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> CommitmentScheme
    for PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    type Output = <G::Affine as AffineCurve>::BaseField;
    type Parameters = (Vec<Vec<G>>, Vec<G>);
    type Randomness = <G as Group>::ScalarField;

    fn setup(message: &str) -> Self {
        PedersenCommitment::setup(message).into()
    }

    /// Returns the affine x-coordinate as the commitment.
    fn commit(&self, input: &[u8], randomness: &Self::Randomness) -> Result<Self::Output, CommitmentError> {
        let affine = self.pedersen.commit(input, randomness)?;
        debug_assert!(affine.is_in_correct_subgroup_assuming_on_curve());
        Ok(affine.to_x_coordinate())
    }

    fn parameters(&self) -> Self::Parameters {
        self.pedersen.parameters()
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    From<PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>>
    for PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from(pedersen: PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>) -> Self {
        Self { pedersen }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> From<(Vec<Vec<G>>, Vec<G>)>
    for PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from(parameters: (Vec<Vec<G>>, Vec<G>)) -> Self {
        Self {
            pedersen: parameters.into(),
        }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> ToBytes
    for PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()> {
        self.pedersen.write_le(writer)
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> FromBytes
    for PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Ok(PedersenCommitment::read_le(reader)?.into())
    }
}

impl<F: Field, G: ProjectiveCurve + ToConstraintField<F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    ToConstraintField<F> for PedersenCompressedCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        self.pedersen.to_field_elements()
    }
}
