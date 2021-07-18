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

use crate::{crh::PedersenCRH, CRHError, CRH};
use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, Field, ToConstraintField};
use snarkvm_utilities::{FromBytes, ToBytes};

use std::{
    fmt::Debug,
    io::{Read, Result as IoResult, Write},
};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PedersenCompressedCRH<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> {
    pub crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>,
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> CRH
    for PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    type Output = <G::Affine as AffineCurve>::BaseField;
    type Parameters = Vec<Vec<G>>;

    const INPUT_SIZE_BITS: usize = WINDOW_SIZE * NUM_WINDOWS;

    fn setup(message: &str) -> Self {
        PedersenCRH::setup(message).into()
    }

    /// Returns the affine x-coordinate as the collision-resistant hash output.
    fn hash(&self, input: &[u8]) -> Result<Self::Output, CRHError> {
        let affine = self.crh.hash(input)?;
        debug_assert!(affine.is_in_correct_subgroup_assuming_on_curve());
        Ok(affine.to_x_coordinate())
    }

    fn parameters(&self) -> &Self::Parameters {
        &self.crh.parameters()
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    From<PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>> for PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from(crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>) -> Self {
        Self { crh }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> From<Vec<Vec<G>>>
    for PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from(bases: Vec<Vec<G>>) -> Self {
        Self { crh: bases.into() }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> ToBytes
    for PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()> {
        self.crh.write_le(writer)
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> FromBytes
    for PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Ok(PedersenCRH::read_le(reader)?.into())
    }
}

impl<F: Field, G: ProjectiveCurve + ToConstraintField<F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    ToConstraintField<F> for PedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        self.crh.to_field_elements()
    }
}
