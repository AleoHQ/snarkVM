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
    crh::{BoweHopwoodPedersenCRH, PedersenCRH},
    CRHError,
    CRH,
};
use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, Field, ToConstraintField};
use snarkvm_utilities::{FromBytes, ToBytes};

use std::{
    fmt::Debug,
    io::{Read, Result as IoResult, Write},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoweHopwoodPedersenCompressedCRH<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> {
    pub bhp: BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>,
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> CRH
    for BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    type Output = <G::Affine as AffineCurve>::BaseField;
    type Parameters = PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>;

    const INPUT_SIZE_BITS: usize = PedersenCRH::<G, NUM_WINDOWS, WINDOW_SIZE>::INPUT_SIZE_BITS;

    fn setup(message: &str) -> Self {
        BoweHopwoodPedersenCRH::<G, NUM_WINDOWS, WINDOW_SIZE>::setup(message).into()
    }

    fn hash(&self, input: &[u8]) -> Result<Self::Output, CRHError> {
        let affine = self.bhp.hash(input)?;
        debug_assert!(affine.is_in_correct_subgroup_assuming_on_curve());
        Ok(affine.to_x_coordinate())
    }

    fn parameters(&self) -> &Self::Parameters {
        &self.bhp.parameters()
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    From<PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>> for BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from(crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>) -> Self {
        Self { bhp: crh.into() }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    From<BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>>
    for BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from(bhp: BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>) -> Self {
        Self { bhp }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> From<Vec<Vec<G>>>
    for BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from(bases: Vec<Vec<G>>) -> Self {
        Self { bhp: bases.into() }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> ToBytes
    for BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()> {
        self.bhp.write_le(writer)
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> FromBytes
    for BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Ok(BoweHopwoodPedersenCRH::read_le(reader)?.into())
    }
}

impl<F: Field, G: ProjectiveCurve + ToConstraintField<F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    ToConstraintField<F> for BoweHopwoodPedersenCompressedCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        self.bhp.to_field_elements()
    }
}
