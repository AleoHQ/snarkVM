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

use crate::{crh::PedersenCRH, hash_to_curve::hash_to_curve, CommitmentError, CommitmentScheme, CRH};
use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, Field, PrimeField, ToConstraintField};
use snarkvm_utilities::{BitIteratorLE, FromBytes, ToBytes};

use std::io::{Read, Result as IoResult, Write};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct PedersenCommitment<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> {
    pub crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>,
    pub random_base: Vec<G>,
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> CommitmentScheme
    for PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    type Output = G::Affine;
    type Parameters = (Vec<Vec<G>>, Vec<G>);
    type Randomness = G::ScalarField;

    fn setup(message: &str) -> Self {
        // First, compute the bases.
        let crh = PedersenCRH::setup(message);

        // Next, compute the random base.
        let random_base_message = format!("{} for random base", message);
        let (generator, _, _) = hash_to_curve::<G::Affine>(&random_base_message);
        let mut base = generator.into_projective();
        let mut random_base = Vec::with_capacity(WINDOW_SIZE);
        for _ in 0..WINDOW_SIZE {
            random_base.push(base);
            base.double_in_place();
        }
        Self { crh, random_base }
    }

    fn commit(&self, input: &[u8], randomness: &Self::Randomness) -> Result<Self::Output, CommitmentError> {
        // If the input is too long, return an error.
        if input.len() > WINDOW_SIZE * NUM_WINDOWS {
            return Err(CommitmentError::IncorrectInputLength(
                input.len(),
                WINDOW_SIZE,
                NUM_WINDOWS,
            ));
        }

        let mut output = self.crh.hash(&input)?.into_projective();

        // Compute h^r.
        let scalar_bits = BitIteratorLE::new(randomness.to_repr());
        for (bit, power) in scalar_bits.into_iter().zip(&self.random_base) {
            if bit {
                output += power
            }
        }

        Ok(output.into_affine())
    }

    fn parameters(&self) -> Self::Parameters {
        (self.crh.bases.clone(), self.random_base.clone())
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> From<(Vec<Vec<G>>, Vec<G>)>
    for PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from((bases, random_base): (Vec<Vec<G>>, Vec<G>)) -> Self {
        Self {
            crh: bases.into(),
            random_base,
        }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> ToBytes
    for PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (self.crh.bases.len() as u32).write_le(&mut writer)?;
        for base in &self.crh.bases {
            (base.len() as u32).write_le(&mut writer)?;
            for g in base {
                g.write_le(&mut writer)?;
            }
        }

        (self.random_base.len() as u32).write_le(&mut writer)?;
        for g in &self.random_base {
            g.write_le(&mut writer)?;
        }

        Ok(())
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> FromBytes
    for PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let num_bases: u32 = FromBytes::read_le(&mut reader)?;
        let mut bases = Vec::with_capacity(num_bases as usize);
        for _ in 0..num_bases {
            let base_len: u32 = FromBytes::read_le(&mut reader)?;
            let mut base = Vec::with_capacity(base_len as usize);

            for _ in 0..base_len {
                let g: G = FromBytes::read_le(&mut reader)?;
                base.push(g);
            }
            bases.push(base);
        }

        let random_base_len: u32 = FromBytes::read_le(&mut reader)?;
        let mut random_base = Vec::with_capacity(random_base_len as usize);
        for _ in 0..random_base_len {
            let g: G = FromBytes::read_le(&mut reader)?;
            random_base.push(g);
        }

        Ok(Self {
            crh: PedersenCRH::from(bases).into(),
            random_base,
        })
    }
}

impl<F: Field, G: ProjectiveCurve + ToConstraintField<F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    ToConstraintField<F> for PedersenCommitment<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        Ok(Vec::new())
    }
}
