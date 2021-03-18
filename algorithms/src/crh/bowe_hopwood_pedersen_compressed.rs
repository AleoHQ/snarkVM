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

pub use crate::crh::pedersen_parameters::PedersenSize;

use crate::{
    crh::{BoweHopwoodPedersenCRH, PedersenCRH, PedersenCRHParameters},
    errors::CRHError,
    traits::CRH,
};
use snarkvm_curves::{AffineCurve, Group, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, Field, ToConstraintField};

use rand::Rng;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BoweHopwoodPedersenCompressedCRH<G: Group + ProjectiveCurve, S: PedersenSize> {
    pub parameters: PedersenCRHParameters<G, S>,
}

impl<G: Group + ProjectiveCurve, S: PedersenSize> CRH for BoweHopwoodPedersenCompressedCRH<G, S> {
    type Output = <G::Affine as AffineCurve>::BaseField;
    type Parameters = PedersenCRHParameters<G, S>;

    const INPUT_SIZE_BITS: usize = PedersenCRH::<G, S>::INPUT_SIZE_BITS;

    fn setup<R: Rng>(rng: &mut R) -> Self {
        let parameters = BoweHopwoodPedersenCRH::<G, S>::setup(rng).parameters;

        Self { parameters }
    }

    fn hash(&self, input: &[u8]) -> Result<Self::Output, CRHError> {
        let crh = BoweHopwoodPedersenCRH::<G, S> {
            parameters: self.parameters.clone(),
        };

        let output = crh.hash(input)?;
        let affine = output.into_affine();
        debug_assert!(affine.is_in_correct_subgroup_assuming_on_curve());
        Ok(affine.to_x_coordinate())
    }

    fn parameters(&self) -> &Self::Parameters {
        &self.parameters
    }
}

impl<G: Group + ProjectiveCurve, S: PedersenSize> From<PedersenCRHParameters<G, S>>
    for BoweHopwoodPedersenCompressedCRH<G, S>
{
    fn from(parameters: PedersenCRHParameters<G, S>) -> Self {
        Self { parameters }
    }
}

impl<F: Field, G: Group + ProjectiveCurve + ToConstraintField<F>, S: PedersenSize> ToConstraintField<F>
    for BoweHopwoodPedersenCompressedCRH<G, S>
{
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        self.parameters.to_field_elements()
    }
}
