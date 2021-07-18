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

use crate::{errors::DPCError, traits::RecordScheme};
use snarkvm_curves::{
    traits::{Group, MontgomeryParameters, TwistedEdwardsParameters},
    ProjectiveCurve,
};
use snarkvm_fields::{FieldParameters, PrimeField};

pub trait EncodedRecordScheme: Sized {
    /// The group is composed of base field elements in `Self::InnerField`.
    type Group: ProjectiveCurve;
    /// The inner field is equivalent to the base field in `Self::Group`.
    type InnerField: PrimeField;
    /// The outer field is unrelated to `Self::Group` and `Self::InnerField`.
    type OuterField: PrimeField;
    type Parameters: MontgomeryParameters + TwistedEdwardsParameters;
    type Record: RecordScheme;
    type DecodedRecord;

    /// This is the bitsize of the scalar field modulus in `Self::Group`.
    const SCALAR_FIELD_BITSIZE: usize =
        <<Self::Group as Group>::ScalarField as PrimeField>::Parameters::MODULUS_BITS as usize;
    /// This is the bitsize of the base field modulus in `Self::Group` and equivalent to `Self::InnerField`.
    const INNER_FIELD_BITSIZE: usize = <Self::InnerField as PrimeField>::Parameters::MODULUS_BITS as usize;
    /// This is the bitsize of the field modulus in `Self::OuterField`.
    const OUTER_FIELD_BITSIZE: usize = <Self::OuterField as PrimeField>::Parameters::MODULUS_BITS as usize;

    /// This is the bitsize of each data ciphertext element serialized by this struct.
    /// Represents a standard unit for packing bits into data elements for storage.
    const DATA_ELEMENT_BITSIZE: usize = Self::INNER_FIELD_BITSIZE - 1;
    /// This is the bitsize of each payload ciphertext element serialized by this struct.
    /// Represents a standard unit for packing the payload into data elements for storage.
    const PAYLOAD_ELEMENT_BITSIZE: usize = Self::DATA_ELEMENT_BITSIZE - 1;

    fn encode(record: &Self::Record) -> Result<Self, DPCError>;

    fn decode(&self) -> Result<Self::DecodedRecord, DPCError>;
}
