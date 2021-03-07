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

use crate::Vec;
use snarkvm_fields::Field;
use snarkvm_utilities::{bytes::ToBytes, errors::SerializationError, serialize::*, Write};

/// TODO (howardwu): We can save 21 bytes here by using an enum and serializing differently.
/// Each prover message that is not a list of oracles is a list of field elements.
#[repr(transparent)]
#[derive(Clone, Debug, Default, CanonicalSerialize, CanonicalDeserialize)]
pub struct ProverMessage<F: Field> {
    /// The field elements that make up the message
    pub field_elements: Vec<F>,
}

impl<F: Field> ToBytes for ProverMessage<F> {
    fn write<W: Write>(&self, mut w: W) -> io::Result<()> {
        CanonicalSerialize::serialize(self, &mut w)
            .map_err(|_| snarkvm_utilities::error("Could not serialize ProverMessage"))
    }
}
