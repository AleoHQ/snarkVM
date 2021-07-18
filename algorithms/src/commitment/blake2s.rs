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

use crate::{errors::CommitmentError, traits::CommitmentScheme};
use snarkvm_fields::{ConstraintFieldError, Field, ToConstraintField};
use snarkvm_utilities::{FromBytes, ToBytes};

use blake2::Blake2s as blake2s;
use digest::Digest;
use std::io::{Read, Result as IoResult, Write};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Blake2sCommitment;

impl CommitmentScheme for Blake2sCommitment {
    type Output = [u8; 32];
    type Parameters = ();
    type Randomness = [u8; 32];

    fn setup(_: &str) -> Self {
        Self
    }

    fn commit(&self, input: &[u8], randomness: &Self::Randomness) -> Result<Self::Output, CommitmentError> {
        let mut h = blake2s::new();
        h.update(input);
        h.update(randomness.as_ref());

        let mut result = [0u8; 32];
        result.copy_from_slice(&h.finalize());
        Ok(result)
    }

    fn parameters(&self) -> Self::Parameters {
        ()
    }
}

impl From<()> for Blake2sCommitment {
    fn from(_: ()) -> Self {
        Self
    }
}

impl ToBytes for Blake2sCommitment {
    fn write_le<W: Write>(&self, _: W) -> IoResult<()> {
        Ok(())
    }
}

impl FromBytes for Blake2sCommitment {
    #[inline]
    fn read_le<R: Read>(_: R) -> IoResult<Self> {
        Ok(Self)
    }
}

impl<F: Field> ToConstraintField<F> for Blake2sCommitment {
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        Ok(Vec::new())
    }
}
