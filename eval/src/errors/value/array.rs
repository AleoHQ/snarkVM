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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ArrayError {
    #[error("{}", _0)]
    Error(String),
}

impl ArrayError {
    fn new(message: String) -> Self {
        ArrayError::Error(message)
    }

    pub fn tuple_index_out_of_bounds(index: usize) -> Self {
        let message = format!("cannot access index {} of tuple out of bounds", index);

        Self::new(message)
    }

    pub fn array_index_out_of_bounds(index: usize, length: usize) -> Self {
        let message = format!("cannot access index {} of array of length {}", index, length);

        Self::new(message)
    }

    pub fn array_invalid_slice_length() -> Self {
        let message = "illegal length of slice".to_string();

        Self::new(message)
    }

    pub fn invalid_index(actual: String) -> Self {
        let message = format!("index must resolve to an integer, found `{}`", actual);

        Self::new(message)
    }

    pub fn array_length_out_of_bounds() -> Self {
        let message = "array length cannot be >= 2^32".to_string();

        Self::new(message)
    }

    pub fn array_index_out_of_legal_bounds() -> Self {
        let message = "array index cannot be >= 2^32".to_string();

        Self::new(message)
    }
}
