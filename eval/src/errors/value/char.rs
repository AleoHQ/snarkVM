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

use crate::errors::FieldError;

#[derive(Debug, Error)]
pub enum CharError {
    #[error("{}", _0)]
    Error(String),

    #[error("{}", _0)]
    FieldError(#[from] FieldError),
}

impl CharError {
    fn new(message: String) -> Self {
        CharError::Error(message)
    }

    pub fn invalid_char(actual: String) -> Self {
        let message = format!("expected char element input type, found `{}`", actual);

        Self::new(message)
    }
}
