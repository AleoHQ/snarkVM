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

use snarkvm_gadgets::errors::{SignedIntegerError, UnsignedIntegerError};
use snarkvm_r1cs::SynthesisError;

#[derive(Debug, Error)]
pub enum IntegerError {
    #[error("{}", _0)]
    Error(String),
    #[error("{}", _0)]
    SignedIntegerError(#[from] SignedIntegerError),
    #[error("{}", _0)]
    UnsignedIntegerError(#[from] UnsignedIntegerError),
}

impl IntegerError {
    fn new(message: String) -> Self {
        IntegerError::Error(message)
    }

    pub fn signed(error: SignedIntegerError) -> Self {
        let message = format!("integer operation failed due to the signed integer error `{:?}`", error);

        Self::new(message)
    }

    pub fn unsigned(error: UnsignedIntegerError) -> Self {
        let message = format!(
            "integer operation failed due to the unsigned integer error `{:?}`",
            error
        );

        Self::new(message)
    }

    pub fn synthesis(error: SynthesisError) -> Self {
        let message = format!("integer operation failed due to the synthesis error `{}`", error);

        Self::new(message)
    }

    pub fn negate_operation() -> Self {
        let message = "integer negation can only be enforced on signed integers".to_string();

        Self::new(message)
    }

    pub fn binary_operation(operation: String) -> Self {
        let message = format!(
            "the integer binary operation `{}` can only be enforced on integers of the same type",
            operation
        );

        Self::new(message)
    }

    pub fn invalid_integer(actual: String) -> Self {
        let message = format!("failed to parse `{}` as expected integer type", actual);

        Self::new(message)
    }

    pub fn missing_integer(expected: String) -> Self {
        let message = format!("expected integer input `{}` not found", expected);

        Self::new(message)
    }

    pub fn cannot_evaluate(operation: String) -> Self {
        let message = format!("no implementation found for `{}`", operation);

        Self::new(message)
    }
}
