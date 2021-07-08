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

use snarkvm_r1cs::SynthesisError;

#[derive(Debug, Error)]
pub enum BooleanError {
    #[error("{}", _0)]
    Error(String),
}

impl BooleanError {
    fn new(message: String) -> Self {
        BooleanError::Error(message)
    }

    pub fn cannot_enforce(operation: String, error: SynthesisError) -> Self {
        let message = format!(
            "the boolean operation `{}` failed due to the synthesis error `{:?}`",
            operation, error,
        );

        Self::new(message)
    }

    pub fn cannot_evaluate(operation: String) -> Self {
        let message = format!("no implementation found for `{}`", operation);

        Self::new(message)
    }

    pub fn invalid_boolean(actual: String) -> Self {
        let message = format!("expected boolean input type, found `{}`", actual);

        Self::new(message)
    }

    pub fn missing_boolean(expected: String) -> Self {
        let message = format!("expected boolean input `{}` not found", expected);

        Self::new(message)
    }
}
