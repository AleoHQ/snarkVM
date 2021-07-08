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

use snarkvm_r1cs::SynthesisError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GroupError {
    #[error("{}", _0)]
    Error(String),
}

impl GroupError {
    fn new(message: String) -> Self {
        GroupError::Error(message)
    }

    pub fn negate_operation(error: SynthesisError) -> Self {
        let message = format!("group negation failed due to the synthesis error `{:?}`", error,);

        Self::new(message)
    }

    pub fn binary_operation(operation: String, error: SynthesisError) -> Self {
        let message = format!(
            "the group binary operation `{}` failed due to the synthesis error `{:?}`",
            operation, error,
        );

        Self::new(message)
    }

    pub fn invalid_group(actual: String) -> Self {
        let message = format!("expected group affine point input type, found `{}`", actual);

        Self::new(message)
    }

    pub fn missing_group(expected: String) -> Self {
        let message = format!("expected group input `{}` not found", expected);

        Self::new(message)
    }

    pub fn synthesis_error(error: SynthesisError) -> Self {
        let message = format!("compilation failed due to group synthesis error `{:?}`", error);

        Self::new(message)
    }

    pub fn x_invalid(x: String) -> Self {
        let message = format!("invalid x coordinate `{}`", x);

        Self::new(message)
    }

    pub fn y_invalid(y: String) -> Self {
        let message = format!("invalid y coordinate `{}`", y);

        Self::new(message)
    }

    pub fn not_on_curve(element: String) -> Self {
        let message = format!("group element `{}` is not on the supported curve", element);

        Self::new(message)
    }

    pub fn x_recover() -> Self {
        let message = "could not recover group element from x coordinate".to_string();

        Self::new(message)
    }

    pub fn y_recover() -> Self {
        let message = "could not recover group element from y coordinate".to_string();

        Self::new(message)
    }

    pub fn n_group(number: String) -> Self {
        let message = format!("cannot multiply group generator by \"{}\"", number);

        Self::new(message)
    }
}
