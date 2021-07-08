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

mod group;
pub use group::*;
mod address;
pub use address::*;
mod field;
pub use field::*;
mod integer;
pub use integer::*;
use snarkvm_r1cs::SynthesisError;
mod char;
pub use self::char::*;
mod boolean;
pub use self::boolean::*;
mod array;
pub use self::array::*;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ValueError {
    #[error("{}", _0)]
    Error(String),

    #[error("{}", _0)]
    AddressError(#[from] AddressError),

    #[error("{}", _0)]
    BooleanError(#[from] BooleanError),

    #[error("{}", _0)]
    FieldError(#[from] FieldError),

    #[error("{}", _0)]
    CharError(#[from] CharError),

    #[error("{}", _0)]
    GroupError(#[from] GroupError),

    #[error("{}", _0)]
    IntegerError(#[from] IntegerError),

    #[error("{}", _0)]
    ArrayError(#[from] ArrayError),
}

impl ValueError {
    fn new(message: String) -> Self {
        ValueError::Error(message)
    }

    pub fn incompatible_types(operation: &str) -> Self {
        let message = format!("no implementation for `{}`", operation);

        Self::new(message)
    }

    pub fn bad_value_for_type(type_: &str, value: &str) -> Self {
        let message = format!("expected '{}' but got value '{}'", type_, value);

        Self::new(message)
    }

    pub fn cannot_enforce(operation: &str, error: SynthesisError) -> Self {
        let message = format!(
            "the gadget operation `{}` failed due to synthesis error `{:?}`",
            operation, error,
        );

        Self::new(message)
    }
}
