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

use snarkvm_dpc::AccountError;

#[derive(Debug, Error)]
pub enum AddressError {
    #[error("{}", _0)]
    Error(String),
    #[error("{}", _0)]
    SynthesisError(#[from] SynthesisError),
}

impl AddressError {
    fn new(message: String) -> Self {
        AddressError::Error(message)
    }

    pub fn account_error(error: AccountError) -> Self {
        let message = format!("account creation failed due to `{}`", error);

        Self::new(message)
    }

    pub fn invalid_address(name: &str) -> Self {
        let message = format!("invalid address value for {}", name);

        Self::new(message)
    }

    pub fn missing_address(name: &str) -> Self {
        let message = format!("expected address input not found for {}", name);

        Self::new(message)
    }
}
