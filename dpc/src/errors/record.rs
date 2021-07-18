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

use snarkvm_algorithms::{CRHError, CommitmentError, EncryptionError, PRFError, SignatureError};

#[derive(Debug, Error)]
pub enum RecordError {
    #[error("{}", _0)]
    AccountError(#[from] crate::AccountError),

    #[error("{}", _0)]
    AnyhowError(#[from] anyhow::Error),

    #[error("Failed to build Record data type. See console logs for error")]
    BuilderError,

    #[error("Cannot verify the provided record commitment")]
    CannotVerifyCommitment,

    #[error("{}", _0)]
    CommitmentError(#[from] CommitmentError),

    #[error("{}: {}", _0, _1)]
    Crate(&'static str, String),

    #[error("{}", _0)]
    CRHError(#[from] CRHError),

    #[error("Attempted to set `value: {}` on a dummy record", _0)]
    DummyMustBeZero(u64),

    #[error("{}", _0)]
    EncryptionError(#[from] EncryptionError),

    #[error("{}", _0)]
    FromHexError(#[from] hex::FromHexError),

    #[error("Given private key does not correspond to the record owner")]
    IncorrectPrivateKey,

    #[error("Attempted to build a record with an invalid commitment. Try `calculate_commitment()`")]
    InvalidCommitment,

    #[error("Missing Record field: {0}")]
    MissingField(String),

    #[error("Missing commitment randomness")]
    MissingRandomness,

    #[error("Attempted to set `is_dummy: true` on a record with a non-zero value")]
    NonZeroValue,

    #[error("{}", _0)]
    PRFError(#[from] PRFError),

    #[error("{}", _0)]
    SignatureError(#[from] SignatureError),
}

impl From<std::io::Error> for RecordError {
    fn from(error: std::io::Error) -> Self {
        RecordError::Crate("std::io", format!("{:?}", error))
    }
}
