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

use crate::{account_format, traits::DPCComponents, AccountError, PrivateKey};
use snarkvm_algorithms::{traits::EncryptionScheme, SignatureScheme};
use snarkvm_utilities::{FromBytes, ToBytes};

use base58::{FromBase58, ToBase58};
use rand::{CryptoRng, Rng};
use std::{
    fmt,
    io::{Read, Result as IoResult, Write},
    str::FromStr,
};

#[derive(Derivative)]
#[derivative(
    Default(bound = "C: DPCComponents"),
    Clone(bound = "C: DPCComponents"),
    PartialEq(bound = "C: DPCComponents"),
    Eq(bound = "C: DPCComponents")
)]
pub struct ViewKey<C: DPCComponents> {
    pub decryption_key: <C::AccountEncryption as EncryptionScheme>::PrivateKey,
}

impl<C: DPCComponents> ViewKey<C> {
    /// Creates a new account view key from an account private key.
    pub fn from_private_key(private_key: &PrivateKey<C>) -> Result<Self, AccountError> {
        Ok(Self {
            decryption_key: private_key.to_decryption_key()?,
        })
    }

    /// Signs a message using the account view key.
    pub fn sign<R: Rng + CryptoRng>(
        &self,
        message: &[u8],
        rng: &mut R,
    ) -> Result<<C::AccountSignature as SignatureScheme>::Signature, AccountError> {
        let signature_private_key = FromBytes::from_bytes_le(&self.decryption_key.to_bytes_le()?)?;
        Ok(C::account_signature().sign(&signature_private_key, message, rng)?)
    }
}

impl<C: DPCComponents> ToBytes for ViewKey<C> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.decryption_key.write_le(&mut writer)
    }
}

impl<C: DPCComponents> FromBytes for ViewKey<C> {
    /// Reads in an account view key buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        Ok(Self {
            decryption_key: <C::AccountEncryption as EncryptionScheme>::PrivateKey::read_le(&mut reader)?,
        })
    }
}

impl<C: DPCComponents> FromStr for ViewKey<C> {
    type Err = AccountError;

    /// Reads in an account view key string.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let data = s.from_base58()?;
        if data.len() != 39 {
            return Err(AccountError::InvalidByteLength(data.len()));
        }

        if data[0..7] != account_format::VIEW_KEY_PREFIX {
            return Err(AccountError::InvalidPrefixBytes(data[0..7].to_vec()));
        }

        let mut reader = &data[7..];

        Ok(Self {
            decryption_key: FromBytes::read_le(&mut reader)?,
        })
    }
}

impl<C: DPCComponents> fmt::Display for ViewKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut view_key = [0u8; 39];
        view_key[0..7].copy_from_slice(&account_format::VIEW_KEY_PREFIX);

        self.decryption_key
            .write_le(&mut view_key[7..39])
            .expect("decryption_key formatting failed");

        write!(f, "{}", view_key.to_base58())
    }
}

impl<C: DPCComponents> fmt::Debug for ViewKey<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "ViewKey {{ decryption_key: {:?} }}", self.decryption_key)
    }
}
