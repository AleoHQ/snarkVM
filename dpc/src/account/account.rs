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

use crate::{
    errors::AccountError,
    traits::{AccountScheme, DPCComponents},
    Address,
    PrivateKey,
};

use rand::{CryptoRng, Rng};
use std::fmt;

#[derive(Derivative)]
#[derivative(Clone(bound = "C: DPCComponents"))]
pub struct Account<C: DPCComponents> {
    pub private_key: PrivateKey<C>,
    pub address: Address<C>,
}

impl<C: DPCComponents> AccountScheme for Account<C> {
    type Address = Address<C>;
    type PrivateKey = PrivateKey<C>;

    /// Creates a new account.
    fn new<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self, AccountError> {
        let private_key = PrivateKey::new(rng)?;
        let address = Address::from_private_key(&private_key)?;

        Ok(Self { private_key, address })
    }
}

impl<C: DPCComponents> fmt::Display for Account<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Account {{ private_key: {}, address: {} }}",
            self.private_key, self.address,
        )
    }
}

impl<C: DPCComponents> fmt::Debug for Account<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Account {{ private_key: {:?}, address: {:?} }}",
            self.private_key, self.address,
        )
    }
}
