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

use crate::errors::SignatureError;
use snarkvm_utilities::{
    serialize::{CanonicalDeserialize, CanonicalSerialize},
    FromBytes,
    ToBytes,
};

use rand::{CryptoRng, Rng};
use std::{fmt::Debug, hash::Hash};

pub trait SignatureScheme:
    Sized + ToBytes + FromBytes + Debug + Clone + Eq + Send + Sync + From<<Self as SignatureScheme>::Parameters>
{
    type Parameters: Clone + Debug + Eq;
    type PublicKey: Clone
        + Debug
        + Default
        + ToBytes
        + FromBytes
        + Hash
        + Eq
        + Send
        + Sync
        + CanonicalSerialize
        + CanonicalDeserialize;
    type PrivateKey: Clone + Debug + Default + ToBytes + FromBytes + PartialEq + Eq;
    type RandomizedPrivateKey: Clone + Debug + Default + ToBytes + FromBytes + PartialEq + Eq + Into<Self::PrivateKey>;
    type Randomizer: Clone + Debug + Default + ToBytes + FromBytes + PartialEq + Eq;
    type Signature: Clone + Debug + Default + ToBytes + FromBytes + Send + Sync + PartialEq + Eq;

    fn setup(message: &str) -> Self;

    fn parameters(&self) -> &Self::Parameters;

    fn generate_private_key<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<Self::PrivateKey, SignatureError>;

    fn generate_public_key(&self, private_key: &Self::PrivateKey) -> Result<Self::PublicKey, SignatureError>;

    fn randomize_private_key(
        &self,
        private_key: &Self::PrivateKey,
        randomizer: &Self::Randomizer,
    ) -> Result<Self::RandomizedPrivateKey, SignatureError>;

    fn randomize_public_key(
        &self,
        public_key: &Self::PublicKey,
        randomizer: &Self::Randomizer,
    ) -> Result<Self::PublicKey, SignatureError>;

    fn sign<R: Rng + CryptoRng>(
        &self,
        private_key: &Self::PrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, SignatureError>;

    fn sign_randomized<R: Rng + CryptoRng>(
        &self,
        randomized_private_key: &Self::RandomizedPrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, SignatureError>;

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, SignatureError>;
}
