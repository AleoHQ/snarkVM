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

use crate::errors::SNARKError;
use snarkvm_utilities::{FromBytes, ToBytes};

use rand::Rng;
use std::fmt::Debug;

/// Defines a trait that describes preparing from an unprepared version to a prepare version
pub trait Prepare<T> {
    fn prepare(&self) -> T;
}

pub trait SNARK {
    type AllocatedCircuit;
    type Circuit;
    type PreparedVerifyingKey: Clone;
    type Proof: Clone + Debug + ToBytes + FromBytes;
    type ProvingKey: Clone + ToBytes + FromBytes;
    type VerifierInput: ?Sized;
    type VerifyingKey: Clone
        + ToBytes
        + FromBytes
        + Prepare<Self::PreparedVerifyingKey>
        + From<Self::PreparedVerifyingKey>
        + From<Self::ProvingKey>;

    fn setup<R: Rng>(
        circuit: &Self::Circuit,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), SNARKError>;

    fn prove<R: Rng>(
        proving_key: &Self::ProvingKey,
        input_and_witness: &Self::AllocatedCircuit,
        rng: &mut R,
    ) -> Result<Self::Proof, SNARKError>;

    fn verify_prepared(
        prepared_verifying_key: &Self::PreparedVerifyingKey,
        input: &Self::VerifierInput,
        proof: &Self::Proof,
    ) -> Result<bool, SNARKError>;

    fn verify(
        verifying_key: &Self::VerifyingKey,
        input: &Self::VerifierInput,
        proof: &Self::Proof,
    ) -> Result<bool, SNARKError> {
        let processed_verifying_key = verifying_key.prepare();
        Self::verify_prepared(&processed_verifying_key, input, proof)
    }
}
