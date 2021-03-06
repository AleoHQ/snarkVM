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

use crate::errors::DPCError;

use rand::Rng;

pub trait Program: Clone {
    type LocalData;
    type PublicInput;
    type PrivateWitness;
    type ProvingKey;
    type VerifyingKey;

    /// Executes and returns the program proof
    fn execute<R: Rng>(
        &self,
        proving_key: &Self::ProvingKey,
        verification_key: &Self::VerifyingKey,
        local_data: &Self::LocalData,
        position: u8,
        rng: &mut R,
    ) -> Result<Self::PrivateWitness, DPCError>;

    /// Returns the evaluation of the program on given input and witness.
    fn evaluate(&self, primary: &Self::PublicInput, witness: &Self::PrivateWitness) -> bool;

    /// Returns the program identity
    #[allow(clippy::wrong_self_convention)]
    fn into_compact_repr(&self) -> Vec<u8>;
}
