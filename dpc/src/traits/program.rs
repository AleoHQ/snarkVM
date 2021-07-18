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

use crate::errors::ProgramError;
use snarkvm_algorithms::SNARK;

use core::fmt::Debug;
use rand::{CryptoRng, Rng};

pub trait ProgramScheme: Clone {
    type ID: Debug;
    type LocalData;
    type LocalDataCommitment;
    type PublicInput;
    type Execution;
    type ProgramIDCRH;
    type ProofSystem: SNARK;
    type ProvingKey;
    type VerifyingKey;

    /// Initializes a new instance of a program.
    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self, ProgramError>;

    /// Loads an instance of a program.
    fn load() -> Result<Self, ProgramError>;

    /// Returns the execution of the program.
    fn execute<R: Rng + CryptoRng>(
        &self,
        local_data: &Self::LocalData,
        position: u8,
        rng: &mut R,
    ) -> Result<Self::Execution, ProgramError>;

    /// Returns the blank execution of the program, typically used for a SNARK setup.
    fn execute_blank<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<Self::Execution, ProgramError>;

    /// Returns the evaluation of the program on given input and witness.
    fn evaluate(&self, primary: &Self::PublicInput, witness: &Self::Execution) -> bool;

    /// Returns the program ID.
    fn id(&self) -> Self::ID;
}
