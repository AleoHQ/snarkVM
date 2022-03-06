// Copyright (C) 2019-2022 Aleo Systems Inc.
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

pub mod global;
pub use global::*;

pub mod local;

use crate::{instructions::Instruction, Immediate, Memory, Register};
use snarkvm_circuits::{Environment, Parser};

use core::hash;

pub trait Function: Parser + Copy + Clone + Eq + PartialEq + hash::Hash {
    type Environment: Environment;
    type Memory: Memory<Environment = <Self as Function>::Environment>;

    /// Allocates a new input in memory, returning the new register.
    fn new_input(input: Immediate<<Self as Function>::Environment>) -> Register<<Self as Function>::Environment>;

    /// Adds the given instruction.
    fn push_instruction(instruction: Instruction<Self::Memory>);

    /// Evaluates the function, returning the outputs.
    fn evaluate() -> Vec<Immediate<<Self as Function>::Environment>>;

    /// Clears and initializes a new function layout.
    fn reset();
}
