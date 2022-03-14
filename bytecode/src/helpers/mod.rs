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

pub mod argument;
pub use argument::*;

pub mod operand;
pub use operand::*;

pub mod register;
pub use register::*;

pub mod variable_length;
pub use variable_length::*;

use crate::Memory;
use snarkvm_circuits::ParserResult;

use core::fmt::Display;

// pub trait Operation: Parser + Into<Instruction<Self::Memory>> {
pub trait Operation: Display {
    type Memory: Memory;

    ///
    /// Returns the opcode of the instruction.
    ///
    fn opcode() -> &'static str;

    ///
    /// Evaluates the instruction in-place.
    ///
    fn evaluate(&self, memory: &Self::Memory);

    ///
    /// Parses a string literal into an object.
    ///
    fn parse(string: &str, memory: Self::Memory) -> ParserResult<Self>
    where
        Self: Sized;

    ///
    /// Returns an object from a string literal.
    ///
    fn from_str(string: &str, memory: &Self::Memory) -> Self
    where
        Self: Sized,
    {
        match Self::parse(string, memory.clone()) {
            Ok((_, circuit)) => circuit,
            Err(error) => Self::Memory::halt(format!("Failed to parse: {}", error)),
        }
    }
}
