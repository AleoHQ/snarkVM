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

use crate::{instructions::Instruction, Argument, Immediate, Memory, Operation, Register};
use snarkvm_circuits::{Mode, Parser, ParserResult};

use core::fmt;
use nom::bytes::complete::tag;

/// Declares a `register` as a function output with type `annotation`.
pub struct Output<M: Memory> {
    argument: Argument<M::Environment>,
}

impl<M: Memory> Output<M> {
    /// Initializes a new output register.
    pub fn new(argument: Argument<M::Environment>) -> Self {
        Self { argument }
    }
}

impl<M: Memory> Operation for Output<M> {
    type Memory = M;

    const OPCODE: &'static str = "output";

    /// Evaluates the operation in-place.
    fn evaluate(&self) {
        M::store_output(&self.argument)
    }
}

impl<M: Memory> Parser for Output<M> {
    type Environment = M::Environment;

    /// Parses a string into an input.
    #[inline]
    fn parse(string: &str) -> ParserResult<Self> {
        // Parse the input keyword from the string.
        let (string, _) = tag(Self::OPCODE)(string)?;
        // Parse the space from the string.
        let (string, _) = tag(" ")(string)?;
        // Parse the argument from the string.
        let (string, argument) = Argument::parse(string)?;
        // Parse the semicolon from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, Output::new(argument)))
    }
}

impl<M: Memory> fmt::Display for Output<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {};", Self::OPCODE, self.argument)
    }
}

#[allow(clippy::from_over_into)]
impl<M: Memory> Into<Instruction<M>> for Output<M> {
    /// Converts the operation into an instruction.
    fn into(self) -> Instruction<M> {
        Instruction::Output(self)
    }
}
