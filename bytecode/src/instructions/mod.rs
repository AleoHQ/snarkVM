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

pub mod add;
pub use add::*;

pub mod store;
pub use store::*;

pub mod sub;
pub use sub::*;

use crate::{Memory, Operation, Sanitizer};
use snarkvm_circuits::{Environment, Parser, ParserResult};

use core::fmt;
use nom::{
    branch::alt,
    bytes::complete::tag,
    combinator::map,
    sequence::{pair, preceded},
};

pub enum Instruction<E: Environment> {
    /// Adds `first` with `second`, storing the outcome in `destination`.
    Add(Add<E>),
    /// Stores `operand` into `register`, if `destination` is not already set.
    Store(Store<E>),
    /// Subtracts `first` from `second`, storing the outcome in `destination`.
    Sub(Sub<E>),
}

impl<E: Environment> Instruction<E> {
    /// Returns the opcode of the instruction.
    #[inline]
    pub(crate) fn opcode(&self) -> &'static str {
        match self {
            Self::Add(..) => "add",
            Self::Store(..) => "store",
            Self::Sub(..) => "sub",
        }
    }

    /// Evaluates the instruction.
    pub(crate) fn evaluate<M: Memory<Environment = E>>(&self, memory: &M) {
        match self {
            Self::Add(instruction) => instruction.evaluate(memory),
            Self::Store(instruction) => instruction.evaluate(memory),
            Self::Sub(instruction) => instruction.evaluate(memory),
        }
    }

    /// Parses a string into an instruction.
    #[inline]
    pub(crate) fn parse<'a, M: Memory<Environment = E>>(string: &'a str, memory: &'a mut M) -> ParserResult<'a, Self> {
        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the instruction from the string.
        let (string, instruction) = alt((
            // Note that order of the individual parsers matters.
            preceded(
                pair(tag(Add::<E>::opcode()), tag(" ")),
                map(|s| Add::parse(s, memory), |operation| operation.into()),
            ),
            preceded(
                pair(tag(Store::<E>::opcode()), tag(" ")),
                map(|s| Store::parse(s, memory), |operation| operation.into()),
            ),
            preceded(
                pair(tag(Sub::<E>::opcode()), tag(" ")),
                map(|s| Sub::parse(s, memory), |operation| operation.into()),
            ),
        ))(string)?;

        // let (string, (_, _)) = pair(tag(Add::<E>::opcode()), tag(" "))(string)?;
        // let (string, operation) = Add::parse(string, memory)?;
        // let instruction = operation.into();

        // Parse the semicolon from the string.
        let (string, _) = tag(";")(string)?;

        Ok((string, instruction))
    }
}

impl<E: Environment> fmt::Display for Instruction<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Add(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Store(instruction) => write!(f, "{} {};", self.opcode(), instruction),
            Self::Sub(instruction) => write!(f, "{} {};", self.opcode(), instruction),
        }
    }
}
