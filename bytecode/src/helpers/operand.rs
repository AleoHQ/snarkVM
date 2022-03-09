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

use crate::{Immediate, Memory, Register};
use snarkvm_circuits::{Environment, Mode, Parser, ParserResult};

use core::fmt;
use nom::{branch::alt, combinator::map};
use snarkvm_utilities::{error, FromBytes, ToBytes};
use std::io::{Read, Result as IoResult, Write};

#[derive(Clone)]
pub enum Operand<E: Environment> {
    Immediate(Immediate<E>),
    Register(Register<E>),
}

impl<E: Environment> Operand<E> {
    /// Returns `true` if the value type is an immediate.
    pub fn is_immediate(&self) -> bool {
        matches!(self, Self::Immediate(..))
    }

    /// Returns `true` if the value type is a register.
    pub fn is_register(&self) -> bool {
        matches!(self, Self::Register(..))
    }

    /// Returns the immediate from a register, otherwise passes the stored immediate through.
    pub(crate) fn load<M: Memory<Environment = E>>(&self, memory: &M) -> Immediate<M::Environment> {
        match self {
            Self::Immediate(immediate) => immediate.clone(),
            Self::Register(register) => memory.load(register),
        }
    }
}

impl<E: Environment> From<Immediate<E>> for Operand<E> {
    /// Ensures that the given immediate is a constant.
    fn from(immediate: Immediate<E>) -> Operand<E> {
        match immediate.mode() {
            Mode::Constant => Operand::Immediate(immediate),
            mode => E::halt(format!("Attempted to assign a {} immediate", mode)),
        }
    }
}

impl<E: Environment> From<&Immediate<E>> for Operand<E> {
    /// Ensures that the given immediate is a constant.
    fn from(immediate: &Immediate<E>) -> Operand<E> {
        Operand::from(immediate.clone())
    }
}

impl<E: Environment> From<Register<E>> for Operand<E> {
    fn from(register: Register<E>) -> Operand<E> {
        Operand::Register(register)
    }
}

impl<E: Environment> From<&Register<E>> for Operand<E> {
    fn from(register: &Register<E>) -> Operand<E> {
        Operand::from(*register)
    }
}

impl<E: Environment> Parser for Operand<E> {
    type Environment = E;

    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "operand"
    }

    /// Parses a string into an operand.
    #[inline]
    fn parse(string: &str) -> ParserResult<Self> {
        alt((
            map(Immediate::parse, |immediate| Self::Immediate(immediate)),
            map(Register::parse, |register| Self::Register(register)),
        ))(string)
    }
}

impl<E: Environment> fmt::Display for Operand<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Immediate(immediate) => immediate.fmt(f),
            Self::Register(register) => register.fmt(f),
        }
    }
}

impl<E: Environment> ToBytes for Operand<E> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()>
    where
        Self: Sized,
    {
        match self {
            Self::Immediate(immediate) => {
                u8::write_le(&(0u8), &mut writer)?;
                immediate.write_le(&mut writer)
            }
            Self::Register(register) => {
                u8::write_le(&(1u8), &mut writer)?;
                register.write_le(&mut writer)
            }
        }
    }
}

impl<E: Environment> FromBytes for Operand<E> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self>
    where
        Self: Sized,
    {
        match u8::read_le(&mut reader) {
            Ok(0) => Ok(Self::Immediate(Immediate::read_le(&mut reader)?)),
            Ok(1) => Ok(Self::Register(Register::read_le(&mut reader)?)),
            Ok(_) => Err(error("FromBytes::read failed for Operand")),
            Err(err) => Err(err),
        }
    }
}
