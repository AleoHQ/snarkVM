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

use snarkvm_circuits::{Affine, BaseField, Boolean, Eject, Environment, Inject, Mode, Parser, ParserResult, Scalar};
use snarkvm_utilities::{error, FromBytes, ToBytes};

use core::fmt;
use nom::{branch::alt, combinator::map};
use std::io::{Read, Result as IoResult, Write};

#[derive(Clone)]
pub enum Immediate<E: Environment> {
    Boolean(Boolean<E>),
    Field(BaseField<E>),
    Group(Affine<E>),
    Scalar(Scalar<E>),
}

impl<E: Environment> Immediate<E> {
    /// Returns the type name of the immediate.
    pub fn type_name(&self) -> &'static str {
        match self {
            Self::Boolean(..) => Boolean::<E>::type_name(),
            Self::Field(..) => BaseField::<E>::type_name(),
            Self::Group(..) => Affine::<E>::type_name(),
            Self::Scalar(..) => Scalar::<E>::type_name(),
        }
    }

    /// Returns the mode of the immediate.
    pub fn mode(&self) -> Mode {
        match self {
            Self::Boolean(boolean) => boolean.eject_mode(),
            Self::Field(field) => field.eject_mode(),
            Self::Group(group) => group.eject_mode(),
            Self::Scalar(scalar) => scalar.eject_mode(),
        }
    }

    /// Returns `true` if the immediate is a constant.
    pub fn is_constant(&self) -> bool {
        self.mode().is_constant()
    }

    /// Returns `true` if the immediate is public.
    pub fn is_public(&self) -> bool {
        self.mode().is_public()
    }

    /// Returns `true` if the immediate is private.
    pub fn is_private(&self) -> bool {
        self.mode().is_private()
    }
}

impl<E: Environment> From<Boolean<E>> for Immediate<E> {
    #[inline]
    fn from(boolean: Boolean<E>) -> Self {
        Self::Boolean(boolean)
    }
}

impl<E: Environment> From<BaseField<E>> for Immediate<E> {
    #[inline]
    fn from(field: BaseField<E>) -> Self {
        Self::Field(field)
    }
}

impl<E: Environment> From<Affine<E>> for Immediate<E> {
    #[inline]
    fn from(group: Affine<E>) -> Self {
        Self::Group(group)
    }
}

impl<E: Environment> From<Scalar<E>> for Immediate<E> {
    #[inline]
    fn from(scalar: Scalar<E>) -> Self {
        Self::Scalar(scalar)
    }
}

impl<E: Environment> Parser for Immediate<E> {
    type Environment = E;

    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "immediate"
    }

    /// Parses a string into an immediate.
    #[inline]
    fn parse(string: &str) -> ParserResult<Self> {
        alt((
            map(Boolean::parse, |boolean| Self::Boolean(boolean)),
            map(BaseField::parse, |field| Self::Field(field)),
            map(Affine::parse, |group| Self::Group(group)),
            map(Scalar::parse, |scalar| Self::Scalar(scalar)),
        ))(string)
    }
}

impl<E: Environment> fmt::Debug for Immediate<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Boolean(boolean) => boolean.fmt(f),
            Self::Field(field) => field.fmt(f),
            Self::Group(group) => group.fmt(f),
            Self::Scalar(scalar) => scalar.fmt(f),
        }
    }
}

impl<E: Environment> fmt::Display for Immediate<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Boolean(boolean) => boolean.fmt(f),
            Self::Field(field) => field.fmt(f),
            Self::Group(group) => group.fmt(f),
            Self::Scalar(scalar) => scalar.fmt(f),
        }
    }
}

impl<E: Environment> PartialEq for Immediate<E> {
    fn eq(&self, other: &Self) -> bool {
        self.mode() == other.mode()
            && match (self, other) {
                (Self::Boolean(this), Self::Boolean(that)) => this.eject_value() == that.eject_value(),
                (Self::Field(this), Self::Field(that)) => this.eject_value() == that.eject_value(),
                (Self::Group(this), Self::Group(that)) => this.eject_value() == that.eject_value(),
                (Self::Scalar(this), Self::Scalar(that)) => this.eject_value() == that.eject_value(),
                _ => false,
            }
    }
}

impl<E: Environment> Eq for Immediate<E> {}

impl<E: Environment> FromBytes for Immediate<E> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let type_ = u8::read_le(&mut reader)?;
        let mode = Mode::read_le(&mut reader)?;
        match type_ {
            0 => Ok(Self::Boolean(Boolean::new(mode, FromBytes::read_le(&mut reader)?))),
            1 => Ok(Self::Field(BaseField::new(mode, FromBytes::read_le(&mut reader)?))),
            2 => Ok(Self::Group(Affine::new(
                mode,
                (FromBytes::read_le(&mut reader)?, Some(FromBytes::read_le(&mut reader)?)),
            ))),
            3 => Ok(Self::Scalar(Scalar::new(mode, FromBytes::read_le(&mut reader)?))),
            _ => Err(error(format!("FromBytes failed to parse an immediate of type {type_}"))),
        }
    }
}

impl<E: Environment> ToBytes for Immediate<E> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Boolean(immediate) => {
                u8::write_le(&0u8, &mut writer)?;
                immediate.eject_mode().write_le(&mut writer)?;
                immediate.eject_value().write_le(&mut writer)
            }
            Self::Field(immediate) => {
                u8::write_le(&1u8, &mut writer)?;
                immediate.eject_mode().write_le(&mut writer)?;
                immediate.eject_value().write_le(&mut writer)
            }
            Self::Group(immediate) => {
                u8::write_le(&2u8, &mut writer)?;
                immediate.eject_mode().write_le(&mut writer)?;
                immediate.eject_value().write_le(&mut writer)
            }
            Self::Scalar(immediate) => {
                u8::write_le(&3u8, &mut writer)?;
                immediate.eject_mode().write_le(&mut writer)?;
                immediate.eject_value().write_le(&mut writer)
            }
        }
    }
}
