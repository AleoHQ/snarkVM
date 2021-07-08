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

use std::fmt;

use crate::ir;

use anyhow::*;

#[derive(Clone, Debug, PartialEq)]
pub enum Type {
    Address,
    Boolean,
    Field,
    Char,
    Group,

    U8,
    U16,
    U32,
    U64,
    U128,
    I8,
    I16,
    I32,
    I64,
    I128,

    Array(Box<Type>, u32),
    Tuple(Vec<Type>),
    Circuit(Vec<(String, Type)>), // represented as a Tuple internally, used for input type description
}

impl Type {
    pub(crate) fn decode(mut type_: ir::Type) -> Result<Self> {
        Ok(match type_.class {
            x if x == ir::TypeClass::TypeAddress as i32 => Type::Address,
            x if x == ir::TypeClass::TypeBoolean as i32 => Type::Boolean,
            x if x == ir::TypeClass::TypeField as i32 => Type::Field,
            x if x == ir::TypeClass::TypeChar as i32 => Type::Char,
            x if x == ir::TypeClass::TypeGroup as i32 => Type::Group,
            x if x == ir::TypeClass::TypeU8 as i32 => Type::U8,
            x if x == ir::TypeClass::TypeU16 as i32 => Type::U16,
            x if x == ir::TypeClass::TypeU32 as i32 => Type::U32,
            x if x == ir::TypeClass::TypeU64 as i32 => Type::U64,
            x if x == ir::TypeClass::TypeU128 as i32 => Type::U128,
            x if x == ir::TypeClass::TypeI8 as i32 => Type::I8,
            x if x == ir::TypeClass::TypeI16 as i32 => Type::I16,
            x if x == ir::TypeClass::TypeI32 as i32 => Type::I32,
            x if x == ir::TypeClass::TypeI64 as i32 => Type::I64,
            x if x == ir::TypeClass::TypeI128 as i32 => Type::I128,
            x if x == ir::TypeClass::TypeArray as i32 => {
                if type_.subtypes.len() != 1 {
                    return Err(anyhow!("invalid subtypes length for array: {}", type_.subtypes.len()));
                }
                Type::Array(Box::new(Type::decode(type_.subtypes.remove(0))?), type_.array_length)
            }
            x if x == ir::TypeClass::TypeTuple as i32 => Type::Tuple(
                type_
                    .subtypes
                    .into_iter()
                    .map(Type::decode)
                    .collect::<Result<Vec<Type>>>()?,
            ),
            x => return Err(anyhow!("unknown type enum: {}", x)),
        })
    }

    pub(crate) fn encode(&self) -> ir::Type {
        ir::Type {
            class: match self {
                Type::Address => ir::TypeClass::TypeAddress as i32,
                Type::Boolean => ir::TypeClass::TypeBoolean as i32,
                Type::Field => ir::TypeClass::TypeField as i32,
                Type::Char => ir::TypeClass::TypeChar as i32,
                Type::Group => ir::TypeClass::TypeGroup as i32,
                Type::U8 => ir::TypeClass::TypeU8 as i32,
                Type::U16 => ir::TypeClass::TypeU16 as i32,
                Type::U32 => ir::TypeClass::TypeU32 as i32,
                Type::U64 => ir::TypeClass::TypeU64 as i32,
                Type::U128 => ir::TypeClass::TypeU128 as i32,
                Type::I8 => ir::TypeClass::TypeI8 as i32,
                Type::I16 => ir::TypeClass::TypeI16 as i32,
                Type::I32 => ir::TypeClass::TypeI32 as i32,
                Type::I64 => ir::TypeClass::TypeI64 as i32,
                Type::I128 => ir::TypeClass::TypeI128 as i32,
                Type::Array(_, _) => ir::TypeClass::TypeArray as i32,
                Type::Tuple(_) => ir::TypeClass::TypeTuple as i32,
                Type::Circuit(_) => ir::TypeClass::TypeCircuit as i32,
            },
            array_length: match self {
                Type::Array(_, length) => *length,
                _ => 0,
            },
            subtypes: match self {
                Type::Array(item, _) => vec![item.encode()],
                Type::Tuple(items) => items.iter().map(|x| x.encode()).collect(),
                Type::Circuit(items) => items.iter().map(|(_, x)| x.encode()).collect(),
                _ => vec![],
            },
            subtype_names: match self {
                Type::Circuit(items) => items.iter().map(|(x, _)| x.clone()).collect(),
                _ => vec![],
            },
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Type::Address => write!(f, "address"),
            Type::Boolean => write!(f, "bool"),
            Type::Field => write!(f, "field"),
            Type::Char => write!(f, "char"),
            Type::Group => write!(f, "group"),
            Type::U8 => write!(f, "u8"),
            Type::U16 => write!(f, "u16"),
            Type::U32 => write!(f, "u32"),
            Type::U64 => write!(f, "u64"),
            Type::U128 => write!(f, "u128"),
            Type::I8 => write!(f, "i8"),
            Type::I16 => write!(f, "i16"),
            Type::I32 => write!(f, "i32"),
            Type::I64 => write!(f, "i64"),
            Type::I128 => write!(f, "i128"),
            Type::Array(inner, len) => write!(f, "[{}; {}]", inner, len),
            Type::Tuple(inner) => {
                write!(f, "(")?;
                for (i, type_) in inner.iter().enumerate() {
                    write!(f, "{}{}", if i != 0 { ", " } else { "" }, type_)?;
                }
                write!(f, ")")
            }
            Type::Circuit(inner) => {
                write!(f, "{{")?;
                for (i, (name, type_)) in inner.iter().enumerate() {
                    write!(f, "{}{}: {}", if i != 0 { ", " } else { "" }, name, type_)?;
                }
                write!(f, "}}")
            }
        }
    }
}
