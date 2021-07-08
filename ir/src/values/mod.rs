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

use crate::{ir, Type};

use anyhow::*;
use bech32::ToBase32;

mod field;
pub use field::*;
mod group;
pub use group::*;

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Integer {
    U8(u8),
    U16(u16),
    U32(u32),
    U64(u64),
    U128(u128),

    I8(i8),
    I16(i16),
    I32(i32),
    I64(i64),
    I128(i128),
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Integer::U8(x) => write!(f, "{}", x),
            Integer::U16(x) => write!(f, "{}", x),
            Integer::U32(x) => write!(f, "{}", x),
            Integer::U64(x) => write!(f, "{}", x),
            Integer::U128(x) => write!(f, "{}", x),
            Integer::I8(x) => write!(f, "{}", x),
            Integer::I16(x) => write!(f, "{}", x),
            Integer::I32(x) => write!(f, "{}", x),
            Integer::I64(x) => write!(f, "{}", x),
            Integer::I128(x) => write!(f, "{}", x),
        }
    }
}

/// A constant value in IR representation or variable reference
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Address(Vec<u8>),
    Boolean(bool),
    Field(Field),
    Char(u32),
    Group(Group),
    Integer(Integer),
    Array(Vec<Value>),
    Tuple(Vec<Value>),
    Str(String), // not a language level string -- used for logs & core call ids
    Ref(u32),    // reference to a variable
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Address(bytes) => write!(
                f,
                "{}",
                bech32::encode("aleo", bytes.to_vec().to_base32(), bech32::Variant::Bech32).unwrap_or_default()
            ),
            Value::Boolean(x) => write!(f, "{}", x),
            Value::Field(field) => write!(f, "{}", field),
            Value::Char(c) => write!(
                f,
                "'{}'",
                std::char::from_u32(*c)
                    .unwrap_or(std::char::REPLACEMENT_CHARACTER)
                    .escape_default()
            ),
            Value::Group(group) => group.fmt(f),
            Value::Integer(x) => write!(f, "{}", x),
            Value::Array(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    write!(f, "{}{}", item, if i == items.len() - 1 { "" } else { ", " })?;
                }
                write!(f, "]")
            }
            Value::Tuple(items) => {
                write!(f, "(")?;
                for (i, item) in items.iter().enumerate() {
                    write!(f, "{}{}", item, if i == items.len() - 1 { "" } else { ", " })?;
                }
                write!(f, ")")
            }
            Value::Str(s) => write!(f, "\"{}\"", s),
            Value::Ref(x) => write!(f, "v{}", x),
        }
    }
}

impl Value {
    pub fn matches_input_type(&self, type_: &Type) -> bool {
        match (self, type_) {
            (Value::Address(_), Type::Address)
            | (Value::Boolean(_), Type::Boolean)
            | (Value::Field(_), Type::Field)
            | (Value::Char(_), Type::Char)
            | (Value::Group(_), Type::Group)
            | (Value::Integer(Integer::I8(_)), Type::I8)
            | (Value::Integer(Integer::I16(_)), Type::I16)
            | (Value::Integer(Integer::I32(_)), Type::I32)
            | (Value::Integer(Integer::I64(_)), Type::I64)
            | (Value::Integer(Integer::I128(_)), Type::I128)
            | (Value::Integer(Integer::U8(_)), Type::U8)
            | (Value::Integer(Integer::U16(_)), Type::U16)
            | (Value::Integer(Integer::U32(_)), Type::U32)
            | (Value::Integer(Integer::U64(_)), Type::U64)
            | (Value::Integer(Integer::U128(_)), Type::U128) => true,
            (Value::Array(inner), Type::Array(inner_type, len)) => {
                inner.len() == *len as usize && inner.iter().all(|inner| inner.matches_input_type(&**inner_type))
            }
            (Value::Tuple(values), Type::Tuple(types)) => values
                .iter()
                .zip(types.iter())
                .all(|(value, type_)| value.matches_input_type(type_)),
            (Value::Tuple(values), Type::Circuit(members)) => values
                .iter()
                .zip(members.iter())
                .all(|(value, (_, type_))| value.matches_input_type(type_)),
            (Value::Str(_), _) => panic!("illegal str type in input type"),
            (Value::Ref(_), _) => panic!("illegal ref in input type"),
            (_, _) => false,
        }
    }

    pub(crate) fn decode(from: ir::Operand) -> Result<Value> {
        Ok(match from {
            ir::Operand {
                address: Some(address), ..
            } if !address.address.is_empty() => Value::Address(address.address),
            ir::Operand {
                boolean: Some(boolean), ..
            } => Value::Boolean(boolean.boolean),
            ir::Operand { field: Some(field), .. } => Value::Field(Field::decode(field)),
            ir::Operand { char: Some(char), .. } => Value::Char(char.char),
            ir::Operand {
                group_single: Some(group_single),
                ..
            } => Value::Group(Group::Single(Field::decode(group_single))),
            ir::Operand {
                group_tuple:
                    Some(ir::Group {
                        left: Some(left),
                        right: Some(right),
                    }),
                ..
            } => Value::Group(Group::Tuple(
                GroupCoordinate::decode(left)?,
                GroupCoordinate::decode(right)?,
            )),
            ir::Operand { u8: Some(u8), .. } => Value::Integer(Integer::U8(u8.u8 as u8)),
            ir::Operand { u16: Some(u16), .. } => Value::Integer(Integer::U16(u16.u16 as u16)),
            ir::Operand { u32: Some(u32), .. } => Value::Integer(Integer::U32(u32.u32)),
            ir::Operand { u64: Some(u64), .. } => Value::Integer(Integer::U64(u64.u64)),
            ir::Operand { u128: Some(u128), .. } => {
                let mut raw = [0u8; 16];
                let len = u128.u128.len().min(16);
                (&mut raw[..len]).copy_from_slice(&u128.u128[..len]);
                Value::Integer(Integer::U128(u128::from_le_bytes(raw)))
            }
            ir::Operand { i8: Some(i8), .. } => Value::Integer(Integer::I8(i8.i8 as i8)),
            ir::Operand { i16: Some(i16), .. } => Value::Integer(Integer::I16(i16.i16 as i16)),
            ir::Operand { i32: Some(i32), .. } => Value::Integer(Integer::I32(i32.i32)),
            ir::Operand { i64: Some(i64), .. } => Value::Integer(Integer::I64(i64.i64)),
            ir::Operand { i128: Some(i128), .. } => {
                let mut raw = [0u8; 16];
                let len = i128.i128.len().min(16);
                (&mut raw[..len]).copy_from_slice(&i128.i128[..len]);
                Value::Integer(Integer::I128(i128::from_le_bytes(raw)))
            }
            ir::Operand { array: Some(array), .. } => Value::Array(
                array
                    .array
                    .into_iter()
                    .map(|x| Value::decode(x))
                    .collect::<Result<Vec<_>>>()?,
            ),
            ir::Operand { tuple: Some(tuple), .. } => Value::Tuple(
                tuple
                    .tuple
                    .into_iter()
                    .map(|x| Value::decode(x))
                    .collect::<Result<Vec<_>>>()?,
            ),
            ir::Operand {
                variable_ref: Some(variable_ref),
                ..
            } => Value::Ref(variable_ref.variable_ref),
            ir::Operand {
                string: Some(string), ..
            } => Value::Str(string.string),
            x => return Err(anyhow!("illegal value data: {:?}", x)),
        })
    }

    pub(crate) fn encode(&self) -> ir::Operand {
        match self {
            Value::Address(address) => ir::Operand {
                address: Some(ir::Address {
                    address: address.clone(),
                }),
                ..Default::default()
            },
            Value::Boolean(value) => ir::Operand {
                boolean: Some(ir::Bool { boolean: *value }),
                ..Default::default()
            },
            Value::Field(field) => ir::Operand {
                field: Some(field.encode()),
                ..Default::default()
            },
            Value::Char(char) => ir::Operand {
                char: Some(ir::Char { char: *char }),
                ..Default::default()
            },
            Value::Group(Group::Single(inner)) => ir::Operand {
                group_single: Some(inner.encode()),
                ..Default::default()
            },
            Value::Group(Group::Tuple(left, right)) => ir::Operand {
                group_tuple: Some(ir::Group {
                    left: Some(left.encode()),
                    right: Some(right.encode()),
                }),
                ..Default::default()
            },
            Value::Integer(i) => match i {
                Integer::U8(i) => ir::Operand {
                    u8: Some(ir::U8 { u8: *i as u32 }),
                    ..Default::default()
                },
                Integer::U16(i) => ir::Operand {
                    u16: Some(ir::U16 { u16: *i as u32 }),
                    ..Default::default()
                },
                Integer::U32(i) => ir::Operand {
                    u32: Some(ir::U32 { u32: *i }),
                    ..Default::default()
                },
                Integer::U64(i) => ir::Operand {
                    u64: Some(ir::U64 { u64: *i }),
                    ..Default::default()
                },
                Integer::U128(i) => ir::Operand {
                    u128: Some(ir::U128 {
                        u128: i.to_le_bytes().to_vec(),
                    }),
                    ..Default::default()
                },
                Integer::I8(i) => ir::Operand {
                    i8: Some(ir::I8 { i8: *i as i32 }),
                    ..Default::default()
                },
                Integer::I16(i) => ir::Operand {
                    i16: Some(ir::I16 { i16: *i as i32 }),
                    ..Default::default()
                },
                Integer::I32(i) => ir::Operand {
                    i32: Some(ir::I32 { i32: *i }),
                    ..Default::default()
                },
                Integer::I64(i) => ir::Operand {
                    i64: Some(ir::I64 { i64: *i as i64 }),
                    ..Default::default()
                },
                Integer::I128(i) => ir::Operand {
                    i128: Some(ir::I128 {
                        i128: i.to_le_bytes().to_vec(),
                    }),
                    ..Default::default()
                },
            },
            Value::Array(items) => ir::Operand {
                array: Some(ir::Array {
                    array: items.iter().map(|x| x.encode()).collect(),
                }),
                ..Default::default()
            },
            Value::Tuple(items) => ir::Operand {
                tuple: Some(ir::Tuple {
                    tuple: items.iter().map(|x| x.encode()).collect(),
                }),
                ..Default::default()
            },
            Value::Ref(variable_ref) => ir::Operand {
                variable_ref: Some(ir::VariableRef {
                    variable_ref: *variable_ref,
                }),
                ..Default::default()
            },
            Value::Str(str) => ir::Operand {
                string: Some(ir::String { string: str.clone() }),
                ..Default::default()
            },
        }
    }
}
