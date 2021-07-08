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

use crate::{ir, Value};

use anyhow::*;

use super::{decode_control_string, decode_control_u32};

#[derive(Debug, Clone, PartialEq)]
pub struct CallData {
    pub destination: u32,
    pub index: u32, // index of function (of all defined functions, not instruction index)
    pub arguments: Vec<Value>,
}

impl fmt::Display for CallData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "&v{}, f{}", self.destination, self.index)?;
        for value in &self.arguments {
            write!(f, ", {}", value)?;
        }
        Ok(())
    }
}

impl CallData {
    pub(crate) fn decode(operands: Vec<ir::Operand>) -> Result<Self> {
        if operands.len() < 2 {
            return Err(anyhow!("illegal operand count for RepeatData: {}", operands.len()));
        }
        let mut operands = operands.into_iter();
        let destination = decode_control_u32(operands.next().unwrap())?;
        let index = decode_control_u32(operands.next().unwrap())?;
        let arguments = operands.map(Value::decode).collect::<Result<Vec<Value>>>()?;
        Ok(Self {
            destination,
            index,
            arguments,
        })
    }

    pub(crate) fn encode(&self) -> Vec<ir::Operand> {
        let mut operands = vec![];
        operands.push(ir::Operand {
            u32: Some(ir::U32 { u32: self.destination }),
            ..Default::default()
        });
        operands.push(ir::Operand {
            u32: Some(ir::U32 { u32: self.index }),
            ..Default::default()
        });
        for value in self.arguments.iter() {
            operands.push(value.encode());
        }
        operands
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CallCoreData {
    pub destination: u32,
    pub identifier: String, // name of core function
    pub arguments: Vec<Value>,
}

impl fmt::Display for CallCoreData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "&v{}, '{}'", self.destination, self.identifier)?;
        for value in &self.arguments {
            write!(f, ", {}", value)?;
        }
        Ok(())
    }
}

impl CallCoreData {
    pub(crate) fn decode(operands: Vec<ir::Operand>) -> Result<Self> {
        if operands.len() < 2 {
            return Err(anyhow!("illegal operand count for RepeatData: {}", operands.len()));
        }
        let mut operands = operands.into_iter();
        let destination = decode_control_u32(operands.next().unwrap())?;
        let identifier = decode_control_string(operands.next().unwrap())?;
        let arguments = operands.map(Value::decode).collect::<Result<Vec<Value>>>()?;
        Ok(Self {
            destination,
            identifier,
            arguments,
        })
    }

    pub(crate) fn encode(&self) -> Vec<ir::Operand> {
        let mut operands = vec![];
        operands.push(ir::Operand {
            u32: Some(ir::U32 { u32: self.destination }),
            ..Default::default()
        });
        operands.push(ir::Operand {
            string: Some(ir::String {
                string: self.identifier.clone(),
            }),
            ..Default::default()
        });
        for value in self.arguments.iter() {
            operands.push(value.encode());
        }
        operands
    }
}
