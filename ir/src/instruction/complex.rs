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
use num_enum::TryFromPrimitive;

use super::decode_control_u32;

#[derive(Debug, Clone, PartialEq)]
pub struct MaskData {
    pub instruction_count: u32,
    pub condition: Value,
}

impl fmt::Display for MaskData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}, {}", self.instruction_count, self.condition)
    }
}

impl MaskData {
    pub(crate) fn decode(operands: Vec<ir::Operand>) -> Result<Self> {
        if operands.len() != 2 {
            return Err(anyhow!("illegal operand count for MaskData: {}", operands.len()));
        }
        let mut operands = operands.into_iter();
        let instruction_count = decode_control_u32(operands.next().unwrap())?;
        let condition = Value::decode(operands.next().unwrap())?;
        Ok(Self {
            instruction_count,
            condition,
        })
    }

    pub(crate) fn encode(&self) -> Vec<ir::Operand> {
        let mut operands = vec![];
        operands.push(ir::Operand {
            u32: Some(ir::U32 {
                u32: self.instruction_count,
            }),
            ..Default::default()
        });
        operands.push(self.condition.encode());
        operands
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct RepeatData {
    pub instruction_count: u32,
    pub iter_variable: u32,
    pub from: Value,
    pub to: Value,
}

impl fmt::Display for RepeatData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}, &v{}, {}, {}",
            self.instruction_count, self.iter_variable, self.from, self.to
        )
    }
}

impl RepeatData {
    pub(crate) fn decode(operands: Vec<ir::Operand>) -> Result<Self> {
        if operands.len() != 4 {
            return Err(anyhow!("illegal operand count for RepeatData: {}", operands.len()));
        }
        let mut operands = operands.into_iter();
        let instruction_count = decode_control_u32(operands.next().unwrap())?;
        let iter_variable = decode_control_u32(operands.next().unwrap())?;
        let from = Value::decode(operands.next().unwrap())?;
        let to = Value::decode(operands.next().unwrap())?;
        Ok(Self {
            instruction_count,
            iter_variable,
            from,
            to,
        })
    }

    pub(crate) fn encode(&self) -> Vec<ir::Operand> {
        let mut operands = vec![];
        operands.push(ir::Operand {
            u32: Some(ir::U32 {
                u32: self.instruction_count,
            }),
            ..Default::default()
        });
        operands.push(ir::Operand {
            u32: Some(ir::U32 {
                u32: self.iter_variable,
            }),
            ..Default::default()
        });
        operands.push(self.from.encode());
        operands.push(self.to.encode());
        operands
    }
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, TryFromPrimitive, PartialEq)]
pub enum LogLevel {
    Error = 0,
    Info,
    Debug,
}

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Debug => write!(f, "DEBUG"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LogData {
    pub log_level: LogLevel,
    pub parts: Vec<Value>,
}

impl fmt::Display for LogData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.log_level)?;
        for value in &self.parts {
            write!(f, ", {}", value)?;
        }
        Ok(())
    }
}

impl LogData {
    pub(crate) fn decode(operands: Vec<ir::Operand>) -> Result<Self> {
        if operands.len() < 2 {
            return Err(anyhow!("illegal operand count for RepeatData: {}", operands.len()));
        }
        let mut operands = operands.into_iter();
        let log_level = LogLevel::try_from_primitive(decode_control_u32(operands.next().unwrap())?)?;
        let parts = operands.map(Value::decode).collect::<Result<Vec<Value>>>()?;
        Ok(Self { log_level, parts })
    }

    pub(crate) fn encode(&self) -> Vec<ir::Operand> {
        let mut operands = vec![];
        operands.push(ir::Operand {
            u32: Some(ir::U32 {
                u32: self.log_level as u32,
            }),
            ..Default::default()
        });
        for value in self.parts.iter() {
            operands.push(value.encode());
        }
        operands
    }
}
