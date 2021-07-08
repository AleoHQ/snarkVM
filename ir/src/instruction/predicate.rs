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

#[derive(Debug, Clone, PartialEq)]
pub struct PredicateData<const N: usize> {
    pub values: Vec<Value>,
}

impl<const N: usize> fmt::Display for PredicateData<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(value) = self.values.first() {
            write!(f, "{}", value)?;
        }
        for value in self.values.iter().skip(1) {
            write!(f, ", {}", value)?;
        }
        Ok(())
    }
}

impl<const N: usize> PredicateData<N> {
    pub(crate) fn decode(operands: Vec<ir::Operand>) -> Result<Self> {
        if operands.len() != N {
            return Err(anyhow!("illegal operand count for PredicateData: {}", operands.len()));
        }
        Ok(Self {
            values: operands
                .into_iter()
                .map(Value::decode)
                .collect::<Result<Vec<Value>>>()?,
        })
    }

    pub(crate) fn encode(&self) -> Vec<ir::Operand> {
        self.values.iter().map(|x| x.encode()).collect()
    }
}
