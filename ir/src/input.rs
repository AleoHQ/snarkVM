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

use crate::{ir, Type, Value};

use anyhow::*;
use indexmap::IndexMap;
use prost::Message;

#[derive(Debug, Clone, PartialEq)]
pub struct Input {
    pub variable: u32,
    pub name: String,
    pub type_: Type,
}

impl Input {
    pub(crate) fn decode(input: ir::Input) -> Result<Self> {
        Ok(Self {
            variable: input.variable,
            name: input.name,
            type_: Type::decode(input.r#type.ok_or_else(|| anyhow!("missing type for input"))?)?,
        })
    }

    pub(crate) fn encode(&self) -> ir::Input {
        ir::Input {
            variable: self.variable,
            name: self.name.clone(),
            r#type: Some(self.type_.encode()),
        }
    }
}

/// Concrete input data
#[derive(Clone, Debug, Default)]
pub struct InputData {
    pub main: IndexMap<String, Value>,
    pub constants: IndexMap<String, Value>,
    pub registers: IndexMap<String, Value>,
    pub public_states: IndexMap<String, Value>,
    pub private_record_states: IndexMap<String, Value>,
    pub private_leaf_states: IndexMap<String, Value>,
}

fn encode_map_key((key, value): (&String, &Value)) -> ir::InputDataItem {
    ir::InputDataItem {
        name: key.clone(),
        value: Some(value.encode()),
    }
}

fn decode_map_key(data: ir::InputDataItem) -> Result<(String, Value)> {
    Ok((
        data.name,
        Value::decode(data.value.ok_or_else(|| anyhow!("missing value from input data"))?)?,
    ))
}

impl InputData {
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut out = vec![];
        self.encode().encode(&mut out)?;
        Ok(out)
    }

    pub fn deserialize(input: &[u8]) -> Result<Self> {
        Self::decode(ir::InputData::decode(input)?)
    }

    pub(crate) fn decode(input: ir::InputData) -> Result<Self> {
        Ok(Self {
            main: input.main.into_iter().map(decode_map_key).collect::<Result<_>>()?,
            constants: input.constants.into_iter().map(decode_map_key).collect::<Result<_>>()?,
            registers: input.registers.into_iter().map(decode_map_key).collect::<Result<_>>()?,
            public_states: input
                .public_state
                .into_iter()
                .map(decode_map_key)
                .collect::<Result<_>>()?,
            private_record_states: input
                .private_record_state
                .into_iter()
                .map(decode_map_key)
                .collect::<Result<_>>()?,
            private_leaf_states: input
                .private_leaf_state
                .into_iter()
                .map(decode_map_key)
                .collect::<Result<_>>()?,
        })
    }

    pub(crate) fn encode(&self) -> ir::InputData {
        ir::InputData {
            main: self.main.iter().map(encode_map_key).collect(),
            constants: self.constants.iter().map(encode_map_key).collect(),
            registers: self.registers.iter().map(encode_map_key).collect(),
            public_state: self.public_states.iter().map(encode_map_key).collect(),
            private_record_state: self.private_record_states.iter().map(encode_map_key).collect(),
            private_leaf_state: self.private_leaf_states.iter().map(encode_map_key).collect(),
        }
    }
}
