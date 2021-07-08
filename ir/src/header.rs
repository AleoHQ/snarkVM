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

use crate::{ir, Input};

use anyhow::*;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SnarkVMVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl Default for SnarkVMVersion {
    fn default() -> Self {
        Self {
            major: env!("CARGO_PKG_VERSION_MAJOR").parse().expect("invalid major version"),
            minor: env!("CARGO_PKG_VERSION_MINOR").parse().expect("invalid minor version"),
            patch: env!("CARGO_PKG_VERSION_PATCH").parse().expect("invalid patch version"),
        }
    }
}

impl SnarkVMVersion {
    pub fn check_compatible(&self) -> bool {
        self == &Self::default()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub version: SnarkVMVersion,
    pub main_inputs: Vec<Input>,
    pub constant_inputs: Vec<Input>,
    pub register_inputs: Vec<Input>,
    pub public_states: Vec<Input>,
    pub private_record_states: Vec<Input>,
    pub private_leaf_states: Vec<Input>,
}

impl Header {
    pub(crate) fn decode(header: ir::Header) -> Result<Self> {
        Ok(Self {
            version: SnarkVMVersion {
                major: header.snarkvm_major,
                minor: header.snarkvm_minor,
                patch: header.snarkvm_patch,
            },
            main_inputs: header
                .main_inputs
                .into_iter()
                .map(Input::decode)
                .collect::<Result<Vec<Input>>>()?,
            constant_inputs: header
                .constant_inputs
                .into_iter()
                .map(Input::decode)
                .collect::<Result<Vec<Input>>>()?,
            register_inputs: header
                .register_inputs
                .into_iter()
                .map(Input::decode)
                .collect::<Result<Vec<Input>>>()?,
            public_states: header
                .public_states
                .into_iter()
                .map(Input::decode)
                .collect::<Result<Vec<Input>>>()?,
            private_record_states: header
                .private_record_states
                .into_iter()
                .map(Input::decode)
                .collect::<Result<Vec<Input>>>()?,
            private_leaf_states: header
                .private_leaf_states
                .into_iter()
                .map(Input::decode)
                .collect::<Result<Vec<Input>>>()?,
        })
    }

    pub(crate) fn encode(&self) -> ir::Header {
        ir::Header {
            snarkvm_major: self.version.major,
            snarkvm_minor: self.version.minor,
            snarkvm_patch: self.version.patch,
            main_inputs: self.main_inputs.iter().map(|x| x.encode()).collect(),
            constant_inputs: self.constant_inputs.iter().map(|x| x.encode()).collect(),
            register_inputs: self.register_inputs.iter().map(|x| x.encode()).collect(),
            public_states: self.public_states.iter().map(|x| x.encode()).collect(),
            private_record_states: self.private_record_states.iter().map(|x| x.encode()).collect(),
            private_leaf_states: self.private_leaf_states.iter().map(|x| x.encode()).collect(),
        }
    }
}
