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

pub mod input;
pub use input::*;

pub mod output;
pub use output::*;

use crate::{instructions::Instruction, Immediate, Memory, Operation, Register, Sanitizer};
use snarkvm_circuits::{Parser, ParserResult};
use snarkvm_utilities::{error, FromBytes, ToBytes};

use core::fmt;
use nom::{
    branch::alt,
    bytes::complete::tag,
    character::complete::{alpha1, alphanumeric1},
    combinator::{map_res, recognize},
    multi::{many0, many1},
    sequence::pair,
};
use std::io::{Read, Result as IoResult, Write};

pub struct Function<M: Memory> {
    /// The function name.
    name: String,
    /// The function arguments provided by the caller.
    arguments: Vec<Register<M::Environment>>,
    /// The instructions to initialize the function inputs.
    inputs: Vec<Input<M>>,
    /// The main instructions of the function.
    instructions: Vec<Instruction<M>>,
    /// The instructions to initialize the function outputs.
    outputs: Vec<Output<M>>,
    /// The function stack of registers.
    memory: M,
}

impl<M: Memory> Function<M> {
    /// Allocates the given inputs, by appending them as function inputs.
    pub fn add_inputs(&mut self, inputs: &[Immediate<M::Environment>]) -> &mut Self {
        // Append new inputs from the index of the last assigned input.
        for (input, immediate) in (self.inputs.iter().skip(self.arguments.len())).zip(inputs) {
            // Store the immediate into the input register.
            input.assign(immediate.clone());
            // Save the input register.
            self.arguments.push(*(*input).register());
        }
        self
    }

    /// Evaluates the function, returning the outputs.
    pub fn evaluate(&mut self, inputs: &[Immediate<M::Environment>]) -> Vec<Immediate<M::Environment>> {
        self.add_inputs(inputs);
        self.inputs.iter().for_each(|input| input.evaluate(&self.memory));
        self.instructions.iter().for_each(|instruction| instruction.evaluate(&self.memory));
        self.outputs.iter().for_each(|output| output.evaluate(&self.memory));
        self.outputs()
    }

    /// Returns the outputs from the function.
    pub(super) fn outputs(&self) -> Vec<Immediate<M::Environment>> {
        self.outputs.iter().map(|output| self.memory.load((*output).register())).collect()
    }

    /// Returns the number of arguments provided by the caller.
    pub fn num_arguments(&self) -> u64 {
        self.arguments.len() as u64
    }

    /// Returns the number of inputs for the function.
    pub fn num_inputs(&self) -> u64 {
        self.inputs.len() as u64
    }

    /// Returns the number of outputs for the function.
    pub fn num_outputs(&self) -> u64 {
        self.outputs.len() as u64
    }
}

impl<M: Memory> Parser for Function<M> {
    type Environment = M::Environment;

    /// Returns the type name as a string.
    #[inline]
    fn type_name() -> &'static str {
        "function"
    }

    /// Parses a string into a local function.
    #[inline]
    fn parse(string: &str) -> ParserResult<Self> {
        // Initialize a new instance of memory.
        let memory = M::default();

        // Parse the whitespace and comments from the string.
        let (string, _) = Sanitizer::parse(string)?;
        // Parse the 'function' keyword from the string.
        let (string, _) = tag(Self::type_name())(string)?;
        // Parse the space from the string.
        let (string, _) = tag(" ")(string)?;
        // Parse the function name from the string.
        let (string, name) = map_res(recognize(pair(alpha1, many0(alt((alphanumeric1, tag("_")))))), |name: &str| {
            let num_characters = name.len();
            match num_characters <= M::NUM_CHARACTERS {
                true => Ok(name),
                false => Err(error(format!("Failed to read function name of length {num_characters} as bytes"))),
            }
        })(string)?;
        // Parse the colon ':' keyword from the string.
        let (string, _) = tag(":")(string)?;

        // Parse the inputs from the string.
        let (string, inputs) = many0(|s| Input::parse(s, memory.clone()))(string)?;
        // Parse the instructions from the string.
        let (string, instructions) = many1(|s| Instruction::parse(s, memory.clone()))(string)?;
        // Parse the outputs from the string.
        let (string, outputs) = many0(|s| Output::parse(s, memory.clone()))(string)?;

        Ok((string, Self {
            name: name.to_string(),
            arguments: Default::default(),
            inputs,
            instructions,
            outputs,
            memory,
        }))
    }
}

impl<M: Memory> fmt::Display for Function<M> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut output = format!("{} {}:\n", Self::type_name(), self.name);
        for instruction in &self.instructions {
            output += &format!("    {}", instruction);
        }
        write!(f, "{}", output)
    }
}

impl<M: Memory> FromBytes for Function<M> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the number of characters for the function name.
        let num_characters = u8::read_le(&mut reader)?;

        // Read the name of the function.
        let mut name_bytes = vec![0u8; num_characters as usize];
        reader.read_exact(&mut name_bytes)?;
        let name = String::from_utf8(name_bytes).expect("Found invalid UTF-8");

        // Read the inputs.
        let num_inputs = u32::read_le(&mut reader)?;
        let mut inputs = Vec::with_capacity(num_inputs as usize);
        for _ in 0..num_inputs {
            inputs.push(Input::read_le(&mut reader)?);
        }

        // Read the instructions.
        let num_instructions = u32::read_le(&mut reader)?;
        let mut instructions = Vec::with_capacity(num_instructions as usize);
        for _ in 0..num_instructions {
            instructions.push(Instruction::read_le(&mut reader)?);
        }

        // Read the outputs.
        let num_outputs = u32::read_le(&mut reader)?;
        let mut outputs = Vec::with_capacity(num_outputs as usize);
        for _ in 0..num_outputs {
            outputs.push(Output::read_le(&mut reader)?);
        }

        Ok(Self { name, arguments: Default::default(), inputs, instructions, outputs, memory: M::default() })
    }
}

impl<M: Memory> ToBytes for Function<M> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the number of characters for the function name.
        let num_characters = self.name.len();
        match num_characters <= M::NUM_CHARACTERS {
            true => (num_characters as u8).write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write function name of length {num_characters} as bytes"))),
        }

        // Write the function name.
        self.name.as_bytes().write_le(&mut writer)?;

        // Write the number of inputs for the function.
        let num_inputs = self.inputs.len();
        match num_inputs <= M::NUM_INPUTS {
            true => (num_inputs as u32).write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_inputs} inputs as bytes"))),
        }

        // Write the inputs.
        for input in &self.inputs {
            input.write_le(&mut writer)?;
        }

        // Write the number of instructions for the function.
        let num_instructions = self.instructions.len();
        match num_instructions <= M::NUM_INPUTS {
            true => (num_instructions as u32).write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_instructions} instructions as bytes"))),
        }

        // Write the instructions.
        for instruction in &self.instructions {
            instruction.write_le(&mut writer)?;
        }

        // Write the number of outputs for the function.
        let num_outputs = self.outputs.len();
        match num_outputs <= M::NUM_INPUTS {
            true => (num_outputs as u32).write_le(&mut writer)?,
            false => return Err(error(format!("Failed to write {num_outputs} outputs as bytes"))),
        }

        // Write the outputs.
        for output in &self.outputs {
            output.write_le(&mut writer)?;
        }

        Ok(())
    }
}
