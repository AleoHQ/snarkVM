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

mod query;
use std::fmt;

pub use query::*;
mod array;
pub use array::*;
mod complex;
pub use complex::*;
mod call;
pub use call::*;
mod predicate;
pub use predicate::*;

mod op;
use op::InstructionOp;

mod code;

use anyhow::*;
use num_enum::TryFromPrimitive;

use crate::ir;

#[derive(Debug, Clone, PartialEq)]
pub enum Instruction {
    // Binary
    Add(BinaryData),
    Sub(BinaryData),
    Mul(BinaryData),
    Div(BinaryData),
    Pow(BinaryData),
    Or(BinaryData),
    And(BinaryData),
    Eq(BinaryData),
    Ne(BinaryData),
    Ge(BinaryData),
    Gt(BinaryData),
    Le(BinaryData),
    Lt(BinaryData),
    BitOr(BinaryData),
    BitAnd(BinaryData),
    BitXor(BinaryData),
    Shr(BinaryData),
    ShrSigned(BinaryData),
    Shl(BinaryData),
    Mod(BinaryData),

    // Unary
    Not(UnaryData),
    Negate(UnaryData),
    BitNot(UnaryData),

    // Cast
    // Cast,

    // Arrays
    ArrayInitRepeat(ArrayInitRepeatData),
    // flatten a single dimension of each argument and concatentes into an array
    ArrayInit(VarData),
    ArrayIndexGet(BinaryData),
    // array, from, to, length (constant)
    ArraySliceGet(QueryData<4>),
    // destination + source, index, item
    ArrayIndexStore(QueryData<2>),
    ArraySliceStore(QueryData<3>),

    // Tuples
    TupleInit(VarData),
    TupleIndexGet(BinaryData),
    TupleIndexStore(QueryData<2>),

    // Complex Expressions
    Pick(QueryData<3>), // ternary / conditional move
    Mask(MaskData),     // mask side effects of following N instructions if condition is set
    Repeat(RepeatData), // const-count iteration of N following instructions with counter register at base

    // Variables
    Store(QueryData<1>),

    // Function Call
    Call(CallData),           // call a function
    Return(PredicateData<1>), // return from a function

    // Debugging
    Assert(PredicateData<1>),
    Log(LogData),

    // FFI/Core
    CallCore(CallCoreData),
}

fn decode_control_u32(operand: ir::Operand) -> Result<u32> {
    match operand {
        ir::Operand { u32: Some(u32), .. } => Ok(u32.u32),
        _ => Err(anyhow!("illegal value for control operand: {:?}", operand)),
    }
}

fn decode_control_string(operand: ir::Operand) -> Result<String> {
    match operand {
        ir::Operand {
            string: Some(string), ..
        } => Ok(string.string),
        _ => Err(anyhow!("illegal value for control operand: {:?}", operand)),
    }
}

impl fmt::Display for Instruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.opcode().mnemonic())?;
        match self {
            Instruction::Add(x) => x.fmt(f)?,
            Instruction::Sub(x) => x.fmt(f)?,
            Instruction::Mul(x) => x.fmt(f)?,
            Instruction::Div(x) => x.fmt(f)?,
            Instruction::Pow(x) => x.fmt(f)?,
            Instruction::Or(x) => x.fmt(f)?,
            Instruction::And(x) => x.fmt(f)?,
            Instruction::Eq(x) => x.fmt(f)?,
            Instruction::Ne(x) => x.fmt(f)?,
            Instruction::Ge(x) => x.fmt(f)?,
            Instruction::Gt(x) => x.fmt(f)?,
            Instruction::Le(x) => x.fmt(f)?,
            Instruction::Lt(x) => x.fmt(f)?,
            Instruction::BitOr(x) => x.fmt(f)?,
            Instruction::BitAnd(x) => x.fmt(f)?,
            Instruction::BitXor(x) => x.fmt(f)?,
            Instruction::Shr(x) => x.fmt(f)?,
            Instruction::ShrSigned(x) => x.fmt(f)?,
            Instruction::Shl(x) => x.fmt(f)?,
            Instruction::Mod(x) => x.fmt(f)?,
            Instruction::Not(x) => x.fmt(f)?,
            Instruction::Negate(x) => x.fmt(f)?,
            Instruction::BitNot(x) => x.fmt(f)?,
            Instruction::ArrayInitRepeat(x) => x.fmt(f)?,
            Instruction::ArrayInit(x) => x.fmt(f)?,
            Instruction::ArrayIndexGet(x) => x.fmt(f)?,
            Instruction::ArraySliceGet(x) => x.fmt(f)?,
            Instruction::ArrayIndexStore(x) => x.fmt(f)?,
            Instruction::ArraySliceStore(x) => x.fmt(f)?,
            Instruction::TupleInit(x) => x.fmt(f)?,
            Instruction::TupleIndexGet(x) => x.fmt(f)?,
            Instruction::TupleIndexStore(x) => x.fmt(f)?,
            Instruction::Pick(x) => x.fmt(f)?,
            Instruction::Mask(x) => x.fmt(f)?,
            Instruction::Repeat(x) => x.fmt(f)?,
            Instruction::Store(x) => x.fmt(f)?,
            Instruction::Call(x) => x.fmt(f)?,
            Instruction::Return(x) => x.fmt(f)?,
            Instruction::Assert(x) => x.fmt(f)?,
            Instruction::Log(x) => x.fmt(f)?,
            Instruction::CallCore(x) => x.fmt(f)?,
        }
        Ok(())
    }
}
