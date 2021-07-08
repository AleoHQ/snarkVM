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

use num_enum::TryFromPrimitive;

#[derive(TryFromPrimitive, Clone, Copy, Debug, PartialEq)]
#[repr(u32)]
pub enum InstructionOp {
    // Binary
    Add = 0,
    Sub,
    Mul,
    Div,
    Pow,
    Or,
    And,
    Eq,
    Ne,
    Ge,
    Gt,
    Le,
    Lt,
    BitOr,
    BitAnd,
    BitXor,
    Shr,
    ShrSigned,
    Shl,
    Mod,

    // Unary
    Not,
    Negate,
    BitNot,

    // Cast
    // Cast,

    // Arrays
    ArrayInitRepeat,
    ArrayInit,
    ArrayIndexGet,
    ArraySliceGet,
    ArrayIndexStore,
    ArraySliceStore,

    // Tuples
    TupleInit,
    TupleIndexGet,
    TupleIndexStore,

    // Complex Expressions
    Pick,
    Mask,
    Repeat,

    // Variables
    Store,

    // Function Call
    Call,
    Return,

    // Debugging
    Assert,
    Log,

    // FFI/Core
    CallCore,
}

impl InstructionOp {
    pub fn mnemonic(&self) -> &'static str {
        match self {
            InstructionOp::Add => "add",
            InstructionOp::Sub => "sub",
            InstructionOp::Mul => "mul",
            InstructionOp::Div => "div",
            InstructionOp::Pow => "pow",
            InstructionOp::Or => "or",
            InstructionOp::And => "and",
            InstructionOp::Eq => "eq",
            InstructionOp::Ne => "ne",
            InstructionOp::Ge => "ge",
            InstructionOp::Gt => "gt",
            InstructionOp::Le => "le",
            InstructionOp::Lt => "lt",
            InstructionOp::BitOr => "bor",
            InstructionOp::BitAnd => "band",
            InstructionOp::BitXor => "bxor",
            InstructionOp::Shr => "shr",
            InstructionOp::ShrSigned => "shrs",
            InstructionOp::Shl => "shl",
            InstructionOp::Mod => "mod",
            InstructionOp::Not => "not",
            InstructionOp::Negate => "negate",
            InstructionOp::BitNot => "bnot",
            InstructionOp::ArrayInitRepeat => "ainitn",
            InstructionOp::ArrayInit => "ainit",
            InstructionOp::ArrayIndexGet => "aget",
            InstructionOp::ArraySliceGet => "asget",
            InstructionOp::ArrayIndexStore => "aset",
            InstructionOp::ArraySliceStore => "asset",
            InstructionOp::TupleInit => "tinit",
            InstructionOp::TupleIndexGet => "tget",
            InstructionOp::TupleIndexStore => "tset",
            InstructionOp::Pick => "pick",
            InstructionOp::Mask => "mask",
            InstructionOp::Repeat => "repeat",
            InstructionOp::Store => "store",
            InstructionOp::Call => "call",
            InstructionOp::Return => "retn",
            InstructionOp::Assert => "assert",
            InstructionOp::Log => "log",
            InstructionOp::CallCore => "ccall",
        }
    }
}

impl fmt::Display for InstructionOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.mnemonic())
    }
}
