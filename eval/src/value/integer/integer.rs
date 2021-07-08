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

//! Conversion of integer declarations to constraints in Leo.

use snarkvm_fields::{Field, PrimeField};
use snarkvm_gadgets::{
    boolean::Boolean,
    integers::{
        int::{Int128, Int16, Int32, Int64, Int8},
        uint::{Sub as UIntSub, *},
    },
    traits::{
        alloc::AllocGadget,
        bits::comparator::{ComparatorGadget, EvaluateLtGadget},
        eq::{ConditionalEqGadget, EqGadget, EvaluateEqGadget},
        integers::{Add, Div, Mul, Neg, Pow, Sub},
        select::CondSelectGadget,
    },
    Integer as IntegerGadget,
};
use snarkvm_ir::{Integer as IrInteger, Value};
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};
use std::{convert::TryInto, fmt};

use crate::{
    allocate_type,
    errors::IntegerError,
    match_integer,
    match_integers,
    match_integers_arithmetic,
    match_signed_integer,
    match_unsigned_integer,
    ConstrainedValue,
    GroupType,
};

/// An integer type enum wrapping the integer value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd)]
pub enum Integer {
    U8(UInt8),
    U16(UInt16),
    U32(UInt32),
    U64(UInt64),
    U128(UInt128),

    I8(Int8),
    I16(Int16),
    I32(Int32),
    I64(Int64),
    I128(Int128),
}

impl fmt::Display for Integer {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let integer = self;
        let option = match_integer!(integer => integer.get_value());
        match option {
            Some(number) => write!(f, "{}", number),
            None => write!(f, "[input]{}", self.get_type()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IntegerType {
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
}

impl fmt::Display for IntegerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntegerType::U8 => write!(f, "u8"),
            IntegerType::U16 => write!(f, "u16"),
            IntegerType::U32 => write!(f, "u32"),
            IntegerType::U64 => write!(f, "u64"),
            IntegerType::U128 => write!(f, "u128"),
            IntegerType::I8 => write!(f, "i8"),
            IntegerType::I16 => write!(f, "i16"),
            IntegerType::I32 => write!(f, "i32"),
            IntegerType::I64 => write!(f, "i64"),
            IntegerType::I128 => write!(f, "i128"),
        }
    }
}

impl Integer {
    ///
    /// Returns a new integer from an expression.
    ///
    /// Checks that the expression is equal to the expected type if given.
    ///
    pub fn new(value: &IrInteger) -> Self {
        match value {
            IrInteger::U8(i) => Integer::U8(UInt8::constant(*i)),
            IrInteger::U16(i) => Integer::U16(UInt16::constant(*i)),
            IrInteger::U32(i) => Integer::U32(UInt32::constant(*i)),
            IrInteger::U64(i) => Integer::U64(UInt64::constant(*i)),
            IrInteger::U128(i) => Integer::U128(UInt128::constant(*i)),
            IrInteger::I8(i) => Integer::I8(Int8::constant(*i)),
            IrInteger::I16(i) => Integer::I16(Int16::constant(*i)),
            IrInteger::I32(i) => Integer::I32(Int32::constant(*i)),
            IrInteger::I64(i) => Integer::I64(Int64::constant(*i)),
            IrInteger::I128(i) => Integer::I128(Int128::constant(*i)),
        }
    }

    pub fn get_bits(&self) -> Vec<Boolean> {
        let integer = self;
        match_integer!(integer => integer.to_bits_le())
    }

    pub fn is_allocated(&self) -> bool {
        self.get_bits()
            .into_iter()
            .any(|b| matches!(b, Boolean::Is(_) | Boolean::Not(_)))
    }

    pub fn get_value(&self) -> Option<String> {
        let integer = self;
        match_integer!(integer => integer.get_value())
    }

    pub fn get_type(&self) -> IntegerType {
        match self {
            Integer::U8(_) => IntegerType::U8,
            Integer::U16(_) => IntegerType::U16,
            Integer::U32(_) => IntegerType::U32,
            Integer::U64(_) => IntegerType::U64,
            Integer::U128(_) => IntegerType::U128,
            Integer::I8(_) => IntegerType::I8,
            Integer::I16(_) => IntegerType::I16,
            Integer::I32(_) => IntegerType::I32,
            Integer::I64(_) => IntegerType::I64,
            Integer::I128(_) => IntegerType::I128,
        }
    }

    pub fn to_usize(&self) -> Option<usize> {
        if self.is_allocated() {
            return None;
        }
        let unsigned_integer = self;
        match_unsigned_integer!(unsigned_integer => unsigned_integer.value.map(|num| num.try_into().ok()).flatten())
    }

    pub fn allocate_type<F: Field, CS: ConstraintSystem<F>>(
        cs: &mut CS,
        name: &str,
        value: snarkvm_ir::Integer,
    ) -> Result<Self, IntegerError> {
        Ok(match value {
            IrInteger::U8(x) => allocate_type!(u8, UInt8, Integer::U8, cs, name, x),
            IrInteger::U16(x) => allocate_type!(u16, UInt16, Integer::U16, cs, name, x),
            IrInteger::U32(x) => allocate_type!(u32, UInt32, Integer::U32, cs, name, x),
            IrInteger::U64(x) => allocate_type!(u64, UInt64, Integer::U64, cs, name, x),
            IrInteger::U128(x) => allocate_type!(u128, UInt128, Integer::U128, cs, name, x),

            IrInteger::I8(x) => allocate_type!(i8, Int8, Integer::I8, cs, name, x),
            IrInteger::I16(x) => allocate_type!(i16, Int16, Integer::I16, cs, name, x),
            IrInteger::I32(x) => allocate_type!(i32, Int32, Integer::I32, cs, name, x),
            IrInteger::I64(x) => allocate_type!(i64, Int64, Integer::I64, cs, name, x),
            IrInteger::I128(x) => allocate_type!(i128, Int128, Integer::I128, cs, name, x),
        })
    }

    pub fn from_input<F: PrimeField, G: GroupType<F>, CS: ConstraintSystem<F>>(
        cs: &mut CS,
        name: &str,
        value: Value,
    ) -> Result<ConstrainedValue<F, G>, IntegerError> {
        let value = match value {
            Value::Integer(x) => x,
            _ => {
                return Err(IntegerError::missing_integer(format!(
                    "missing proper type for '{}' integer",
                    name
                )));
            }
        };
        Ok(ConstrainedValue::Integer(Self::allocate_type(cs, name, value)?))
    }

    pub fn constant(value: &IrInteger) -> Result<Integer, IntegerError> {
        Ok(match value {
            IrInteger::U8(x) => Integer::U8(UInt8::constant(*x)),
            IrInteger::U16(x) => Integer::U16(UInt16::constant(*x)),
            IrInteger::U32(x) => Integer::U32(UInt32::constant(*x)),
            IrInteger::U64(x) => Integer::U64(UInt64::constant(*x)),
            IrInteger::U128(x) => Integer::U128(UInt128::constant(*x)),
            IrInteger::I8(x) => Integer::I8(Int8::constant(*x)),
            IrInteger::I16(x) => Integer::I16(Int16::constant(*x)),
            IrInteger::I32(x) => Integer::I32(Int32::constant(*x)),
            IrInteger::I64(x) => Integer::I64(Int64::constant(*x)),
            IrInteger::I128(x) => Integer::I128(Int128::constant(*x)),
        })
    }

    pub fn negate<F: PrimeField, CS: ConstraintSystem<F>>(self, cs: &mut CS) -> Result<Self, IntegerError> {
        let unique_namespace = format!("enforce -{}", self);

        let a = self;

        let result = match_signed_integer!(a => a.neg(cs.ns(|| unique_namespace)));

        result.ok_or_else(|| IntegerError::negate_operation())
    }

    pub fn add<F: PrimeField, CS: ConstraintSystem<F>>(self, cs: &mut CS, other: Self) -> Result<Self, IntegerError> {
        let unique_namespace = format!("enforce {} + {}", self, other);

        let a = self;
        let b = other;

        let result = match_integers_arithmetic!((a, b) => a.add(cs.ns(|| unique_namespace), &b));

        result.ok_or_else(|| IntegerError::binary_operation("+".to_string()))
    }

    pub fn sub<F: PrimeField, CS: ConstraintSystem<F>>(self, cs: &mut CS, other: Self) -> Result<Self, IntegerError> {
        let unique_namespace = format!("enforce {} - {}", self, other);

        let a = self;
        let b = other;

        let result = match_integers_arithmetic!((a, b) => a.sub(cs.ns(|| unique_namespace), &b));

        result.ok_or_else(|| IntegerError::binary_operation("-".to_string()))
    }

    pub fn mul<F: PrimeField, CS: ConstraintSystem<F>>(self, cs: &mut CS, other: Self) -> Result<Self, IntegerError> {
        let unique_namespace = format!("enforce {} * {}", self, other);

        let a = self;
        let b = other;

        let result = match_integers_arithmetic!((a, b) => a.mul(cs.ns(|| unique_namespace), &b));

        result.ok_or_else(|| IntegerError::binary_operation("*".to_string()))
    }

    pub fn div<F: PrimeField, CS: ConstraintSystem<F>>(self, cs: &mut CS, other: Self) -> Result<Self, IntegerError> {
        let unique_namespace = format!("enforce {} ÷ {}", self, other);

        let a = self;
        let b = other;

        let result = match_integers_arithmetic!((a, b) => a.div(cs.ns(|| unique_namespace), &b));

        result.ok_or_else(|| IntegerError::binary_operation("÷".to_string()))
    }

    pub fn pow<F: PrimeField, CS: ConstraintSystem<F>>(self, cs: &mut CS, other: Self) -> Result<Self, IntegerError> {
        let unique_namespace = format!("enforce {} ** {}", self, other);

        let a = self;
        let b = other;

        let result = match_integers_arithmetic!((a, b) => a.pow(cs.ns(|| unique_namespace), &b));

        result.ok_or_else(|| IntegerError::binary_operation("**".to_string()))
    }
}

impl<F: PrimeField> EvaluateEqGadget<F> for Integer {
    fn evaluate_equal<CS: ConstraintSystem<F>>(&self, cs: CS, other: &Self) -> Result<Boolean, SynthesisError> {
        let a = self;
        let b = other;

        let result = match_integers!((a, b) => a.evaluate_equal(cs, b));

        result.ok_or(SynthesisError::Unsatisfiable)
    }
}

impl<F: PrimeField> EvaluateLtGadget<F> for Integer {
    fn less_than<CS: ConstraintSystem<F>>(&self, cs: CS, other: &Self) -> Result<Boolean, SynthesisError> {
        let a = self;
        let b = other;
        let result = match_integers!((a, b) => a.less_than(cs, b));

        result.ok_or(SynthesisError::Unsatisfiable)
    }
}

impl<F: PrimeField> ComparatorGadget<F> for Integer {}

impl<F: PrimeField> EqGadget<F> for Integer {}

impl<F: PrimeField> ConditionalEqGadget<F> for Integer {
    fn conditional_enforce_equal<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        other: &Self,
        condition: &Boolean,
    ) -> Result<(), SynthesisError> {
        let a = self;
        let b = other;

        let result = match_integers!((a, b) => a.conditional_enforce_equal(cs, b, condition));

        result.ok_or(SynthesisError::Unsatisfiable)
    }

    fn cost() -> usize {
        unimplemented!() // cannot determine which integer we are enforcing
    }
}

impl<F: PrimeField> CondSelectGadget<F> for Integer {
    fn conditionally_select<CS: ConstraintSystem<F>>(
        cs: CS,
        cond: &Boolean,
        first: &Self,
        second: &Self,
    ) -> Result<Self, SynthesisError> {
        match (first, second) {
            (Integer::U8(a), Integer::U8(b)) => Ok(Integer::U8(UInt8::conditionally_select(cs, cond, a, b)?)),
            (Integer::U16(a), Integer::U16(b)) => Ok(Integer::U16(UInt16::conditionally_select(cs, cond, a, b)?)),
            (Integer::U32(a), Integer::U32(b)) => Ok(Integer::U32(UInt32::conditionally_select(cs, cond, a, b)?)),
            (Integer::U64(a), Integer::U64(b)) => Ok(Integer::U64(UInt64::conditionally_select(cs, cond, a, b)?)),
            (Integer::U128(a), Integer::U128(b)) => Ok(Integer::U128(UInt128::conditionally_select(cs, cond, a, b)?)),
            (Integer::I8(a), Integer::I8(b)) => Ok(Integer::I8(Int8::conditionally_select(cs, cond, a, b)?)),
            (Integer::I16(a), Integer::I16(b)) => Ok(Integer::I16(Int16::conditionally_select(cs, cond, a, b)?)),
            (Integer::I32(a), Integer::I32(b)) => Ok(Integer::I32(Int32::conditionally_select(cs, cond, a, b)?)),
            (Integer::I64(a), Integer::I64(b)) => Ok(Integer::I64(Int64::conditionally_select(cs, cond, a, b)?)),
            (Integer::I128(a), Integer::I128(b)) => Ok(Integer::I128(Int128::conditionally_select(cs, cond, a, b)?)),

            (_, _) => Err(SynthesisError::Unsatisfiable), // types do not match
        }
    }

    fn cost() -> usize {
        unimplemented!() // cannot determine which integer we are enforcing
    }
}
