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

use crate::{helpers::integers::IntegerType, Mode};

use num_traits::Inv;
use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Not, Sub, SubAssign},
};

/// Representation of a boolean.
pub trait BooleanTrait:
    Adder + And + Clone + Debug + Equal + Nand + Nor + Not + Or + Subtractor + Ternary + Xor
{
}

/// Representation of a base field.
pub trait BaseFieldTrait:
    Add
    + AddAssign
    + Clone
    + Debug
    + Div
    + DivAssign
    + Double
    + Equal
    + FromBits
    + Inv
    + Mul
    + MulAssign
    + Neg
    + One
    + Square
    + Sub
    + SubAssign
    + Ternary
    + ToBits
    + Zero
{
}

/// Representation of an integer.
pub trait IntegerTrait<I: IntegerType>:
    AddAssign
    + Add<Output = Self>
    + AddChecked<Output = Self>
    + AddWrapped<Output = Self>
    + Clone
    + Debug
    + Equal
    + Neg<Output = Self>
    + SubAssign
    + Sub<Output = Self>
    + SubChecked<Output = Self>
    + SubWrapped<Output = Self>
    + One
    + Zero
// + Div
// + DivAssign
// + Double
// + Equal
// + Inv
// + Mul
// + MulAssign
// + Neg
// + One
// + Square
// + Sub
// + SubAssign
// + Ternary
// + ToBits
// + Zero
{
    /// Initializes a new integer.
    fn new(mode: Mode, value: I) -> Self;

    /// Returns `true` if the integer is a constant.
    fn is_constant(&self) -> bool;

    /// Ejects the unsigned integer as a constant unsigned integer value.
    fn eject_value(&self) -> I;
}

// TODO why not use num_traits::Zero?
/// Representation of the zero value.
pub trait Zero {
    type Boolean: BooleanTrait;

    /// Returns a new zero constant.
    fn zero() -> Self;

    /// Returns `true` if `self` is zero.
    fn is_zero(&self) -> Self::Boolean;
}

/// Representation of the one value.
pub trait One {
    type Boolean: BooleanTrait;

    /// Returns a new one constant.
    fn one() -> Self;

    /// Returns `true` if `self` is one.
    fn is_one(&self) -> Self::Boolean;
}

/// Trait for equality comparisons.
pub trait Equal<Rhs: ?Sized = Self> {
    type Boolean: BooleanTrait;

    /// Returns `true` if `self` and `other` are equal.
    fn is_eq(&self, other: &Rhs) -> Self::Boolean;

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_neq(&self, other: &Rhs) -> Self::Boolean;
}

pub trait LessThan<Rhs: ?Sized = Self> {
    type Boolean: BooleanTrait;
    type Output;

    /// Returns `true` if `self` is less than `other`.
    fn is_lt(&self, other: &Rhs) -> Self::Output;
}

/// Binary operator for performing `a AND b`.
pub trait And<Rhs: ?Sized = Self> {
    type Boolean: BooleanTrait;
    type Output;

    /// Returns `(a AND b)`.
    fn and(&self, other: &Rhs) -> Self::Output;
}

/// Binary operator for performing `a OR b`.
pub trait Or<Rhs: ?Sized = Self> {
    type Boolean: BooleanTrait;
    type Output;

    /// Returns `(a OR b)`.
    fn or(&self, other: &Rhs) -> Self::Output;
}

/// Binary operator for performing `NOT (a AND b)`.
pub trait Nand<Rhs: ?Sized = Self> {
    type Boolean: BooleanTrait;
    type Output;

    /// Returns `NOT (a AND b)`.
    fn nand(&self, other: &Rhs) -> Self::Output;
}

/// Binary operator for performing `(NOT a) AND (NOT b)`.
pub trait Nor<Rhs: ?Sized = Self> {
    type Boolean: BooleanTrait;
    type Output;

    /// Returns `(NOT a) AND (NOT b)`.
    fn nor(&self, other: &Rhs) -> Self::Output;
}

/// Binary operator for performing `(a != b)`.
pub trait Xor<Rhs: ?Sized = Self> {
    type Boolean: BooleanTrait;
    type Output;

    /// Returns `(a != b)`.
    fn xor(&self, other: &Rhs) -> Self::Output;
}

/// Trait for ternary operations.
pub trait Ternary {
    type Boolean: BooleanTrait;
    type Output;

    /// Returns `first` if `condition` is `true`, otherwise returns `second`.
    fn ternary(condition: &Self::Boolean, first: &Self, second: &Self) -> Self::Output;
}

/// Binary operator for adding two values, enforcing an overflow never occurs.
pub trait AddChecked<Rhs: ?Sized = Self> {
    type Output;

    fn add_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for adding two values, bounding the sum to `MAX` if an overflow occurs.
pub trait AddSaturating<Rhs: ?Sized = Self> {
    type Output;

    fn add_saturating(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for adding two values, wrapping the sum if an overflow occurs.
pub trait AddWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn add_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for subtracting two values, enforcing an underflow never occurs.
pub trait SubChecked<Rhs: ?Sized = Self> {
    type Output;

    fn sub_checked(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for subtracting two values, bounding the difference to `MIN` if an underflow occurs.
pub trait SubSaturating<Rhs: ?Sized = Self> {
    type Output;

    fn sub_saturating(&self, rhs: &Rhs) -> Self::Output;
}

/// Binary operator for subtracting two values, wrapping the difference if an underflow occurs.
pub trait SubWrapped<Rhs: ?Sized = Self> {
    type Output;

    fn sub_wrapped(&self, rhs: &Rhs) -> Self::Output;
}

/// Unary operator for retrieving the doubled value.
pub trait Double {
    type Output;

    fn double(self) -> Self::Output;
}

/// Unary operator for retrieving the squared value.
pub trait Square {
    type Output;

    fn square(&self) -> Self::Output;
}

/// Unary operator for converting to bits.
pub trait ToBits {
    type Boolean: BooleanTrait;

    fn to_bits_le(&self) -> Vec<Self::Boolean>;

    fn to_bits_be(&self) -> Vec<Self::Boolean>;
}

/// Unary operator for instantiating from bits.
pub trait FromBits {
    type Boolean: BooleanTrait;

    fn from_bits_le(mode: Mode, bits_le: &[Self::Boolean]) -> Self;

    fn from_bits_be(mode: Mode, bits_be: &[Self::Boolean]) -> Self;
}

///
/// A single-bit binary adder with a carry bit.
///
/// https://en.wikipedia.org/wiki/Adder_(electronics)#Full_adder
///
/// sum = (a XOR b) XOR carry
/// carry = a AND b OR carry AND (a XOR b)
/// return (sum, carry)
///
pub trait Adder {
    type Carry;
    type Sum;

    /// Returns the sum of `self` and `other` as a sum bit and carry bit.
    fn adder(&self, other: &Self, carry: &Self) -> (Self::Sum, Self::Carry);
}

///
/// A single-bit binary subtractor with a borrow bit.
///
/// https://en.wikipedia.org/wiki/Subtractor#Full_subtractor
///
/// difference = (a XOR b) XOR borrow
/// borrow = ((NOT a) AND b) OR (borrow AND (NOT (a XOR b)))
/// return (difference, borrow)
///
pub trait Subtractor {
    type Borrow;
    type Difference;

    /// Returns the difference of `self` and `other` as a difference bit and borrow bit.
    fn subtractor(&self, other: &Self, borrow: &Self) -> (Self::Difference, Self::Borrow);
}
