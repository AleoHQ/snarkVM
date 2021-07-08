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

use crate::errors::GroupError;

use snarkvm_fields::{Field, One};
use snarkvm_gadgets::{
    bits::{ToBitsBEGadget, ToBytesGadget},
    traits::{
        alloc::AllocGadget,
        eq::{ConditionalEqGadget, EqGadget, EvaluateEqGadget},
        select::CondSelectGadget,
    },
};
use snarkvm_ir::Group;
use snarkvm_r1cs::ConstraintSystem;
use std::fmt::{Debug, Display};

pub mod edwards_bls12;

pub use snarkvm_fields::PrimeField;

pub trait GroupType<F: Field>:
    Sized
    + Clone
    + Debug
    + Display
    + One
    + EvaluateEqGadget<F>
    + EqGadget<F>
    + ConditionalEqGadget<F>
    + AllocGadget<Group, F>
    + CondSelectGadget<F>
    + ToBitsBEGadget<F>
    + ToBytesGadget<F>
{
    fn constant(value: &Group) -> Result<Self, GroupError>;

    fn to_allocated<CS: ConstraintSystem<F>>(&self, cs: CS) -> Result<Self, GroupError>;

    fn negate<CS: ConstraintSystem<F>>(&self, cs: CS) -> Result<Self, GroupError>;

    fn add<CS: ConstraintSystem<F>>(&self, cs: CS, other: &Self) -> Result<Self, GroupError>;

    fn sub<CS: ConstraintSystem<F>>(&self, cs: CS, other: &Self) -> Result<Self, GroupError>;
}
