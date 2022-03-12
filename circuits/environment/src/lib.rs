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

#![forbid(unsafe_code)]
#![allow(clippy::type_complexity)]

#[macro_use]
extern crate num_derive;

pub mod circuit;
pub use circuit::*;

pub mod environment;
pub use environment::*;

pub mod helpers;
pub use helpers::*;

pub mod parser;
pub use parser::*;

mod r1cs;
use r1cs::*;

#[macro_export]
macro_rules! scoped {
    ($scope_name:expr, $block:block) => {
        E::scoped($scope_name, || $block)
    };
}
