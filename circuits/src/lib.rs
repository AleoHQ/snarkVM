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

#[macro_use]
extern crate enum_index_derive;

pub mod literal;
pub use literal::*;

pub mod type_;
pub use type_::*;

pub use snarkvm_circuits_environment::*;

pub use snarkvm_circuits_core::*;
pub use snarkvm_circuits_edge::*;
pub use snarkvm_circuits_types::*;

pub mod prelude {
    pub use super::*;
    pub use snarkvm_circuits_environment::{prelude::*, Circuit};
}

pub trait Library<E: Environment> {
    const VERSION: u32;
}

pub type V1 = Literal<Circuit>;

impl Library<Circuit> for V1 {
    const VERSION: u32 = 1;
}
