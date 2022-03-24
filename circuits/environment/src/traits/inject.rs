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

use crate::Mode;

/// Operations to inject from a primitive form into a circuit environment.
pub trait Inject {
    type Primitive: Default;

    ///
    /// Initializes a circuit of the given mode and primitive value.
    ///
    fn new(mode: Mode, value: Self::Primitive) -> Self;

    ///
    /// Initializes a constant circuit of the given primitive value.
    ///
    fn constant(value: Self::Primitive) -> Self
    where
        Self: Sized,
    {
        Self::new(Mode::Constant, value)
    }

    ///
    /// Initializes a blank default of the circuit for the given mode.
    /// This operation is used commonly to derive a proving and verifying key.
    ///
    fn blank(mode: Mode) -> Self
    where
        Self: Sized,
    {
        Self::new(mode, Default::default())
    }
}

impl<C: Inject<Primitive = P>, P: Default> Inject for Vec<C> {
    type Primitive = Vec<P>;

    #[inline]
    fn new(mode: Mode, value: Self::Primitive) -> Self {
        value.into_iter().map(|v| C::new(mode, v)).collect()
    }
}

impl<C1: Inject<Primitive = P1>, P1: Default, C2: Inject<Primitive = P2>, P2: Default> Inject for (C1, C2) {
    type Primitive = (P1, P2);

    #[inline]
    fn new(mode: Mode, value: Self::Primitive) -> Self {
        (C1::new(mode, value.0), C2::new(mode, value.1))
    }
}
