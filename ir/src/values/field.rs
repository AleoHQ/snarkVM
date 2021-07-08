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

use crate::ir;

/// An unbounded field value
#[derive(Clone, Debug, PartialEq)]
pub struct Field {
    pub negate: bool,
    pub values: Vec<u64>,
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let negate = if self.negate { "-" } else { "" };
        write!(f, "{}{:?}", negate, self.values)
    }
}

impl Field {
    pub(crate) fn decode(from: ir::Field) -> Self {
        Self {
            negate: from.negate,
            values: from.values,
        }
    }

    pub(crate) fn encode(&self) -> ir::Field {
        ir::Field {
            negate: self.negate,
            values: self.values.clone(),
        }
    }
}
