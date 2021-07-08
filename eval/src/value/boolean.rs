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

use snarkvm_fields::PrimeField;
use snarkvm_gadgets::{AllocGadget, Boolean};
use snarkvm_ir::Value;
use snarkvm_r1cs::ConstraintSystem;

use crate::{errors::BooleanError, ConstrainedValue, GroupType};

pub(crate) fn allocate_bool<F: PrimeField, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    name: &str,
    option: bool,
) -> Result<Boolean, BooleanError> {
    Boolean::alloc(cs.ns(|| format!("`{}: bool`", name)), || Ok(option))
        .map_err(|_| BooleanError::missing_boolean(format!("{}: bool", name)))
}

pub(crate) fn bool_from_input<F: PrimeField, G: GroupType<F>, CS: ConstraintSystem<F>>(
    cs: &mut CS,
    name: &str,
    value: Value,
) -> Result<ConstrainedValue<F, G>, BooleanError> {
    // Check that the input value is the correct type
    let value = if let Value::Boolean(character) = value {
        character
    } else {
        return Err(BooleanError::invalid_boolean(value.to_string()));
    };

    let number = allocate_bool(cs, name, value)?;

    Ok(ConstrainedValue::Boolean(number))
}
