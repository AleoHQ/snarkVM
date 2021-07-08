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

use super::*;

impl<'a, F: PrimeField, G: GroupType<F>, CS: ConstraintSystem<F>> EvaluatorState<'a, F, G, CS> {
    pub(super) fn evaluate_array_slice_get(&mut self, instruction: &Instruction) -> Result<()> {
        let (destination, values) = if let Instruction::ArraySliceGet(QueryData { destination, values }) = instruction {
            (destination, values)
        } else {
            unimplemented!("unsupported instruction in evaluate_array_slice_get");
        };

        let array = self.resolve(values.get(0).unwrap())?.into_owned();
        let array = array
            .extract_array()
            .map_err(|value| anyhow!("illegal value for array slice: {}", value))?;
        let from = self.resolve(values.get(1).unwrap())?.into_owned();
        let from_resolved = from
            .extract_integer()
            .map_err(|value| anyhow!("invalid value for array slice from index: {}", value))?;
        let to = self.resolve(values.get(2).unwrap())?.into_owned();
        let to_resolved = to
            .extract_integer()
            .map_err(|value| anyhow!("invalid value for array slice to index: {}", value))?;
        let length = self.resolve(values.get(3).unwrap())?.into_owned();
        let length = length
            .extract_integer()
            .map_err(|value| anyhow!("invalid value for array slice length: {}", value))?
            .to_usize()
            .ok_or_else(|| anyhow!("cannot have non-const array length for array slice"))?;

        let const_dimensions = match (from_resolved.to_usize(), to_resolved.to_usize()) {
            (Some(from), Some(to)) => Some((from, to)),
            (Some(from), None) => Some((from, from + length)),
            (None, Some(to)) => {
                if to < length {
                    return Err(ArrayError::array_invalid_slice_length().into());
                }
                Some((to - length, to))
            }
            (None, None) => None,
        };

        let out = if let Some((left, right)) = const_dimensions {
            if right - left != length {
                return Err(ArrayError::array_invalid_slice_length().into());
            }
            if right > array.len() {
                return Err(ArrayError::array_index_out_of_bounds(right, array.len()).into());
            }
            ConstrainedValue::Array(array[left..right].to_owned())
        } else {
            let mut cs = self.cs();
            {
                let calc_len = operations::enforce_sub::<F, G, _>(
                    &mut cs,
                    ConstrainedValue::Integer(to_resolved.clone()),
                    ConstrainedValue::Integer(from_resolved.clone()),
                )?;
                let calc_len = match calc_len {
                    ConstrainedValue::Integer(i) => i,
                    _ => unimplemented!("illegal non-Integer returned from sub"),
                };
                let namespace_string = format!("evaluate array range access length check");
                let mut unique_namespace = cs.ns(|| namespace_string);
                calc_len
                    .enforce_equal(&mut unique_namespace, &Integer::new(&IrInteger::U32(length as u32)))
                    .map_err(|e| ValueError::cannot_enforce("array length check", e))?;
            }
            {
                Self::array_bounds_check(
                    &mut cs,
                    to_resolved,
                    array
                        .len()
                        .try_into()
                        .map_err(|_| ArrayError::array_length_out_of_bounds())?,
                )?;
            }
            let mut windows = array.windows(length);
            let mut result = ConstrainedValue::Array(vec![]);

            for i in 0..length {
                let window = if let Some(window) = windows.next() {
                    window
                } else {
                    break;
                };
                let array_value = ConstrainedValue::Array(window.to_vec());
                let mut unique_namespace = cs.ns(|| format!("array index eq-check {}", i));

                let equality = operations::evaluate_eq::<F, G, _>(
                    &mut unique_namespace,
                    ConstrainedValue::Integer(from_resolved.clone()),
                    ConstrainedValue::Integer(Integer::new(&IrInteger::U32(i as u32))),
                )?;
                let equality = match equality {
                    ConstrainedValue::Boolean(b) => b,
                    _ => unimplemented!("unexpected non-Boolean for evaluate_eq"),
                };

                let unique_namespace = unique_namespace.ns(|| format!("array index {}", i));
                result = ConstrainedValue::conditionally_select(unique_namespace, &equality, &array_value, &result)
                    .map_err(|e| ValueError::cannot_enforce("conditional select", e))?;
            }
            result
        };
        self.store(*destination, out);
        Ok(())
    }
}
