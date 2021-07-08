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
    pub(super) fn evaluate_array_slice_store(&mut self, instruction: &Instruction) -> Result<()> {
        let (destination, values) = if let Instruction::ArraySliceStore(QueryData { destination, values }) = instruction
        {
            (destination, values)
        } else {
            unimplemented!("unsupported instruction in evaluate_array_slice_get");
        };

        let array = self.resolve(&Value::Ref(*destination))?.into_owned();
        let array = array
            .extract_array()
            .map_err(|value| anyhow!("illegal target for array slice store: {}", value))?;
        let from = self.resolve(values.get(0).unwrap())?.into_owned();
        let from_resolved = from
            .extract_integer()
            .map_err(|value| anyhow!("invalid value for array slice store from index: {}", value))?;
        let to = self.resolve(values.get(1).unwrap())?.into_owned();
        let to_resolved = to
            .extract_integer()
            .map_err(|value| anyhow!("invalid value for array slice store to index: {}", value))?;
        let target = self.resolve(values.get(2).unwrap())?.into_owned();
        let target_values = target
            .extract_array()
            .map_err(|value| anyhow!("illegal value for array slice store: {}", value))?;

        let const_dimensions = match (from_resolved.to_usize(), to_resolved.to_usize()) {
            (Some(from), Some(to)) => Some((from, to)),
            (Some(from), None) => Some((from, from + target_values.len())),
            (None, Some(to)) => {
                if to < target_values.len() {
                    return Err(ArrayError::array_invalid_slice_length().into());
                }
                Some((to - target_values.len(), to))
            }
            (None, None) => return Err(anyhow!("illegal reference to non-const array slice store index")),
        };

        let out = if let Some((left, right)) = const_dimensions {
            if right - left != target_values.len() {
                return Err(ArrayError::array_invalid_slice_length().into());
            }
            if right > array.len() {
                return Err(ArrayError::array_index_out_of_bounds(right, array.len()).into());
            }
            let mut new_value = array.clone();
            let _: Vec<_> = new_value.splice(left..right, target_values.iter().cloned()).collect();
            ConstrainedValue::Array(new_value)
        } else {
            unimplemented!("dynamic array slice assignment");
        };
        self.store(*destination, out);
        Ok(())
    }
}
