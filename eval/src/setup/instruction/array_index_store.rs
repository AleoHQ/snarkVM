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
    pub(super) fn evaluate_array_index_store(&mut self, instruction: &Instruction) -> Result<()> {
        let (destination, values) = if let Instruction::ArrayIndexStore(QueryData { destination, values }) = instruction
        {
            (destination, values)
        } else {
            unimplemented!("unsupported instruction in evaluate_array_index_store");
        };

        //todo: optimize array copies here

        let index = self.resolve(values.get(0).unwrap())?.into_owned();
        let target = self.resolve(values.get(1).unwrap())?.into_owned();
        let array = self.resolve(&Value::Ref(*destination))?.into_owned();

        let index_resolved = index
            .extract_integer()
            .map_err(|value| anyhow!("invalid value for array index store: {}", value))?;
        let array = array
            .extract_array()
            .map_err(|value| anyhow!("invalid array for array index store: {}", value))?;

        let out = if let Some(index) = index_resolved.to_usize() {
            if index >= array.len() {
                return Err(ArrayError::array_index_out_of_bounds(index, array.len()).into());
            }
            let mut out = array.clone();
            out[index] = target;
            ConstrainedValue::Array(out)
        } else if array.is_empty() {
            return Err(ArrayError::array_index_out_of_bounds(0, 0).into());
        } else {
            let mut cs = self.cs();
            {
                let array_len: u32 = array
                    .len()
                    .try_into()
                    .map_err(|_| ArrayError::array_length_out_of_bounds())?;
                Self::array_bounds_check(&mut cs, index_resolved, array_len)?;
            }

            let array = array.clone();
            let mut out = Vec::with_capacity(array.len());
            for (i, item) in array.into_iter().enumerate() {
                let namespace_string = format!("evaluate dyn array assignment eq {}", i);
                let eq_namespace = cs.ns(|| namespace_string);

                let i = match &index_resolved {
                    Integer::U8(_) => Integer::U8(UInt8::constant(
                        i.try_into()
                            .map_err(|_| ArrayError::array_index_out_of_legal_bounds())?,
                    )),
                    Integer::U16(_) => Integer::U16(UInt16::constant(
                        i.try_into()
                            .map_err(|_| ArrayError::array_index_out_of_legal_bounds())?,
                    )),
                    Integer::U32(_) => Integer::U32(UInt32::constant(
                        i.try_into()
                            .map_err(|_| ArrayError::array_index_out_of_legal_bounds())?,
                    )),
                    _ => return Err(ArrayError::invalid_index(index_resolved.get_type().to_string()).into()),
                };
                let index_comparison = index_resolved
                    .evaluate_equal(eq_namespace, &i)
                    .map_err(|e| ValueError::cannot_enforce("==", e))?;

                let unique_namespace = cs.ns(|| format!("select array dyn assignment {}", i));
                let value = ConstrainedValue::conditionally_select(unique_namespace, &index_comparison, &target, &item)
                    .map_err(|e| ValueError::cannot_enforce("conditional select", e))?;
                out.push(value);
            }
            ConstrainedValue::Array(out)
        };
        self.store(*destination, out);
        Ok(())
    }
}
