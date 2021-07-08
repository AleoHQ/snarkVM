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
    pub(super) fn array_bounds_check<CS2: ConstraintSystem<F>>(
        cs: &mut CS2,
        index_resolved: &Integer,
        array_len: u32,
    ) -> Result<()> {
        // todo: support non-homogenous comparison
        let array_len_value = match index_resolved {
            Integer::U8(_) => IrInteger::U8(
                array_len
                    .try_into()
                    .map_err(|_| ArrayError::array_index_out_of_legal_bounds())?,
            ),
            Integer::U16(_) => IrInteger::U16(
                array_len
                    .try_into()
                    .map_err(|_| ArrayError::array_index_out_of_legal_bounds())?,
            ),
            Integer::U32(_) => IrInteger::U32(array_len),
            value => return Err(ArrayError::invalid_index(value.to_string()).into()),
        };
        let bounds_check = operations::evaluate_lt::<F, G, _>(
            cs,
            ConstrainedValue::Integer(index_resolved.clone()),
            ConstrainedValue::Integer(Integer::new(&array_len_value)),
        )?;
        let bounds_check = match bounds_check {
            ConstrainedValue::Boolean(b) => b,
            _ => unimplemented!("illegal non-Integer returned from lt"),
        };
        let namespace_string = format!("evaluate array access bounds");
        let mut unique_namespace = cs.ns(|| namespace_string);
        bounds_check
            .enforce_equal(&mut unique_namespace, &Boolean::Constant(true))
            .map_err(|e| ValueError::cannot_enforce("array bounds check", e))?;
        Ok(())
    }

    pub(super) fn evaluate_array_index_get(&mut self, instruction: &Instruction) -> Result<()> {
        let (destination, values) = if let Instruction::ArrayIndexGet(QueryData { destination, values }) = instruction {
            (destination, values)
        } else {
            unimplemented!("unsupported instruction in evaluate_array_index_get");
        };

        let index = self.resolve(values.get(1).unwrap())?.into_owned();
        let array = self.resolve(values.get(0).unwrap())?.into_owned();
        let index_resolved = index
            .extract_integer()
            .map_err(|value| anyhow!("invalid value for array index: {}", value))?;
        let array = array
            .extract_array()
            .map_err(|value| anyhow!("invalid array for array index: {}", value))?;
        let out = if let Some(index) = index_resolved.to_usize() {
            if index >= array.len() {
                return Err(ArrayError::array_index_out_of_bounds(index, array.len()).into());
            }
            array.get(index).cloned().unwrap()
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

            let mut array = array.clone();
            let mut current_value = array.pop().unwrap();
            for (i, item) in array.into_iter().enumerate() {
                let namespace_string = format!("evaluate array access eq {}", i);
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

                let unique_namespace = cs.ns(|| format!("select array access {}", i));
                let value =
                    ConstrainedValue::conditionally_select(unique_namespace, &index_comparison, &item, &current_value)
                        .map_err(|e| ValueError::cannot_enforce("conditional select", e))?;
                current_value = value;
            }
            current_value
        };
        self.store(*destination, out);
        Ok(())
    }
}
