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

use snarkvm_r1cs::Namespace;

use super::*;

pub(super) struct EvaluatorState<'a, F: PrimeField, G: GroupType<F>, CS: ConstraintSystem<F>> {
    pub program: &'a Program,
    variables: HashMap<u32, ConstrainedValue<F, G>>,
    call_depth: usize,
    cs: CS,
    pub parent_variables: HashMap<u32, ConstrainedValue<F, G>>,
    pub function_index: u32,
    pub instruction_index: u32,
}

impl<'a, F: PrimeField, G: GroupType<F>, CS: ConstraintSystem<F>> EvaluatorState<'a, F, G, CS> {
    pub fn new(program: &'a Program, cs: CS) -> Self {
        Self {
            program,
            variables: HashMap::new(),
            call_depth: 0,
            cs,
            parent_variables: HashMap::new(),
            function_index: 0,
            instruction_index: 0,
        }
    }

    pub fn child<T, E, I: FnMut(&mut EvaluatorState<'a, F, G, Namespace<'_, F, CS::Root>>) -> Result<T, E>>(
        &mut self,
        name: &str,
        mut inner: I,
        merge: &mut HashMap<u32, ConstrainedValue<F, G>>,
    ) -> Result<T, E> {
        let function_index = self.function_index;
        let instruction_index = self.instruction_index;

        let mut state = EvaluatorState {
            program: self.program,
            variables: HashMap::new(),
            call_depth: self.call_depth,
            parent_variables: self.variables.clone().union(self.parent_variables.clone()), // todo: eval perf of im::map here
            cs: self
                .cs
                .ns(|| format!("f#{}i#{} block: {}", function_index, instruction_index, name)),
            function_index: self.function_index,
            instruction_index: self.instruction_index,
        };
        let out = inner(&mut state)?;
        *merge = state.variables;
        Ok(out)
    }

    pub fn cs<'b>(&'b mut self) -> impl ConstraintSystem<F> + 'b {
        let function_index = self.function_index;
        let instruction_index = self.instruction_index;
        self.cs
            .ns(move || format!("f#{}i#{}", function_index, instruction_index))
    }

    pub fn cs_meta<'b>(&'b mut self, meta: &str) -> impl ConstraintSystem<F> + 'b {
        let function_index = self.function_index;
        let instruction_index = self.instruction_index;
        self.cs
            .ns(move || format!("f#{}i#{}: {}", function_index, instruction_index, meta))
    }

    fn allocate_input<CS2: ConstraintSystem<F>>(
        cs: &mut CS2,
        type_: &Type,
        name: &str,
        value: Value,
    ) -> Result<ConstrainedValue<F, G>, ValueError> {
        Ok(match type_ {
            Type::Address => Address::from_input(&mut cs.ns(|| name.to_string()), name, value)?,
            Type::Boolean => bool_from_input(&mut cs.ns(|| name.to_string()), name, value)?,
            Type::Field => FieldType::from_input(&mut cs.ns(|| name.to_string()), name, value)?,
            Type::Char => Char::from_input(&mut cs.ns(|| name.to_string()), name, value)?,
            Type::Group => match value {
                Value::Group(g) => {
                    ConstrainedValue::Group(G::constant(&g)?.to_allocated(&mut cs.ns(|| name.to_string()))?)
                }
                _ => {
                    return Err(
                        GroupError::invalid_group("expected group, didn't find group in input".to_string()).into(),
                    );
                }
            },
            Type::U8
            | Type::U16
            | Type::U32
            | Type::U64
            | Type::U128
            | Type::I8
            | Type::I16
            | Type::I32
            | Type::I64
            | Type::I128 => Integer::from_input(&mut cs.ns(|| name.to_string()), name, value)?,
            Type::Array(inner, len) => {
                let values = match value {
                    Value::Array(x) => x,
                    value => return Err(ValueError::bad_value_for_type(&*type_.to_string(), &*value.to_string())),
                };
                if values.len() != *len as usize {
                    return Err(ValueError::bad_value_for_type(
                        &*type_.to_string(),
                        &*format!("array of length {}", values.len()),
                    ));
                }
                let mut out = Vec::with_capacity(values.len());
                for (i, value) in values.into_iter().enumerate() {
                    out.push(Self::allocate_input(
                        &mut cs.ns(|| format!("{}[{}]", name, i)),
                        &**inner,
                        name,
                        value,
                    )?);
                }
                ConstrainedValue::Array(out)
            }
            Type::Tuple(inner) => {
                let values = match value {
                    Value::Tuple(x) => x,
                    value => return Err(ValueError::bad_value_for_type(&*type_.to_string(), &*value.to_string())),
                };
                if values.len() != inner.len() {
                    return Err(ValueError::bad_value_for_type(
                        &*type_.to_string(),
                        &*format!("tuple of length {}", values.len()),
                    ));
                }
                let mut out = Vec::with_capacity(values.len());
                for (i, (value, type_)) in values.into_iter().zip(inner.iter()).enumerate() {
                    out.push(Self::allocate_input(
                        &mut cs.ns(|| format!("{}.{}", name, i)),
                        type_,
                        name,
                        value,
                    )?);
                }
                ConstrainedValue::Tuple(out)
            }
            Type::Circuit(_) => return Err(ValueError::incompatible_types("cannot have circuit input")),
        })
    }

    pub fn resolve<'b>(&'b mut self, value: &Value) -> Result<Cow<'b, ConstrainedValue<F, G>>> {
        Ok(Cow::Owned(match value {
            Value::Address(bytes) => ConstrainedValue::Address(Address::constant(&bytes[..])?),
            Value::Boolean(value) => ConstrainedValue::Boolean(Boolean::Constant(*value)),
            Value::Field(limbs) => ConstrainedValue::Field(FieldType::constant(&mut self.cs, &limbs)?),
            Value::Char(c) => ConstrainedValue::Char(Char::constant(&mut self.cs, *c)?),
            Value::Group(g) => ConstrainedValue::Group(G::constant(g)?),
            Value::Integer(i) => ConstrainedValue::Integer(Integer::constant(i)?),
            Value::Array(items) => {
                let mut out = Vec::with_capacity(items.len());
                // todo: optionally check inner types
                for item in items {
                    out.push(self.resolve(item)?.into_owned());
                }
                ConstrainedValue::Array(out)
            }
            Value::Tuple(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(self.resolve(item)?.into_owned());
                }
                ConstrainedValue::Tuple(out)
            }
            Value::Str(_) => return Err(anyhow!("cannot have resolved control string")),
            Value::Ref(i) => {
                return Ok(Cow::Borrowed(
                    self.variables
                        .get(i)
                        .or(self.parent_variables.get(i))
                        // .expect("reference to unknown variable")
                        .ok_or_else(|| anyhow!("reference to unknown variable"))?,
                ));
            }
        }))
    }

    pub fn store(&mut self, variable: u32, value: ConstrainedValue<F, G>) {
        self.variables.insert(variable, value);
    }

    pub fn handle_input_block(
        &mut self,
        name: &str,
        input_header: &[IrInput],
        input_values: &IndexMap<String, Value>,
    ) -> Result<()> {
        let mut cs = self.cs.ns(|| format!("input {}", name));
        for ir_input in input_header {
            let value = input_values
                .get(&ir_input.name)
                .ok_or_else(|| anyhow!("missing input value for '{}'", ir_input.name))?;
            if !value.matches_input_type(&ir_input.type_) {
                return Err(anyhow!(
                    "type mismatch for input '{}', expected {}",
                    ir_input.name,
                    ir_input.type_
                ));
            }
            let value = Self::allocate_input(&mut cs, &ir_input.type_, &*ir_input.name, value.clone())?;
            self.variables.insert(ir_input.variable, value);
        }
        Ok(())
    }

    pub fn handle_const_input_block(
        &mut self,
        input_header: &[IrInput],
        input_values: &IndexMap<String, Value>,
    ) -> Result<()> {
        for ir_input in input_header {
            let value = input_values
                .get(&ir_input.name)
                .ok_or_else(|| anyhow!("missing input value for '{}'", ir_input.name))?;
            if !value.matches_input_type(&ir_input.type_) {
                return Err(anyhow!(
                    "type mismatch for input '{}', expected {}",
                    ir_input.name,
                    ir_input.type_
                ));
            }
            let value = self.resolve(value)?.into_owned();
            self.variables.insert(ir_input.variable, value);
        }
        Ok(())
    }

    pub fn evaluate_function(
        &mut self,
        index: usize,
        arguments: &[ConstrainedValue<F, G>],
    ) -> Result<ConstrainedValue<F, G>> {
        let function = self.program.functions.get(index).expect("missing function");

        let mut arg_register = function.argument_start_variable;
        for argument in arguments {
            self.variables.insert(arg_register, argument.clone());
            arg_register += 1;
        }
        let mut result = None;

        let prior_function_index = self.function_index;
        let prior_instruction_index = self.instruction_index;
        self.function_index = index as u32;
        self.instruction_index = 0;
        self.call_depth += 1;

        let out = self.evaluate_block(0, &function.instructions[..], &mut result);

        self.call_depth -= 1;
        self.instruction_index = prior_instruction_index;
        self.function_index = prior_function_index;

        if let Err(e) = out {
            return Err(anyhow!("f#{}: {:?}", index, e));
        }
        Ok(result.unwrap_or_else(|| ConstrainedValue::Tuple(vec![])))
    }

    fn evaluate_control_instruction(
        &mut self,
        base_instruction_index: usize,
        instruction_index: &mut usize,
        block: &[Instruction],
        instruction: &Instruction,
        mut result: &mut Option<ConstrainedValue<F, G>>,
    ) -> Result<bool> {
        match instruction {
            Instruction::Mask(MaskData {
                instruction_count,
                condition,
            }) => {
                let instruction_count = *instruction_count as usize;
                if instruction_count + *instruction_index >= block.len() {
                    return Err(anyhow!("illegal mask block length"));
                }

                let condition = self.resolve(condition)?.into_owned();
                let condition = condition
                    .extract_bool()
                    .map_err(|value| anyhow!("illegal condition type for conditional block: {}", value))?;
                *instruction_index += 1;

                let mut interior = result.clone();
                let mut assignments = HashMap::new();
                let child_result = self.child(
                    &*format!("{}: conditional block", self.instruction_index),
                    |state| {
                        state.evaluate_block(
                            base_instruction_index + *instruction_index,
                            &block[*instruction_index..*instruction_index + instruction_count],
                            &mut interior,
                        )
                    },
                    &mut assignments,
                );
                if child_result.is_err() && condition.get_value().unwrap_or(true) {
                    return Err(child_result.unwrap_err());
                }
                for (variable, value) in assignments {
                    if let Some(prior) = self.variables.get(&variable).or(self.parent_variables.get(&variable)) {
                        let prior = prior.clone(); //todo: optimize away clone
                        let value = ConstrainedValue::conditionally_select(
                            &mut self.cs_meta(&*format!("selection {}", variable)),
                            condition,
                            &value,
                            &prior,
                        )?;
                        self.store(variable, value);
                    } else {
                        // if it didnt exist in parent scope before, it cant exist now
                        // self.store(variable, value);
                    }
                }

                *instruction_index += instruction_count;
                match (result.clone(), interior) {
                    (Some(prior), Some(interior)) => {
                        *result = Some(ConstrainedValue::conditionally_select(
                            &mut self.cs_meta(&*format!("selection result")),
                            condition,
                            &interior,
                            &prior,
                        )?);
                    }
                    (None, Some(interior)) => {
                        // will produce garbage if invalid IR (incomplete return path)
                        *result = Some(interior);
                    }
                    (_, None) => (),
                }
            }
            Instruction::Repeat(RepeatData {
                instruction_count,
                iter_variable,
                from,
                to,
            }) => {
                let instruction_count = *instruction_count as usize;
                if instruction_count + *instruction_index >= block.len() {
                    return Err(anyhow!("illegal repeat block length"));
                }

                let from = self.resolve(from)?.into_owned();
                let from_int = from
                    .extract_integer()
                    .map_err(|value| anyhow!("illegal type for loop init: {}", value))?
                    .to_owned();
                let from = from_int
                    .to_usize()
                    .ok_or_else(|| anyhow!("illegal input-derived loop index"))?;

                let to = self.resolve(to)?.into_owned();
                let to = to
                    .extract_integer()
                    .map_err(|value| anyhow!("illegal type for loop terminator: {}", value))?
                    .to_usize()
                    .ok_or_else(|| anyhow!("illegal input-derived loop terminator"))?;

                *instruction_index += 1;
                //todo: max loop count (DOS vector)
                for i in from..to {
                    self.variables.insert(
                        *iter_variable,
                        ConstrainedValue::Integer(match from_int.get_type() {
                            IntegerType::U8 => Integer::U8(UInt8::constant(
                                i.try_into().map_err(|_| anyhow!("loop index out of range for u8"))?,
                            )),
                            IntegerType::U16 => Integer::U16(UInt16::constant(
                                i.try_into().map_err(|_| anyhow!("loop index out of range for u16"))?,
                            )),
                            IntegerType::U32 => Integer::U32(UInt32::constant(
                                i.try_into().map_err(|_| anyhow!("loop index out of range for u32"))?,
                            )),
                            _ => return Err(anyhow!("illegal type for loop index")),
                        }),
                    );

                    let mut assignments = HashMap::new();

                    self.child(
                        &*format!("{}: iteration #{}", self.instruction_index, i),
                        |state| {
                            state.evaluate_block(
                                base_instruction_index + *instruction_index,
                                &block[*instruction_index..*instruction_index + instruction_count],
                                &mut result,
                            )
                        },
                        &mut assignments,
                    )?;

                    for (variable, value) in assignments {
                        self.store(variable, value);
                    }
                }
                *instruction_index += instruction_count as usize;
            }
            instruction => {
                match self.evaluate_instruction(instruction) {
                    Ok(Some(returned)) => {
                        *result = Some(returned);
                        return Ok(true);
                    }
                    Ok(None) => (),
                    Err(e) => return Err(anyhow!("i#{}: {:?}", *instruction_index + base_instruction_index, e)),
                }
                *instruction_index += 1;
            }
        }

        Ok(false)
    }

    pub fn evaluate_block(
        &mut self,
        base_instruction_index: usize,
        block: &[Instruction],
        result: &mut Option<ConstrainedValue<F, G>>,
    ) -> Result<()> {
        let mut instruction_index = 0usize;
        while instruction_index < block.len() {
            let instruction = &block[instruction_index];
            self.instruction_index = instruction_index as u32 + base_instruction_index as u32;
            if self.evaluate_control_instruction(
                base_instruction_index,
                &mut instruction_index,
                block,
                instruction,
                result,
            )? {
                return Ok(());
            }
        }
        Ok(())
    }
}
