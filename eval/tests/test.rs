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

use std::{collections::BTreeMap, fs, path::Path};

use anyhow::*;
use snarkvm_curves::bls12_377::Fr;
use snarkvm_eval::{edwards_bls12::EdwardsGroupType, ConstrainedValue, Evaluator, SetupEvaluator};
use snarkvm_ir::{InputData, Program, SnarkVMVersion};
use snarkvm_r1cs::TestConstraintSystem;

fn inner_load_tests<P: AsRef<Path>>(path: P, out: &mut BTreeMap<String, Vec<u8>>) {
    for item in path.as_ref().read_dir().unwrap() {
        let item = item.unwrap();
        let type_ = item.file_type().unwrap();
        let path = item.path();
        if type_.is_file() && path.extension().map(|x| x.to_string_lossy() == "ir").unwrap_or(false) {
            out.insert(path.to_string_lossy().into_owned(), fs::read(&path).unwrap());
        } else if type_.is_dir() {
            inner_load_tests(&path, out);
        }
    }
}

pub fn load_tests() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    inner_load_tests("../tests/ir/", &mut out);
    out
}

// fn mock_type(type_: &Type, index: u32) -> Value {
//     match type_ {
//         Type::Address => {
//             let account = AccountAddress::<Components>::from_str(
//                 "aleo1qnr4dkkvkgfqph0vzc3y6z2eu975wnpz2925ntjccd5cfqxtyu8sta57j8",
//             )
//             .unwrap();
//             let mut out = vec![];
//             account.write(&mut out).unwrap();
//             Value::Address(out)
//         }
//         Type::Boolean => Value::Boolean(index % 2 == 0),
//         Type::Field => Value::Field(Field {
//             negate: false,
//             values: vec![index as u64],
//         }),
//         Type::Char => Value::Char('a' as u32 + index % 24),
//         Type::Group => Value::Group(if index % 2 == 0 {
//             Group::Single(Field {
//                 negate: false,
//                 values: vec![index as u64],
//             })
//         } else {
//             Group::Tuple(
//                 GroupCoordinate::Field(Field {
//                     negate: false,
//                     values: vec![index as u64],
//                 }),
//                 GroupCoordinate::Inferred,
//             )
//         }),
//         Type::U8 => Value::Integer(Integer::U8(index as u8)),
//         Type::U16 => Value::Integer(Integer::U16(index as u16)),
//         Type::U32 => Value::Integer(Integer::U32(index as u32)),
//         Type::U64 => Value::Integer(Integer::U64(index as u64)),
//         Type::U128 => Value::Integer(Integer::U128(index as u128)),
//         Type::I8 => Value::Integer(Integer::I8(index as i8)),
//         Type::I16 => Value::Integer(Integer::I16(index as i16)),
//         Type::I32 => Value::Integer(Integer::I32(index as i32)),
//         Type::I64 => Value::Integer(Integer::I64(index as i64)),
//         Type::I128 => Value::Integer(Integer::I128(index as i128)),
//         Type::Array(inner, length) => {
//             let mut out = Vec::with_capacity(*length as usize);
//             for i in 0..*length {
//                 out.push(mock_type(&**inner, index * *length + i));
//             }
//             Value::Array(out)
//         }
//         Type::Tuple(inner) => {
//             let mut out = Vec::with_capacity(inner.len());
//             for (i, type_) in inner.iter().enumerate() {
//                 out.push(mock_type(type_, index * inner.len() as u32 + i as u32));
//             }
//             Value::Tuple(out)
//         }
//         Type::Circuit(inner) => {
//             let mut out = Vec::with_capacity(inner.len());
//             for (i, (_, type_)) in inner.iter().enumerate() {
//                 out.push(mock_type(type_, index * inner.len() as u32 + i as u32));
//             }
//             Value::Tuple(out)
//         }
//     }
// }

// fn mock_inputs(source: &[IrInput], dest: &mut IndexMap<String, Value>, index: u32) {
//     for (i, input) in source.iter().enumerate() {
//         let value = mock_type(&input.type_, i as u32 + index * source.len() as u32);
//         dest.insert(input.name.clone(), value);
//     }
// }

// fn mock_input(header: &Header, index: u32) -> InputData {
//     let mut input = InputData::default();
//     mock_inputs(&header.constant_inputs, &mut input.constants, index * 6);
//     mock_inputs(&header.main_inputs, &mut input.main, index * 6 + 1);
//     mock_inputs(&header.register_inputs, &mut input.registers, index * 6 + 2);
//     mock_inputs(&header.public_states, &mut input.public_states, index * 6 + 3);
//     mock_inputs(
//         &header.private_leaf_states,
//         &mut input.private_leaf_states,
//         index * 6 + 4,
//     );
//     mock_inputs(
//         &header.private_record_states,
//         &mut input.private_record_states,
//         index * 6 + 5,
//     );
//     input
// }

fn setup_test_item(
    raw: &[u8],
    input: &[u8],
) -> Result<(TestConstraintSystem<Fr>, ConstrainedValue<Fr, EdwardsGroupType>)> {
    let deserialized = Program::deserialize(raw)?;
    let mut cs = TestConstraintSystem::<Fr>::new();
    let mut eval = SetupEvaluator::<Fr, EdwardsGroupType, _>::new(&mut cs);
    assert_eq!(deserialized.header.version, SnarkVMVersion::default());
    // let input_data = mock_input(&deserialized.header, 0);
    let input_data = InputData::deserialize(input)?;
    let output = eval.evaluate(&deserialized, &input_data)?;
    Ok((cs, output))
}

#[test]
fn setup_test() {
    let tests = load_tests();
    let mut fail = 0usize;
    for (name, raw) in &tests {
        let input = fs::read(&*format!("{}.input", name)).expect("failed to read test input");
        match setup_test_item(&raw[..], &input[..]) {
            Ok((cs, output)) => {
                if !cs.is_satisfied() {
                    eprintln!("<{}> failed (unsatisfied)", name);
                    fail += 1;
                }
                println!("<{}> {} constraints: {}", name, cs.num_constraints(), output);
            }
            Err(e) => {
                eprintln!("<{}> failed due to: {:?}", name, e);
                fail += 1;
            }
        }
    }
    if fail > 0 {
        panic!("{}/{} tests failed", fail, tests.len());
    } else {
        println!("{}/{} tests passed", tests.len(), tests.len());
    }
}
