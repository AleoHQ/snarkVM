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

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    str::FromStr,
};

use snarkvm_ir::{InputData, Program};

fn inner_load_tests<P: AsRef<Path>>(path: P, out: &mut BTreeMap<String, Vec<u8>>, extension: &str) {
    for item in path.as_ref().read_dir().unwrap() {
        let item = item.unwrap();
        let type_ = item.file_type().unwrap();
        let path = item.path();
        if type_.is_file()
            && path
                .extension()
                .map(|x| x.to_string_lossy() == extension)
                .unwrap_or(false)
        {
            out.insert(path.to_string_lossy().into_owned(), fs::read(&path).unwrap());
        } else if type_.is_dir() {
            inner_load_tests(&path, out, extension);
        }
    }
}

pub fn load_tests() -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    inner_load_tests("../tests/ir/", &mut out, "ir");
    out
}

#[test]
fn reserialize_test() {
    let tests = load_tests();
    for (name, raw) in tests {
        let deserialized = Program::deserialize(&raw[..]).expect(&*format!("failed to deserialize {}", name));
        let reserialized = deserialized
            .serialize()
            .expect(&*format!("failed to reserialize {}", name));
        if reserialized != raw {
            panic!("reserialized mismatch for {}", name);
        }
    }
}

#[test]
fn reserialize_input_test() {
    let mut tests = BTreeMap::new();
    inner_load_tests("../tests/ir/", &mut tests, "input");
    for (name, raw) in tests {
        let deserialized = InputData::deserialize(&raw[..]).expect(&*format!("failed to deserialize {}", name));
        let reserialized = deserialized
            .serialize()
            .expect(&*format!("failed to reserialize {}", name));
        if reserialized != raw {
            panic!("reserialized mismatch for {}\n{:?}\n{:?}", name, raw, reserialized);
        }
    }
}

#[test]
fn format_test() {
    let tests = load_tests();
    for (name, raw) in tests {
        let deserialized = Program::deserialize(&raw[..]).expect(&*format!("failed to deserialize {}", name));
        let formatted = deserialized.to_string();
        let expectation_path = PathBuf::from_str(&*format!("{}.fmt", name)).unwrap();
        if expectation_path.exists() {
            let expectation = fs::read_to_string(&expectation_path).unwrap();
            if expectation != formatted {
                panic!(
                    "format mismatch for {}:\nexpected:\n{}\ngot:\n{}",
                    name, expectation, formatted
                );
            }
        } else {
            fs::write(&expectation_path, formatted.as_bytes()).unwrap();
        };
    }
}
