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

use snarkvm_bytecode::{instructions::Add, Function, Global, Immediate, Operand};
use snarkvm_circuits::{traits::*, BaseField, Circuit};

pub struct HelloWorld;

impl HelloWorld {
    /// Initializes a new instance of `HelloWorld` with the given inputs.
    pub fn run<F: Function>(inputs: [Immediate<F::Environment>; 2]) -> Vec<Immediate<F::Environment>> {
        // Allocate a new register for each input, and store each input in the register.
        let mut registers = Vec::with_capacity(2);
        for input in inputs {
            registers.push(F::new_input(input));
        }

        // Add the values in the registers, storing the result in a newly allocated register.
        for pair in registers.chunks(2) {
            let first = Operand::Register(pair[0]);
            let second = Operand::Register(pair[1]);
            let output = F::new_output();
            F::push_instruction(Add::new(output, first, second).into());
        }

        F::evaluate()
    }
}

fn main() {
    let first = Immediate::Base(BaseField::<Circuit>::from_str("1field.public"));
    let second = Immediate::Base(BaseField::from_str("1field.private"));

    let expected = BaseField::one() + BaseField::one();
    let candidate = HelloWorld::run::<Global>([first, second]);
    match &candidate[0] {
        Immediate::Base(output) => assert!(output.is_eq(&expected).eject_value()),
        _ => panic!("Failed to load output"),
    }
}

#[test]
fn test_hello_world() {
    let first = Immediate::Base(BaseField::<Circuit>::from_str("1field.public"));
    let second = Immediate::Base(BaseField::from_str("1field.private"));

    let expected = BaseField::one() + BaseField::one();
    let candidate = HelloWorld::run::<Global>([first, second]);
    match &candidate[0] {
        Immediate::Base(output) => assert!(output.is_eq(&expected).eject_value()),
        _ => panic!("Failed to load output"),
    }
}
