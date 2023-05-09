// Copyright (C) 2019-2023 Aleo Systems Inc.
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

use crate::utilities::{Benchmark, Operation};

use console::{
    network::Network,
    program::{Address, Literal, Plaintext, Value, Zero, U64},
};
use snarkvm_synthesizer::Program;
use snarkvm_utilities::TestRng;

use std::{marker::PhantomData, str::FromStr};

pub struct TransferPublic<N: Network> {
    num_executions: usize,
    phantom: PhantomData<N>,
}

impl<N: Network> TransferPublic<N> {
    pub fn new(num_executions: usize) -> Self {
        Self { num_executions, phantom: Default::default() }
    }
}

impl<N: Network> Benchmark<N> for TransferPublic<N> {
    fn name(&self) -> String {
        format!("transfer_public/{}_executions", self.num_executions)
    }

    fn setup_operations(&mut self) -> Vec<Vec<Operation<N>>> {
        // Construct the program.
        let program = Program::from_str(&format!(
            r"
program transfer_public_{}.aleo;
mapping account:
    key left as address.public;
    value right as u64.public;
function transfer_public:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as u64.public;
    finalize r0 r1 r2;
finalize transfer_public:
    input r0 as address.public;
    input r1 as address.public;
    input r2 as u64.public;
    get.or_init account[r0] 0u64 into r3;
    sub r3 r2 into r4;
    set r4 into account[r0];
    get.or_init account[r1] 0u64 into r5;
    add r5 r2 into r6;
    set r6 into account[r1];
",
            self.num_executions
        ))
        .unwrap();
        vec![vec![Operation::Deploy(Box::new(program))]]
    }

    fn benchmark_operations(&mut self) -> Vec<Operation<N>> {
        // Initialize storage for the benchmark operations.
        let mut benchmarks = Vec::with_capacity(self.num_executions);
        // Initialize an RNG for generating the operations.
        let rng = &mut TestRng::default();
        // Construct the operations.
        for _ in 0..self.num_executions {
            #[allow(deprecated)]
            let sender = Address::rand(rng);
            #[allow(deprecated)]
            let receiver = Address::rand(rng);
            benchmarks.push(Operation::Execute(
                format!("transfer_public_{}.aleo", self.num_executions),
                "transfer_public".to_string(),
                vec![
                    Value::Plaintext(Plaintext::from(Literal::Address(sender))),
                    Value::Plaintext(Plaintext::from(Literal::Address(receiver))),
                    Value::Plaintext(Plaintext::from(Literal::U64(U64::zero()))),
                ],
            ));
        }
        benchmarks
    }
}
