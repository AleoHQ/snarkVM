// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::*;

impl<N: Network> Client<N> {
    /// Executes a program function call with the given inputs.
    pub fn execute(
        &self,
        private_key: &PrivateKey<N>,
        program_id: impl TryInto<ProgramID<N>>,
        function_name: impl TryInto<Identifier<N>>,
        inputs: impl IntoIterator<IntoIter = impl ExactSizeIterator<Item = impl TryInto<Value<N>>>>,
        fee_record: Option<Record<N, Plaintext<N>>>,
        priority_fee_in_microcredits: u64,
    ) -> Result<Transaction<N>> {
        let rng = &mut rand::thread_rng();
        // Prepare the program ID.
        let program_id = program_id.try_into().map_err(|_| anyhow!("Invalid program ID"))?;

        // Initialize the query.
        let query: Query<N, BlockMemory<_>> = (&self.node_url().to_string()).into();
        // Check if the program exists.
        if !self.vm.contains_program(&program_id) {
            match query.get_program(&program_id) {
                // Insert the program into the VM.
                Ok(program) => self.vm.process().write().add_program(&program)?,
                Err(_) => bail!("Program '{program_id}' does not exist"),
            }
        }

        // Return the transaction
        self.vm.execute(
            private_key,
            (program_id, function_name),
            inputs.into_iter(),
            fee_record,
            priority_fee_in_microcredits,
            Some(query),
            rng,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::console::program::{Entry, Literal, Plaintext};

    use core::str::FromStr;
    use std::convert::TryFrom;

    type N = crate::prelude::Testnet3;

    #[test]
    fn test_execute() {
        // Initialize the client.
        let client = Client::<N>::new("https://vm.aleo.org/api").unwrap();

        // Derive the view key.
        let private_key =
            PrivateKey::<N>::from_str("APrivateKey1zkp5fCUVzS9b7my34CdraHBF9XzB58xYiPzFJQvjhmvv7A8").unwrap();
        let view_key = ViewKey::<N>::try_from(&private_key).unwrap();
        let address = view_key.to_address();

        // Scan for the record.
        let records = client.scan(private_key, 14200..14300).unwrap();
        assert_eq!(records.len(), 2);
        let (_commitment, record) = records[0].clone();
        let (_commitment, fee_record) = records[0].clone();

        // Decrypt the record.
        let record = record.decrypt(&view_key).unwrap();
        let amount = match record.data().get(&Identifier::from_str("microcredits").unwrap()).unwrap() {
            Entry::Private(Plaintext::Literal(Literal::<N>::U64(amount), _)) => amount,
            _ => unreachable!(),
        };
        //Decrypt the fee record.
        let fee_record = fee_record.decrypt(&view_key).unwrap();

        // Prepare the inputs.
        let inputs = [record.to_string(), address.to_string(), (**amount).to_string()];
        // Execute the program.
        let transaction =
            client.execute(&private_key, "credits.aleo", "transfer_private", inputs, Some(fee_record), 10).unwrap();
        assert_eq!(transaction.transitions().count(), 2);

        // let response = reqwest::blocking::Client::new()
        //     .post(format!("{}/testnet3/transaction/broadcast", client.base_url))
        //     .header("Content-Type", "application/json")
        //     .body(serde_json::to_string(&transaction).unwrap()).send().unwrap();
        // println!("{:#?}\n\n{:#?}", transaction, response);
    }
}
