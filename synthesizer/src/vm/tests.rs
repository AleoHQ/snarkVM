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

use crate::{vm::test_helpers::sample_next_block, VM};
use console::{
    account::{Address, PrivateKey, ViewKey},
    network::Testnet3,
    program::{Entry, Literal, Plaintext, ProgramID, Record, Value},
    types::U64,
};
use ledger_block::{Block, Input, Transaction, Transition};
use ledger_store::helpers::memory::ConsensusMemory;

type CurrentNetwork = Testnet3;

/// A helper function to initialize the VM.
/// Returns a VM, the genesis block, and a list of records in the genesis block.
fn initialize_vm(
    rng: &mut TestRng,
) -> (
    VM<CurrentNetwork, ConsensusMemory<CurrentNetwork>>,
    Block<CurrentNetwork>,
    Vec<Record<CurrentNetwork, Plaintext<CurrentNetwork>>>,
) {
    // Initialize a new caller.
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();

    // Initialize the VM.
    let vm = crate::vm::test_helpers::sample_vm();

    // Initialize the genesis block.
    let genesis = crate::vm::test_helpers::sample_genesis_block(rng);

    // Update the VM.
    vm.add_next_block(&genesis).unwrap();

    // Select records to spend.
    let records = genesis.transitions().cloned().flat_map(Transition::into_records).collect::<Vec<(_, _)>>();
    let decrypted_records =
        records.iter().map(|(_, record)| record.decrypt(&caller_view_key).unwrap()).collect::<Vec<_>>();

    (vm, genesis, decrypted_records)
}

/// Returns the `private_key`, `view_key`, and `address` of the caller.
fn caller_account(rng: &mut TestRng) -> (PrivateKey<CurrentNetwork>, ViewKey<CurrentNetwork>, Address<CurrentNetwork>) {
    let caller_private_key = crate::vm::test_helpers::sample_genesis_private_key(rng);
    let caller_view_key = ViewKey::try_from(&caller_private_key).unwrap();
    let caller_address = Address::try_from(&caller_private_key).unwrap();

    (caller_private_key, caller_view_key, caller_address)
}

/// Returns the `private_key`, `view_key`, and `address` of the recipient.
fn recipient_account(
    rng: &mut TestRng,
) -> (PrivateKey<CurrentNetwork>, ViewKey<CurrentNetwork>, Address<CurrentNetwork>) {
    let recipient_private_key = PrivateKey::new(rng).unwrap();
    let recipient_view_key = ViewKey::try_from(&recipient_private_key).unwrap();
    let recipient_address = Address::try_from(&recipient_private_key).unwrap();

    (recipient_private_key, recipient_view_key, recipient_address)
}

/// Helper function to get the balance of a `credits.aleo` record.
fn get_balance(record: &Record<CurrentNetwork, Plaintext<CurrentNetwork>>) -> Result<u64> {
    match record.data().get(&Identifier::from_str("microcredits")?) {
        Some(Entry::Private(Plaintext::Literal(Literal::U64(amount), ..))) => Ok(**amount),
        _ => bail!("Invalid entry type for credits.aleo."),
    }
}

#[test]
fn test_credits_program_mint() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let (caller_private_key, caller_view_key, caller_address) = caller_account(rng);

    // Initialize the VM.
    let (vm, _, _) = initialize_vm(rng);

    // Prepare the inputs.
    let amount = 123456u64;
    let inputs = [
        Value::<CurrentNetwork>::from_str(&caller_address.to_string()).unwrap(),
        Value::<CurrentNetwork>::from_str(&format!("{amount}u64")).unwrap(),
    ]
    .into_iter();

    // Create a mint transaction.
    let transaction = vm.execute(&caller_private_key, ("credits.aleo", "mint"), inputs, None, None, rng).unwrap();

    // Check that the transaction is valid.
    assert!(vm.verify_transaction(&transaction, None));

    // Check that the transaction is an execute transaction with 1 transition.
    assert!(transaction.is_execute());
    let Transaction::Execute(_, execution, _) = transaction else {
        unreachable!("Invalid transaction type.")
    };
    let transitions = execution.transitions().collect::<Vec<_>>();
    assert_eq!(transitions.len(), 1);
    let transition: &Transition<CurrentNetwork> = transitions[0];

    /* Inputs */

    // Check that the transition inputs are correct.
    let transition_inputs = transition.inputs();
    assert_eq!(transition_inputs.len(), 2);

    // Check that the first input is the caller address.
    let Input::Public(_, Some(Plaintext::Literal(Literal::Address(input_address), _))) = &transition_inputs[0] else {
        unreachable!("Invalid input type for `credits.aleo/mint`.")
    };
    assert_eq!(input_address, &caller_address);
    // Check that the second input is the amount.
    let Input::Public(_, Some(Plaintext::Literal(Literal::U64(input_amount), _))) = &transition_inputs[1] else {
        unreachable!("Invalid input type for `credits.aleo/mint`.");
    };
    assert_eq!(**input_amount, amount);

    /* Outputs */

    // Check that the transition outputs are correct.
    let transition_outputs = transition.outputs();
    assert_eq!(transition_outputs.len(), 1);

    // Check that the output record is correct.
    let (_, record) = transition_outputs[0].record().unwrap();
    let record = record.decrypt(&caller_view_key).unwrap();
    assert_eq!(**record.owner(), caller_address);
    assert_eq!(get_balance(&record).unwrap(), amount);
}

#[test]
fn test_credits_program_transfer_public() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let (caller_private_key, caller_view_key, caller_address) = caller_account(rng);

    // Initialize a new recipient.
    let (_, _, recipient_address) = recipient_account(rng);

    // Initialize the VM.
    let (vm, _, records) = initialize_vm(rng);

    // Select records to spend.
    let transfer_record = records[0].clone();
    let fee_record = records[1].clone();
    let second_fee_record = records[2].clone();

    // Prepare the inputs.
    let amount_1 = 123456u64;
    let inputs = [
        Value::<CurrentNetwork>::Record(transfer_record),
        Value::<CurrentNetwork>::from_str(&caller_address.to_string()).unwrap(),
        Value::<CurrentNetwork>::from_str(&format!("{amount_1}u64")).unwrap(),
    ]
    .into_iter();

    // Create a transfer_private_to_public transaction.
    let transaction = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_private_to_public"),
            inputs,
            Some((fee_record, 0)),
            None,
            rng,
        )
        .unwrap();

    // Construct and add the new block.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    vm.add_next_block(&block).unwrap();

    // Prepare the inputs.
    let amount_2 = 100000u64;
    let inputs = [
        Value::<CurrentNetwork>::from_str(&recipient_address.to_string()).unwrap(),
        Value::<CurrentNetwork>::from_str(&format!("{amount_2}u64")).unwrap(),
    ]
    .into_iter();

    // Create a transfer_private_to_public transaction.
    let transaction = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public"),
            inputs,
            Some((second_fee_record, 0)),
            None,
            rng,
        )
        .unwrap();

    // Check that the transaction is valid.
    assert!(vm.verify_transaction(&transaction, None));

    // Check that the transaction is an execute transaction with 1 transition.
    assert!(transaction.is_execute());
    let Transaction::Execute(_, execution, Some(fee)) = &transaction else {
        unreachable!("Invalid transaction type.")
    };
    let transitions = execution.transitions().collect::<Vec<_>>();
    assert_eq!(transitions.len(), 1);
    let transition: &Transition<CurrentNetwork> = transitions[0];

    /* Inputs */
    // Check that the transition inputs are correct.
    let transition_inputs = transition.inputs();
    assert_eq!(transition_inputs.len(), 2);

    // Check that the first input is the recipient address.
    let Input::Public(_, Some(Plaintext::Literal(Literal::Address(input_address), _))) = &transition_inputs[0] else {
        unreachable!("Invalid input type for `credits.aleo/transfer_public`.")
    };
    assert_eq!(input_address, &recipient_address);
    // Check that the second input is the amount.
    let Input::Public(_, Some(Plaintext::Literal(Literal::U64(input_amount), _))) = &transition_inputs[1] else {
        unreachable!("Invalid input type for `credits.aleo/transfer_public`.");
    };
    assert_eq!(**input_amount, amount_2);

    /* Outputs */

    // Check that the transition outputs are correct.
    let transition_outputs = transition.outputs();
    assert_eq!(transition_outputs.len(), 0);

    /* Fee */

    // Check that the change record is correct.
    let fee_records = fee.transition().records().map(|(_, record)| record).collect::<Vec<_>>();
    assert_eq!(fee_records.len(), 1);
    assert_eq!(**fee_records[0].decrypt(&caller_view_key).unwrap().owner(), caller_address);

    /* Finalize */

    let program_id = ProgramID::from_str("credits.aleo").unwrap();
    let mapping_name = Identifier::from_str("account").unwrap();
    let caller_key = Plaintext::from(Literal::Address(caller_address));
    let recipient_key = Plaintext::from(Literal::Address(recipient_address));

    // Check the initial finalize state.
    let expected_amount_for_caller = Value::from(Literal::U64(U64::new(amount_1)));
    assert_eq!(
        vm.finalize_store().get_value_speculative(&program_id, &mapping_name, &caller_key).unwrap(),
        Some(expected_amount_for_caller)
    );
    assert!(vm.finalize_store().get_value_speculative(&program_id, &mapping_name, &recipient_key).unwrap().is_none());

    // Construct and add the new block.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    vm.add_next_block(&block).unwrap();

    // Check that the finalize state is correct.
    let expected_amount_for_caller = Value::from(Literal::U64(U64::new(amount_1 - amount_2)));
    let expected_amount_for_recipient = Value::from(Literal::U64(U64::new(amount_2)));
    assert_eq!(
        vm.finalize_store().get_value_speculative(&program_id, &mapping_name, &caller_key).unwrap(),
        Some(expected_amount_for_caller)
    );
    assert_eq!(
        vm.finalize_store().get_value_speculative(&program_id, &mapping_name, &recipient_key).unwrap(),
        Some(expected_amount_for_recipient)
    );
}

#[test]
fn test_credits_program_transfer_private() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let (caller_private_key, caller_view_key, caller_address) = caller_account(rng);

    // Initialize a new recipient.
    let (_, recipient_view_key, recipient_address) = recipient_account(rng);

    // Initialize the VM.
    let (vm, genesis, records) = initialize_vm(rng);

    // Select records to spend.
    let transfer_record = records[0].clone();
    let fee_record = records[1].clone();

    // Prepare the inputs.
    let amount = 123456u64;
    let inputs = [
        Value::<CurrentNetwork>::Record(transfer_record.clone()),
        Value::<CurrentNetwork>::from_str(&recipient_address.to_string()).unwrap(),
        Value::<CurrentNetwork>::from_str(&format!("{amount}u64")).unwrap(),
    ]
    .into_iter();

    // Create a transfer_private transaction.
    let transaction = vm
        .execute(&caller_private_key, ("credits.aleo", "transfer_private"), inputs, Some((fee_record, 0)), None, rng)
        .unwrap();

    // Check that the transaction is valid.
    assert!(vm.verify_transaction(&transaction, None));

    // Check that the transaction is an execute transaction with 1 transition.
    assert!(transaction.is_execute());
    let Transaction::Execute(_, execution, Some(fee)) = transaction else {
        unreachable!("Invalid transaction type.")
    };
    let transitions = execution.transitions().collect::<Vec<_>>();
    assert_eq!(transitions.len(), 1);
    let transition: &Transition<CurrentNetwork> = transitions[0];

    /* Inputs */

    // Check that the transition inputs are correct.
    let transition_inputs = transition.inputs();
    assert_eq!(transition_inputs.len(), 3);
    // Check that the first input is the encrypted input record.
    let Input::Record(serial_number, _) = &transition_inputs[0] else {
        unreachable!("Invalid input type for `credits.aleo/transfer_private`.")
    };
    let commitment = genesis.commitments().next().ok_or_else(|| anyhow!("No commitments found")).unwrap();
    assert_eq!(
        *serial_number,
        Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::serial_number(caller_private_key, *commitment).unwrap()
    );
    // Check that the second input is the private recipient address.
    assert!(matches!(transition_inputs[1], Input::Private(_, Some(_))));
    // Check that the third input is the private amount.
    assert!(matches!(transition_inputs[2], Input::Private(_, Some(_))));

    /* Outputs */

    // Check that the transition outputs are correct.
    let transition_outputs = transition.outputs();
    assert_eq!(transition_outputs.len(), 2);

    // Check that the output record is correct.
    let (_, record) = transition_outputs[0].record().unwrap();
    let record = record.decrypt(&recipient_view_key).unwrap();
    assert_eq!(**record.owner(), recipient_address);
    assert_eq!(get_balance(&record).unwrap(), amount);

    // Check that the output record is correct.
    let (_, record) = transition_outputs[1].record().unwrap();
    let record = record.decrypt(&caller_view_key).unwrap();
    assert_eq!(**record.owner(), caller_address);
    assert_eq!(get_balance(&record).unwrap(), get_balance(&transfer_record).unwrap() - amount);

    /* Fee */

    // Check that the change record is correct.
    let fee_records = fee.transition().records().map(|(_, record)| record).collect::<Vec<_>>();
    assert_eq!(fee_records.len(), 1);
    assert_eq!(**fee_records[0].decrypt(&caller_view_key).unwrap().owner(), caller_address);
}

#[test]
fn test_credits_program_transfer_private_to_public() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let (caller_private_key, caller_view_key, caller_address) = caller_account(rng);

    // Initialize a new recipient.
    let (_, _, recipient_address) = recipient_account(rng);

    // Initialize the VM.
    let (vm, genesis, records) = initialize_vm(rng);

    // Select records to spend.
    let transfer_record = records[0].clone();
    let fee_record = records[1].clone();

    // Prepare the inputs.
    let amount = 123456u64;
    let inputs = [
        Value::<CurrentNetwork>::Record(transfer_record.clone()),
        Value::<CurrentNetwork>::from_str(&recipient_address.to_string()).unwrap(),
        Value::<CurrentNetwork>::from_str(&format!("{amount}u64")).unwrap(),
    ]
    .into_iter();

    // Create a transfer_private_to_public transaction.
    let transaction = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_private_to_public"),
            inputs,
            Some((fee_record, 0)),
            None,
            rng,
        )
        .unwrap();

    // Check that the transaction is valid.
    assert!(vm.verify_transaction(&transaction, None));

    // Check that the transaction is an execute transaction with 1 transition.
    assert!(transaction.is_execute());
    let Transaction::Execute(_, execution, Some(fee)) = &transaction else {
        unreachable!("Invalid transaction type.")
    };
    let transitions = execution.transitions().collect::<Vec<_>>();
    assert_eq!(transitions.len(), 1);
    let transition: &Transition<CurrentNetwork> = transitions[0];

    /* Inputs */

    // Check that the transition inputs are correct.
    let transition_inputs = transition.inputs();
    assert_eq!(transition_inputs.len(), 3);

    // Check that the first input is the input record.
    let Input::Record(serial_number, _) = &transition_inputs[0] else {
        unreachable!("Invalid input type for `credits.aleo/transfer_private`.")
    };
    let commitment = genesis.commitments().next().ok_or_else(|| anyhow!("No commitments found")).unwrap();
    assert_eq!(
        *serial_number,
        Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::serial_number(caller_private_key, *commitment).unwrap()
    );
    // Check that the second input is the recipient address.
    let Input::Public(_, Some(Plaintext::Literal(Literal::Address(input_address), _))) = &transition_inputs[1] else {
        unreachable!("Invalid input type for `credits.aleo/transfer_private_to_public`.")
    };
    assert_eq!(input_address, &recipient_address);
    // Check that the third input is the amount.
    let Input::Public(_, Some(Plaintext::Literal(Literal::U64(input_amount), _))) = &transition_inputs[2] else {
        unreachable!("Invalid input type for `credits.aleo/transfer_private_to_public`.");
    };
    assert_eq!(**input_amount, amount);

    /* Outputs */

    // Check that the transition outputs are correct.
    let transition_outputs = transition.outputs();
    assert_eq!(transition_outputs.len(), 1);

    // Check that the output record is correct.
    let (_, record) = transition_outputs[0].record().unwrap();
    let record = record.decrypt(&caller_view_key).unwrap();
    assert_eq!(**record.owner(), caller_address);
    assert_eq!(get_balance(&record).unwrap(), get_balance(&transfer_record).unwrap() - amount);

    /* Fee */

    // Check that the change record is correct.
    let fee_records = fee.transition().records().map(|(_, record)| record).collect::<Vec<_>>();
    assert_eq!(fee_records.len(), 1);
    assert_eq!(**fee_records[0].decrypt(&caller_view_key).unwrap().owner(), caller_address);

    /* Finalize */

    let program_id = ProgramID::from_str("credits.aleo").unwrap();
    let mapping_name = Identifier::from_str("account").unwrap();
    let key = Plaintext::from(Literal::Address(recipient_address));

    // Check the initial finalize state.
    assert!(vm.finalize_store().get_value_speculative(&program_id, &mapping_name, &key).unwrap().is_none());

    // Construct and add the new block.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    vm.add_next_block(&block).unwrap();

    // Check that the finalize state is correct.
    let expected = Value::from(Literal::U64(U64::new(amount)));
    assert_eq!(vm.finalize_store().get_value_speculative(&program_id, &mapping_name, &key).unwrap(), Some(expected));
}

#[test]
fn test_credits_program_transfer_public_to_private() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let (caller_private_key, caller_view_key, caller_address) = caller_account(rng);

    // Initialize a new recipient.
    let (_, recipient_view_key, recipient_address) = recipient_account(rng);

    // Initialize the VM.
    let (vm, _, records) = initialize_vm(rng);

    // Select records to spend.
    let transfer_record = records[0].clone();
    let fee_record = records[1].clone();
    let second_fee_record = records[2].clone();

    // Prepare the inputs.
    let amount_1 = 123456u64;
    let inputs = [
        Value::<CurrentNetwork>::Record(transfer_record),
        Value::<CurrentNetwork>::from_str(&caller_address.to_string()).unwrap(),
        Value::<CurrentNetwork>::from_str(&format!("{amount_1}u64")).unwrap(),
    ]
    .into_iter();

    // Create a transfer_private_to_public transaction.
    let transaction = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_private_to_public"),
            inputs,
            Some((fee_record, 0)),
            None,
            rng,
        )
        .unwrap();

    // Construct and add the new block.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    vm.add_next_block(&block).unwrap();

    // Prepare the inputs.
    let amount_2 = 100000u64;
    let inputs = [
        Value::<CurrentNetwork>::from_str(&recipient_address.to_string()).unwrap(),
        Value::<CurrentNetwork>::from_str(&format!("{amount_2}u64")).unwrap(),
    ]
    .into_iter();

    // Create a transfer_private_to_public transaction.
    let transaction = vm
        .execute(
            &caller_private_key,
            ("credits.aleo", "transfer_public_to_private"),
            inputs,
            Some((second_fee_record, 0)),
            None,
            rng,
        )
        .unwrap();

    // Check that the transaction is valid.
    assert!(vm.verify_transaction(&transaction, None));

    // Check that the transaction is an execute transaction with 1 transition.
    assert!(transaction.is_execute());
    let Transaction::Execute(_, execution, Some(fee)) = &transaction else {
        unreachable!("Invalid transaction type.")
    };
    let transitions = execution.transitions().collect::<Vec<_>>();
    assert_eq!(transitions.len(), 1);
    let transition: &Transition<CurrentNetwork> = transitions[0];

    /* Inputs */
    // Check that the transition inputs are correct.
    let transition_inputs = transition.inputs();
    assert_eq!(transition_inputs.len(), 2);

    // Check that the first input is the recipient address.
    let Input::Public(_, Some(Plaintext::Literal(Literal::Address(input_address), _))) = &transition_inputs[0] else {
        unreachable!("Invalid input type for `credits.aleo/transfer_public_to_private`.")
    };
    assert_eq!(input_address, &recipient_address);
    // Check that the second input is the amount.
    let Input::Public(_, Some(Plaintext::Literal(Literal::U64(input_amount), _))) = &transition_inputs[1] else {
        unreachable!("Invalid input type for `credits.aleo/transfer_public_to_private`.");
    };
    assert_eq!(**input_amount, amount_2);

    /* Outputs */

    // Check that the transition outputs are correct.
    let transition_outputs = transition.outputs();
    assert_eq!(transition_outputs.len(), 1);

    // Check that the output record is correct.
    let (_, record) = transition_outputs[0].record().unwrap();
    let record = record.decrypt(&recipient_view_key).unwrap();
    assert_eq!(**record.owner(), recipient_address);
    assert_eq!(get_balance(&record).unwrap(), amount_2);

    /* Fee */

    // Check that the change record is correct.
    let fee_records = fee.transition().records().map(|(_, record)| record).collect::<Vec<_>>();
    assert_eq!(fee_records.len(), 1);
    assert_eq!(**fee_records[0].decrypt(&caller_view_key).unwrap().owner(), caller_address);

    /* Finalize */

    let program_id = ProgramID::from_str("credits.aleo").unwrap();
    let mapping_name = Identifier::from_str("account").unwrap();
    let caller_key = Plaintext::from(Literal::Address(caller_address));

    // Check the initial finalize state.
    let expected_amount_for_caller = Value::from(Literal::U64(U64::new(amount_1)));
    assert_eq!(
        vm.finalize_store().get_value_speculative(&program_id, &mapping_name, &caller_key).unwrap(),
        Some(expected_amount_for_caller)
    );

    // Construct and add the new block.
    let block = sample_next_block(&vm, &caller_private_key, &[transaction], rng).unwrap();
    vm.add_next_block(&block).unwrap();

    // Check that the finalize state is correct.
    let expected_amount_for_caller = Value::from(Literal::U64(U64::new(amount_1 - amount_2)));
    assert_eq!(
        vm.finalize_store().get_value_speculative(&program_id, &mapping_name, &caller_key).unwrap(),
        Some(expected_amount_for_caller)
    );
}

#[test]
fn test_credits_program_join() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let (caller_private_key, caller_view_key, caller_address) = caller_account(rng);

    // Initialize the VM.
    let (vm, genesis, records) = initialize_vm(rng);

    // Select records to spend.
    let first_record = records[0].clone();
    let second_record = records[1].clone();
    let fee_record = records[2].clone();

    // Prepare the inputs.
    let inputs =
        [Value::<CurrentNetwork>::Record(first_record.clone()), Value::<CurrentNetwork>::Record(second_record.clone())]
            .into_iter();

    // Create a join transaction.
    let transaction =
        vm.execute(&caller_private_key, ("credits.aleo", "join"), inputs, Some((fee_record, 0)), None, rng).unwrap();

    // Check that the transaction is valid.
    assert!(vm.verify_transaction(&transaction, None));

    // Check that the transaction is an execute transaction with 1 transition.
    assert!(transaction.is_execute());
    let Transaction::Execute(_, execution, Some(fee)) = transaction else {
        unreachable!("Invalid transaction type.")
    };
    let transitions = execution.transitions().collect::<Vec<_>>();
    assert_eq!(transitions.len(), 1);
    let transition: &Transition<CurrentNetwork> = transitions[0];

    /* Inputs */

    let commitments = genesis.commitments().collect::<Vec<_>>();

    // Check that the transition inputs are correct.
    let transition_inputs = transition.inputs();
    assert_eq!(transition_inputs.len(), 2);
    // Check that the first input is the encrypted input record.
    let Input::Record(serial_number, _) = &transition_inputs[0] else {
        unreachable!("Invalid input type for `credits.aleo/join`.")
    };
    assert_eq!(
        *serial_number,
        Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::serial_number(caller_private_key, *commitments[0])
            .unwrap()
    );
    // Check that the second input is the encrypted input record.
    let Input::Record(serial_number, _) = &transition_inputs[1] else {
        unreachable!("Invalid input type for `credits.aleo/join`.")
    };
    assert_eq!(
        *serial_number,
        Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::serial_number(caller_private_key, *commitments[1])
            .unwrap()
    );

    /* Outputs */

    // Check that the transition outputs are correct.
    let transition_outputs = transition.outputs();
    assert_eq!(transition_outputs.len(), 1);

    // Check that the output record is correct.
    let (_, record) = transition_outputs[0].record().unwrap();
    let record = record.decrypt(&caller_view_key).unwrap();
    assert_eq!(**record.owner(), caller_address);
    assert_eq!(
        get_balance(&record).unwrap(),
        get_balance(&first_record).unwrap() + get_balance(&second_record).unwrap()
    );

    /* Fee */

    // Check that the change record is correct.
    let fee_records = fee.transition().records().map(|(_, record)| record).collect::<Vec<_>>();
    assert_eq!(fee_records.len(), 1);
    assert_eq!(**fee_records[0].decrypt(&caller_view_key).unwrap().owner(), caller_address);
}

#[test]
fn test_credits_program_split() {
    let rng = &mut TestRng::default();

    // Initialize a new caller.
    let (caller_private_key, caller_view_key, caller_address) = caller_account(rng);

    // Initialize the VM.
    let (vm, genesis, records) = initialize_vm(rng);

    // Select records to spend.
    let split_record = records[0].clone();
    let fee_record = records[1].clone();

    // Prepare the inputs.
    let amount = 123456u64;
    let inputs = [
        Value::<CurrentNetwork>::Record(split_record.clone()),
        Value::<CurrentNetwork>::from_str(&format!("{amount}u64")).unwrap(),
    ]
    .into_iter();

    // Create a split transaction.
    let transaction =
        vm.execute(&caller_private_key, ("credits.aleo", "split"), inputs, Some((fee_record, 0)), None, rng).unwrap();

    // Check that the transaction is valid.
    assert!(vm.verify_transaction(&transaction, None));

    // Check that the transaction is an execute transaction with 1 transition.
    assert!(transaction.is_execute());
    let Transaction::Execute(_, execution, Some(fee)) = transaction else {
        unreachable!("Invalid transaction type.")
    };
    let transitions = execution.transitions().collect::<Vec<_>>();
    assert_eq!(transitions.len(), 1);
    let transition: &Transition<CurrentNetwork> = transitions[0];

    /* Inputs */

    // Check that the transition inputs are correct.
    let transition_inputs = transition.inputs();
    assert_eq!(transition_inputs.len(), 2);
    // Check that the first input is the encrypted input record.
    let Input::Record(serial_number, _) = &transition_inputs[0] else {
        unreachable!("Invalid input type for `credits.aleo/split`.")
    };
    let commitment = genesis.commitments().next().ok_or_else(|| anyhow!("No commitments found")).unwrap();
    assert_eq!(
        *serial_number,
        Record::<CurrentNetwork, Plaintext<CurrentNetwork>>::serial_number(caller_private_key, *commitment).unwrap()
    );
    // Check that the second input is the private recipient amount.
    assert!(matches!(transition_inputs[1], Input::Private(_, Some(_))));

    /* Outputs */

    // Check that the transition outputs are correct.
    let transition_outputs = transition.outputs();
    assert_eq!(transition_outputs.len(), 2);

    // Check that the output record is correct.
    let (_, record) = transition_outputs[0].record().unwrap();
    let record = record.decrypt(&caller_view_key).unwrap();
    assert_eq!(**record.owner(), caller_address);
    assert_eq!(get_balance(&record).unwrap(), amount);

    // Check that the output record is correct.
    let (_, record) = transition_outputs[1].record().unwrap();
    let record = record.decrypt(&caller_view_key).unwrap();
    assert_eq!(**record.owner(), caller_address);
    assert_eq!(get_balance(&record).unwrap(), get_balance(&split_record).unwrap() - amount);

    /* Fee */

    // Check that the change record is correct.
    let fee_records = fee.transition().records().map(|(_, record)| record).collect::<Vec<_>>();
    assert_eq!(fee_records.len(), 1);
    assert_eq!(**fee_records[0].decrypt(&caller_view_key).unwrap().owner(), caller_address);
}
