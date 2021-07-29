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

use snarkvm_algorithms::{
    merkle_tree::MerklePath,
    traits::{CRH, SNARK},
    SRS,
};
use snarkvm_curves::bls12_377::{Fq, Fr};
use snarkvm_dpc::{
    execute_inner_circuit,
    execute_outer_circuit,
    prelude::*,
    testnet1::parameters::*,
    InnerCircuit,
    NoopProgram,
    Payload,
    Record,
    TransactionKernel,
};
use snarkvm_integration::{ledger::*, memdb::MemDb, testnet1::*};
use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};
use snarkvm_utilities::{to_bytes_le, FromBytes, ToBytes};

use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use snarkvm_fields::ToConstraintField;
use std::time::{SystemTime, UNIX_EPOCH};

fn testnet1_inner_circuit_id() -> anyhow::Result<Vec<u8>> {
    let dpc = Testnet1DPC::load(false)?;

    let inner_snark_vk: <<Testnet1Parameters as Parameters>::InnerSNARK as SNARK>::VerifyingKey =
        dpc.inner_snark_parameters.1.clone().into();

    let inner_circuit_id =
        <Testnet1Parameters as Parameters>::inner_circuit_id_crh().hash(&inner_snark_vk.to_bytes_le()?)?;

    Ok(to_bytes_le![inner_circuit_id]?)
}

#[ignore]
#[test]
fn test_testnet1_inner_circuit_sanity_check() {
    let expected_testnet1_inner_circuit_id = vec![
        132, 243, 19, 234, 73, 219, 14, 105, 124, 12, 23, 229, 144, 168, 24, 163, 93, 33, 139, 247, 16, 201, 132, 0,
        141, 28, 29, 2, 131, 75, 18, 78, 248, 57, 118, 61, 81, 53, 11, 91, 196, 233, 80, 186, 167, 144, 163, 0,
    ];
    let candidate_testnet1_inner_circuit_id = testnet1_inner_circuit_id().unwrap();
    assert_eq!(expected_testnet1_inner_circuit_id, candidate_testnet1_inner_circuit_id);
}

#[test]
fn dpc_testnet1_integration_test() {
    let mut rng = ChaChaRng::seed_from_u64(1231275789u64);

    // Generate or load DPC.
    let dpc = setup_or_load_dpc(false, &mut rng);

    // Generate accounts.
    let genesis_account = Account::new(&mut rng).unwrap();
    let recipient = Account::new(&mut rng).unwrap();

    // Create a genesis block.
    let genesis_block = Block {
        header: BlockHeader {
            previous_block_hash: BlockHeaderHash([0u8; 32]),
            merkle_root_hash: MerkleRootHash([0u8; 32]),
            pedersen_merkle_root_hash: PedersenMerkleRootHash([0u8; 32]),
            time: 0,
            difficulty_target: 0x07FF_FFFF_FFFF_FFFF_u64,
            nonce: 0,
            proof: ProofOfSuccinctWork([0u8; 972]),
        },
        transactions: Transactions::new(),
    };

    let ledger = initialize_test_blockchain::<Testnet1Parameters, MemDb>(genesis_block);

    // Generate dummy input records having as address the genesis address.
    let old_private_keys = vec![genesis_account.private_key.clone(); Testnet1Parameters::NUM_INPUT_RECORDS];

    let dpc_noop_program_selector_tree_root = to_bytes_le![dpc.noop_program_selector_tree.root()].unwrap();

    let mut joint_serial_numbers = vec![];
    let mut old_records = vec![];
    for i in 0..Testnet1Parameters::NUM_INPUT_RECORDS {
        let old_sn_nonce = <Testnet1Parameters as Parameters>::serial_number_nonce_crh()
            .hash(&[64u8 + (i as u8); 1])
            .unwrap();

        let old_record = Record::new(
            genesis_account.address.clone(),
            true, // The input record is dummy
            0,
            Payload::default(),
            dpc_noop_program_selector_tree_root.clone(),
            dpc_noop_program_selector_tree_root.clone(),
            old_sn_nonce,
            &mut rng,
        )
        .unwrap();

        let (sn, _) = old_record.to_serial_number(&old_private_keys[i]).unwrap();
        joint_serial_numbers.extend_from_slice(&to_bytes_le![sn].unwrap());

        old_records.push(old_record);
    }

    // Construct new records.

    // Set the new records' program to be the "always-accept" program.
    let mut new_records = vec![];
    for j in 0..Testnet1Parameters::NUM_OUTPUT_RECORDS {
        new_records.push(
            Record::new_full(
                recipient.address.clone(),
                false,
                10,
                Payload::default(),
                dpc_noop_program_selector_tree_root.clone(),
                dpc_noop_program_selector_tree_root.clone(),
                (Testnet1Parameters::NUM_INPUT_RECORDS + j) as u8,
                joint_serial_numbers.clone(),
                &mut rng,
            )
            .unwrap(),
        );
    }

    // Offline execution to generate a DPC transaction kernel.
    let memo = [4u8; 64];
    let transaction_kernel = dpc
        .execute_offline_phase(&old_private_keys, old_records, new_records, memo, &mut rng)
        .unwrap();

    // Generate the program proofs
    let mut program_proofs = vec![];
    for i in 0..Testnet1Parameters::NUM_TOTAL_RECORDS {
        let program_selector_path = dpc
            .noop_program_selector_tree
            .generate_program_path(0, &dpc.noop_program.id())
            .unwrap();

        program_proofs.push(
            dpc.noop_program
                .execute(
                    &transaction_kernel.into_local_data(),
                    i as u8,
                    program_selector_path,
                    &mut rng,
                )
                .unwrap(),
        );
    }

    let (new_records, transaction) = dpc
        .execute_online_phase(&old_private_keys, transaction_kernel, program_proofs, &ledger, &mut rng)
        .unwrap();

    // Check that the transaction is serialized and deserialized correctly
    let transaction_bytes = to_bytes_le![transaction].unwrap();
    let recovered_transaction = Testnet1Transaction::read_le(&transaction_bytes[..]).unwrap();
    assert_eq!(transaction, recovered_transaction);

    // Check that new_records can be decrypted from the transaction.
    {
        let encrypted_records = transaction.encrypted_records();
        let new_account_private_keys = vec![recipient.private_key; Testnet1Parameters::NUM_OUTPUT_RECORDS];

        for ((encrypted_record, private_key), new_record) in
            encrypted_records.iter().zip(new_account_private_keys).zip(new_records)
        {
            let account_view_key = ViewKey::from_private_key(&private_key).unwrap();
            let decrypted_record = encrypted_record.decrypt(&account_view_key).unwrap();
            assert_eq!(decrypted_record, new_record);
        }
    }

    // Craft the block

    let previous_block = ledger.latest_block().unwrap();

    let mut transactions = Transactions::new();
    transactions.push(transaction);

    let transaction_ids = transactions.to_transaction_ids().unwrap();

    let mut merkle_root_bytes = [0u8; 32];
    merkle_root_bytes[..].copy_from_slice(&merkle_root(&transaction_ids));

    let time = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs() as i64;

    let header = BlockHeader {
        previous_block_hash: previous_block.header.get_hash(),
        merkle_root_hash: MerkleRootHash(merkle_root_bytes),
        time,
        difficulty_target: previous_block.header.difficulty_target,
        nonce: 0,
        pedersen_merkle_root_hash: PedersenMerkleRootHash([0u8; 32]),
        proof: ProofOfSuccinctWork([0u8; 972]),
    };

    assert!(Testnet1DPC::verify_transactions(&dpc, &transactions.0, &ledger));

    let block = Block { header, transactions };

    ledger.insert_and_commit(&block).unwrap();
    assert_eq!(ledger.block_height(), 1);
}

#[test]
fn test_testnet1_transaction_kernel_serialization() {
    let mut rng = ChaChaRng::seed_from_u64(1231275789u64);

    let dpc = Testnet1DPC::load(false).unwrap();

    // Generate metadata and an account for a dummy initial record.
    let test_account = Account::new(&mut rng).unwrap();

    let old_private_keys = vec![test_account.private_key.clone(); Testnet1Parameters::NUM_INPUT_RECORDS];

    let dpc_noop_program_selector_tree_root = to_bytes_le![dpc.noop_program_selector_tree.root()].unwrap();

    // Set the input records for our transaction to be the initial dummy records.
    let mut joint_serial_numbers = vec![];
    let mut old_records = vec![];
    for i in 0..Testnet1Parameters::NUM_INPUT_RECORDS {
        let old_record = Record::new(
            test_account.address.clone(),
            true,
            0,
            Payload::default(),
            dpc_noop_program_selector_tree_root.clone(),
            dpc_noop_program_selector_tree_root.clone(),
            <Testnet1Parameters as Parameters>::serial_number_nonce_crh()
                .hash(&[0u8; 1])
                .unwrap(),
            &mut rng,
        )
        .unwrap();

        let (sn, _) = old_record.to_serial_number(&old_private_keys[i]).unwrap();
        joint_serial_numbers.extend_from_slice(&to_bytes_le![sn].unwrap());

        old_records.push(old_record);
    }

    // Construct new records.

    // Set the new record's program to be the "always-accept" program.
    let mut new_records = vec![];
    for j in 0..Testnet1Parameters::NUM_OUTPUT_RECORDS {
        new_records.push(
            Record::new_full(
                test_account.address.clone(),
                false,
                10,
                Payload::default(),
                dpc_noop_program_selector_tree_root.clone(),
                dpc_noop_program_selector_tree_root.clone(),
                (Testnet1Parameters::NUM_INPUT_RECORDS + j) as u8,
                joint_serial_numbers.clone(),
                &mut rng,
            )
            .unwrap(),
        );
    }

    // Generate transaction kernel.
    let transaction_kernel = dpc
        .execute_offline_phase(&old_private_keys, old_records, new_records, [0u8; 64], &mut rng)
        .unwrap();

    // Serialize the transaction kernel.
    let recovered_transaction_kernel = FromBytes::read_le(&transaction_kernel.to_bytes_le().unwrap()[..]).unwrap();

    assert_eq!(transaction_kernel, recovered_transaction_kernel);
}

#[test]
fn test_testnet1_dpc_execute_constraints() {
    let mut rng = ChaChaRng::seed_from_u64(1231275789u64);

    let dpc = Testnet1DPC::setup(&mut rng).unwrap();

    let alternate_noop_program = NoopProgram::<Testnet1Parameters>::setup(&mut rng).unwrap();
    let alternate_noop_program_selector_tree =
        ProgramSelectorTree::<Testnet1Parameters>::new(vec![alternate_noop_program.id()]).unwrap();
    let alternate_noop_program_selector_tree_root = to_bytes_le![alternate_noop_program_selector_tree.root()].unwrap();

    // Generate metadata and an account for a dummy initial record.
    let dummy_account = Account::new(&mut rng).unwrap();

    let genesis_block = Block {
        header: BlockHeader {
            previous_block_hash: BlockHeaderHash([0u8; 32]),
            merkle_root_hash: MerkleRootHash([0u8; 32]),
            time: 0,
            difficulty_target: 0x07FF_FFFF_FFFF_FFFF_u64,
            nonce: 0,
            pedersen_merkle_root_hash: PedersenMerkleRootHash([0u8; 32]),
            proof: ProofOfSuccinctWork([0u8; 972]),
        },
        transactions: Transactions::new(),
    };

    // Use genesis record, serial number, and memo to initialize the ledger.
    let ledger = initialize_test_blockchain::<Testnet1Parameters, MemDb>(genesis_block);

    let old_private_keys = vec![dummy_account.private_key; Testnet1Parameters::NUM_INPUT_RECORDS];

    let dpc_noop_program_selector_tree_root = to_bytes_le![dpc.noop_program_selector_tree.root()].unwrap();

    // Set the input records for our transaction to be the initial dummy records.
    let mut joint_serial_numbers = vec![];
    let mut old_records = vec![];
    for i in 0..Testnet1Parameters::NUM_INPUT_RECORDS {
        let old_record = Record::new(
            dummy_account.address.clone(),
            true,
            0,
            Payload::default(),
            alternate_noop_program_selector_tree_root.clone(),
            alternate_noop_program_selector_tree_root.clone(),
            <Testnet1Parameters as Parameters>::serial_number_nonce_crh()
                .hash(&[0u8; 1])
                .unwrap(),
            &mut rng,
        )
        .unwrap();

        let (sn, _) = old_record.to_serial_number(&old_private_keys[i]).unwrap();
        joint_serial_numbers.extend_from_slice(&to_bytes_le![sn].unwrap());

        old_records.push(old_record);
    }

    // Create an account for an actual new record.
    let new_account = Account::new(&mut rng).unwrap();

    // Construct new records.

    // Set the new record's program to be the "always-accept" program.
    let mut new_records = vec![];
    for j in 0..Testnet1Parameters::NUM_OUTPUT_RECORDS {
        new_records.push(
            Record::new_full(
                new_account.address.clone(),
                false,
                10,
                Payload::default(),
                dpc_noop_program_selector_tree_root.clone(),
                dpc_noop_program_selector_tree_root.clone(),
                (Testnet1Parameters::NUM_INPUT_RECORDS + j) as u8,
                joint_serial_numbers.clone(),
                &mut rng,
            )
            .unwrap(),
        );
    }

    let memo = [0u8; 64];
    let transaction_kernel = dpc
        .execute_offline_phase(&old_private_keys, old_records, new_records, memo, &mut rng)
        .unwrap();

    // Generate the program proofs

    let mut program_proofs = vec![];
    for i in 0..Testnet1Parameters::NUM_INPUT_RECORDS {
        let program_selector_path = alternate_noop_program_selector_tree
            .generate_program_path(0, &alternate_noop_program.id())
            .unwrap();

        program_proofs.push(
            alternate_noop_program
                .execute(
                    &transaction_kernel.into_local_data(),
                    i as u8,
                    program_selector_path,
                    &mut rng,
                )
                .unwrap(),
        );
    }
    for j in 0..Testnet1Parameters::NUM_OUTPUT_RECORDS {
        let program_selector_path = dpc
            .noop_program_selector_tree
            .generate_program_path(0, &dpc.noop_program.id())
            .unwrap();

        program_proofs.push(
            dpc.noop_program
                .execute(
                    &transaction_kernel.into_local_data(),
                    (Testnet1Parameters::NUM_INPUT_RECORDS + j) as u8,
                    program_selector_path,
                    &mut rng,
                )
                .unwrap(),
        );
    }

    let TransactionKernel {
        old_records,
        old_serial_numbers,

        new_records,
        new_commitments,

        new_records_encryption_randomness,
        new_encrypted_records: _,
        new_encrypted_record_hashes,

        program_commitment,
        program_randomness,
        local_data_merkle_tree,
        local_data_commitment_randomizers,
        value_balance,
        memorandum,
        network_id,
        signatures: _,
    } = transaction_kernel;

    let local_data_root = local_data_merkle_tree.root();

    // Construct the ledger witnesses
    let ledger_digest = ledger.latest_digest().expect("could not get digest");

    // Generate the ledger membership witnesses
    let mut old_witnesses = Vec::with_capacity(Testnet1Parameters::NUM_INPUT_RECORDS);

    // Compute the ledger membership witness and serial number from the old records.
    for record in old_records.iter() {
        if record.is_dummy() {
            old_witnesses.push(MerklePath::default());
        } else {
            let witness = ledger.prove_cm(&record.commitment()).unwrap();
            old_witnesses.push(witness);
        }
    }

    //////////////////////////////////////////////////////////////////////////
    // Check that the core check constraint system was satisfied.
    let mut inner_circuit_cs = TestConstraintSystem::<Fr>::new();

    execute_inner_circuit(
        &mut inner_circuit_cs.ns(|| "Inner circuit"),
        &ledger_digest,
        &old_records,
        &old_witnesses,
        &old_private_keys,
        &old_serial_numbers,
        &new_records,
        &new_commitments,
        &new_records_encryption_randomness,
        &new_encrypted_record_hashes,
        &program_commitment,
        &program_randomness,
        &local_data_root,
        &local_data_commitment_randomizers,
        &memo,
        value_balance,
        network_id,
    )
    .unwrap();

    if !inner_circuit_cs.is_satisfied() {
        println!("=========================================================");
        println!("Unsatisfied constraints:");
        println!("{}", inner_circuit_cs.which_is_unsatisfied().unwrap());
        println!("=========================================================");
    }

    {
        println!("=========================================================");
        let num_constraints = inner_circuit_cs.num_constraints();
        println!("Inner circuit num constraints: {:?}", num_constraints);
        assert_eq!(293209, num_constraints);
        println!("=========================================================");
    }

    assert!(inner_circuit_cs.is_satisfied());

    // Generate inner snark parameters and proof for verification in the outer snark
    let inner_snark_parameters = <Testnet1Parameters as Parameters>::InnerSNARK::setup(
        &InnerCircuit::<Testnet1Parameters>::blank(),
        &mut SRS::CircuitSpecific(&mut rng),
    )
    .unwrap();

    let inner_snark_vk: <<Testnet1Parameters as Parameters>::InnerSNARK as SNARK>::VerifyingKey =
        inner_snark_parameters.1.clone().into();

    let inner_snark_vk_field_elements = inner_snark_vk.to_field_elements().unwrap();

    let inner_circuit_id = <Testnet1Parameters as Parameters>::inner_circuit_id_crh()
        .hash_field_elements(&inner_snark_vk_field_elements)
        .unwrap();

    let inner_snark_proof = <Testnet1Parameters as Parameters>::InnerSNARK::prove(
        &inner_snark_parameters.0,
        &InnerCircuit::new(
            ledger_digest,
            old_records,
            old_witnesses,
            old_private_keys,
            old_serial_numbers.clone(),
            new_records,
            new_commitments.clone(),
            new_records_encryption_randomness,
            new_encrypted_record_hashes.clone(),
            program_commitment,
            program_randomness,
            local_data_root,
            local_data_commitment_randomizers,
            memo,
            value_balance,
            network_id,
        ),
        &mut rng,
    )
    .unwrap();

    // Check that the proof check constraint system was satisfied.
    let mut outer_circuit_cs = TestConstraintSystem::<Fq>::new();

    execute_outer_circuit::<Testnet1Parameters, _>(
        &mut outer_circuit_cs.ns(|| "Outer circuit"),
        &ledger_digest,
        &old_serial_numbers,
        &new_commitments,
        &new_encrypted_record_hashes,
        &memorandum,
        value_balance,
        network_id,
        &inner_snark_vk,
        &inner_snark_proof,
        &program_proofs,
        &program_commitment,
        &program_randomness,
        &local_data_root,
        &inner_circuit_id,
    )
    .unwrap();

    if !outer_circuit_cs.is_satisfied() {
        println!("=========================================================");
        println!(
            "Outer circuit num constraints: {:?}",
            outer_circuit_cs.num_constraints()
        );
        println!("Unsatisfied constraints:");
        println!("{}", outer_circuit_cs.which_is_unsatisfied().unwrap());
        println!("=========================================================");
    }

    {
        println!("=========================================================");
        let num_constraints = outer_circuit_cs.num_constraints();
        println!("Outer circuit num constraints: {:?}", num_constraints);
        assert_eq!(422723, num_constraints);
        println!("=========================================================");
    }

    assert!(outer_circuit_cs.is_satisfied());
}
