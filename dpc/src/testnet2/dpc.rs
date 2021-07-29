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

use crate::prelude::*;
use rand::{CryptoRng, Rng};
use snarkvm_algorithms::{commitment_tree::CommitmentMerkleTree, merkle_tree::MerklePath, prelude::*};
use snarkvm_fields::ToConstraintField;
use snarkvm_parameters::{prelude::*, testnet2::*};
use snarkvm_utilities::{has_duplicates, rand::UniformRand, to_bytes_le, FromBytes, ToBytes};

pub struct DPC<C: Parameters> {
    pub noop_program: NoopProgram<C>,
    pub inner_snark_parameters: (
        Option<<C::InnerSNARK as SNARK>::ProvingKey>,
        <C::InnerSNARK as SNARK>::VerifyingKey,
    ),
    pub outer_snark_parameters: (
        Option<<C::OuterSNARK as SNARK>::ProvingKey>,
        <C::OuterSNARK as SNARK>::VerifyingKey,
    ),
}

impl<C: Parameters> DPCScheme<C> for DPC<C> {
    type Account = Account<C>;
    type Execution = Execution<C, C::ProgramSNARK>;
    type Record = Record<C>;
    type Transaction = Transaction<C>;
    type TransactionKernel = TransactionKernel<C>;

    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> anyhow::Result<Self> {
        let setup_time = start_timer!(|| "DPC::setup");

        let noop_program_timer = start_timer!(|| "Noop program SNARK setup");
        let noop_program = NoopProgram::setup(rng)?;
        let noop_program_execution = noop_program.execute_blank(rng)?;
        end_timer!(noop_program_timer);

        let snark_setup_time = start_timer!(|| "Execute inner SNARK setup");
        let inner_circuit = InnerCircuit::<C>::blank();
        let inner_snark_parameters = C::InnerSNARK::setup(&inner_circuit, &mut SRS::CircuitSpecific(rng))?;
        end_timer!(snark_setup_time);

        let snark_setup_time = start_timer!(|| "Execute outer SNARK setup");
        let inner_snark_vk: <C::InnerSNARK as SNARK>::VerifyingKey = inner_snark_parameters.1.clone().into();
        let inner_snark_proof = C::InnerSNARK::prove(&inner_snark_parameters.0, &inner_circuit, rng)?;

        let outer_snark_parameters = C::OuterSNARK::setup(
            &OuterCircuit::<C>::blank(inner_snark_vk, inner_snark_proof, noop_program_execution),
            &mut SRS::CircuitSpecific(rng),
        )?;
        end_timer!(snark_setup_time);
        end_timer!(setup_time);

        Ok(Self {
            noop_program,
            inner_snark_parameters: (Some(inner_snark_parameters.0), inner_snark_parameters.1),
            outer_snark_parameters: (Some(outer_snark_parameters.0), outer_snark_parameters.1),
        })
    }

    fn load(verify_only: bool) -> anyhow::Result<Self> {
        let timer = start_timer!(|| "DPC::load");
        let noop_program = NoopProgram::load()?;
        let inner_snark_parameters = {
            let inner_snark_pk = match verify_only {
                true => None,
                false => Some(<C::InnerSNARK as SNARK>::ProvingKey::read_le(
                    InnerSNARKPKParameters::load_bytes()?.as_slice(),
                )?),
            };
            let inner_snark_vk: <C::InnerSNARK as SNARK>::VerifyingKey =
                <C::InnerSNARK as SNARK>::VerifyingKey::read_le(InnerSNARKVKParameters::load_bytes()?.as_slice())?;

            (inner_snark_pk, inner_snark_vk)
        };

        let outer_snark_parameters = {
            let outer_snark_pk = match verify_only {
                true => None,
                false => Some(<C::OuterSNARK as SNARK>::ProvingKey::read_le(
                    OuterSNARKPKParameters::load_bytes()?.as_slice(),
                )?),
            };
            let outer_snark_vk: <C::OuterSNARK as SNARK>::VerifyingKey =
                <C::OuterSNARK as SNARK>::VerifyingKey::read_le(OuterSNARKVKParameters::load_bytes()?.as_slice())?;

            (outer_snark_pk, outer_snark_vk)
        };
        end_timer!(timer);

        Ok(Self {
            noop_program,
            inner_snark_parameters,
            outer_snark_parameters,
        })
    }

    fn execute_offline_phase<R: Rng + CryptoRng>(
        &self,
        old_private_keys: &Vec<<Self::Account as AccountScheme>::PrivateKey>,
        old_records: Vec<Self::Record>,
        new_records: Vec<Self::Record>,
        memorandum: <Self::Transaction as TransactionScheme>::Memorandum,
        rng: &mut R,
    ) -> anyhow::Result<Self::TransactionKernel> {
        assert_eq!(C::NUM_INPUT_RECORDS, old_private_keys.len());
        assert_eq!(C::NUM_INPUT_RECORDS, old_records.len());
        assert_eq!(C::NUM_OUTPUT_RECORDS, new_records.len());

        let mut value_balance = AleoAmount::ZERO;

        let mut old_serial_numbers = Vec::with_capacity(C::NUM_INPUT_RECORDS);
        let mut old_randomizers = Vec::with_capacity(C::NUM_INPUT_RECORDS);
        let mut joint_serial_numbers = Vec::new();
        let mut old_death_program_selector_roots = Vec::with_capacity(C::NUM_INPUT_RECORDS);

        // Compute the ledger membership witness and serial number from the old records.
        for (i, record) in old_records.iter().enumerate().take(C::NUM_INPUT_RECORDS) {
            let input_record_time = start_timer!(|| format!("Process input record {}", i));

            if !record.is_dummy() {
                value_balance = value_balance.add(AleoAmount::from_bytes(record.value() as i64));
            }

            let (sn, randomizer) = record.to_serial_number(&old_private_keys[i])?;
            joint_serial_numbers.extend_from_slice(&sn.to_bytes_le()?);
            old_serial_numbers.push(sn);
            old_randomizers.push(randomizer);
            old_death_program_selector_roots.push(record.death_program_selector_root().to_vec());

            end_timer!(input_record_time);
        }

        let mut new_birth_program_selector_roots = Vec::with_capacity(C::NUM_OUTPUT_RECORDS);
        let mut new_commitments = Vec::with_capacity(C::NUM_OUTPUT_RECORDS);

        for record in new_records.iter().take(C::NUM_OUTPUT_RECORDS) {
            new_birth_program_selector_roots.push(record.birth_program_selector_root());
            new_commitments.push(record.commitment());

            if !record.is_dummy() {
                value_balance = value_balance.sub(AleoAmount::from_bytes(record.value() as i64));
            }
        }

        // Generate Schnorr signature on transaction data.
        let signature_time = start_timer!(|| "Sign and randomize signature");

        let signature_message = to_bytes_le![
            C::NETWORK_ID,
            old_serial_numbers,
            new_commitments,
            value_balance,
            memorandum
        ]?;

        let mut signatures = Vec::with_capacity(C::NUM_INPUT_RECORDS);
        for i in 0..C::NUM_INPUT_RECORDS {
            // Randomize the private key.
            let randomized_private_key = C::account_signature_scheme()
                .randomize_private_key(&old_private_keys[i].sk_sig, &old_randomizers[i])?;

            // Sign the transaction data.
            let randomized_signature =
                C::account_signature_scheme().sign_randomized(&randomized_private_key, &signature_message, rng)?;

            signatures.push(randomized_signature);
        }

        end_timer!(signature_time);

        // TODO (raychu86): Add index and program register inputs + outputs to local data commitment leaves
        let local_data_merkle_tree_timer = start_timer!(|| "Compute local data merkle tree");

        let mut local_data_commitment_randomizers = Vec::with_capacity(C::NUM_INPUT_RECORDS);
        let mut old_record_commitments = Vec::with_capacity(C::NUM_INPUT_RECORDS);
        for i in 0..C::NUM_INPUT_RECORDS {
            let input_bytes = to_bytes_le![
                old_serial_numbers[i],
                &old_records[i].commitment(),
                memorandum,
                C::NETWORK_ID
            ]?;

            let commitment_randomness = <C::LocalDataCommitmentScheme as CommitmentScheme>::Randomness::rand(rng);
            let commitment = C::local_data_commitment_scheme().commit(&input_bytes, &commitment_randomness)?;

            old_record_commitments.push(commitment);
            local_data_commitment_randomizers.push(commitment_randomness);
        }

        let mut new_record_commitments = Vec::with_capacity(C::NUM_OUTPUT_RECORDS);
        for record in new_records.iter().take(C::NUM_OUTPUT_RECORDS) {
            let input_bytes = to_bytes_le![record.commitment(), memorandum, C::NETWORK_ID]?;

            let commitment_randomness = <C::LocalDataCommitmentScheme as CommitmentScheme>::Randomness::rand(rng);
            let commitment = C::local_data_commitment_scheme().commit(&input_bytes, &commitment_randomness)?;

            new_record_commitments.push(commitment);
            local_data_commitment_randomizers.push(commitment_randomness);
        }

        let leaves = [
            old_record_commitments[0].clone(),
            old_record_commitments[1].clone(),
            new_record_commitments[0].clone(),
            new_record_commitments[1].clone(),
        ];
        let local_data_merkle_tree = CommitmentMerkleTree::new(C::local_data_crh().clone(), &leaves)?;

        end_timer!(local_data_merkle_tree_timer);

        let program_comm_timer = start_timer!(|| "Compute program commitment");
        let (program_commitment, program_randomness) = {
            let mut input = Vec::new();
            for id in old_death_program_selector_roots {
                input.extend_from_slice(&id);
            }
            for id in new_birth_program_selector_roots {
                input.extend_from_slice(&id);
            }
            let program_randomness = <C::ProgramCommitmentScheme as CommitmentScheme>::Randomness::rand(rng);
            let program_commitment = C::program_commitment_scheme().commit(&input, &program_randomness)?;

            (program_commitment, program_randomness)
        };
        end_timer!(program_comm_timer);

        // Encrypt the new records and construct the ciphertext hashes

        let mut new_records_encryption_randomness = Vec::with_capacity(C::NUM_OUTPUT_RECORDS);
        let mut new_encrypted_record_hashes = Vec::with_capacity(C::NUM_OUTPUT_RECORDS);
        let mut new_encrypted_records = Vec::with_capacity(C::NUM_OUTPUT_RECORDS);

        for record in &new_records {
            let (encrypted_record, record_encryption_randomness) = EncryptedRecord::encrypt(record, rng)?;

            new_records_encryption_randomness.push(record_encryption_randomness);
            new_encrypted_record_hashes.push(encrypted_record.to_hash()?);
            new_encrypted_records.push(encrypted_record);
        }

        Ok(TransactionKernel {
            old_records,
            old_serial_numbers,

            new_records,
            new_commitments,

            new_records_encryption_randomness,
            new_encrypted_records,
            new_encrypted_record_hashes,

            program_commitment,
            program_randomness,
            local_data_merkle_tree,
            local_data_commitment_randomizers,

            value_balance,
            memorandum,
            network_id: C::NETWORK_ID,
            signatures,
        })
    }

    fn execute_online_phase<L: LedgerScheme<C>, R: Rng + CryptoRng>(
        &self,
        old_private_keys: &Vec<<Self::Account as AccountScheme>::PrivateKey>,
        transaction_kernel: Self::TransactionKernel,
        program_proofs: Vec<Self::Execution>,
        ledger: &L,
        rng: &mut R,
    ) -> anyhow::Result<(Vec<Self::Record>, Self::Transaction)> {
        assert_eq!(C::NUM_INPUT_RECORDS, old_private_keys.len());
        assert_eq!(C::NUM_TOTAL_RECORDS, program_proofs.len());

        let exec_time = start_timer!(|| "DPC::execute_online_phase");

        let TransactionKernel {
            old_records,
            old_serial_numbers,

            new_records,
            new_commitments,

            new_records_encryption_randomness,
            new_encrypted_records,
            new_encrypted_record_hashes,

            program_commitment,
            program_randomness,
            local_data_merkle_tree,
            local_data_commitment_randomizers,
            value_balance,
            memorandum,
            network_id,
            signatures,
        } = transaction_kernel;

        let local_data_root = local_data_merkle_tree.root();

        // Construct the ledger witnesses

        let ledger_digest = ledger.latest_digest().expect("could not get digest");

        // Generate the ledger membership witnesses
        let mut old_witnesses = Vec::with_capacity(C::NUM_INPUT_RECORDS);

        // Compute the ledger membership witness and serial number from the old records.
        for record in old_records.iter() {
            if record.is_dummy() {
                old_witnesses.push(MerklePath::default());
            } else {
                let witness = ledger.prove_cm(&record.commitment())?;
                old_witnesses.push(witness);
            }
        }

        let inner_proof = {
            let circuit = InnerCircuit::<C>::new(
                ledger_digest.clone(),
                old_records,
                old_witnesses,
                old_private_keys.clone(),
                old_serial_numbers.clone(),
                new_records.clone(),
                new_commitments.clone(),
                new_records_encryption_randomness,
                new_encrypted_record_hashes.clone(),
                program_commitment.clone(),
                program_randomness.clone(),
                local_data_root.clone(),
                local_data_commitment_randomizers,
                memorandum,
                value_balance,
                network_id,
            );

            let inner_snark_parameters = match &self.inner_snark_parameters.0 {
                Some(inner_snark_parameters) => inner_snark_parameters,
                None => return Err(DPCError::MissingInnerSnarkProvingParameters.into()),
            };

            C::InnerSNARK::prove(&inner_snark_parameters, &circuit, rng)?
        };

        // Verify that the inner proof passes
        {
            let input = InnerCircuitVerifierInput {
                ledger_digest: ledger_digest.clone(),
                old_serial_numbers: old_serial_numbers.clone(),
                new_commitments: new_commitments.clone(),
                new_encrypted_record_hashes: new_encrypted_record_hashes.clone(),
                memo: memorandum,
                program_commitment: Some(program_commitment.clone()),
                local_data_root: Some(local_data_root.clone()),
                value_balance,
                network_id,
            };

            assert!(C::InnerSNARK::verify(
                &self.inner_snark_parameters.1,
                &input,
                &inner_proof
            )?);
        }

        let inner_snark_vk: <C::InnerSNARK as SNARK>::VerifyingKey = self.inner_snark_parameters.1.clone().into();
        let inner_snark_vk_field_elements = inner_snark_vk.to_field_elements()?;
        let inner_circuit_id = C::inner_circuit_id_crh().hash_field_elements(&inner_snark_vk_field_elements)?;

        let transaction_proof = {
            let circuit = OuterCircuit::<C>::new(
                ledger_digest.clone(),
                old_serial_numbers.clone(),
                new_commitments.clone(),
                new_encrypted_record_hashes.clone(),
                memorandum,
                value_balance,
                network_id,
                inner_snark_vk,
                inner_proof,
                program_proofs,
                program_commitment.clone(),
                program_randomness,
                local_data_root.clone(),
                inner_circuit_id.clone(),
            );

            let outer_snark_parameters = match &self.outer_snark_parameters.0 {
                Some(outer_snark_parameters) => outer_snark_parameters,
                None => return Err(DPCError::MissingOuterSnarkProvingParameters.into()),
            };

            C::OuterSNARK::prove(outer_snark_parameters, &circuit, rng)?
        };

        // Verify the outer proof passes.
        {
            let inner_snark_input = InnerCircuitVerifierInput {
                ledger_digest: ledger_digest.clone(),
                old_serial_numbers: old_serial_numbers.clone(),
                new_commitments: new_commitments.clone(),
                new_encrypted_record_hashes,
                memo: memorandum,
                program_commitment: None,
                local_data_root: None,
                value_balance,
                network_id,
            };

            let input = OuterCircuitVerifierInput {
                inner_snark_verifier_input: inner_snark_input,
                inner_circuit_id: inner_circuit_id.clone(),
            };

            assert!(C::OuterSNARK::verify(
                &self.outer_snark_parameters.1,
                &input,
                &transaction_proof
            )?);
        }

        let transaction = Self::Transaction::new(
            Network::from_id(network_id),
            old_serial_numbers,
            new_commitments,
            memorandum,
            ledger_digest,
            inner_circuit_id,
            transaction_proof,
            value_balance,
            signatures,
            new_encrypted_records,
        );

        end_timer!(exec_time);

        Ok((new_records, transaction))
    }

    fn verify<L: LedgerScheme<C>>(&self, transaction: &Self::Transaction, ledger: &L) -> bool {
        let verify_time = start_timer!(|| "DPC::verify");

        // Returns false if the number of serial numbers in the transaction is incorrect.
        if transaction.old_serial_numbers().len() != C::NUM_INPUT_RECORDS {
            eprintln!("Transaction contains incorrect number of serial numbers");
            return false;
        }

        // Returns false if there are duplicate serial numbers in the transaction.
        if has_duplicates(transaction.old_serial_numbers().iter()) {
            eprintln!("Transaction contains duplicate serial numbers");
            return false;
        }

        // Returns false if the number of commitments in the transaction is incorrect.
        if transaction.new_commitments().len() != C::NUM_OUTPUT_RECORDS {
            eprintln!("Transaction contains incorrect number of commitments");
            return false;
        }

        // Returns false if there are duplicate commitments numbers in the transaction.
        if has_duplicates(transaction.new_commitments().iter()) {
            eprintln!("Transaction contains duplicate commitments");
            return false;
        }

        let ledger_time = start_timer!(|| "Ledger checks");

        // Returns false if any transaction serial number previously existed in the ledger.
        for sn in transaction.old_serial_numbers() {
            if ledger.contains_serial_number(sn) {
                eprintln!("Ledger already contains this transaction serial number.");
                return false;
            }
        }

        // Returns false if any transaction commitment previously existed in the ledger.
        for cm in transaction.new_commitments() {
            if ledger.contains_commitment(cm) {
                eprintln!("Ledger already contains this transaction commitment.");
                return false;
            }
        }

        // Returns false if the ledger digest in the transaction is invalid.
        if !ledger.is_valid_digest(&transaction.ledger_digest) {
            eprintln!("Ledger digest is invalid.");
            return false;
        }

        end_timer!(ledger_time);

        let signature_time = start_timer!(|| "Signature checks");

        // Returns false if the number of signatures in the transaction is incorrect.
        if transaction.signatures().len() != C::NUM_OUTPUT_RECORDS {
            eprintln!("Transaction contains incorrect number of commitments");
            return false;
        }

        let signature_message = match to_bytes_le![
            transaction.network_id(),
            transaction.old_serial_numbers(),
            transaction.new_commitments(),
            transaction.value_balance(),
            transaction.memorandum()
        ] {
            Ok(message) => message,
            _ => {
                eprintln!("Unable to construct signature message.");
                return false;
            }
        };

        for (pk, sig) in transaction.old_serial_numbers().iter().zip(transaction.signatures()) {
            match C::account_signature_scheme().verify(pk, &signature_message, sig) {
                Ok(is_valid) => {
                    if !is_valid {
                        eprintln!("Signature failed to verify.");
                        return false;
                    }
                }
                _ => {
                    eprintln!("Unable to verify signature.");
                    return false;
                }
            }
        }

        end_timer!(signature_time);

        // Construct the ciphertext hashes

        // Returns false if the number of encrypted records in the transaction is incorrect.
        if transaction.encrypted_records().len() != C::NUM_OUTPUT_RECORDS {
            eprintln!("Transaction contains incorrect number of encrypted records");
            return false;
        }

        let mut new_encrypted_record_hashes = Vec::with_capacity(C::NUM_OUTPUT_RECORDS);
        for encrypted_record in transaction.encrypted_records() {
            match encrypted_record.to_hash() {
                Ok(hash) => new_encrypted_record_hashes.push(hash),
                _ => {
                    eprintln!("Unable to hash encrypted record.");
                    return false;
                }
            }
        }

        let inner_snark_input = InnerCircuitVerifierInput {
            ledger_digest: transaction.ledger_digest().clone(),
            old_serial_numbers: transaction.old_serial_numbers().to_vec(),
            new_commitments: transaction.new_commitments().to_vec(),
            new_encrypted_record_hashes,
            memo: *transaction.memorandum(),
            program_commitment: None,
            local_data_root: None,
            value_balance: transaction.value_balance(),
            network_id: transaction.network_id(),
        };

        let inner_snark_vk: <C::InnerSNARK as SNARK>::VerifyingKey = self.inner_snark_parameters.1.clone().into();

        let inner_snark_vk_field_elements =
            ToConstraintField::<C::OuterScalarField>::to_field_elements(&inner_snark_vk).unwrap();

        let outer_snark_input = OuterCircuitVerifierInput {
            inner_snark_verifier_input: inner_snark_input,
            inner_circuit_id: match C::inner_circuit_id_crh().hash_field_elements(&inner_snark_vk_field_elements) {
                Ok(hash) => hash,
                _ => {
                    eprintln!("Unable to hash inner snark vk.");
                    return false;
                }
            },
        };

        match C::OuterSNARK::verify(
            &self.outer_snark_parameters.1,
            &outer_snark_input,
            &transaction.transaction_proof,
        ) {
            Ok(is_valid) => {
                if !is_valid {
                    eprintln!("Transaction proof failed to verify.");
                    return false;
                }
            }
            Err(error) => {
                eprintln!("Unable to verify transaction proof: {:?}", error);
                return false;
            }
        }

        end_timer!(verify_time);

        true
    }

    /// Returns true iff all the transactions in the block are valid according to the ledger.
    fn verify_transactions<L: LedgerScheme<C>>(&self, transactions: &[Self::Transaction], ledger: &L) -> bool {
        for transaction in transactions {
            if !self.verify(transaction, ledger) {
                return false;
            }
        }

        true
    }
}
