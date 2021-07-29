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

use crate::{
    record::{encoded::*, encrypted::*},
    testnet2::parameters::*,
    Account,
    AccountScheme,
    EncodedRecordScheme,
    NoopProgram,
    Parameters,
    Payload,
    ProgramScheme,
    Record,
    ViewKey,
    PAYLOAD_SIZE,
};
use snarkvm_algorithms::traits::CRH;

use rand::{Rng, SeedableRng};
use rand_chacha::ChaChaRng;

pub(crate) const ITERATIONS: usize = 5;

#[test]
fn test_record_serialization() {
    let mut rng = ChaChaRng::seed_from_u64(1231275789u64);

    for _ in 0..ITERATIONS {
        let noop_program = NoopProgram::<Testnet2Parameters>::setup(&mut rng).unwrap();

        for _ in 0..ITERATIONS {
            let dummy_account = Account::<Testnet2Parameters>::new(&mut rng).unwrap();

            let sn_nonce_input: [u8; 32] = rng.gen();
            let value = rng.gen();
            let mut payload = [0u8; PAYLOAD_SIZE];
            rng.fill(&mut payload);

            let given_record = Record::new(
                dummy_account.address,
                false,
                value,
                Payload::from_bytes(&payload),
                noop_program.id(),
                noop_program.id(),
                <Testnet2Parameters as Parameters>::serial_number_nonce_crh()
                    .hash(&sn_nonce_input)
                    .unwrap(),
                &mut rng,
            )
            .unwrap();

            let encoded_record = EncodedRecord::<_>::encode(&given_record).unwrap();
            let record_components = encoded_record.decode().unwrap();

            assert_eq!(given_record.serial_number_nonce, record_components.serial_number_nonce);
            assert_eq!(
                given_record.commitment_randomness,
                record_components.commitment_randomness
            );
            assert_eq!(
                given_record.birth_program_selector_root,
                record_components.birth_program_selector_root
            );
            assert_eq!(
                given_record.death_program_selector_root,
                record_components.death_program_selector_root
            );
            assert_eq!(given_record.value, record_components.value);
            assert_eq!(given_record.payload, record_components.payload);
        }
    }
}

#[test]
fn test_record_encryption() {
    let mut rng = ChaChaRng::seed_from_u64(1231275789u64);

    for _ in 0..ITERATIONS {
        let noop_program = NoopProgram::<Testnet2Parameters>::setup(&mut rng).unwrap();

        for _ in 0..ITERATIONS {
            let dummy_account = Account::<Testnet2Parameters>::new(&mut rng).unwrap();

            let sn_nonce_input: [u8; 32] = rng.gen();
            let value = rng.gen();
            let mut payload = [0u8; PAYLOAD_SIZE];
            rng.fill(&mut payload);

            let given_record = Record::new(
                dummy_account.address,
                false,
                value,
                Payload::from_bytes(&payload),
                noop_program.id(),
                noop_program.id(),
                <Testnet2Parameters as Parameters>::serial_number_nonce_crh()
                    .hash(&sn_nonce_input)
                    .unwrap(),
                &mut rng,
            )
            .unwrap();

            // Encrypt the record
            let (encryped_record, _) = EncryptedRecord::encrypt(&given_record, &mut rng).unwrap();
            let account_view_key = ViewKey::from_private_key(&dummy_account.private_key).unwrap();

            // Decrypt the record
            let decrypted_record = encryped_record.decrypt(&account_view_key).unwrap();

            assert_eq!(given_record, decrypted_record);
        }
    }
}
