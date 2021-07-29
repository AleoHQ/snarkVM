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
    record::encoded::*,
    Address,
    DPCError,
    EncodedRecordScheme,
    Parameters,
    Payload,
    Record,
    RecordScheme,
    ViewKey,
};
use rand::{thread_rng, CryptoRng, Rng};
use snarkvm_algorithms::traits::{CommitmentScheme, EncryptionScheme, CRH};
use snarkvm_utilities::{io::Result as IoResult, to_bytes_le, FromBytes, Read, ToBytes, Write};

#[derive(Derivative)]
#[derivative(
    Clone(bound = "C: Parameters"),
    PartialEq(bound = "C: Parameters"),
    Eq(bound = "C: Parameters"),
    Debug(bound = "C: Parameters")
)]
pub struct EncryptedRecord<C: Parameters> {
    pub encrypted_elements: Vec<C::InnerScalarField>,
}

impl<C: Parameters> EncryptedRecord<C> {
    /// Encrypt the given vector of records and returns
    /// 1. Encrypted record
    /// 2. Encryption randomness
    pub fn encrypt<R: Rng + CryptoRng>(
        record: &Record<C>,
        rng: &mut R,
    ) -> Result<
        (
            Self,
            <<C as Parameters>::AccountEncryptionScheme as EncryptionScheme>::Randomness,
        ),
        DPCError,
    > {
        // Serialize the record into group elements
        let encoded_record = EncodedRecord::<C>::encode(record)?;

        // Encrypt the record plaintext
        let record_public_key = record.owner().to_encryption_key();
        let encryption_randomness = C::account_encryption_scheme().generate_randomness(record_public_key, rng)?;
        let encrypted_record = C::account_encryption_scheme().encrypt(
            record_public_key,
            &encryption_randomness,
            &encoded_record.encoded_elements,
        )?;

        let encrypted_record = Self {
            encrypted_elements: encrypted_record,
        };

        Ok((encrypted_record, encryption_randomness))
    }

    /// Decrypt and reconstruct the encrypted record.
    pub fn decrypt(&self, account_view_key: &ViewKey<C>) -> Result<Record<C>, DPCError> {
        // Decrypt the encrypted record
        let plaintext_elements =
            C::account_encryption_scheme().decrypt(&account_view_key.decryption_key, &self.encrypted_elements)?;

        // Deserialize the plaintext record into record components
        let encoded_record = EncodedRecord::<C>::new(plaintext_elements);

        let record_components = encoded_record.decode()?;

        let DecodedRecord {
            serial_number_nonce,
            commitment_randomness,
            birth_program_selector_root,
            death_program_selector_root,
            payload,
            value,
        } = record_components;

        // Construct the record account address
        let owner = Address::from_view_key(&account_view_key)?;

        // Determine if the record is a dummy
        // TODO (raychu86) Establish `is_dummy` flag properly by checking that the value is 0 and the programs are equivalent to a global dummy
        let dummy_program = birth_program_selector_root.clone();

        let is_dummy = (value == 0)
            && (payload == Payload::default())
            && (death_program_selector_root == dummy_program)
            && (birth_program_selector_root == dummy_program);

        // Calculate record commitment
        let commitment_input = to_bytes_le![
            owner,
            is_dummy,
            value,
            payload,
            birth_program_selector_root,
            death_program_selector_root,
            serial_number_nonce
        ]?;

        let commitment = C::record_commitment_scheme().commit(&commitment_input, &commitment_randomness)?;

        Ok(Record::from(
            owner,
            is_dummy,
            value,
            payload,
            birth_program_selector_root,
            death_program_selector_root,
            serial_number_nonce,
            commitment,
            commitment_randomness,
        ))
    }

    /// Returns the encrypted record hash.
    /// The hash input is the ciphertext x-coordinates appended with the selector bits.
    pub fn to_hash(&self) -> Result<<<C as Parameters>::EncryptedRecordCRH as CRH>::Output, DPCError> {
        Ok(C::encrypted_record_crh().hash_field_elements(&self.encrypted_elements)?)
    }
}

impl<C: Parameters> Default for EncryptedRecord<C> {
    fn default() -> Self {
        let default_record = Record::<C>::default();
        let mut rng = thread_rng();

        let (record, _randomness) = Self::encrypt(&default_record, &mut rng).unwrap();
        record
    }
}

impl<C: Parameters> ToBytes for EncryptedRecord<C> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (self.encrypted_elements.len() as u64).write_le(&mut writer)?;
        self.encrypted_elements.write_le(&mut writer)
    }
}

impl<C: Parameters> FromBytes for EncryptedRecord<C> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let encrypted_elements_len = u64::read_le(&mut reader)?;

        let mut encrypted_elements = Vec::with_capacity(encrypted_elements_len as usize);
        for _ in 0..encrypted_elements_len {
            encrypted_elements.push(C::InnerScalarField::read_le(&mut reader)?);
        }

        Ok(Self { encrypted_elements })
    }
}
