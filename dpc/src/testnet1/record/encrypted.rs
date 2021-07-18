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
    testnet1::{
        payload::Payload,
        record::{encoded::*, Record},
        Testnet1Components,
    },
    traits::{DPCComponents, EncodedRecordScheme, RecordScheme},
    Address,
    DPCError,
    ViewKey,
};
use snarkvm_algorithms::{
    encoding::Elligator2,
    traits::{CommitmentScheme, EncryptionScheme, CRH},
};
use snarkvm_curves::traits::{AffineCurve, ModelParameters, ProjectiveCurve};
use snarkvm_fields::One;
use snarkvm_utilities::{
    from_bits_le_to_bytes_le,
    from_bytes_le_to_bits_le,
    to_bytes_le,
    variable_length_integer::*,
    FromBytes,
    ToBytes,
};

use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::io::{Error, ErrorKind, Read, Result as IoResult, Write};

type BaseField<T> = <<T as Testnet1Components>::EncryptionParameters as ModelParameters>::BaseField;

#[derive(Derivative)]
#[derivative(
    Clone(bound = "C: Testnet1Components"),
    PartialEq(bound = "C: Testnet1Components"),
    Eq(bound = "C: Testnet1Components")
)]
pub struct RecordEncryptionGadgetComponents<C: Testnet1Components> {
    /// Record field element representations
    pub record_field_elements: Vec<<C::EncryptionParameters as ModelParameters>::BaseField>,
    /// Record group element encodings - Represented in (x,y) affine coordinates
    pub record_group_encoding: Vec<(BaseField<C>, BaseField<C>)>,
    /// Record ciphertext selectors - Used for ciphertext compression/decompression
    pub ciphertext_selectors: Vec<bool>,
    /// Record fq high selectors - Used for plaintext serialization/deserialization
    pub fq_high_selectors: Vec<bool>,
    /// Record ciphertext blinding exponents used to encrypt the record
    pub encryption_blinding_exponents: Vec<<C::AccountEncryption as EncryptionScheme>::BlindingExponent>,
}

impl<C: Testnet1Components> Default for RecordEncryptionGadgetComponents<C> {
    fn default() -> Self {
        // TODO (raychu86) Fix the lengths to be generic
        let record_encoding_length = 7;
        let base_field_one = <C::EncryptionParameters as ModelParameters>::BaseField::one();
        let base_field_default = <C::EncryptionParameters as ModelParameters>::BaseField::default();

        let record_field_elements = vec![base_field_one; record_encoding_length];
        let record_group_encoding = vec![(base_field_default, base_field_default); record_encoding_length];

        let ciphertext_selectors = vec![false; record_encoding_length + 1];
        let fq_high_selectors = vec![false; record_encoding_length];

        let encryption_blinding_exponents =
            vec![<C::AccountEncryption as EncryptionScheme>::BlindingExponent::default(); record_encoding_length];

        Self {
            record_field_elements,
            record_group_encoding,
            ciphertext_selectors,
            fq_high_selectors,
            encryption_blinding_exponents,
        }
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "C: Testnet1Components"),
    PartialEq(bound = "C: Testnet1Components"),
    Eq(bound = "C: Testnet1Components"),
    Debug(bound = "C: Testnet1Components")
)]
pub struct EncryptedRecord<C: Testnet1Components> {
    pub encrypted_elements: Vec<<<C as DPCComponents>::AccountEncryption as EncryptionScheme>::Text>,
    pub final_fq_high_selector: bool,
}

impl<C: Testnet1Components> EncryptedRecord<C> {
    /// Encrypt the given vector of records and returns
    /// 1. Encryption randomness
    /// 2. Encrypted record
    pub fn encrypt<R: Rng + CryptoRng>(
        record: &Record<C>,
        rng: &mut R,
    ) -> Result<
        (
            Self,
            <<C as DPCComponents>::AccountEncryption as EncryptionScheme>::Randomness,
        ),
        DPCError,
    > {
        // Serialize the record into group elements and fq_high bits
        let encoded_record = EncodedRecord::<C, C::EncryptionParameters, C::EncryptionGroup>::encode(record)?;
        let final_fq_high_selector = encoded_record.final_sign_high;

        let mut record_plaintexts = Vec::with_capacity(encoded_record.encoded_elements.len());
        for element in encoded_record.encoded_elements.iter() {
            // Construct the plaintext element from the serialized group elements
            // This value will be used in the inner circuit to validate the encryption
            let plaintext_element = <<C as DPCComponents>::AccountEncryption as EncryptionScheme>::Text::read_le(
                &to_bytes_le![element]?[..],
            )?;
            record_plaintexts.push(plaintext_element);
        }

        // Encrypt the record plaintext
        let record_public_key = record.owner().into_repr();
        let encryption_randomness = C::account_encryption().generate_randomness(record_public_key, rng)?;
        let encrypted_record =
            C::account_encryption().encrypt(record_public_key, &encryption_randomness, &record_plaintexts)?;

        let encrypted_record = Self {
            encrypted_elements: encrypted_record,
            final_fq_high_selector,
        };

        Ok((encrypted_record, encryption_randomness))
    }

    /// Decrypt and reconstruct the encrypted record.
    pub fn decrypt(&self, account_view_key: &ViewKey<C>) -> Result<Record<C>, DPCError> {
        // Decrypt the encrypted record
        let plaintext_elements =
            C::account_encryption().decrypt(&account_view_key.decryption_key, &self.encrypted_elements)?;

        let mut plaintext = Vec::with_capacity(plaintext_elements.len());
        for element in plaintext_elements {
            let plaintext_element = <C as Testnet1Components>::EncryptionGroup::read_le(&to_bytes_le![element]?[..])?;

            plaintext.push(plaintext_element);
        }

        // Deserialize the plaintext record into record components
        let encoded_record = EncodedRecord::<
            C,
            <C as Testnet1Components>::EncryptionParameters,
            <C as Testnet1Components>::EncryptionGroup,
        >::new(plaintext, self.final_fq_high_selector);
        let record_components = encoded_record.decode()?;

        let DecodedRecord {
            serial_number_nonce,
            commitment_randomness,
            birth_program_id,
            death_program_id,
            payload,
            value,
        } = record_components;

        // Construct the record account address

        let owner = Address::from_view_key(&account_view_key)?;

        // Determine if the record is a dummy

        // TODO (raychu86) Establish `is_dummy` flag properly by checking that the value is 0 and the programs are equivalent to a global dummy
        let dummy_program = birth_program_id.clone();

        let is_dummy = (value == 0)
            && (payload == Payload::default())
            && (death_program_id == dummy_program)
            && (birth_program_id == dummy_program);

        // Calculate record commitment

        let commitment_input = to_bytes_le![
            owner,
            is_dummy,
            value,
            payload,
            birth_program_id,
            death_program_id,
            serial_number_nonce
        ]?;

        let commitment = C::record_commitment().commit(&commitment_input, &commitment_randomness)?;

        Ok(Record::from(
            owner,
            is_dummy,
            value,
            payload,
            birth_program_id,
            death_program_id,
            serial_number_nonce,
            commitment,
            commitment_randomness,
        ))
    }

    /// Returns the encrypted record hash.
    /// The hash input is the ciphertext x-coordinates appended with the selector bits.
    pub fn to_hash(&self) -> Result<<<C as DPCComponents>::EncryptedRecordCRH as CRH>::Output, DPCError> {
        let mut ciphertext_affine_x = Vec::with_capacity(self.encrypted_elements.len());
        let mut selector_bits = Vec::with_capacity(self.encrypted_elements.len() + 1);
        for ciphertext_element in &self.encrypted_elements {
            // Compress the ciphertext element to the affine x coordinate
            let ciphertext_element_affine =
                <C as Testnet1Components>::EncryptionGroup::read_le(&to_bytes_le![ciphertext_element]?[..])?
                    .into_affine();
            let ciphertext_x_coordinate = ciphertext_element_affine.to_x_coordinate();

            // Fetch the ciphertext selector bit
            let selector =
                match <<C as Testnet1Components>::EncryptionGroup as ProjectiveCurve>::Affine::from_x_coordinate(
                    ciphertext_x_coordinate,
                    true,
                ) {
                    Some(affine) => ciphertext_element_affine == affine,
                    None => false,
                };

            selector_bits.push(selector);
            ciphertext_affine_x.push(ciphertext_x_coordinate);
        }

        // Concatenate the ciphertext selector bits and the final fq_high selector bit
        selector_bits.push(self.final_fq_high_selector);
        let selector_bytes = from_bits_le_to_bytes_le(&selector_bits);

        Ok(C::encrypted_record_crh().hash(&to_bytes_le![ciphertext_affine_x, selector_bytes]?)?)
    }

    /// Returns the intermediate components of the encryption algorithm that the inner SNARK
    /// needs to validate the new record was encrypted correctly
    /// 1. Record field element representations
    /// 2. Record group element encodings - Represented in (x,y) affine coordinates
    /// 3. Record ciphertext selectors - Used for ciphertext compression/decompression
    /// 4. Record fq high selectors - Used for plaintext serialization/deserialization
    /// 5. Record ciphertext blinding exponents used to encrypt the record
    pub fn prepare_encryption_gadget_components(
        record: &Record<C>,
        encryption_randomness: &<<C as DPCComponents>::AccountEncryption as EncryptionScheme>::Randomness,
    ) -> Result<RecordEncryptionGadgetComponents<C>, DPCError> {
        // Serialize the record into group elements and fq_high bits
        let encoded_record = EncodedRecord::<C, C::EncryptionParameters, C::EncryptionGroup>::encode(record)?;
        let num_encoded_elements = encoded_record.encoded_elements.len();
        let final_fq_high_selector = encoded_record.final_sign_high;

        // Extract the fq_bits from the serialized record
        let fq_high_selectors = {
            let final_element = &encoded_record.encoded_elements[num_encoded_elements - 1];
            let final_element_bytes = decode_from_group::<C::EncryptionParameters, C::EncryptionGroup>(
                final_element.into_affine(),
                final_fq_high_selector,
            )?;
            let final_element_bits = from_bytes_le_to_bits_le(&final_element_bytes);
            [
                &final_element_bits
                    .skip(1)
                    .take(num_encoded_elements.saturating_sub(1))
                    .collect::<Vec<_>>(),
                &[final_fq_high_selector][..],
            ]
            .concat()
        };

        let mut record_field_elements = Vec::with_capacity(num_encoded_elements);
        let mut record_group_encoding = Vec::with_capacity(num_encoded_elements);
        let mut record_plaintexts = Vec::with_capacity(num_encoded_elements);

        for (i, (element, fq_high)) in encoded_record
            .encoded_elements
            .iter()
            .zip_eq(&fq_high_selectors)
            .enumerate()
        {
            let element_affine = element.into_affine();

            // Decode the field elements from the serialized group element
            // These values will be used in the inner circuit to validate bit packing and serialization
            if i == 0 {
                // Serial number nonce
                let record_field_element =
                    <<C as Testnet1Components>::EncryptionParameters as ModelParameters>::BaseField::read_le(
                        &to_bytes_le![element]?[..],
                    )?;
                record_field_elements.push(record_field_element);
            } else {
                // Decode the encoded groups into their respective field elements
                let record_field_element = Elligator2::<
                    <C as Testnet1Components>::EncryptionParameters,
                    <C as Testnet1Components>::EncryptionGroup,
                >::decode(&element_affine, *fq_high)?;

                record_field_elements.push(record_field_element);
            }

            // Fetch the x and y coordinates of the serialized group elements
            // These values will be used in the inner circuit to validate the Elligator2 encoding
            let x = <<C as Testnet1Components>::EncryptionParameters as ModelParameters>::BaseField::read_le(
                &to_bytes_le![element_affine.to_x_coordinate()]?[..],
            )?;
            let y = <<C as Testnet1Components>::EncryptionParameters as ModelParameters>::BaseField::read_le(
                &to_bytes_le![element_affine.to_y_coordinate()]?[..],
            )?;
            record_group_encoding.push((x, y));

            // Construct the plaintext element from the serialized group elements
            // This value will be used in the inner circuit to validate the encryption
            let plaintext_element = <<C as DPCComponents>::AccountEncryption as EncryptionScheme>::Text::read_le(
                &to_bytes_le![element]?[..],
            )?;
            record_plaintexts.push(plaintext_element);
        }

        // Encrypt the record plaintext
        let record_public_key = record.owner().into_repr();
        let encryption_blinding_exponents = C::account_encryption().generate_blinding_exponents(
            record_public_key,
            encryption_randomness,
            record_plaintexts.len(),
        )?;

        let encrypted_record =
            C::account_encryption().encrypt(record_public_key, &encryption_randomness, &record_plaintexts)?;

        // Compute the compressed ciphertext selector bits
        let mut ciphertext_selectors = Vec::with_capacity(encrypted_record.len());
        for ciphertext_element in encrypted_record.iter() {
            // Compress the ciphertext element to the affine x coordinate
            let ciphertext_element_affine =
                <C as Testnet1Components>::EncryptionGroup::read_le(&to_bytes_le![ciphertext_element]?[..])?
                    .into_affine();

            // Fetch the ciphertext selector bit
            let selector =
                match <<C as Testnet1Components>::EncryptionGroup as ProjectiveCurve>::Affine::from_x_coordinate(
                    ciphertext_element_affine.to_x_coordinate(),
                    true,
                ) {
                    Some(affine) => ciphertext_element_affine == affine,
                    None => false,
                };

            ciphertext_selectors.push(selector);
        }

        Ok(RecordEncryptionGadgetComponents {
            record_field_elements,
            record_group_encoding,
            ciphertext_selectors,
            fq_high_selectors,
            encryption_blinding_exponents,
        })
    }
}

impl<C: Testnet1Components> ToBytes for EncryptedRecord<C> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        let mut ciphertext_selectors = Vec::with_capacity(self.encrypted_elements.len() + 1);

        // Write the encrypted record
        variable_length_integer(self.encrypted_elements.len() as u64).write_le(&mut writer)?;
        for ciphertext_element in &self.encrypted_elements {
            // Compress the ciphertext representation to the affine x-coordinate and the selector bit
            let ciphertext_element_affine =
                <C as Testnet1Components>::EncryptionGroup::read_le(&to_bytes_le![ciphertext_element]?[..])?
                    .into_affine();

            let x_coordinate = ciphertext_element_affine.to_x_coordinate();
            x_coordinate.write_le(&mut writer)?;

            let selector =
                match <<C as Testnet1Components>::EncryptionGroup as ProjectiveCurve>::Affine::from_x_coordinate(
                    x_coordinate,
                    true,
                ) {
                    Some(affine) => ciphertext_element_affine == affine,
                    None => false,
                };

            ciphertext_selectors.push(selector);
        }

        ciphertext_selectors.push(self.final_fq_high_selector);

        // Write the ciphertext and fq_high selector bits
        let selector_bytes = from_bits_le_to_bytes_le(&ciphertext_selectors);
        selector_bytes.write_le(&mut writer)?;

        Ok(())
    }
}

impl<C: Testnet1Components> FromBytes for EncryptedRecord<C> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the ciphertext x coordinates
        let num_ciphertext_elements = read_variable_length_integer(&mut reader)?;
        let mut ciphertext_x_coordinates = Vec::with_capacity(num_ciphertext_elements);
        for _ in 0..num_ciphertext_elements {
            let ciphertext_element_x_coordinate: <<<C as Testnet1Components>::EncryptionGroup as ProjectiveCurve>::Affine as AffineCurve>::BaseField =
                FromBytes::read_le(&mut reader)?;
            ciphertext_x_coordinates.push(ciphertext_element_x_coordinate);
        }

        // Read the selector bits

        let num_selector_bytes = num_ciphertext_elements / 8 + 1;
        let mut selector_bytes = vec![0u8; num_selector_bytes];
        reader.read_exact(&mut selector_bytes)?;

        let mut selector_bits = from_bytes_le_to_bits_le(&selector_bytes);
        let ciphertext_selectors = selector_bits.by_ref().take(num_ciphertext_elements);

        // Recover the ciphertext
        let mut ciphertext = Vec::with_capacity(ciphertext_x_coordinates.len());
        for (x_coordinate, ciphertext_selector_bit) in ciphertext_x_coordinates.iter().zip_eq(ciphertext_selectors) {
            let ciphertext_element_affine =
                match <<C as Testnet1Components>::EncryptionGroup as ProjectiveCurve>::Affine::from_x_coordinate(
                    *x_coordinate,
                    ciphertext_selector_bit,
                ) {
                    Some(affine) => affine,
                    None => return Err(Error::new(ErrorKind::Other, "Could not read ciphertext")),
                };

            let ciphertext_element: <C::AccountEncryption as EncryptionScheme>::Text =
                FromBytes::read_le(&to_bytes_le![ciphertext_element_affine.into_projective()]?[..])?;

            ciphertext.push(ciphertext_element);
        }

        let final_fq_high_selector = selector_bits.next().unwrap();

        Ok(Self {
            encrypted_elements: ciphertext,
            final_fq_high_selector,
        })
    }
}
