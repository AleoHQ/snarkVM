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
    testnet1::{payload::Payload, record::Record, Testnet1Components},
    traits::{DPCComponents, EncodedRecordScheme, RecordScheme},
    DPCError,
};
use snarkvm_algorithms::{
    encoding::Elligator2,
    traits::{CommitmentScheme, CRH},
};
use snarkvm_curves::traits::{AffineCurve, MontgomeryParameters, ProjectiveCurve, TwistedEdwardsParameters};
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{
    from_bits_le_to_bytes_le,
    from_bytes_le_to_bits_le,
    to_bytes_le,
    BigInteger,
    FromBytes,
    ToBytes,
};

use itertools::Itertools;
use std::marker::PhantomData;

/// Encode a base field element bytes to a group representation
pub fn encode_to_group<P: MontgomeryParameters + TwistedEdwardsParameters, G: ProjectiveCurve>(
    x_bytes: &[u8],
) -> Result<(<G as ProjectiveCurve>::Affine, bool), DPCError> {
    // TODO (howardwu): Remove this hardcoded value and use BaseField's size in bits to pad length.
    let mut bytes = x_bytes.to_vec();
    while bytes.len() < 32 {
        bytes.push(0)
    }

    let input = P::BaseField::read_le(&bytes[..])?;
    let (output, fq_high) = Elligator2::<P, G>::encode(&input)?;
    Ok((output, fq_high))
}

/// Decode a group into the byte representation of a base field element
pub fn decode_from_group<P: MontgomeryParameters + TwistedEdwardsParameters, G: ProjectiveCurve>(
    affine: <G as ProjectiveCurve>::Affine,
    fq_high: bool,
) -> Result<Vec<u8>, DPCError> {
    let output = Elligator2::<P, G>::decode(&affine, fq_high)?;
    Ok(to_bytes_le![output]?)
}

pub struct DecodedRecord<C: Testnet1Components> {
    pub value: u64,
    pub payload: Payload,
    pub birth_program_id: Vec<u8>,
    pub death_program_id: Vec<u8>,
    pub serial_number_nonce: <C::SerialNumberNonceCRH as CRH>::Output,
    pub commitment_randomness: <C::RecordCommitment as CommitmentScheme>::Randomness,
}

pub struct EncodedRecord<C: Testnet1Components, P: MontgomeryParameters + TwistedEdwardsParameters, G: ProjectiveCurve>
{
    pub(super) encoded_elements: Vec<G>,
    pub(super) final_sign_high: bool,
    _components: PhantomData<C>,
    _parameters: PhantomData<P>,
}

impl<C: Testnet1Components, P: MontgomeryParameters + TwistedEdwardsParameters, G: ProjectiveCurve>
    EncodedRecord<C, P, G>
{
    pub fn new(encoded_elements: Vec<G>, final_sign_high: bool) -> Self {
        Self {
            encoded_elements,
            final_sign_high,
            _components: PhantomData,
            _parameters: PhantomData,
        }
    }
}

impl<C: Testnet1Components, P: MontgomeryParameters + TwistedEdwardsParameters, G: ProjectiveCurve> EncodedRecordScheme
    for EncodedRecord<C, P, G>
{
    type DecodedRecord = DecodedRecord<C>;
    type Group = G;
    type InnerField = <C as DPCComponents>::InnerScalarField;
    type OuterField = <C as DPCComponents>::OuterScalarField;
    type Parameters = P;
    type Record = Record<C>;

    /// Records are serialized in a specialized format to be space-saving.
    ///
    /// Encoded element 1 - [ Serial number nonce ]
    /// Encoded element 2 - [ Commitment randomness ]
    /// Encoded element 3 - [ Birth program id (part 1) ]
    /// Encoded element 4 - [ Death program id (part 1) ]
    /// Encoded element 5 - [ Birth program id (part 2) || Death program id (part 2) ]
    /// Encoded element 6 - [ Payload (part 1) || 1 ]
    /// Encoded element 7 - [ 1 || Sign high bits (7 bits) || Value || Payload (part 2) ]
    ///
    fn encode(record: &Self::Record) -> Result<Self, DPCError> {
        // Assumption 1 - The scalar field bit size must be strictly less than the base field bit size
        // for the logic below to work correctly.
        assert!(Self::SCALAR_FIELD_BITSIZE < Self::INNER_FIELD_BITSIZE);

        // Assumption 2 - this implementation assumes the outer field bit size is larger than
        // the data field bit size by at most one additional scalar field bit size.
        assert!((Self::OUTER_FIELD_BITSIZE - Self::DATA_ELEMENT_BITSIZE) <= Self::DATA_ELEMENT_BITSIZE);

        // Assumption 3 - this implementation assumes the remainder of two outer field bit sizes
        // can fit within one data field element's bit size.
        assert!((2 * (Self::OUTER_FIELD_BITSIZE - Self::DATA_ELEMENT_BITSIZE)) <= Self::DATA_ELEMENT_BITSIZE);

        // Assumption 4 - this implementation assumes the payload and value may be zero values.
        // As such, to ensure the values are non-zero for encoding and decoding, we explicitly
        // reserve the MSB of the data field element's valid bitsize and set the bit to 1.
        assert_eq!(Self::PAYLOAD_ELEMENT_BITSIZE, Self::DATA_ELEMENT_BITSIZE - 1);

        // This element needs to be represented in the constraint field; its bits and the number of elements
        // are calculated early, so that the storage vectors can be pre-allocated.
        let payload = record.payload();
        let payload_bytes = to_bytes_le![payload]?;
        let payload_bits_count = payload_bytes.len() * 8;
        let payload_bits = from_bytes_le_to_bits_le(&payload_bytes);
        let num_payload_elements = payload_bits_count / Self::PAYLOAD_ELEMENT_BITSIZE;

        // Create the vector for storing data elements.
        let mut data_elements = Vec::with_capacity(5 + num_payload_elements + 2);
        let mut data_high_bits = Vec::with_capacity(5 + num_payload_elements);

        // These elements are already in the constraint field.

        let serial_number_nonce = record.serial_number_nonce();
        let serial_number_nonce_encoded =
            <Self::Group as ProjectiveCurve>::Affine::from_random_bytes(&to_bytes_le![serial_number_nonce]?.to_vec())
                .unwrap();

        data_elements.push(serial_number_nonce_encoded);
        data_high_bits.push(false);

        assert_eq!(data_elements.len(), 1);
        assert_eq!(data_high_bits.len(), 1);

        // These elements need to be represented in the constraint field.

        let commitment_randomness = record.commitment_randomness();
        let birth_program_id = record.birth_program_id();
        let death_program_id = record.death_program_id();
        let value = record.value();

        // Process commitment_randomness. (Assumption 1 applies)

        let (encoded_commitment_randomness, sign_high) =
            encode_to_group::<Self::Parameters, Self::Group>(&to_bytes_le![commitment_randomness]?[..])?;
        data_elements.push(encoded_commitment_randomness);
        data_high_bits.push(sign_high);

        assert_eq!(data_elements.len(), 2);
        assert_eq!(data_high_bits.len(), 2);

        // Process birth_program_id and death_program_id. (Assumption 2 and 3 applies)

        let birth_program_id_biginteger = Self::OuterField::read_le(birth_program_id)?.to_repr();
        let death_program_id_biginteger = Self::OuterField::read_le(death_program_id)?.to_repr();

        let mut birth_program_id_bits = Vec::with_capacity(Self::INNER_FIELD_BITSIZE);
        let mut death_program_id_bits = Vec::with_capacity(Self::INNER_FIELD_BITSIZE);
        let mut birth_program_id_remainder_bits =
            Vec::with_capacity(Self::OUTER_FIELD_BITSIZE - Self::DATA_ELEMENT_BITSIZE);
        let mut death_program_id_remainder_bits =
            Vec::with_capacity(Self::OUTER_FIELD_BITSIZE - Self::DATA_ELEMENT_BITSIZE);

        for i in 0..Self::DATA_ELEMENT_BITSIZE {
            birth_program_id_bits.push(birth_program_id_biginteger.get_bit(i));
            death_program_id_bits.push(death_program_id_biginteger.get_bit(i));
        }

        // (Assumption 2 applies)
        for i in Self::DATA_ELEMENT_BITSIZE..Self::OUTER_FIELD_BITSIZE {
            birth_program_id_remainder_bits.push(birth_program_id_biginteger.get_bit(i));
            death_program_id_remainder_bits.push(death_program_id_biginteger.get_bit(i));
        }
        birth_program_id_remainder_bits.append(&mut death_program_id_remainder_bits);

        // (Assumption 3 applies)

        let (encoded_birth_program_id, sign_high) =
            encode_to_group::<Self::Parameters, Self::Group>(&from_bits_le_to_bytes_le(&birth_program_id_bits)[..])?;
        drop(birth_program_id_bits);
        data_elements.push(encoded_birth_program_id);
        data_high_bits.push(sign_high);

        let (encoded_death_program_id, sign_high) =
            encode_to_group::<Self::Parameters, Self::Group>(&from_bits_le_to_bytes_le(&death_program_id_bits)[..])?;
        drop(death_program_id_bits);
        data_elements.push(encoded_death_program_id);
        data_high_bits.push(sign_high);

        let (encoded_birth_program_id_remainder, sign_high) = encode_to_group::<Self::Parameters, Self::Group>(
            &from_bits_le_to_bytes_le(&birth_program_id_remainder_bits)[..],
        )?;
        drop(birth_program_id_remainder_bits);
        data_elements.push(encoded_birth_program_id_remainder);
        data_high_bits.push(sign_high);

        assert_eq!(data_elements.len(), 5);
        assert_eq!(data_high_bits.len(), 5);

        // Process payload.

        let mut payload_field_bits = Vec::with_capacity(Self::PAYLOAD_ELEMENT_BITSIZE + 1);

        for (i, bit) in payload_bits.enumerate() {
            payload_field_bits.push(bit);

            if (i > 0) && ((i + 1) % Self::PAYLOAD_ELEMENT_BITSIZE == 0) {
                // (Assumption 4)
                payload_field_bits.push(true);
                let (encoded_payload_field, sign_high) = encode_to_group::<Self::Parameters, Self::Group>(
                    &from_bits_le_to_bytes_le(&payload_field_bits)[..],
                )?;

                data_elements.push(encoded_payload_field);
                data_high_bits.push(sign_high);

                payload_field_bits.clear();
            }
        }

        assert_eq!(data_elements.len(), 5 + num_payload_elements);
        assert_eq!(data_high_bits.len(), 5 + num_payload_elements);

        // Process payload remainder and value.

        // Determine if value can fit in current payload_field_bits.
        let value_does_not_fit =
            (payload_field_bits.len() + data_high_bits.len() + (std::mem::size_of_val(&value) * 8))
                > Self::PAYLOAD_ELEMENT_BITSIZE;

        if value_does_not_fit {
            // (Assumption 4)
            payload_field_bits.push(true);

            let (encoded_payload_field, fq_high) =
                encode_to_group::<Self::Parameters, Self::Group>(&from_bits_le_to_bytes_le(&payload_field_bits)[..])?;

            data_elements.push(encoded_payload_field);
            data_high_bits.push(fq_high);

            payload_field_bits.clear();
        }

        assert_eq!(
            data_elements.len(),
            5 + num_payload_elements + (value_does_not_fit as usize)
        );

        // Append the value bits and create the final base element.
        let value_bits = from_bytes_le_to_bits_le(&to_bytes_le![value]?).collect();

        // (Assumption 4)
        let final_element = [vec![true], data_high_bits, value_bits, payload_field_bits].concat();
        let (encoded_final_element, final_sign_high) =
            encode_to_group::<Self::Parameters, Self::Group>(&from_bits_le_to_bytes_le(&final_element)[..])?;

        data_elements.push(encoded_final_element);

        assert_eq!(
            data_elements.len(),
            5 + num_payload_elements + (value_does_not_fit as usize) + 1
        );

        // Compute the encoded group elements.

        let mut encoded_elements = Vec::with_capacity(data_elements.len());
        for element in data_elements.iter() {
            encoded_elements.push(element.into_projective());
        }

        Ok(Self::new(encoded_elements, final_sign_high))
    }

    /// Decode and return the record components
    fn decode(&self) -> Result<Self::DecodedRecord, DPCError> {
        let remainder_size = Self::OUTER_FIELD_BITSIZE - Self::DATA_ELEMENT_BITSIZE;

        // Extract the fq_bits
        let final_element = &self.encoded_elements[self.encoded_elements.len() - 1];
        let final_element_bytes =
            decode_from_group::<Self::Parameters, Self::Group>(final_element.into_affine(), self.final_sign_high)?;
        let final_element_bits = from_bytes_le_to_bits_le(&final_element_bytes).collect::<Vec<_>>();

        let fq_high_bits = &final_element_bits[1..self.encoded_elements.len()];

        // Deserialize serial number nonce

        let (serial_number_nonce, _) = &(self.encoded_elements[0], fq_high_bits[0]);
        let serial_number_nonce_bytes = to_bytes_le![serial_number_nonce.into_affine().to_x_coordinate()]?;
        let serial_number_nonce = <C::SerialNumberNonceCRH as CRH>::Output::read_le(&serial_number_nonce_bytes[..])?;

        // Deserialize commitment randomness

        let (commitment_randomness, commitment_randomness_fq_high) = &(self.encoded_elements[1], fq_high_bits[1]);
        let commitment_randomness_bytes = decode_from_group::<Self::Parameters, Self::Group>(
            commitment_randomness.into_affine(),
            *commitment_randomness_fq_high,
        )?;
        let commitment_randomness_bits = &from_bytes_le_to_bits_le(&commitment_randomness_bytes)
            .take(Self::DATA_ELEMENT_BITSIZE)
            .collect::<Vec<_>>();
        let commitment_randomness = <C::RecordCommitment as CommitmentScheme>::Randomness::read_le(
            &from_bits_le_to_bytes_le(commitment_randomness_bits)[..],
        )?;

        // Deserialize birth and death programs

        let (birth_program_id, birth_program_id_sign_high) = &(self.encoded_elements[2], fq_high_bits[2]);
        let birth_program_id_bytes = decode_from_group::<Self::Parameters, Self::Group>(
            birth_program_id.into_affine(),
            *birth_program_id_sign_high,
        )?;

        let (death_program_id, death_program_id_sign_high) = &(self.encoded_elements[3], fq_high_bits[3]);
        let death_program_id_bytes = decode_from_group::<Self::Parameters, Self::Group>(
            death_program_id.into_affine(),
            *death_program_id_sign_high,
        )?;

        let (program_id_remainder, program_id_sign_high) = &(self.encoded_elements[4], fq_high_bits[4]);
        let program_id_remainder_bytes = decode_from_group::<Self::Parameters, Self::Group>(
            program_id_remainder.into_affine(),
            *program_id_sign_high,
        )?;

        let mut birth_program_id_bits = from_bytes_le_to_bits_le(&birth_program_id_bytes)
            .take(Self::DATA_ELEMENT_BITSIZE)
            .collect::<Vec<_>>();
        let mut death_program_id_bits = from_bytes_le_to_bits_le(&death_program_id_bytes)
            .take(Self::DATA_ELEMENT_BITSIZE)
            .collect::<Vec<_>>();

        let mut program_id_remainder_bits = from_bytes_le_to_bits_le(&program_id_remainder_bytes);
        birth_program_id_bits.extend(program_id_remainder_bits.by_ref().take(remainder_size));
        death_program_id_bits.extend(program_id_remainder_bits.take(remainder_size));

        let birth_program_id = from_bits_le_to_bytes_le(&birth_program_id_bits);
        let death_program_id = from_bits_le_to_bytes_le(&death_program_id_bits);

        // Deserialize the value

        let value_start = self.encoded_elements.len();
        let value_end = value_start + (std::mem::size_of_val(&<Self::Record as RecordScheme>::Value::default()) * 8);
        let value: <Self::Record as RecordScheme>::Value =
            FromBytes::read_le(&from_bits_le_to_bytes_le(&final_element_bits[value_start..value_end])[..])?;

        // Deserialize payload

        let mut payload_bits = vec![];
        for (element, fq_high) in self.encoded_elements[5..self.encoded_elements.len() - 1]
            .iter()
            .zip_eq(&fq_high_bits[5..])
        {
            let element_bytes = decode_from_group::<Self::Parameters, Self::Group>(element.into_affine(), *fq_high)?;
            payload_bits.extend(from_bytes_le_to_bits_le(&element_bytes).take(Self::PAYLOAD_ELEMENT_BITSIZE));
        }
        payload_bits.extend_from_slice(&final_element_bits[value_end..]);

        let payload = Payload::read_le(&from_bits_le_to_bytes_le(&payload_bits)[..])?;

        Ok(DecodedRecord {
            value,
            payload,
            birth_program_id,
            death_program_id,
            serial_number_nonce,
            commitment_randomness,
        })
    }
}
