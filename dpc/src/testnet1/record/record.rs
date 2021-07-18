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
    testnet1::{payload::Payload, Testnet1Components},
    traits::RecordScheme,
    Address,
    PrivateKey,
    RecordError,
};
use snarkvm_algorithms::traits::{CommitmentScheme, SignatureScheme, CRH, PRF};
use snarkvm_utilities::{to_bytes_le, variable_length_integer::*, FromBytes, ToBytes, UniformRand};

use rand::{CryptoRng, Rng};
use std::{
    fmt,
    io::{Read, Result as IoResult, Write},
    str::FromStr,
};

fn default_program_id<C: CRH>() -> Vec<u8> {
    to_bytes_le![C::Output::default()].unwrap()
}

#[derive(Derivative)]
#[derivative(
    Default(bound = "C: Testnet1Components"),
    Debug(bound = "C: Testnet1Components"),
    Clone(bound = "C: Testnet1Components"),
    PartialEq(bound = "C: Testnet1Components"),
    Eq(bound = "C: Testnet1Components")
)]
pub struct Record<C: Testnet1Components> {
    pub(crate) owner: Address<C>,
    pub(crate) is_dummy: bool,
    // TODO (raychu86) use AleoAmount which will guard the value range
    pub(crate) value: u64,
    pub(crate) payload: Payload,

    #[derivative(Default(value = "default_program_id::<C::ProgramIDCRH>()"))]
    pub(crate) birth_program_id: Vec<u8>,
    #[derivative(Default(value = "default_program_id::<C::ProgramIDCRH>()"))]
    pub(crate) death_program_id: Vec<u8>,

    pub(crate) serial_number_nonce: <C::SerialNumberNonceCRH as CRH>::Output,
    pub(crate) commitment: <C::RecordCommitment as CommitmentScheme>::Output,
    pub(crate) commitment_randomness: <C::RecordCommitment as CommitmentScheme>::Randomness,

    #[derivative(PartialEq = "ignore")]
    pub(crate) serial_number_nonce_randomness: Option<[u8; 32]>,
    #[derivative(PartialEq = "ignore")]
    pub(crate) position: Option<u8>,
}

impl<C: Testnet1Components> Record<C> {
    #[allow(clippy::too_many_arguments)]
    pub fn new_full<R: Rng + CryptoRng>(
        owner: Address<C>,
        is_dummy: bool,
        value: u64,
        payload: Payload,
        birth_program_id: Vec<u8>,
        death_program_id: Vec<u8>,
        position: u8,
        joint_serial_numbers: Vec<u8>,
        rng: &mut R,
    ) -> Result<Self, RecordError> {
        let record_time = start_timer!(|| "Generate record");

        // Sample randomness sn_randomness for the CRH input.
        let sn_randomness: [u8; 32] = rng.gen();

        let crh_input = to_bytes_le![position, sn_randomness, joint_serial_numbers]?;
        let serial_number_nonce = C::serial_number_nonce_crh().hash(&crh_input)?;

        let mut record = Self::new(
            owner,
            is_dummy,
            value,
            payload,
            birth_program_id,
            death_program_id,
            serial_number_nonce,
            rng,
        )?;
        record.serial_number_nonce_randomness = Some(sn_randomness);
        record.position = Some(position);

        end_timer!(record_time);
        Ok(record)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new<R: Rng + CryptoRng>(
        owner: Address<C>,
        is_dummy: bool,
        value: u64,
        payload: Payload,
        birth_program_id: Vec<u8>,
        death_program_id: Vec<u8>,
        serial_number_nonce: <C::SerialNumberNonceCRH as CRH>::Output,
        rng: &mut R,
    ) -> Result<Self, RecordError> {
        let record_time = start_timer!(|| "Generate record");
        // Sample new commitment randomness.
        let commitment_randomness = <C::RecordCommitment as CommitmentScheme>::Randomness::rand(rng);

        // Total = 32 + 1 + 8 + 32 + 48 + 48 + 32 = 201 bytes
        let commitment_input = to_bytes_le![
            owner,               // 256 bits = 32 bytes
            is_dummy,            // 1 bit = 1 byte
            value,               // 64 bits = 8 bytes
            payload,             // 256 bits = 32 bytes
            birth_program_id,    // 384 bits = 48 bytes
            death_program_id,    // 384 bits = 48 bytes
            serial_number_nonce  // 256 bits = 32 bytes
        ]?;

        let commitment = C::record_commitment().commit(&commitment_input, &commitment_randomness)?;

        end_timer!(record_time);

        Ok(Self::from(
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

    #[allow(clippy::too_many_arguments)]
    pub fn from(
        owner: Address<C>,
        is_dummy: bool,
        value: u64,
        payload: Payload,
        birth_program_id: Vec<u8>,
        death_program_id: Vec<u8>,
        serial_number_nonce: <C::SerialNumberNonceCRH as CRH>::Output,
        commitment: <C::RecordCommitment as CommitmentScheme>::Output,
        commitment_randomness: <C::RecordCommitment as CommitmentScheme>::Randomness,
    ) -> Self {
        Self {
            owner,
            is_dummy,
            value,
            payload,
            birth_program_id,
            death_program_id,
            serial_number_nonce,
            commitment,
            commitment_randomness,

            serial_number_nonce_randomness: None,
            position: None,
        }
    }

    // TODO (howardwu) - Change the private_key input to a signature_public_key.
    pub fn to_serial_number(
        &self,
        private_key: &PrivateKey<C>,
    ) -> Result<
        (
            <C::AccountSignature as SignatureScheme>::PublicKey,
            <C::AccountSignature as SignatureScheme>::Randomizer,
        ),
        RecordError,
    > {
        let timer = start_timer!(|| "Generate serial number");

        // TODO (howardwu) - Implement after removing parameters from the inputs.
        // // Check that the private key corresponds with the owner of the record.
        // if self.owner != &Address::<C>::from_private_key(private_key)? {
        //     return Err(RecordError::IncorrectPrivateKey);
        // }

        // Compute the serial number.
        let seed = FromBytes::read_le(to_bytes_le!(&private_key.sk_prf)?.as_slice())?;
        let input = FromBytes::read_le(to_bytes_le!(self.serial_number_nonce)?.as_slice())?;
        let randomizer = FromBytes::from_bytes_le(&C::PRF::evaluate(&seed, &input)?.to_bytes_le()?)?;
        let serial_number = C::account_signature().randomize_public_key(&private_key.pk_sig()?, &randomizer)?;

        end_timer!(timer);
        Ok((serial_number, randomizer))
    }
}

impl<C: Testnet1Components> RecordScheme for Record<C> {
    type Commitment = <C::RecordCommitment as CommitmentScheme>::Output;
    type CommitmentRandomness = <C::RecordCommitment as CommitmentScheme>::Randomness;
    type Owner = Address<C>;
    type Payload = Payload;
    type SerialNumber = <C::AccountSignature as SignatureScheme>::PublicKey;
    type SerialNumberNonce = <C::SerialNumberNonceCRH as CRH>::Output;
    type Value = u64;

    fn owner(&self) -> &Self::Owner {
        &self.owner
    }

    fn is_dummy(&self) -> bool {
        self.is_dummy
    }

    fn value(&self) -> Self::Value {
        self.value
    }

    fn payload(&self) -> &Self::Payload {
        &self.payload
    }

    fn birth_program_id(&self) -> &[u8] {
        &self.birth_program_id
    }

    fn death_program_id(&self) -> &[u8] {
        &self.death_program_id
    }

    fn serial_number_nonce(&self) -> &Self::SerialNumberNonce {
        &self.serial_number_nonce
    }

    fn serial_number_nonce_randomness(&self) -> &Option<[u8; 32]> {
        &self.serial_number_nonce_randomness
    }

    fn commitment(&self) -> Self::Commitment {
        self.commitment.clone()
    }

    fn commitment_randomness(&self) -> Self::CommitmentRandomness {
        self.commitment_randomness.clone()
    }
}

impl<C: Testnet1Components> ToBytes for Record<C> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.owner.write_le(&mut writer)?;
        self.is_dummy.write_le(&mut writer)?;
        self.value.write_le(&mut writer)?;
        self.payload.write_le(&mut writer)?;

        variable_length_integer(self.birth_program_id.len() as u64).write_le(&mut writer)?;
        self.birth_program_id.write_le(&mut writer)?;

        variable_length_integer(self.death_program_id.len() as u64).write_le(&mut writer)?;
        self.death_program_id.write_le(&mut writer)?;

        self.serial_number_nonce.write_le(&mut writer)?;
        self.commitment.write_le(&mut writer)?;
        self.commitment_randomness.write_le(&mut writer)
    }
}

impl<C: Testnet1Components> FromBytes for Record<C> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let owner: Address<C> = FromBytes::read_le(&mut reader)?;
        let is_dummy: bool = FromBytes::read_le(&mut reader)?;
        let value: u64 = FromBytes::read_le(&mut reader)?;
        let payload: Payload = FromBytes::read_le(&mut reader)?;

        let birth_program_id_size: usize = read_variable_length_integer(&mut reader)?;

        let mut birth_program_id = Vec::with_capacity(birth_program_id_size);
        for _ in 0..birth_program_id_size {
            let byte: u8 = FromBytes::read_le(&mut reader)?;
            birth_program_id.push(byte);
        }

        let death_program_id_size: usize = read_variable_length_integer(&mut reader)?;

        let mut death_program_id = Vec::with_capacity(death_program_id_size);
        for _ in 0..death_program_id_size {
            let byte: u8 = FromBytes::read_le(&mut reader)?;
            death_program_id.push(byte);
        }

        let serial_number_nonce: <C::SerialNumberNonceCRH as CRH>::Output = FromBytes::read_le(&mut reader)?;
        let commitment: <C::RecordCommitment as CommitmentScheme>::Output = FromBytes::read_le(&mut reader)?;
        let commitment_randomness: <C::RecordCommitment as CommitmentScheme>::Randomness =
            FromBytes::read_le(&mut reader)?;

        Ok(Self {
            owner,
            is_dummy,
            value,
            payload,
            birth_program_id,
            death_program_id,
            serial_number_nonce,
            commitment,
            commitment_randomness,

            serial_number_nonce_randomness: None,
            position: None,
        })
    }
}

impl<C: Testnet1Components> FromStr for Record<C> {
    type Err = RecordError;

    fn from_str(record: &str) -> Result<Self, Self::Err> {
        Ok(Self::read_le(&hex::decode(record)?[..])?)
    }
}

impl<C: Testnet1Components> fmt::Display for Record<C> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            hex::encode(to_bytes_le![self].expect("serialization to bytes failed"))
        )
    }
}
