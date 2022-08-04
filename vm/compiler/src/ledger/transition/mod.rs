// Copyright (C) 2019-2022 Aleo Systems Inc.
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

mod input;
pub use input::Origin;
use input::*;

mod leaf;
pub use leaf::*;

mod merkle;
pub use merkle::*;

mod output;
use output::*;

mod bytes;
mod serialize;
mod string;

use crate::Proof;
use console::{
    collections::merkle_tree::MerklePath,
    network::{prelude::*, BHPMerkleTree},
    program::{
        Ciphertext,
        Identifier,
        InputID,
        OutputID,
        ProgramID,
        Record,
        Register,
        Request,
        Response,
        Value,
        ValueType,
    },
    types::{Field, Group},
};

#[derive(Clone, PartialEq, Eq)]
pub struct Transition<N: Network> {
    /// The transition ID.
    id: N::TransitionID,
    /// The program ID.
    program_id: ProgramID<N>,
    /// The function name.
    function_name: Identifier<N>,
    /// The transition inputs.
    inputs: Vec<Input<N>>,
    /// The transition outputs.
    outputs: Vec<Output<N>>,
    /// The transition proof.
    proof: Proof<N>,
    /// The transition public key.
    tpk: Group<N>,
    /// The transition commitment.
    tcm: Field<N>,
    /// The network fee.
    fee: i64,
}

impl<N: Network> Transition<N> {
    /// Initializes a new transition.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        program_id: ProgramID<N>,
        function_name: Identifier<N>,
        inputs: Vec<Input<N>>,
        outputs: Vec<Output<N>>,
        proof: Proof<N>,
        tpk: Group<N>,
        tcm: Field<N>,
        fee: i64,
    ) -> Result<Self> {
        // Compute the transition ID.
        let id = *Self::function_tree(&program_id, &function_name, &inputs, &outputs)?.root();
        // Return the transition.
        Ok(Self { id: id.into(), program_id, function_name, inputs, outputs, proof, tpk, tcm, fee })
    }

    /// Initializes a new transition from a request and response.
    pub fn from(
        request: &Request<N>,
        response: &Response<N>,
        output_types: &[ValueType<N>],
        output_registers: &[Register<N>],
        proof: Proof<N>,
        fee: i64,
    ) -> Result<Self> {
        let program_id = *request.program_id();
        let function_name = *request.function_name();
        let num_inputs = request.inputs().len();

        let inputs = request
            .input_ids()
            .iter()
            .zip_eq(request.inputs())
            .enumerate()
            .map(|(index, (input_id, input))| {
                // Construct the transition input.
                match (input_id, input) {
                    (InputID::Constant(input_hash), Value::Plaintext(plaintext)) => {
                        // Compute the plaintext hash.
                        let plaintext_hash = N::hash_bhp1024(&plaintext.to_bits_le())?;
                        // Ensure the plaintext hash matches.
                        ensure!(*input_hash == plaintext_hash, "The constant input plaintext hash is incorrect");
                        // Return the constant input.
                        Ok(Input::Constant(*input_hash, Some(plaintext.clone())))
                    }
                    (InputID::Public(input_hash), Value::Plaintext(plaintext)) => {
                        // Compute the plaintext hash.
                        let plaintext_hash = N::hash_bhp1024(&plaintext.to_bits_le())?;
                        // Ensure the plaintext hash matches.
                        ensure!(*input_hash == plaintext_hash, "The public input plaintext hash is incorrect");
                        // Return the public input.
                        Ok(Input::Public(*input_hash, Some(plaintext.clone())))
                    }
                    (InputID::Private(input_hash), Value::Plaintext(plaintext)) => {
                        // Construct the (console) input index as a field element.
                        let index = Field::from_u16(index as u16);
                        // Compute the ciphertext, with the input view key as `Hash(tvk || index)`.
                        let ciphertext = plaintext.encrypt_symmetric(N::hash_psd2(&[*request.tvk(), index])?)?;
                        // Compute the ciphertext hash.
                        let ciphertext_hash = N::hash_bhp1024(&ciphertext.to_bits_le())?;
                        // Ensure the ciphertext hash matches.
                        ensure!(*input_hash == ciphertext_hash, "The input ciphertext hash is incorrect");
                        // Return the private input.
                        Ok(Input::Private(*input_hash, Some(ciphertext)))
                    }
                    (InputID::Record(commitment, _, serial_number), Value::Record(..)) => {
                        Ok(Input::Record(*serial_number, Origin::Commitment(*commitment)))
                    }
                    (InputID::ExternalRecord(input_commitment), Value::Record(..)) => {
                        Ok(Input::ExternalRecord(*input_commitment))
                    }
                    _ => bail!("Malformed request input: {:?}, {input}", input_id),
                }
            })
            .collect::<Result<Vec<_>>>()?;

        let outputs = response
            .output_ids()
            .iter()
            .zip_eq(response.outputs())
            .zip_eq(output_types)
            .zip_eq(output_registers)
            .enumerate()
            .map(|(index, (((output_id, output), output_type), output_register))| {
                // Construct the transition output.
                match (output_id, output) {
                    (OutputID::Constant(output_hash), Value::Plaintext(plaintext)) => {
                        // Compute the plaintext hash.
                        let plaintext_hash = N::hash_bhp1024(&plaintext.to_bits_le())?;
                        // Ensure the plaintext hash matches.
                        ensure!(*output_hash == plaintext_hash, "The constant output plaintext hash is incorrect");
                        // Return the constant output.
                        Ok(Output::Constant(*output_hash, Some(plaintext.clone())))
                    }
                    (OutputID::Public(output_hash), Value::Plaintext(plaintext)) => {
                        // Compute the plaintext hash.
                        let plaintext_hash = N::hash_bhp1024(&plaintext.to_bits_le())?;
                        // Ensure the plaintext hash matches.
                        ensure!(*output_hash == plaintext_hash, "The public output plaintext hash is incorrect");
                        // Return the public output.
                        Ok(Output::Public(*output_hash, Some(plaintext.clone())))
                    }
                    (OutputID::Private(output_hash), Value::Plaintext(plaintext)) => {
                        // Construct the (console) output index as a field element.
                        let index = Field::from_u16((num_inputs + index) as u16);
                        // Compute the ciphertext, with the input view key as `Hash(tvk || index)`.
                        let ciphertext = plaintext.encrypt_symmetric(N::hash_psd2(&[*request.tvk(), index])?)?;
                        // Compute the ciphertext hash.
                        let ciphertext_hash = N::hash_bhp1024(&ciphertext.to_bits_le())?;
                        // Ensure the ciphertext hash matches.
                        ensure!(*output_hash == ciphertext_hash, "The output ciphertext hash is incorrect");
                        // Return the private output.
                        Ok(Output::Private(*output_hash, Some(ciphertext)))
                    }
                    (OutputID::Record(commitment, checksum), Value::Record(record)) => {
                        // Retrieve the record name.
                        let record_name = match output_type {
                            ValueType::Record(record_name) => record_name,
                            // Ensure the input type is a record.
                            _ => bail!("Expected a record type at output {index}"),
                        };

                        // Compute the record commitment.
                        let candidate_cm = record.to_commitment(&program_id, record_name)?;
                        // Ensure the commitment matches.
                        ensure!(*commitment == candidate_cm, "The output record commitment is incorrect");

                        // Construct the (console) output index as a field element.
                        let index = Field::from_u64(output_register.locator());
                        // Compute the encryption randomizer as `HashToScalar(tvk || index)`.
                        let randomizer = N::hash_to_scalar_psd2(&[*request.tvk(), index])?;

                        // Encrypt the record, using the randomizer.
                        let record_ciphertext = record.encrypt(randomizer)?;
                        // Compute the record checksum, as the hash of the encrypted record.
                        let ciphertext_checksum = N::hash_bhp1024(&record_ciphertext.to_bits_le())?;
                        // Ensure the checksum matches.
                        ensure!(*checksum == ciphertext_checksum, "The output record ciphertext checksum is incorrect");

                        // Return the record output.
                        Ok(Output::Record(*commitment, *checksum, Some(record_ciphertext)))
                    }
                    (OutputID::ExternalRecord(commitment), Value::Record(record)) => {
                        // Construct the (console) output index as a field element.
                        let index = Field::from_u16((num_inputs + index) as u16);
                        // Compute the output randomizer as `HashToScalar(tvk || index)`.
                        let output_randomizer = N::hash_to_scalar_psd2(&[*request.tvk(), index])?;
                        // Commit the output to a field element.
                        let candidate_cm = N::commit_bhp1024(&record.to_bits_le(), &output_randomizer)?;
                        // Ensure the commitment matches.
                        ensure!(*commitment == candidate_cm, "The output commitment is incorrect");
                        // Return the record output.
                        Ok(Output::ExternalRecord(*commitment))
                    }
                    _ => bail!("Malformed response output: {:?}, {output}", output_id),
                }
            })
            .collect::<Result<Vec<_>>>()?;

        // Retrieve the `tpk`.
        let tpk = request.to_tpk();
        // Retrieve the `tcm`.
        let tcm = *request.tcm();
        // Return the transition.
        Self::new(program_id, function_name, inputs, outputs, proof, tpk, tcm, fee)
    }

    /// Returns the transition ID.
    pub const fn id(&self) -> &N::TransitionID {
        &self.id
    }

    /// Consumes `self`, returning the transition ID.
    pub fn into_id(self) -> N::TransitionID {
        self.id
    }

    /// Returns the program ID.
    pub const fn program_id(&self) -> &ProgramID<N> {
        &self.program_id
    }

    /// Returns the function name.
    pub const fn function_name(&self) -> &Identifier<N> {
        &self.function_name
    }

    /// Returns the inputs.
    pub fn inputs(&self) -> &[Input<N>] {
        &self.inputs
    }

    /// Returns the input IDs.
    pub fn input_ids(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.inputs.iter().map(Input::id)
    }

    /// Return the outputs.
    pub fn outputs(&self) -> &[Output<N>] {
        &self.outputs
    }

    /// Returns the output IDs.
    pub fn output_ids(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.outputs.iter().map(Output::id)
    }

    /// Returns the output records as a tuple comprised of `(commitment, record)`.
    pub fn output_records(&self) -> impl '_ + Iterator<Item = (&Field<N>, &Record<N, Ciphertext<N>>)> {
        self.outputs.iter().flat_map(Output::record)
    }

    /// Consumes `self` and returns the output records as a tuple comprised of `(commitment, record)`.
    pub fn into_output_records(self) -> impl Iterator<Item = (Field<N>, Record<N, Ciphertext<N>>)> {
        self.outputs.into_iter().flat_map(Output::into_record)
    }

    /// Returns the proof.
    pub const fn proof(&self) -> &Proof<N> {
        &self.proof
    }

    /// Returns the transition public key.
    pub const fn tpk(&self) -> &Group<N> {
        &self.tpk
    }

    /// Consumes `self`, returning the transition public key.
    pub fn into_tpk(self) -> Group<N> {
        self.tpk
    }

    /// Returns the transition commitment.
    pub const fn tcm(&self) -> &Field<N> {
        &self.tcm
    }

    /// Returns the network fee.
    pub const fn fee(&self) -> &i64 {
        &self.fee
    }
}

impl<N: Network> Transition<N> {
    /// Returns an iterator over the origins, for inputs that are records.
    pub fn origins(&self) -> impl '_ + Iterator<Item = &Origin<N>> {
        self.inputs.iter().flat_map(Input::origin)
    }

    /// Returns an iterator over the serial numbers, for inputs that are records.
    pub fn serial_numbers(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.inputs.iter().flat_map(Input::serial_number)
    }

    /// Returns a consuming iterator over the serial numbers, for inputs that are records.
    pub fn into_serial_numbers(self) -> impl Iterator<Item = Field<N>> {
        self.inputs.into_iter().flat_map(Input::into_serial_number)
    }

    /// Returns an iterator over the commitments, for outputs that are records.
    pub fn commitments(&self) -> impl '_ + Iterator<Item = &Field<N>> {
        self.outputs.iter().flat_map(Output::commitment)
    }

    /// Returns a consuming iterator over the commitments, for outputs that are records.
    pub fn into_commitments(self) -> impl Iterator<Item = Field<N>> {
        self.outputs.into_iter().flat_map(Output::into_commitment)
    }

    /// Returns an iterator over the nonces, for outputs that are records.
    pub fn nonces(&self) -> impl '_ + Iterator<Item = &Group<N>> {
        self.outputs.iter().flat_map(Output::nonce)
    }

    /// Returns a consuming iterator over the nonces, for outputs that are records.
    pub fn into_nonces(self) -> impl Iterator<Item = Group<N>> {
        self.outputs.into_iter().flat_map(Output::into_nonce)
    }
}
