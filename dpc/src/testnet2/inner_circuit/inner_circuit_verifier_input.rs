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
    testnet2::{parameters::SystemParameters, Testnet2Components},
    AleoAmount,
};
use snarkvm_algorithms::{
    merkle_tree::MerkleTreeDigest,
    traits::{CommitmentScheme, EncryptionScheme, MerkleParameters, SignatureScheme, CRH},
};
use snarkvm_fields::{ConstraintFieldError, ToConstraintField};

use std::sync::Arc;

#[derive(Derivative)]
#[derivative(Clone(bound = "C: Testnet2Components"))]
pub struct InnerCircuitVerifierInput<C: Testnet2Components> {
    // Commitment, CRH, and signature parameters
    pub system_parameters: SystemParameters<C>,

    // Ledger parameters and digest
    pub ledger_parameters: Arc<C::MerkleParameters>,
    pub ledger_digest: MerkleTreeDigest<C::MerkleParameters>,

    // Input record serial numbers
    pub old_serial_numbers: Vec<<C::AccountSignature as SignatureScheme>::PublicKey>,

    // Output record commitments
    pub new_commitments: Vec<<C::RecordCommitment as CommitmentScheme>::Output>,

    // New encrypted record hashes
    pub new_encrypted_record_hashes: Vec<<C::EncryptedRecordCRH as CRH>::Output>,

    // Program input commitment and local data root
    pub program_commitment: <C::ProgramVerificationKeyCommitment as CommitmentScheme>::Output,
    pub local_data_root: <C::LocalDataCRH as CRH>::Output,

    pub memo: [u8; 32],
    pub value_balance: AleoAmount,
    pub network_id: u8,
}

impl<C: Testnet2Components> ToConstraintField<C::InnerScalarField> for InnerCircuitVerifierInput<C>
where
    <C::AccountCommitment as CommitmentScheme>::Parameters: ToConstraintField<C::InnerScalarField>,
    <C::AccountCommitment as CommitmentScheme>::Output: ToConstraintField<C::InnerScalarField>,

    <C::AccountEncryption as EncryptionScheme>::Parameters: ToConstraintField<C::InnerScalarField>,

    <C::AccountSignature as SignatureScheme>::Parameters: ToConstraintField<C::InnerScalarField>,
    <C::AccountSignature as SignatureScheme>::PublicKey: ToConstraintField<C::InnerScalarField>,

    <C::RecordCommitment as CommitmentScheme>::Parameters: ToConstraintField<C::InnerScalarField>,
    <C::RecordCommitment as CommitmentScheme>::Output: ToConstraintField<C::InnerScalarField>,

    <C::EncryptedRecordCRH as CRH>::Parameters: ToConstraintField<C::InnerScalarField>,
    <C::EncryptedRecordCRH as CRH>::Output: ToConstraintField<C::InnerScalarField>,

    <C::SerialNumberNonceCRH as CRH>::Parameters: ToConstraintField<C::InnerScalarField>,

    <C::ProgramVerificationKeyCommitment as CommitmentScheme>::Parameters: ToConstraintField<C::InnerScalarField>,
    <C::ProgramVerificationKeyCommitment as CommitmentScheme>::Output: ToConstraintField<C::InnerScalarField>,

    <C::LocalDataCRH as CRH>::Parameters: ToConstraintField<C::InnerScalarField>,
    <C::LocalDataCRH as CRH>::Output: ToConstraintField<C::InnerScalarField>,

    <C::LocalDataCommitment as CommitmentScheme>::Parameters: ToConstraintField<C::InnerScalarField>,

    <<C::MerkleParameters as MerkleParameters>::H as CRH>::Parameters: ToConstraintField<C::InnerScalarField>,
    MerkleTreeDigest<C::MerkleParameters>: ToConstraintField<C::InnerScalarField>,
{
    fn to_field_elements(&self) -> Result<Vec<C::InnerScalarField>, ConstraintFieldError> {
        let mut v = Vec::new();

        v.extend_from_slice(
            &self
                .system_parameters
                .account_commitment
                .parameters()
                .to_field_elements()?,
        );
        v.extend_from_slice(
            &<C::AccountEncryption as EncryptionScheme>::parameters(&self.system_parameters.account_encryption)
                .to_field_elements()?,
        );
        v.extend_from_slice(
            &self
                .system_parameters
                .account_signature
                .parameters()
                .to_field_elements()?,
        );
        v.extend_from_slice(
            &self
                .system_parameters
                .record_commitment
                .parameters()
                .to_field_elements()?,
        );
        v.extend_from_slice(
            &self
                .system_parameters
                .encrypted_record_crh
                .parameters()
                .to_field_elements()?,
        );
        v.extend_from_slice(
            &self
                .system_parameters
                .program_verification_key_commitment
                .parameters()
                .to_field_elements()?,
        );
        v.extend_from_slice(&self.system_parameters.local_data_crh.parameters().to_field_elements()?);
        v.extend_from_slice(
            &self
                .system_parameters
                .local_data_commitment
                .parameters()
                .to_field_elements()?,
        );
        v.extend_from_slice(
            &self
                .system_parameters
                .serial_number_nonce
                .parameters()
                .to_field_elements()?,
        );

        v.extend_from_slice(&self.ledger_parameters.parameters().to_field_elements()?);
        v.extend_from_slice(&self.ledger_digest.to_field_elements()?);

        for sn in &self.old_serial_numbers {
            v.extend_from_slice(&sn.to_field_elements()?);
        }

        for (cm, encrypted_record_hash) in self.new_commitments.iter().zip(&self.new_encrypted_record_hashes) {
            v.extend_from_slice(&cm.to_field_elements()?);
            v.extend_from_slice(&encrypted_record_hash.to_field_elements()?);
        }

        v.extend_from_slice(&self.program_commitment.to_field_elements()?);
        v.extend_from_slice(&ToConstraintField::<C::InnerScalarField>::to_field_elements(
            &self.memo,
        )?);
        v.extend_from_slice(&ToConstraintField::<C::InnerScalarField>::to_field_elements(
            &[self.network_id][..],
        )?);
        v.extend_from_slice(&self.local_data_root.to_field_elements()?);

        v.extend_from_slice(&ToConstraintField::<C::InnerScalarField>::to_field_elements(
            &self.value_balance.0.to_le_bytes()[..],
        )?);
        Ok(v)
    }
}
