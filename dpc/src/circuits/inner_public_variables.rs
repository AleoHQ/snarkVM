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

use crate::{AleoAmount, Network, ValueBalanceCommitment};
use snarkvm_fields::{ConstraintFieldError, ToConstraintField};
use snarkvm_utilities::ToBytes;

use anyhow::Result;
use itertools::Itertools;

#[derive(Clone, Debug)]
pub struct InnerPublicVariables<N: Network> {
    /// The serial numbers of the input records.
    serial_numbers: Vec<N::SerialNumber>,
    /// The commitments of the output records.
    commitments: Vec<N::Commitment>,
    /// A value balance is the difference between the input and output record values.
    value_balance: AleoAmount,
    /// The commitments on the input record values.
    input_value_commitments: Vec<N::ValueCommitment>,
    /// The commitments on the output record values.
    output_value_commitments: Vec<N::ValueCommitment>,
    /// The value balance commitments.
    value_balance_commitment: N::ValueBalanceCommitment,
    ledger_root: N::LedgerRoot,
    local_transitions_root: N::TransactionID,
    // These are required in natively verifying an inner circuit proof.
    // However for verification in the outer circuit, these must be provided as witness.
    /// Program ID
    pub(super) program_id: Option<N::ProgramID>,
}

impl<N: Network> InnerPublicVariables<N> {
    pub(crate) fn blank() -> Self {
        let default_value_commitment: N::ProgramAffineCurve = Default::default();
        Self {
            serial_numbers: vec![Default::default(); N::NUM_INPUT_RECORDS],
            commitments: vec![Default::default(); N::NUM_INPUT_RECORDS],
            value_balance: AleoAmount::ZERO,
            input_value_commitments: vec![default_value_commitment.into(); N::NUM_INPUT_RECORDS],
            output_value_commitments: vec![default_value_commitment.into(); N::NUM_OUTPUT_RECORDS],
            value_balance_commitment: ValueBalanceCommitment::default().into(),
            ledger_root: N::LedgerRoot::default(),
            local_transitions_root: Default::default(),
            program_id: Some(N::ProgramID::default()),
        }
    }

    pub(crate) fn new(
        serial_numbers: Vec<N::SerialNumber>,
        commitments: Vec<N::Commitment>,
        value_balance: AleoAmount,
        input_value_commitments: Vec<N::ValueCommitment>,
        output_value_commitments: Vec<N::ValueCommitment>,
        value_balance_commitment: N::ValueBalanceCommitment,
        ledger_root: N::LedgerRoot,
        local_transitions_root: N::TransactionID,
        program_id: Option<N::ProgramID>,
    ) -> Self {
        Self {
            serial_numbers,
            commitments,
            value_balance,
            input_value_commitments,
            output_value_commitments,
            value_balance_commitment,
            ledger_root,
            local_transitions_root,
            program_id,
        }
    }

    /// Returns a reference to the serial numbers.
    pub(crate) fn serial_numbers(&self) -> &Vec<N::SerialNumber> {
        &self.serial_numbers
    }

    /// Returns a reference to the commitments.
    pub(crate) fn commitments(&self) -> &Vec<N::Commitment> {
        &self.commitments
    }

    /// Returns the value balance of the transition.
    pub(crate) fn value_balance(&self) -> AleoAmount {
        self.value_balance
    }

    /// Returns the commitments on the input record values.
    pub(crate) fn input_value_commitments(&self) -> &Vec<N::ValueCommitment> {
        &self.input_value_commitments
    }

    /// Returns the commitments on the output record values.
    pub(crate) fn output_value_commitments(&self) -> &Vec<N::ValueCommitment> {
        &self.output_value_commitments
    }

    /// Returns the value balance commitment.
    pub(crate) fn value_balance_commitment(&self) -> &N::ValueBalanceCommitment {
        &self.value_balance_commitment
    }

    /// Returns the ledger root.
    pub(crate) fn ledger_root(&self) -> N::LedgerRoot {
        self.ledger_root
    }

    pub(crate) fn local_transitions_root(&self) -> N::TransactionID {
        self.local_transitions_root
    }
}

impl<N: Network> ToConstraintField<N::InnerScalarField> for InnerPublicVariables<N> {
    fn to_field_elements(&self) -> Result<Vec<N::InnerScalarField>, ConstraintFieldError> {
        let mut v = Vec::new();
        v.extend_from_slice(&self.ledger_root.to_field_elements()?);
        v.extend_from_slice(&self.local_transitions_root.to_field_elements()?);

        if let Some(program_id) = &self.program_id {
            v.extend_from_slice(&program_id.to_bytes_le()?.to_field_elements()?);
        } else {
            v.extend_from_slice(&vec![0u8; N::PROGRAM_ID_SIZE_IN_BYTES].to_field_elements()?);
        }

        for (serial_number, input_value_commitment) in self.serial_numbers.iter().zip_eq(&self.input_value_commitments)
        {
            v.extend_from_slice(&serial_number.to_field_elements()?);
            v.extend_from_slice(&input_value_commitment.to_field_elements()?);
        }
        for (commitment, output_value_commitment) in self.commitments.iter().zip_eq(&self.output_value_commitments) {
            v.extend_from_slice(&commitment.to_field_elements()?);
            v.extend_from_slice(&output_value_commitment.to_field_elements()?);
        }

        v.extend_from_slice(&self.value_balance.to_bytes_le()?.to_field_elements()?);
        v.extend_from_slice(&self.value_balance_commitment().to_field_elements()?);

        Ok(v)
    }
}
