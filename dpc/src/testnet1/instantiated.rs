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
    account::{ACCOUNT_COMMITMENT_INPUT, ACCOUNT_ENCRYPTION_INPUT, ACCOUNT_SIGNATURE_INPUT},
    testnet1::{
        inner_circuit::InnerCircuit,
        inner_circuit_verifier_input::InnerCircuitVerifierInput,
        outer_circuit::OuterCircuit,
        outer_circuit_verifier_input::OuterCircuitVerifierInput,
        program::{NoopCircuit, ProgramLocalData},
        transaction::Transaction,
        Testnet1Components,
        DPC,
    },
    DPCComponents,
    Network,
};
use snarkvm_algorithms::{
    commitment::{Blake2sCommitment, PedersenCompressedCommitment},
    crh::BoweHopwoodPedersenCompressedCRH,
    define_merkle_tree_parameters,
    encryption::GroupEncryption,
    prelude::*,
    prf::Blake2s,
    signature::Schnorr,
    snark::{gm17::GM17, groth16::Groth16},
};
use snarkvm_curves::{
    bls12_377::Bls12_377,
    bw6_761::BW6_761,
    edwards_bls12::{EdwardsParameters, EdwardsProjective as EdwardsBls12},
    edwards_bw6::EdwardsProjective as EdwardsBW6,
    PairingEngine,
};
use snarkvm_gadgets::{
    algorithms::{
        commitment::{Blake2sCommitmentGadget, PedersenCompressedCommitmentGadget},
        crh::BoweHopwoodPedersenCompressedCRHGadget,
        encryption::GroupEncryptionGadget,
        prf::Blake2sGadget,
        signature::SchnorrGadget,
        snark::{GM17VerifierGadget, Groth16VerifierGadget},
    },
    curves::{bls12_377::PairingGadget, edwards_bls12::EdwardsBls12Gadget, edwards_bw6::EdwardsBW6Gadget},
};

use once_cell::sync::OnceCell;

macro_rules! dpc_setup {
    ($fn_name: ident, $static_name: ident, $type_name: ident, $setup_msg: expr) => {
        #[inline]
        fn $fn_name() -> &'static Self::$type_name {
            static $static_name: OnceCell<<Components as DPCComponents>::$type_name> = OnceCell::new();
            $static_name.get_or_init(|| Self::$type_name::setup($setup_msg))
        }
    };
}

pub type Testnet1DPC = DPC<Components>;
pub type Testnet1Transaction = Transaction<Components>;

define_merkle_tree_parameters!(
    CommitmentMerkleTreeParameters,
    <Components as DPCComponents>::LedgerMerkleTreeCRH,
    32
);

pub struct Components;

#[rustfmt::skip]
impl DPCComponents for Components {
    const NETWORK_ID: u8 = Network::Testnet1.id();
    
    const NUM_INPUT_RECORDS: usize = 2;
    const NUM_OUTPUT_RECORDS: usize = 2;

    type InnerCurve = Bls12_377;
    type OuterCurve = BW6_761;

    type InnerScalarField = <Self::InnerCurve as PairingEngine>::Fr;
    type OuterScalarField = <Self::OuterCurve as PairingEngine>::Fr;
    
    type AccountCommitment = PedersenCompressedCommitment<EdwardsBls12, 8, 192>;
    type AccountCommitmentGadget = PedersenCompressedCommitmentGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 8, 192>;
    
    type AccountEncryption = GroupEncryption<EdwardsBls12>;
    type AccountEncryptionGadget = GroupEncryptionGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget>;

    type AccountSignature = Schnorr<EdwardsBls12>;
    type AccountSignatureGadget = SchnorrGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget>;
    
    type EncryptedRecordCRH = BoweHopwoodPedersenCompressedCRH<EdwardsBls12, 48, 44>;
    type EncryptedRecordCRHGadget = BoweHopwoodPedersenCompressedCRHGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 48, 44>;
    
    type InnerCircuitIDCRH = BoweHopwoodPedersenCompressedCRH<EdwardsBW6, 296, 63>;
    type InnerCircuitIDCRHGadget = BoweHopwoodPedersenCompressedCRHGadget<EdwardsBW6, Self::OuterScalarField, EdwardsBW6Gadget, 296, 63>;

    type LedgerMerkleTreeCRH = BoweHopwoodPedersenCompressedCRH<EdwardsBls12, 8, 32>;
    type LedgerMerkleTreeCRHGadget = BoweHopwoodPedersenCompressedCRHGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 8, 32>;
    type LedgerMerkleTreeParameters = CommitmentMerkleTreeParameters;

    type LocalDataCommitment = PedersenCompressedCommitment<EdwardsBls12, 8, 129>;
    type LocalDataCommitmentGadget = PedersenCompressedCommitmentGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 8, 129>;

    type LocalDataCRH = BoweHopwoodPedersenCompressedCRH<EdwardsBls12, 16, 32>;
    type LocalDataCRHGadget = BoweHopwoodPedersenCompressedCRHGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 16, 32>;

    type PRF = Blake2s;
    type PRFGadget = Blake2sGadget;

    type ProgramIDCommitment = Blake2sCommitment;
    type ProgramIDCommitmentGadget = Blake2sCommitmentGadget;
    
    type ProgramIDCRH = BoweHopwoodPedersenCompressedCRH<EdwardsBW6, 144, 63>;
    type ProgramIDCRHGadget = BoweHopwoodPedersenCompressedCRHGadget<EdwardsBW6, Self::OuterScalarField, EdwardsBW6Gadget, 144, 63>;
    
    type RecordCommitment = PedersenCompressedCommitment<EdwardsBls12, 8, 233>;
    type RecordCommitmentGadget = PedersenCompressedCommitmentGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 8, 233>;
    
    type SerialNumberNonceCRH = BoweHopwoodPedersenCompressedCRH<EdwardsBls12, 32, 63>;
    type SerialNumberNonceCRHGadget = BoweHopwoodPedersenCompressedCRHGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 32, 63>;
    
    dpc_setup!{account_commitment, ACCOUNT_COMMITMENT, AccountCommitment, ACCOUNT_COMMITMENT_INPUT}
    dpc_setup!{account_encryption, ACCOUNT_ENCRYPTION, AccountEncryption, ACCOUNT_ENCRYPTION_INPUT}
    dpc_setup!{account_signature, ACCOUNT_SIGNATURE, AccountSignature, ACCOUNT_SIGNATURE_INPUT}
    dpc_setup!{encrypted_record_crh, ENCRYPTED_RECORD_CRH, EncryptedRecordCRH, "AleoEncryptedRecordCRH0"}
    dpc_setup!{inner_circuit_id_crh, INNER_CIRCUIT_ID_CRH, InnerCircuitIDCRH, "AleoInnerCircuitIDCRH0"}
    dpc_setup!{ledger_merkle_tree_crh, LEDGER_MERKLE_TREE_CRH, LedgerMerkleTreeCRH, "AleoLedgerMerkleTreeCRH0"}
    dpc_setup!{local_data_commitment, LOCAL_DATA_COMMITMENT, LocalDataCommitment, "AleoLocalDataCommitment0"}
    dpc_setup!{local_data_crh, LOCAL_DATA_CRH, LocalDataCRH, "AleoLocalDataCRH0"}
    dpc_setup!{program_id_commitment, PROGRAM_ID_COMMITMENT, ProgramIDCommitment, "AleoProgramIDCommitment0"}
    dpc_setup!{program_id_crh, PROGRAM_ID_CRH, ProgramIDCRH, "AleoProgramIDCRH0"}
    dpc_setup!{record_commitment, RECORD_COMMITMENT, RecordCommitment, "AleoRecordCommitment0"}
    dpc_setup!{serial_number_nonce_crh, SERIAL_NUMBER_NONCE_CRH, SerialNumberNonceCRH, "AleoSerialNumberNonceCRH0"}

    // TODO (howardwu): TEMPORARY - Deprecate this with a ledger rearchitecture.
    fn ledger_merkle_tree_parameters() -> &'static Self::LedgerMerkleTreeParameters {
        static LEDGER_MERKLE_TREE_PARAMETERS: OnceCell<<Components as DPCComponents>::LedgerMerkleTreeParameters> = OnceCell::new();
        LEDGER_MERKLE_TREE_PARAMETERS.get_or_init(|| Self::LedgerMerkleTreeParameters::from(Self::ledger_merkle_tree_crh().clone()))
    }
}

impl Testnet1Components for Components {
    type EncryptionGroup = EdwardsBls12;
    type EncryptionParameters = EdwardsParameters;
    type InnerSNARK = Groth16<Self::InnerCurve, InnerCircuit<Components>, InnerCircuitVerifierInput<Components>>;
    type InnerSNARKGadget = Groth16VerifierGadget<Self::InnerCurve, PairingGadget>;
    type NoopProgramSNARK = GM17<Self::InnerCurve, NoopCircuit<Self>, ProgramLocalData<Self>>;
    type NoopProgramSNARKGadget = GM17VerifierGadget<Self::InnerCurve, PairingGadget>;
    type OuterSNARK = Groth16<Self::OuterCurve, OuterCircuit<Components>, OuterCircuitVerifierInput<Components>>;
}
