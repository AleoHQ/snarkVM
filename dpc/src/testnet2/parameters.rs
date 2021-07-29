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
    account::{ACCOUNT_COMMITMENT_INPUT, ACCOUNT_ENCRYPTION_AND_SIGNATURE_INPUT},
    testnet2::DPC,
    InnerCircuitVerifierInput,
    Network,
    OuterCircuitVerifierInput,
    Parameters,
    ProgramLocalData,
    Transaction,
};
use snarkvm_algorithms::{
    commitment::{BHPCompressedCommitment, Blake2sCommitment},
    crh::BHPCompressedCRH,
    crypto_hash::PoseidonCryptoHash,
    define_additional_merkle_tree_parameters,
    define_merkle_tree_parameters,
    encryption::ECIESPoseidonEncryption,
    prelude::*,
    prf::Blake2s,
    signature::Schnorr,
    snark::groth16::Groth16,
};
use snarkvm_curves::{
    bls12_377::Bls12_377,
    bw6_761::BW6_761,
    edwards_bls12::{EdwardsParameters, EdwardsProjective as EdwardsBls12},
    PairingEngine,
};
use snarkvm_gadgets::{
    algorithms::{
        commitment::{BHPCompressedCommitmentGadget, Blake2sCommitmentGadget},
        crh::BHPCompressedCRHGadget,
        crypto_hash::PoseidonCryptoHashGadget,
        encryption::ECIESPoseidonEncryptionGadget,
        prf::Blake2sGadget,
        signature::SchnorrGadget,
        snark::Groth16VerifierGadget,
    },
    curves::{bls12_377::PairingGadget, edwards_bls12::EdwardsBls12Gadget},
};
use snarkvm_marlin::{
    constraints::{snark::MarlinSNARK, verifier::MarlinVerificationGadget},
    marlin::MarlinTestnet2Mode,
    FiatShamirAlgebraicSpongeRng,
    PoseidonSponge,
};
use snarkvm_parameters::{testnet2::UniversalSRSParameters, Parameter};
use snarkvm_polycommit::marlin_pc::{marlin_kzg10::MarlinKZG10Gadget, MarlinKZG10};
use snarkvm_utilities::FromBytes;

use anyhow::Result;
use once_cell::sync::OnceCell;
use rand::{CryptoRng, Rng};

macro_rules! dpc_setup {
    ($fn_name: ident, $static_name: ident, $type_name: ident, $setup_msg: expr) => {
        #[inline]
        fn $fn_name() -> &'static Self::$type_name {
            static $static_name: OnceCell<<Testnet2Parameters as Parameters>::$type_name> = OnceCell::new();
            $static_name.get_or_init(|| Self::$type_name::setup($setup_msg))
        }
    };
}

pub type Testnet2DPC = DPC<Testnet2Parameters>;
pub type Testnet2Transaction = Transaction<Testnet2Parameters>;

define_merkle_tree_parameters!(
    CommitmentMerkleTreeParameters,
    <Testnet2Parameters as Parameters>::RecordCommitmentTreeCRH,
    32
);

define_additional_merkle_tree_parameters!(
    ProgramSelectorMerkleTreeParameters,
    <Testnet2Parameters as Parameters>::ProgramSelectorTreeCRH,
    8
);

pub struct Testnet2Parameters;

// TODO (raychu86): Optimize each of the window sizes in the type declarations below.
#[rustfmt::skip]
impl Parameters for Testnet2Parameters {
    const NETWORK_ID: u8 = Network::Testnet2.id();

    const NUM_INPUT_RECORDS: usize = 2;
    const NUM_OUTPUT_RECORDS: usize = 2;

    type InnerCurve = Bls12_377;
    type OuterCurve = BW6_761;

    type InnerScalarField = <Self::InnerCurve as PairingEngine>::Fr;
    type OuterScalarField = <Self::OuterCurve as PairingEngine>::Fr;
    type OuterBaseField = <Self::OuterCurve as PairingEngine>::Fq;

    type InnerSNARK = Groth16<Self::InnerCurve, InnerCircuitVerifierInput<Testnet2Parameters>>;
    type InnerSNARKGadget = Groth16VerifierGadget<Self::InnerCurve, PairingGadget>;

    type OuterSNARK = Groth16<Self::OuterCurve, OuterCircuitVerifierInput<Testnet2Parameters>>;

    type ProgramSNARK = MarlinSNARK<
        Self::InnerScalarField,
        Self::OuterScalarField,
        MarlinKZG10<Self::InnerCurve>,
        FiatShamirAlgebraicSpongeRng<Self::InnerScalarField, Self::OuterScalarField, PoseidonSponge<Self::OuterScalarField>>,
        MarlinTestnet2Mode,
        ProgramLocalData<Self>,
    >;
    type ProgramSNARKGadget = MarlinVerificationGadget<
        Self::InnerScalarField,
        Self::OuterScalarField,
        MarlinKZG10<Self::InnerCurve>,
        MarlinKZG10Gadget<Self::InnerCurve, Self::OuterCurve, PairingGadget>,
    >;

    type AccountCommitmentScheme = BHPCompressedCommitment<EdwardsBls12, 33, 48>;
    type AccountCommitmentGadget = BHPCompressedCommitmentGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 33, 48>;
    type AccountCommitment = <Self::AccountCommitmentScheme as CommitmentScheme>::Output;

    type AccountEncryptionScheme = ECIESPoseidonEncryption<EdwardsParameters>;
    type AccountEncryptionGadget = ECIESPoseidonEncryptionGadget<EdwardsParameters, Self::InnerScalarField>;

    type AccountSignatureScheme = Schnorr<EdwardsBls12>;
    type AccountSignatureGadget = SchnorrGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget>;
    type AccountSignaturePublicKey = <Self::AccountSignatureScheme as SignatureScheme>::PublicKey;

    type EncryptedRecordCRH = PoseidonCryptoHash<Self::InnerScalarField, 4, false>;
    type EncryptedRecordCRHGadget = PoseidonCryptoHashGadget<Self::InnerScalarField, 4, false>;
    type EncryptedRecordDigest = <Self::EncryptedRecordCRH as CRH>::Output;

    type InnerCircuitIDCRH = PoseidonCryptoHash<Self::OuterScalarField, 4, false>;
    type InnerCircuitIDCRHGadget = PoseidonCryptoHashGadget<Self::OuterScalarField, 4, false>;
    type InnerCircuitIDCRHDigest = <Self::InnerCircuitIDCRH as CRH>::Output;

    type LocalDataCommitmentScheme = BHPCompressedCommitment<EdwardsBls12, 24, 62>;
    type LocalDataCommitmentGadget = BHPCompressedCommitmentGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 24, 62>;

    type LocalDataCRH = BHPCompressedCRH<EdwardsBls12, 16, 32>;
    type LocalDataCRHGadget = BHPCompressedCRHGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 16, 32>;
    type LocalDataDigest = <Self::LocalDataCRH as CRH>::Output;

    type PRF = Blake2s;
    type PRFGadget = Blake2sGadget;

    type ProgramCommitmentScheme = Blake2sCommitment;
    type ProgramCommitmentGadget = Blake2sCommitmentGadget;
    type ProgramCommitment = <Self::ProgramCommitmentScheme as CommitmentScheme>::Output;

    type ProgramSelectorTreeCRH = BHPCompressedCRH<EdwardsBls12, 8, 32>;
    type ProgramSelectorTreeCRHGadget = BHPCompressedCRHGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 8, 32>;
    type ProgramSelectorTreeDigest = <Self::ProgramSelectorTreeCRH as CRH>::Output;
    type ProgramSelectorTreeParameters = ProgramSelectorMerkleTreeParameters;
    
    type ProgramIDCRH = PoseidonCryptoHash<Self::OuterScalarField, 4, false>;
    type ProgramIDCRHGadget = PoseidonCryptoHashGadget<Self::OuterScalarField, 4, false>;

    type RecordCommitmentScheme = BHPCompressedCommitment<EdwardsBls12, 48, 50>;
    type RecordCommitmentGadget = BHPCompressedCommitmentGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 48, 50>;
    type RecordCommitment = <Self::RecordCommitmentScheme as CommitmentScheme>::Output;

    type RecordCommitmentTreeCRH = BHPCompressedCRH<EdwardsBls12, 8, 32>;
    type RecordCommitmentTreeCRHGadget = BHPCompressedCRHGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 8, 32>;
    type RecordCommitmentTreeDigest = <Self::RecordCommitmentTreeCRH as CRH>::Output;
    type RecordCommitmentTreeParameters = CommitmentMerkleTreeParameters;

    type SerialNumberNonceCRH = BHPCompressedCRH<EdwardsBls12, 32, 63>;
    type SerialNumberNonceCRHGadget = BHPCompressedCRHGadget<EdwardsBls12, Self::InnerScalarField, EdwardsBls12Gadget, 32, 63>;

    dpc_setup!{account_commitment_scheme, ACCOUNT_COMMITMENT_SCHEME, AccountCommitmentScheme, ACCOUNT_COMMITMENT_INPUT} // TODO (howardwu): Rename to "AleoAccountCommitmentScheme0".
    dpc_setup!{account_encryption_scheme, ACCOUNT_ENCRYPTION_SCHEME, AccountEncryptionScheme, ACCOUNT_ENCRYPTION_AND_SIGNATURE_INPUT}
    dpc_setup!{account_signature_scheme, ACCOUNT_SIGNATURE_SCHEME, AccountSignatureScheme, ACCOUNT_ENCRYPTION_AND_SIGNATURE_INPUT}
    dpc_setup!{encrypted_record_crh, ENCRYPTED_RECORD_CRH, EncryptedRecordCRH, "AleoEncryptedRecordCRH0"}
    dpc_setup!{inner_circuit_id_crh, INNER_CIRCUIT_ID_CRH, InnerCircuitIDCRH, "AleoInnerCircuitIDCRH0"}
    dpc_setup!{local_data_commitment_scheme, LOCAL_DATA_COMMITMENT_SCHEME, LocalDataCommitmentScheme, "AleoLocalDataCommitment0"} // TODO (howardwu): Rename to "AleoLocalDataCommitmentScheme0".
    dpc_setup!{local_data_crh, LOCAL_DATA_CRH, LocalDataCRH, "AleoLocalDataCRH0"}
    dpc_setup!{program_commitment_scheme, PROGRAM_COMMITMENT_SCHEME, ProgramCommitmentScheme, "AleoProgramIDCommitment0"} // TODO (howardwu): Rename to "AleoProgramCommitmentScheme0".
    dpc_setup!{program_id_crh, PROGRAM_ID_CRH, ProgramIDCRH, "AleoProgramIDCRH0"}
    dpc_setup!{program_selector_tree_crh, PROGRAM_SELECTOR_TREE_CRH, ProgramSelectorTreeCRH, "AleoProgramSelectorTreeCRH0"}
    dpc_setup!{record_commitment_scheme, RECORD_COMMITMENT_SCHEME, RecordCommitmentScheme, "AleoRecordCommitment0"} // TODO (howardwu): Rename to "AleoRecordCommitmentScheme0".
    dpc_setup!{record_commitment_tree_crh, RECORD_COMMITMENT_TREE_CRH, RecordCommitmentTreeCRH, "AleoLedgerMerkleTreeCRH0"} // TODO (howardwu): Rename to "AleoRecordCommitmentTreeCRH0".
    dpc_setup!{serial_number_nonce_crh, SERIAL_NUMBER_NONCE_CRH, SerialNumberNonceCRH, "AleoSerialNumberNonceCRH0"}

    // TODO (howardwu): TEMPORARY - Refactor this to a proper tree.
    fn record_commitment_tree_parameters() -> &'static Self::RecordCommitmentTreeParameters {
        static RECORD_COMMITMENT_TREE_PARAMETERS: OnceCell<<Testnet2Parameters as Parameters>::RecordCommitmentTreeParameters> = OnceCell::new();
        RECORD_COMMITMENT_TREE_PARAMETERS.get_or_init(|| Self::RecordCommitmentTreeParameters::from(Self::record_commitment_tree_crh().clone()))
    }

    // TODO (howardwu): TEMPORARY - Making this oncecell.
    /// Returns the program SRS for Aleo applications.
    fn program_srs<R: Rng + CryptoRng>(_rng: &mut R) -> Result<SRS<R, <Self::ProgramSNARK as SNARK>::UniversalSetupParameters>> {
        let bytes = UniversalSRSParameters::load_bytes()?;
        let srs = <Self::ProgramSNARK as SNARK>::UniversalSetupParameters::from_bytes_le(&bytes)?;
        Ok(SRS::<R, _>::Universal(srs))
    }
}

// This is currently unused.
//
// use snarkvm_marlin::{FiatShamirAlgebraicSpongeRngVar, PoseidonSpongeVar};
//
// pub type FSG = FiatShamirAlgebraicSpongeRngVar<
//     Self::InnerScalarField,
//     Self::OuterScalarField,
//     PoseidonSponge<Self::OuterScalarField>,
//     PoseidonSpongeVar<Self::OuterScalarField>,
// >;
