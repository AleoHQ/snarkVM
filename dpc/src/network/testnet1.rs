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

use crate::{
    account::ACCOUNT_ENCRYPTION_AND_SIGNATURE_INPUT,
    posw::PoSW,
    AleoLocator,
    AleoObject,
    Block,
    Ciphertext,
    InnerPublicVariables,
    Network,
    PoSWScheme,
    ProgramPublicVariables,
    ValueBalanceCommitment,
};
use snarkvm_algorithms::{
    commitment::PedersenCommitment,
    crh::{PedersenCompressedCRH, PoseidonCRH, BHPCRH},
    crypto_hash::poseidon::PoseidonSponge,
    encryption::ECIESPoseidonEncryption,
    merkle_tree::{MaskedMerkleTreeParameters, MerkleTreeParameters},
    polycommit::sonic_pc::SonicKZG10,
    prelude::*,
    prf::PoseidonPRF,
    signature::AleoSignatureScheme,
    snark::{
        groth16::Groth16,
        marlin::{FiatShamirAlgebraicSpongeRng, MarlinNonHidingMode, MarlinSNARK},
    },
};
use snarkvm_curves::{
    bls12_377::Bls12_377,
    edwards_bls12::{
        EdwardsAffine as EdwardsBls12Affine,
        EdwardsParameters,
        EdwardsProjective as EdwardsBls12Projective,
    },
    edwards_bw6::EdwardsProjective as EdwardsBW6,
    traits::*,
};
use snarkvm_gadgets::{
    algorithms::{
        commitment::PedersenCommitmentGadget,
        crh::{BHPCRHGadget, PedersenCompressedCRHGadget, PoseidonCRHGadget},
        encryption::ECIESPoseidonEncryptionGadget,
        prf::PoseidonPRFGadget,
        signature::AleoSignatureSchemeGadget,
    },
    curves::edwards_bls12::EdwardsBls12Gadget,
};
use snarkvm_parameters::{testnet1::*, Genesis};
use snarkvm_utilities::{FromBytes, ToMinimalBits};

use once_cell::sync::OnceCell;
use rand::{CryptoRng, Rng};
use serde::{Deserialize, Serialize};
use std::{cell::RefCell, rc::Rc};

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Testnet1;

#[rustfmt::skip]
impl Network for Testnet1 {
    const NETWORK_ID: u16 = 1u16;
    const NETWORK_NAME: &'static str = "testnet1";

    const NUM_INPUT_RECORDS: usize = 2;
    const NUM_OUTPUT_RECORDS: usize = 2;
    const NUM_TRANSITIONS: u8 = u8::pow(2, Self::TRANSACTION_TREE_DEPTH as u32);
    const NUM_EVENTS: u16 = 2;

    const BLOCK_HASH_PREFIX: u16 = hrp2!("ab");
    const LEDGER_ROOT_PREFIX: u16 = hrp2!("al");
    const PROGRAM_ID_PREFIX: u16 = hrp2!("ap");
    const TRANSITION_ID_PREFIX: u16 = hrp2!("as");
    const TRANSACTION_ID_PREFIX: u16 = hrp2!("at");

    const COMMITMENT_PREFIX: u16 = hrp2!("cm");
    const FUNCTION_INPUTS_HASH_PREFIX: u16 = hrp2!("fi");
    const FUNCTION_ID_PREFIX: u16 = hrp2!("fn");
    const HEADER_NONCE_PREFIX: u16 = hrp2!("hn");
    const HEADER_ROOT_PREFIX: u16 = hrp2!("hr");
    const HEADER_TRANSACTIONS_ROOT_PREFIX: u16 = hrp2!("ht");
    const INNER_CIRCUIT_ID_PREFIX: u16 = hrp2!("ic");
    const RECORD_RANDOMIZER_PREFIX: u16 = hrp2!("rr");
    const RECORD_VIEW_KEY_COMMITMENT_PREFIX: u16 = hrp2!("rc");
    const SERIAL_NUMBER_PREFIX: u16 = hrp2!("sn");

    const HEADER_PROOF_PREFIX: u32 = hrp4!("hzkp");
    const INNER_PROOF_PREFIX: u32 = hrp4!("izkp");
    const PROGRAM_PROOF_PREFIX: u32 = hrp4!("pzkp");
    const RECORD_CIPHERTEXT_PREFIX: u32 = hrp4!("recd");
    const RECORD_VIEW_KEY_PREFIX: u32 = hrp4!("rcvk");
    const SIGNATURE_PREFIX: u32 = hrp4!("sign");
    const VALUE_COMMITMENT_PREFIX: u32 = hrp4!("valc");
    const VALUE_BALANCE_COMMITMENT_PREFIX: u32 = hrp4!("vbco");

    const ADDRESS_SIZE_IN_BYTES: usize = 32;
    const HEADER_SIZE_IN_BYTES: usize = 1015;
    const HEADER_PROOF_SIZE_IN_BYTES: usize = 883;
    const INNER_PROOF_SIZE_IN_BYTES: usize = 193;
    const PROGRAM_PROOF_SIZE_IN_BYTES: usize = 193;
    const PROGRAM_ID_SIZE_IN_BYTES: usize = 32;
    const RECORD_CIPHERTEXT_SIZE_IN_BYTES: usize = 294;
    const RECORD_PAYLOAD_SIZE_IN_BYTES: usize = 128;
    const RECORD_VIEW_KEY_SIZE_IN_BYTES: usize = 32;
    const SIGNATURE_SIZE_IN_BYTES: usize = 128;
    const VALUE_COMMITMENT_SIZE_IN_BYTES: usize = 64;
    const VALUE_BALANCE_COMMITMENT_SIZE_IN_BYTES: usize = 96;

    const HEADER_TRANSACTIONS_TREE_DEPTH: usize = 15;
    const HEADER_TREE_DEPTH: usize = 2;
    const LEDGER_TREE_DEPTH: usize = 32;
    const PROGRAM_TREE_DEPTH: usize = 8;
    const TRANSITION_TREE_DEPTH: usize = 2;
    const TRANSACTION_TREE_DEPTH: usize = 5;

    const ALEO_BLOCK_TIME_IN_SECS: i64 = 20i64;
    const ALEO_STARTING_SUPPLY_IN_CREDITS: i64 = 1_000_000_000;
    const ALEO_FUTURE_TIME_LIMIT_IN_SECS: i64 = 90;
    const ALEO_MAXIMUM_FORK_DEPTH: u32 = 4096;

    type InnerCurve = Bls12_377;
    type InnerScalarField = <Self::InnerCurve as PairingEngine>::Fr;
    type InnerBaseField = <Self::InnerCurve as PairingEngine>::Fq;

    type ProgramAffineCurve = EdwardsBls12Affine;
    type ProgramAffineCurveGadget = EdwardsBls12Gadget;
    type ProgramProjectiveCurve = EdwardsBls12Projective;
    type ProgramCurveParameters = EdwardsParameters;
    type ProgramScalarField = <Self::ProgramCurveParameters as ModelParameters>::ScalarField;

    type InnerSNARK = Groth16<Self::InnerCurve, InnerPublicVariables<Testnet1>>;
    type InnerProof = AleoObject<<Self::InnerSNARK as SNARK>::Proof, { Self::INNER_PROOF_PREFIX }, { Self::INNER_PROOF_SIZE_IN_BYTES }>;

    type ProgramSNARK = Groth16<Self::InnerCurve, ProgramPublicVariables<Self>>;
    type ProgramProvingKey = <Self::ProgramSNARK as SNARK>::ProvingKey;
    type ProgramVerifyingKey = <Self::ProgramSNARK as SNARK>::VerifyingKey;
    type ProgramProof = AleoObject<<Self::ProgramSNARK as SNARK>::Proof, { Self::PROGRAM_PROOF_PREFIX }, { Self::PROGRAM_PROOF_SIZE_IN_BYTES }>;

    type PoSWSNARK = MarlinSNARK<Self::InnerScalarField, Self::InnerBaseField, SonicKZG10<Self::InnerCurve>, FiatShamirAlgebraicSpongeRng<Self::InnerScalarField, Self::InnerBaseField, PoseidonSponge<Self::InnerBaseField, 6, 1>>, MarlinNonHidingMode, Vec<Self::InnerScalarField>>;
    type PoSWProof = AleoObject<<Self::PoSWSNARK as SNARK>::Proof, { Self::HEADER_PROOF_PREFIX }, { Self::HEADER_PROOF_SIZE_IN_BYTES }>;
    type PoSW = PoSW<Self>;

    type AccountEncryptionScheme = ECIESPoseidonEncryption<Self::ProgramCurveParameters>;
    type AccountEncryptionGadget = ECIESPoseidonEncryptionGadget<Self::ProgramCurveParameters, Self::InnerScalarField>;

    type AccountSeedPRF = PoseidonPRF<Self::ProgramScalarField, 4, false>;
    type AccountSeed = <Self::AccountSeedPRF as PRF>::Seed;
    
    type AccountSignatureScheme = AleoSignatureScheme<Self::ProgramCurveParameters>;
    type AccountSignatureGadget = AleoSignatureSchemeGadget<Self::ProgramCurveParameters, Self::InnerScalarField>;
    type AccountSignaturePublicKey = <Self::AccountSignatureScheme as SignatureScheme>::PublicKey;
    type AccountSignature = AleoObject<<Self::AccountSignatureScheme as SignatureScheme>::Signature, { Self::SIGNATURE_PREFIX }, { Self::SIGNATURE_SIZE_IN_BYTES }>;

    type BlockHashCRH = BHPCRH<Self::ProgramProjectiveCurve, 16, 32>;
    type BlockHashCRHGadget = BHPCRHGadget<Self::ProgramProjectiveCurve, Self::InnerScalarField, Self::ProgramAffineCurveGadget, 16, 32>;
    type BlockHash = AleoLocator<<Self::BlockHashCRH as CRH>::Output, { Self::BLOCK_HASH_PREFIX }>;

    type BlockHeaderRootCRH = PedersenCompressedCRH<Self::ProgramProjectiveCurve, 4, 128>;
    type BlockHeaderRootCRHGadget = PedersenCompressedCRHGadget<Self::ProgramProjectiveCurve, Self::InnerScalarField, Self::ProgramAffineCurveGadget, 4, 128>;
    type BlockHeaderRootParameters = MaskedMerkleTreeParameters<Self::BlockHeaderRootCRH, { Self::HEADER_TREE_DEPTH }>;
    type BlockHeaderRoot = AleoLocator<<Self::BlockHeaderRootCRH as CRH>::Output, { Self::HEADER_ROOT_PREFIX }>;

    type CommitmentScheme = BHPCRH<Self::ProgramProjectiveCurve, 41, 63>;
    type CommitmentGadget = BHPCRHGadget<Self::ProgramProjectiveCurve, Self::InnerScalarField, Self::ProgramAffineCurveGadget, 41, 63>;
    type Commitment = AleoLocator<<Self::CommitmentScheme as CRH>::Output, { Self::COMMITMENT_PREFIX }>;

    type FunctionIDCRH = PoseidonCRH<Self::InnerBaseField, 34>;
    type FunctionIDCRHGadget = PoseidonCRHGadget<Self::InnerBaseField, 34>;
    type FunctionID = AleoLocator<<Self::FunctionIDCRH as CRH>::Output, { Self::FUNCTION_ID_PREFIX }>;

    type FunctionInputsCRH = PoseidonCRH<Self::InnerScalarField, 128>;
    type FunctionInputsCRHGadget = PoseidonCRHGadget<Self::InnerScalarField, 128>;
    type FunctionInputsHash = AleoLocator<<Self::FunctionInputsCRH as CRH>::Output, { Self::FUNCTION_INPUTS_HASH_PREFIX }>;

    type InnerCircuitIDCRH = BHPCRH<EdwardsBW6, 175, 63>;
    type InnerCircuitID = AleoLocator<<Self::InnerCircuitIDCRH as CRH>::Output, { Self::INNER_CIRCUIT_ID_PREFIX }>;

    type LedgerRootCRH = BHPCRH<Self::ProgramProjectiveCurve, 16, 32>;
    type LedgerRootCRHGadget = BHPCRHGadget<Self::ProgramProjectiveCurve, Self::InnerScalarField, Self::ProgramAffineCurveGadget, 16, 32>;
    type LedgerRootParameters = MerkleTreeParameters<Self::LedgerRootCRH, { Self::LEDGER_TREE_DEPTH }>;
    type LedgerRoot = AleoLocator<<Self::LedgerRootCRH as CRH>::Output, { Self::LEDGER_ROOT_PREFIX }>;

    type PoSWMaskPRF = PoseidonPRF<Self::InnerScalarField, 4, false>;
    type PoSWMaskPRFGadget = PoseidonPRFGadget<Self::InnerScalarField, 4, false>;
    type PoSWNonce = AleoLocator<Self::InnerScalarField, { Self::HEADER_NONCE_PREFIX }>;

    type ProgramIDCRH = BHPCRH<Self::ProgramProjectiveCurve, 16, 48>;
    type ProgramIDParameters = MerkleTreeParameters<Self::ProgramIDCRH, { Self::PROGRAM_TREE_DEPTH }>;
    type ProgramID = AleoLocator<<Self::ProgramIDCRH as CRH>::Output, { Self::PROGRAM_ID_PREFIX }>;

    type RecordCiphertext = AleoObject<Ciphertext<Self>, { Self::RECORD_CIPHERTEXT_PREFIX }, { Self::RECORD_CIPHERTEXT_SIZE_IN_BYTES }>;
    type RecordRandomizer = AleoLocator<<Self::AccountEncryptionScheme as EncryptionScheme>::CiphertextRandomizer, { Self::RECORD_RANDOMIZER_PREFIX }>;
    type RecordViewKey = AleoObject<<Self::AccountEncryptionScheme as EncryptionScheme>::SymmetricKey, { Self::RECORD_VIEW_KEY_PREFIX }, { Self::RECORD_VIEW_KEY_SIZE_IN_BYTES }>;
    type RecordViewKeyCommitment = AleoLocator<<Self::AccountEncryptionScheme as EncryptionScheme>::SymmetricKeyCommitment, { Self::RECORD_VIEW_KEY_COMMITMENT_PREFIX }>;

    type SerialNumberPRF = PoseidonPRF<Self::InnerScalarField, 4, false>;
    type SerialNumberPRFGadget = PoseidonPRFGadget<Self::InnerScalarField, 4, false>;
    type SerialNumber = AleoLocator<<Self::SerialNumberPRF as PRF>::Output, { Self::SERIAL_NUMBER_PREFIX }>;

    type TransactionsRootCRH = BHPCRH<Self::ProgramProjectiveCurve, 16, 32>;
    type TransactionsRootCRHGadget = BHPCRHGadget<Self::ProgramProjectiveCurve, Self::InnerScalarField, Self::ProgramAffineCurveGadget, 16, 32>;
    type TransactionsRootParameters = MerkleTreeParameters<Self::TransactionsRootCRH, { Self::HEADER_TRANSACTIONS_TREE_DEPTH }>;
    type TransactionsRoot = AleoLocator<<Self::TransactionsRootCRH as CRH>::Output, { Self::HEADER_TRANSACTIONS_ROOT_PREFIX }>;

    type TransactionIDCRH = BHPCRH<Self::ProgramProjectiveCurve, 16, 32>;
    type TransactionIDCRHGadget = BHPCRHGadget<Self::ProgramProjectiveCurve, Self::InnerScalarField, Self::ProgramAffineCurveGadget, 16, 32>;
    type TransactionIDParameters = MerkleTreeParameters<Self::TransactionIDCRH, { Self::TRANSACTION_TREE_DEPTH }>;
    type TransactionID = AleoLocator<<Self::TransactionIDCRH as CRH>::Output, { Self::TRANSACTION_ID_PREFIX }>;

    type TransitionIDCRH = BHPCRH<Self::ProgramProjectiveCurve, 16, 32>;
    type TransitionIDCRHGadget = BHPCRHGadget<Self::ProgramProjectiveCurve, Self::InnerScalarField, Self::ProgramAffineCurveGadget, 16, 32>;
    type TransitionIDParameters = MerkleTreeParameters<Self::TransitionIDCRH, { Self::TRANSITION_TREE_DEPTH }>;
    type TransitionID = AleoLocator<<Self::TransitionIDCRH as CRH>::Output, { Self::TRANSITION_ID_PREFIX }>;

    type ValueCommitmentScheme = PedersenCommitment<Self::ProgramProjectiveCurve, 4, 32>;
    type ValueCommitmentGadget = PedersenCommitmentGadget<Self::ProgramProjectiveCurve, Self::InnerScalarField, Self::ProgramAffineCurveGadget, 4, 32>;
    type ValueCommitment = AleoObject<<Self::ValueCommitmentScheme as CommitmentScheme>::Output, { Self::VALUE_COMMITMENT_PREFIX }, { Self::VALUE_COMMITMENT_SIZE_IN_BYTES }>;
    type ValueBalanceCommitment = AleoObject<ValueBalanceCommitment<Self>, { Self::VALUE_BALANCE_COMMITMENT_PREFIX }, { Self::VALUE_BALANCE_COMMITMENT_SIZE_IN_BYTES }>;

    dpc_setup!{Testnet1, account_encryption_scheme, AccountEncryptionScheme, ACCOUNT_ENCRYPTION_AND_SIGNATURE_INPUT}
    dpc_setup!{Testnet1, account_signature_scheme, AccountSignatureScheme, ACCOUNT_ENCRYPTION_AND_SIGNATURE_INPUT}
    dpc_setup!{Testnet1, block_hash_crh, BlockHashCRH, "AleoBlockHashCRH0"}
    dpc_setup!{Testnet1, block_header_root_parameters, BlockHeaderRootParameters, "AleoBlockHeaderRootCRH0"}
    dpc_setup!{Testnet1, commitment_scheme, CommitmentScheme, "AleoCommitmentScheme0"}
    dpc_setup!{Testnet1, function_id_crh, FunctionIDCRH, "AleoFunctionIDCRH0"}
    dpc_setup!{Testnet1, inner_circuit_id_crh, InnerCircuitIDCRH, "AleoInnerCircuitIDCRH0"}
    dpc_setup!{Testnet1, ledger_root_parameters, LedgerRootParameters, "AleoLedgerRootCRH0"}
    dpc_setup!{Testnet1, program_id_parameters, ProgramIDParameters, "AleoProgramIDCRH0"}
    dpc_setup!{Testnet1, transactions_root_parameters, TransactionsRootParameters, "AleoTransactionsRootCRH0"}
    dpc_setup!{Testnet1, transaction_id_parameters, TransactionIDParameters, "AleoTransactionIDCRH0"}
    dpc_setup!{Testnet1, transition_id_parameters, TransitionIDParameters, "AleoTransitionIDCRH0"}
    dpc_setup!{Testnet1, value_commitment_scheme, ValueCommitmentScheme, "AleoValueCommitment0"}

    dpc_snark_setup!{Testnet1, inner_proving_key, InnerSNARK, ProvingKey, InnerProvingKeyBytes, "inner proving key"}
    dpc_snark_setup!{Testnet1, inner_verifying_key, InnerSNARK, VerifyingKey, InnerVerifyingKeyBytes, "inner verifying key"}

    dpc_snark_setup!{Testnet1, posw_proving_key, PoSWSNARK, ProvingKey, PoSWProvingKeyBytes, "posw proving key"}
    dpc_snark_setup!{Testnet1, posw_verifying_key, PoSWSNARK, VerifyingKey, PoSWVerifyingKeyBytes, "posw verifying key"}

    fn inner_circuit_id() -> &'static Self::InnerCircuitID {
        static INNER_CIRCUIT_ID: OnceCell<<Testnet1 as Network>::InnerCircuitID> = OnceCell::new();
        INNER_CIRCUIT_ID.get_or_init(|| Self::inner_circuit_id_crh()
            .hash_bits(&Self::inner_verifying_key().to_minimal_bits())
            .expect("Failed to hash inner circuit verifying key elements").into())
    }

    fn posw() -> &'static Self::PoSW {
        static POSW: OnceCell<<Testnet1 as Network>::PoSW> = OnceCell::new();
        POSW.get_or_init(|| <Self::PoSW as PoSWScheme<Self>>::load(true).expect("Failed to load PoSW"))        
    }

    fn genesis_block() -> &'static Block<Self> {
        static BLOCK: OnceCell<Block<Testnet1>> = OnceCell::new();
        BLOCK.get_or_init(|| FromBytes::read_le(&GenesisBlock::load_bytes()[..]).expect("Failed to load genesis block"))
    }

    /// Returns the program SRS for Aleo applications.
    fn program_srs<R: Rng + CryptoRng>(rng: &mut R) -> Rc<RefCell<SRS<R, <Self::ProgramSNARK as SNARK>::UniversalSetupParameters>>> {
        Rc::new(RefCell::new(SRS::CircuitSpecific(rng)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_name_sanity_check() {
        assert_eq!(Testnet1::NETWORK_NAME, "testnet1");
    }

    #[test]
    fn test_inner_circuit_sanity_check() {
        // Verify the inner circuit verifying key matches the one derived from the inner circuit proving key.
        assert_eq!(
            Testnet1::inner_verifying_key(),
            &Testnet1::inner_proving_key().vk,
            "The inner circuit verifying key does not correspond to the inner circuit proving key"
        );
    }

    #[test]
    fn test_inner_circuit_id_derivation() {
        // Verify the inner circuit ID matches the one derived from the inner circuit verifying key.
        assert_eq!(
            Testnet1::inner_circuit_id(),
            &Testnet1::inner_circuit_id_crh()
                .hash_bits(&Testnet1::inner_verifying_key().to_minimal_bits())
                .expect("Failed to hash inner circuit ID")
                .into(),
            "The inner circuit ID does not correspond to the inner circuit verifying key"
        );
    }

    #[test]
    fn test_posw_tree_sanity_check() {
        // Verify the PoSW tree depth matches the declared depth.
        assert_eq!(
            Testnet1::HEADER_TREE_DEPTH,
            <<Testnet1 as Network>::BlockHeaderRootParameters as MerkleParameters>::DEPTH
        );
    }
}
