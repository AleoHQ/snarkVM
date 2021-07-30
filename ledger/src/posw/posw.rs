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

//! Generic PoSW Miner and Verifier, compatible with any implementer of the SNARK trait.

use crate::{
    block::{
        pedersen_merkle_tree::{pedersen_merkle_root_hash_with_leaves, PedersenMerkleRootHash, PARAMS},
        MaskedMerkleTreeParameters,
    },
    posw::circuit::POSWCircuit,
    PoswError,
};
use snarkvm_algorithms::{
    crh::sha256d_to_u64,
    traits::{MaskedMerkleParameters, SNARK},
    SRS,
};
use snarkvm_curves::{
    bls12_377::Fr,
    edwards_bls12::{EdwardsProjective, Fq},
    traits::PairingEngine,
};
use snarkvm_fields::{PrimeField, ToConstraintField};
use snarkvm_gadgets::{
    algorithms::crh::PedersenCompressedCRHGadget,
    curves::edwards_bls12::EdwardsBls12Gadget,
    traits::algorithms::MaskedCRHGadget,
};
use snarkvm_marlin::snark::MarlinSRS;
use snarkvm_parameters::{
    testnet1::{PoswSNARKPKParameters, PoswSNARKVKParameters},
    traits::Parameter,
};
use snarkvm_profiler::{end_timer, start_timer};
use snarkvm_utilities::{to_bytes_le, FromBytes, ToBytes};

use blake2::{digest::Digest, Blake2s};
use rand::{CryptoRng, Rng};
use std::marker::PhantomData;

/// TODO (howardwu): Deprecate this function and use the implementation in `snarkvm-algorithms`.
/// Commits to the nonce and pedersen merkle root.
fn commit(nonce: u32, root: &PedersenMerkleRootHash) -> Vec<u8> {
    let mut h = Blake2s::new();
    h.update(&nonce.to_le_bytes());
    h.update(root.0.as_ref());
    h.finalize().to_vec()
}

// We need to instantiate the Merkle tree and the Gadget, but these should not be
// proving system specific.
pub(crate) type M = MaskedMerkleTreeParameters;
pub(crate) type HG = PedersenCompressedCRHGadget<EdwardsProjective, Fq, EdwardsBls12Gadget, 4, 128>;

/// A Proof of Succinct Work miner and verifier
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posw<
    S: SNARK,
    F: PrimeField,
    M: MaskedMerkleParameters,
    HG: MaskedCRHGadget<M::H, F>,
    const MASK_NUM_BYTES: usize,
> {
    /// The proving key. If not provided, the PoSW runner will work in verify-only
    /// mode and the `mine` function will panic.
    pub pk: Option<S::ProvingKey>,

    /// The (prepared) verifying key.
    pub vk: S::VerifyingKey,

    _circuit: PhantomData<POSWCircuit<F, M, HG, MASK_NUM_BYTES>>,
}

impl<S: SNARK<ScalarField = Fr, VerifierInput = Vec<Fr>>, const MASK_NUM_BYTES: usize>
    Posw<S, Fr, M, HG, MASK_NUM_BYTES>
{
    /// Loads the PoSW runner from the locally stored parameters.
    pub fn verify_only() -> Result<Self, PoswError> {
        let params = PoswSNARKVKParameters::load_bytes()?;
        let vk = S::VerifyingKey::read_le(&params[..])?;

        Ok(Self {
            pk: None,
            vk: vk.into(),
            _circuit: PhantomData,
        })
    }

    /// Loads the PoSW runner from the locally stored parameters.
    pub fn load() -> Result<Self, PoswError> {
        let vk = S::VerifyingKey::read_le(&PoswSNARKVKParameters::load_bytes()?[..])?;
        let pk = S::ProvingKey::read_le(&PoswSNARKPKParameters::load_bytes()?[..])?;

        Ok(Self {
            pk: Some(pk),
            vk: vk.into(),
            _circuit: PhantomData,
        })
    }

    /// Creates a POSW circuit from the provided transaction ids and nonce.
    fn circuit_from(nonce: u32, leaves: &[[u8; 32]]) -> POSWCircuit<Fr, M, HG, MASK_NUM_BYTES> {
        let (root, leaves) = pedersen_merkle_root_hash_with_leaves(leaves);

        // Generate the mask by committing to the nonce and the root
        let mask = commit(nonce, &root.into());

        // Convert the leaves to Options for the SNARK
        let leaves = leaves.into_iter().map(Some).collect();

        POSWCircuit {
            leaves,
            merkle_parameters: PARAMS.clone(),
            mask: Some(mask),
            root: Some(root),
            field_type: PhantomData,
            crh_gadget_type: PhantomData,
        }
    }

    /// Hashes the proof and checks it against the difficulty
    fn check_difficulty(&self, proof: &[u8], difficulty_target: u64) -> bool {
        let hash_result = sha256d_to_u64(proof);
        hash_result <= difficulty_target
    }

    /// Performs a trusted setup for the PoSW circuit and returns an instance of the runner
    // TODO (howardwu): Find a workaround to keeping this method disabled.
    //  We need this method for benchmarking currently. There are two options:
    //  (1) Remove the benchmark for GM17 (since it is outdated anyways)
    //  (2) Update `Posw::setup` to take in an `OptionalRng` and account for the universal setup.
    // #[cfg(any(test, feature = "test-helpers"))]
    #[deprecated]
    pub fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self, PoswError>
    where
        S: SNARK,
    {
        let params = S::setup(
            &POSWCircuit::<Fr, M, HG, MASK_NUM_BYTES> {
                // the circuit will be padded internally
                leaves: vec![None; 0],
                merkle_parameters: PARAMS.clone(),
                mask: None,
                root: None,
                field_type: PhantomData,
                crh_gadget_type: PhantomData,
            },
            &mut SRS::CircuitSpecific(rng),
        )?;

        Ok(Self {
            pk: Some(params.0),
            vk: params.1,
            _circuit: PhantomData,
        })
    }

    /// Performs a deterministic setup for systems with universal setups
    pub fn index<E, R: Rng + CryptoRng>(srs: MarlinSRS<E>) -> Result<Self, PoswError>
    where
        E: PairingEngine,
        S: SNARK<UniversalSetupParameters = MarlinSRS<E>>,
    {
        let params = S::setup::<_, R>(
            &POSWCircuit::<Fr, M, HG, MASK_NUM_BYTES> {
                // the circuit will be padded internally
                leaves: vec![None; 0],
                merkle_parameters: PARAMS.clone(),
                mask: None,
                root: None,
                field_type: PhantomData,
                crh_gadget_type: PhantomData,
            },
            &mut SRS::<R, _>::Universal(srs),
        )?;

        Ok(Self {
            pk: Some(params.0),
            vk: params.1,
            _circuit: PhantomData,
        })
    }

    /// Given the subroots of the block, it will calculate a POSW and a nonce such that they are
    /// under the difficulty target. These can then be used in the block header's field.
    pub fn mine<R: Rng + CryptoRng>(
        &self,
        subroots: &[[u8; 32]],
        difficulty_target: u64, // TODO: Change to Bignum?
        rng: &mut R,
        max_nonce: u32,
    ) -> Result<(u32, Vec<u8>), PoswError> {
        let pk = self.pk.as_ref().expect("tried to mine without a PK set up");

        let mut nonce;
        let mut proof;
        let mut serialized_proof;
        loop {
            nonce = rng.gen_range(0..max_nonce);
            proof = Self::prove(&pk, nonce, subroots, rng)?;

            serialized_proof = to_bytes_le!(proof)?;
            if self.check_difficulty(&serialized_proof, difficulty_target) {
                break;
            }
        }

        Ok((nonce, serialized_proof))
    }

    /// Runs the internal SNARK `prove` function on the POSW circuit and returns
    /// the proof serialized as bytes
    fn prove<R: Rng + CryptoRng>(
        pk: &S::ProvingKey,
        nonce: u32,
        subroots: &[[u8; 32]],
        rng: &mut R,
    ) -> Result<S::Proof, PoswError> {
        // instantiate the circuit with the nonce
        let circuit = Self::circuit_from(nonce, subroots);

        // generate the proof
        let proof_timer = start_timer!(|| "POSW proof");
        let proof = S::prove(pk, &circuit, rng)?;
        end_timer!(proof_timer);

        Ok(proof)
    }

    /// Verifies the Proof of Succinct Work against the nonce and pedersen merkle
    /// root hash (produced by running a pedersen hash over the roots of the subtrees
    /// created by the block's transaction ids)
    pub fn verify(
        &self,
        nonce: u32,
        proof: &S::Proof,
        pedersen_merkle_root: &PedersenMerkleRootHash,
    ) -> Result<(), PoswError> {
        // commit to it and the nonce
        let mask = commit(nonce, pedersen_merkle_root);

        // get the mask and the root in public inputs format
        let merkle_root = Fr::read_le(&pedersen_merkle_root.0[..])?;
        let inputs = [mask.to_field_elements()?, vec![merkle_root]].concat();

        let res = S::verify(&self.vk, &inputs, &proof)?;
        if !res {
            return Err(PoswError::PoswVerificationFailed);
        }

        Ok(())
    }
}
