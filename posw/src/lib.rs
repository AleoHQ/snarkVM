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

pub mod circuit;

mod posw;
use posw::{HG, M};

pub mod error;

use snarkvm_algorithms::snark;
use snarkvm_curves::{bls12_377::Bls12_377, traits::PairingEngine};
use snarkvm_dpc::block::{
    merkle_root_with_subroots,
    pedersen_merkle_root,
    MerkleRootHash,
    PedersenMerkleRootHash,
    MASKED_TREE_DEPTH,
};

/// GM17 type alias for the PoSW circuit
#[deprecated]
pub type GM17<E> = snark::gm17::GM17<E, PoswCircuit<<E as PairingEngine>::Fr>, Vec<<E as PairingEngine>::Fr>>;

/// PoSW instantiated over BLS12-377 with Marlin.
pub type PoswMarlin = Posw<Marlin<Bls12_377>, Bls12_377>;

/// Marlin proof system on PoSW
pub type Marlin<E> =
    snarkvm_marlin::snark::MarlinSystem<E, PoswCircuit<<E as PairingEngine>::Fr>, Vec<<E as PairingEngine>::Fr>>;

/// A generic PoSW.
pub type Posw<S, E> = posw::Posw<S, <E as PairingEngine>::Fr, M, HG, params::PoSWParams>;

/// Instantiate the circuit with the CRH to Fq.
type PoswCircuit<F> = circuit::POSWCircuit<F, M, HG, params::PoSWParams>;

// Do not leak private type
mod params {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct PoSWParams;
    impl crate::circuit::POSWCircuitParameters for PoSWParams {
        // A 32 byte mask is sufficient for Pedersen hashes on BLS12-377, leaves and the root
        const MASK_LENGTH: usize = 32;
    }
}

/// Subtree calculation
pub fn txids_to_roots(transaction_ids: &[[u8; 32]]) -> (MerkleRootHash, PedersenMerkleRootHash, Vec<[u8; 32]>) {
    let (root, subroots) = merkle_root_with_subroots(transaction_ids, MASKED_TREE_DEPTH);
    let mut merkle_root_bytes = [0u8; 32];
    merkle_root_bytes[..].copy_from_slice(&root);

    (
        MerkleRootHash(merkle_root_bytes),
        pedersen_merkle_root(&subroots),
        subroots,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_xorshift::XorShiftRng;
    use snarkvm_algorithms::traits::SNARK;
    use snarkvm_utilities::FromBytes;

    #[test]
    fn test_load_verify_only() {
        let _params = PoswMarlin::verify_only().unwrap();
    }

    #[test]
    fn test_load() {
        let _params = PoswMarlin::load().unwrap();
    }

    #[test]
    #[allow(deprecated)]
    fn test_posw_gm17() {
        let rng = &mut XorShiftRng::seed_from_u64(1234567);

        // PoSW instantiated over BLS12-377 with GM17.
        pub type PoswGM17 = Posw<GM17<Bls12_377>, Bls12_377>;

        // run the trusted setup
        let posw = PoswGM17::setup(rng).unwrap();
        // super low difficulty so we find a solution immediately
        let difficulty_target = 0xFFFF_FFFF_FFFF_FFFF_u64;

        let transaction_ids = vec![[1u8; 32]; 8];
        let (_, pedersen_merkle_root, subroots) = txids_to_roots(&transaction_ids);

        // generate the proof
        let (nonce, proof) = posw
            .mine(&subroots, difficulty_target, &mut rand::thread_rng(), std::u32::MAX)
            .unwrap();
        assert_eq!(proof.len(), 193); // NOTE: GM17 compressed serialization

        let proof = <GM17<Bls12_377> as SNARK>::Proof::read(&proof[..]).unwrap();
        posw.verify(nonce, &proof, &pedersen_merkle_root).unwrap();
    }

    #[test]
    fn test_posw_marlin() {
        let rng = &mut XorShiftRng::seed_from_u64(1234567);

        // run the trusted setup
        let universal_srs = snarkvm_marlin::MarlinTestnet1::universal_setup(10000, 10000, 100000, rng).unwrap();

        // run the deterministic setup
        let posw = PoswMarlin::index(universal_srs).unwrap();

        // super low difficulty so we find a solution immediately
        let difficulty_target = 0xFFFF_FFFF_FFFF_FFFF_u64;

        let transaction_ids = vec![[1u8; 32]; 8];
        let (_, pedersen_merkle_root, subroots) = txids_to_roots(&transaction_ids);

        // generate the proof
        let (nonce, proof) = posw
            .mine(&subroots, difficulty_target, &mut rand::thread_rng(), std::u32::MAX)
            .unwrap();

        assert_eq!(proof.len(), 972); // NOTE: Marlin proofs use compressed serialization

        let proof = <Marlin<Bls12_377> as SNARK>::Proof::read_le(&proof[..]).unwrap();
        posw.verify(nonce, &proof, &pedersen_merkle_root).unwrap();
    }
}
