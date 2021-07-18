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
    commitment::PedersenCompressedCommitment,
    commitment_tree::*,
    crh::BoweHopwoodPedersenCompressedCRH,
    traits::{CommitmentScheme, CRH},
};
use snarkvm_curves::edwards_bls12::EdwardsProjective as EdwardsBls;
use snarkvm_utilities::{rand::UniformRand, FromBytes, ToBytes};

use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

const CRH_NUM_WINDOWS: usize = 16;
const CRH_WINDOW_SIZE: usize = 32;

const COMMITMENT_NUM_WINDOWS: usize = 8;
const COMMITMENT_WINDOW_SIZE: usize = 32;

pub type H = BoweHopwoodPedersenCompressedCRH<EdwardsBls, CRH_NUM_WINDOWS, CRH_WINDOW_SIZE>;
pub type C = PedersenCompressedCommitment<EdwardsBls, COMMITMENT_NUM_WINDOWS, COMMITMENT_WINDOW_SIZE>;
pub type CM = CommitmentMerklePath<C, H>;

/// Generates a valid Merkle tree and verifies the Merkle path witness for each leaf.
fn generate_merkle_tree<C: CommitmentScheme, H: CRH, R: Rng>(
    commitment: &C,
    crh: &H,
    rng: &mut R,
) -> CommitmentMerkleTree<C, H> {
    let default = <C as CommitmentScheme>::Output::default();
    let mut leaves = [default.clone(), default.clone(), default.clone(), default];

    for leaf in &mut leaves {
        let leaf_input: [u8; 32] = rng.gen();
        let randomness = <C as CommitmentScheme>::Randomness::rand(rng);

        *leaf = commitment.commit(&leaf_input, &randomness).unwrap();
    }

    CommitmentMerkleTree::new(crh.clone(), &leaves).unwrap()
}

#[test]
fn commitment_tree_good_root_test() {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);

    let commitment = C::setup("a");
    let crh = H::setup("b");

    let merkle_tree = generate_merkle_tree(&commitment, &crh, rng);

    for leaf in merkle_tree.leaves().iter() {
        let proof = merkle_tree.generate_proof(&leaf).unwrap();
        assert!(proof.verify(&crh, &merkle_tree.root(), &leaf).unwrap());
    }
}

#[should_panic]
#[test]
fn commitment_tree_bad_root_test() {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);

    let commitment = C::setup("a");
    let crh = H::setup("b");

    let merkle_tree = generate_merkle_tree(&commitment, &crh, rng);

    for leaf in merkle_tree.leaves().iter() {
        let proof = merkle_tree.generate_proof(&leaf).unwrap();
        assert!(proof.verify(&crh, &<H as CRH>::Output::default(), &leaf).unwrap());
    }
}

#[test]
fn test_serialize_commitment_merkle_tree() {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);

    let commitment = C::setup("a");
    let crh = H::setup("b");

    let merkle_tree = generate_merkle_tree(&commitment, &crh, rng);

    let merkle_tree_bytes = merkle_tree.to_bytes_le().unwrap();
    let recovered_merkle_tree = CommitmentMerkleTree::<C, H>::from_bytes(&merkle_tree_bytes[..], crh).unwrap();

    assert!(merkle_tree == recovered_merkle_tree);
}

#[test]
fn test_serialize_commitment_path() {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);

    let commitment = C::setup("a");
    let crh = H::setup("b");

    let merkle_tree = generate_merkle_tree(&commitment, &crh, rng);

    for leaf in merkle_tree.leaves().iter() {
        let proof = merkle_tree.generate_proof(&leaf).unwrap();

        let proof_bytes = proof.to_bytes_le().unwrap();
        let recovered_proof = CM::read_le(&proof_bytes[..]).unwrap();

        assert!(proof == recovered_proof);
        assert!(recovered_proof.verify(&crh, &merkle_tree.root(), &leaf).unwrap());
    }
}
