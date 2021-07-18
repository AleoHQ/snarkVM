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
    crh::{PedersenCRH, PedersenCompressedCRH},
    define_merkle_tree_parameters,
    merkle_tree::MerkleTree,
    traits::{crh::CRH, merkle_tree::LoadableMerkleParameters},
};
use snarkvm_utilities::{to_bytes_le, ToBytes};

use std::sync::Arc;

/// Generates a valid Merkle tree and verifies the Merkle path witness for each leaf.
fn generate_merkle_tree<P: LoadableMerkleParameters, L: ToBytes + Send + Sync + Clone + Eq>(
    leaves: &[L],
    parameters: &P,
) -> MerkleTree<P> {
    let tree = MerkleTree::<P>::new(Arc::new(parameters.clone()), &leaves[..]).unwrap();
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.generate_proof(i, &leaf).unwrap();
        assert_eq!(P::DEPTH, proof.path.len());
        assert!(proof.verify(&tree.root(), &leaf).unwrap());
    }
    tree
}

/// Generates a valid Merkle tree and verifies the Merkle path witness for each leaf does not verify to an invalid root hash.
fn bad_merkle_tree_verify<P: LoadableMerkleParameters, L: ToBytes + Send + Sync + Clone + Eq>(
    leaves: &[L],
    parameters: &P,
) {
    let tree = MerkleTree::<P>::new(Arc::new(parameters.clone()), &leaves[..]).unwrap();
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.generate_proof(i, &leaf).unwrap();
        assert!(proof.verify(&<P::H as CRH>::Output::default(), &leaf).unwrap());
    }
}

fn run_empty_merkle_tree_test<P: LoadableMerkleParameters>() {
    let parameters = &P::default();
    generate_merkle_tree::<P, Vec<u8>>(&[], parameters);
}

fn run_good_root_test<P: LoadableMerkleParameters>() {
    let parameters = &P::default();

    let mut leaves = vec![];
    for i in 0..4u8 {
        leaves.push([i, i, i, i, i, i, i, i]);
    }
    generate_merkle_tree::<P, _>(&leaves, parameters);

    let mut leaves = vec![];
    for i in 0..15u8 {
        leaves.push([i, i, i, i, i, i, i, i]);
    }
    generate_merkle_tree::<P, _>(&leaves, parameters);
}

fn run_bad_root_test<P: LoadableMerkleParameters>() {
    let parameters = &P::default();

    let mut leaves = vec![];
    for i in 0..4u8 {
        leaves.push([i, i, i, i, i, i, i, i]);
    }
    generate_merkle_tree::<P, _>(&leaves, parameters);

    let mut leaves = vec![];
    for i in 0..15u8 {
        leaves.push([i, i, i, i, i, i, i, i]);
    }
    bad_merkle_tree_verify::<P, _>(&leaves, parameters);
}

fn run_merkle_tree_matches_hashing_test<P: LoadableMerkleParameters>() {
    let parameters = &P::default();

    // Evaluate the Merkle tree root

    let mut leaves = Vec::new();
    for i in 0..4u8 {
        let input = [i; 64];
        leaves.push(input.to_vec());
    }
    let merkle_tree = generate_merkle_tree(&leaves, parameters);
    let merkle_tree_root = merkle_tree.root();

    // Evaluate the root by direct hashing

    let pedersen = &P::crh(parameters);

    // depth 2
    let leaf1 = pedersen.hash(&leaves[0]).unwrap();
    let leaf2 = pedersen.hash(&leaves[1]).unwrap();
    let leaf3 = pedersen.hash(&leaves[2]).unwrap();
    let leaf4 = pedersen.hash(&leaves[3]).unwrap();

    // depth 1
    let left = pedersen.hash(&to_bytes_le![leaf1, leaf2].unwrap()).unwrap();
    let right = pedersen.hash(&to_bytes_le![leaf3, leaf4].unwrap()).unwrap();

    // depth 0
    let expected_root = pedersen.hash(&to_bytes_le![left, right].unwrap()).unwrap();

    println!(
        "merkle_root == expected_root\n\t{} == {}",
        merkle_tree.root(),
        expected_root
    );
    assert_eq!(merkle_tree_root, expected_root);
}

fn run_padded_merkle_tree_matches_hashing_test<P: LoadableMerkleParameters>() {
    let parameters = &P::default();

    // Evaluate the Merkle tree root

    let mut leaves = Vec::new();
    for i in 0..4u8 {
        let input = [i; 64];
        leaves.push(input.to_vec());
    }
    let merkle_tree = generate_merkle_tree(&leaves, parameters);
    let merkle_tree_root = merkle_tree.root();

    // Evaluate the root by direct hashing

    let pedersen = &P::crh(parameters);

    // depth 3
    let leaf1 = pedersen.hash(&leaves[0]).unwrap();
    let leaf2 = pedersen.hash(&leaves[1]).unwrap();
    let leaf3 = pedersen.hash(&leaves[2]).unwrap();
    let leaf4 = pedersen.hash(&leaves[3]).unwrap();

    // depth 2
    let left = pedersen.hash(&to_bytes_le![leaf1, leaf2].unwrap()).unwrap();
    let right = pedersen.hash(&to_bytes_le![leaf3, leaf4].unwrap()).unwrap();

    // depth 1
    let penultimate_left = pedersen.hash(&to_bytes_le![left, right].unwrap()).unwrap();
    let penultimate_right = parameters.hash_empty().unwrap();

    // depth 0
    let expected_root = pedersen
        .hash(&to_bytes_le![penultimate_left, penultimate_right].unwrap())
        .unwrap();

    println!(
        "merkle_root == expected_root\n\t{} == {}",
        merkle_tree.root(),
        expected_root
    );
    assert_eq!(merkle_tree_root, expected_root);
}

mod pedersen_crh_on_projective {
    use super::*;
    use snarkvm_curves::edwards_bls12::EdwardsProjective as Edwards;

    const NUM_WINDOWS: usize = 256;
    const WINDOW_SIZE: usize = 4;

    #[test]
    fn empty_merkle_tree_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 32);
        run_empty_merkle_tree_test::<MTParameters>();
    }

    #[test]
    fn good_root_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 32);
        run_good_root_test::<MTParameters>();
    }

    #[should_panic]
    #[test]
    fn bad_root_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 32);
        run_bad_root_test::<MTParameters>();
    }

    // TODO (howardwu): Debug why PedersenCRH fails and make this test pass.
    #[ignore]
    #[test]
    fn depth2_merkle_tree_matches_hashing_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 2);
        run_merkle_tree_matches_hashing_test::<MTParameters>();
    }

    // TODO (howardwu): Debug why PedersenCRH fails and make this test pass.
    #[ignore]
    #[test]
    fn depth3_padded_merkle_tree_matches_hashing_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 3);
        run_padded_merkle_tree_matches_hashing_test::<MTParameters>();
    }
}

mod pedersen_compressed_crh_on_projective {
    use super::*;
    use snarkvm_curves::edwards_bls12::EdwardsProjective as Edwards;

    const NUM_WINDOWS: usize = 256;
    const WINDOW_SIZE: usize = 4;

    #[test]
    fn empty_merkle_tree_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCompressedCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 32);
        run_empty_merkle_tree_test::<MTParameters>();
    }

    #[test]
    fn good_root_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCompressedCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 32);
        run_good_root_test::<MTParameters>();
    }

    #[should_panic]
    #[test]
    fn bad_root_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCompressedCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 32);
        run_bad_root_test::<MTParameters>();
    }

    #[test]
    fn depth2_merkle_tree_matches_hashing_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCompressedCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 2);
        run_merkle_tree_matches_hashing_test::<MTParameters>();
    }

    #[test]
    fn depth3_padded_merkle_tree_matches_hashing_test() {
        define_merkle_tree_parameters!(MTParameters, PedersenCompressedCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 3);
        run_padded_merkle_tree_matches_hashing_test::<MTParameters>();
    }
}
