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

use std::sync::Arc;

use blake2::{digest::Digest, Blake2s};

use snarkvm_algorithms::{
    crh::{BoweHopwoodPedersenCompressedCRH, PedersenCRH, PedersenCompressedCRH},
    define_masked_merkle_tree_parameters,
    merkle_tree::MerkleTree,
    traits::{MaskedMerkleParameters, MerkleParameters, CRH},
};
use snarkvm_curves::{bls12_377::Fr, edwards_bls12::EdwardsProjective};
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};
use snarkvm_utilities::ToBytes;

use crate::{
    algorithms::{
        crh::{BoweHopwoodPedersenCompressedCRHGadget, PedersenCRHGadget, PedersenCompressedCRHGadget},
        merkle_tree::*,
    },
    curves::edwards_bls12::EdwardsBls12Gadget,
    integers::uint::UInt8,
    traits::{
        algorithms::{CRHGadget, MaskedCRHGadget},
        alloc::AllocGadget,
        eq::EqGadget,
    },
};

const PEDERSEN_NUM_WINDOWS: usize = 256;
const PEDERSEN_WINDOW_SIZE: usize = 4;

const BHP_NUM_WINDOWS: usize = 32;
const BHP_WINDOW_SIZE: usize = 60;

fn generate_merkle_tree<P: MerkleParameters, F: PrimeField, HG: CRHGadget<P::H, F>>(
    leaves: &[[u8; 30]],
    use_bad_root: bool,
) {
    let parameters = P::default();
    let tree = MerkleTree::<P>::new(Arc::new(parameters.clone()), &leaves[..]).unwrap();
    let root = tree.root();
    let mut satisfied = true;
    for (i, leaf) in leaves.iter().enumerate() {
        let mut cs = TestConstraintSystem::<F>::new();
        let proof = tree.generate_proof(i, &leaf).unwrap();
        assert!(proof.verify(&root, &leaf).unwrap());

        // Allocate Merkle tree root
        let root = <HG as CRHGadget<_, _>>::OutputGadget::alloc(&mut cs.ns(|| format!("new_digest_{}", i)), || {
            if use_bad_root {
                Ok(<P::H as CRH>::Output::default())
            } else {
                Ok(root.clone())
            }
        })
        .unwrap();

        let constraints_from_digest = cs.num_constraints();
        println!("constraints from digest: {}", constraints_from_digest);

        // Allocate CRH
        let crh_parameters = HG::alloc(&mut cs.ns(|| format!("new_parameters_{}", i)), || {
            Ok(parameters.crh().clone())
        })
        .unwrap();

        let constraints_from_parameters = cs.num_constraints() - constraints_from_digest;
        println!("constraints from parameters: {}", constraints_from_parameters);

        // Allocate Leaf
        let leaf_g = UInt8::constant_vec(leaf);

        let constraints_from_leaf = cs.num_constraints() - constraints_from_parameters - constraints_from_digest;
        println!("constraints from leaf: {}", constraints_from_leaf);

        // Allocate Merkle tree path
        let cw =
            MerklePathGadget::<_, HG, _>::alloc(&mut cs.ns(|| format!("new_witness_{}", i)), || Ok(proof)).unwrap();

        let constraints_from_path =
            cs.num_constraints() - constraints_from_parameters - constraints_from_digest - constraints_from_leaf;
        println!("constraints from path: {}", constraints_from_path);
        let leaf_g: &[UInt8] = leaf_g.as_slice();
        cw.check_membership(
            &mut cs.ns(|| format!("new_witness_check_{}", i)),
            &crh_parameters,
            &root,
            &leaf_g,
        )
        .unwrap();
        if !cs.is_satisfied() {
            satisfied = false;
            println!("Unsatisfied constraint: {}", cs.which_is_unsatisfied().unwrap());
        }
        let setup_constraints =
            constraints_from_leaf + constraints_from_digest + constraints_from_parameters + constraints_from_path;
        println!("number of constraints: {}", cs.num_constraints() - setup_constraints);
    }

    assert!(satisfied);
}

fn generate_masked_merkle_tree<P: MaskedMerkleParameters, F: PrimeField, HG: MaskedCRHGadget<P::H, F>>(
    leaves: &[[u8; 30]],
    use_bad_root: bool,
) {
    let parameters = P::default();
    let tree = MerkleTree::<P>::new(Arc::new(parameters.clone()), &leaves[..]).unwrap();
    let root = tree.root();

    let mut cs = TestConstraintSystem::<F>::new();
    let leaf_gadgets = tree
        .hashed_leaves()
        .iter()
        .enumerate()
        .map(|(i, l)| <HG as CRHGadget<_, _>>::OutputGadget::alloc(cs.ns(|| format!("leaf {}", i)), || Ok(l)))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let nonce: [u8; 4] = rand::random();
    let mut root_bytes = [0u8; 32];
    root.write_le(&mut root_bytes[..]).unwrap();

    let mut h = Blake2s::new();
    h.update(nonce.as_ref());
    h.update(&root_bytes);
    let mask = h.finalize().to_vec();
    let mask_bytes = UInt8::alloc_vec(cs.ns(|| "mask"), &mask).unwrap();

    let crh_parameters = HG::alloc(&mut cs.ns(|| "new_parameters"), || Ok(parameters.crh().clone())).unwrap();

    let mask_crh_parameters =
        <HG as MaskedCRHGadget<_, _>>::MaskParametersGadget::alloc(&mut cs.ns(|| "new_mask_parameters"), || {
            Ok(parameters.mask_parameters().clone())
        })
        .unwrap();

    let computed_root = compute_root::<_, HG, _, _, _>(
        cs.ns(|| "compute masked root"),
        &crh_parameters,
        &mask_crh_parameters,
        &mask_bytes,
        &leaf_gadgets,
    )
    .unwrap();

    let given_root = if use_bad_root {
        <P::H as CRH>::Output::default()
    } else {
        root
    };

    let given_root_gadget =
        <HG as CRHGadget<_, _>>::OutputGadget::alloc(&mut cs.ns(|| "given root"), || Ok(given_root)).unwrap();

    computed_root
        .enforce_equal(
            &mut cs.ns(|| "Check that computed root matches provided root"),
            &given_root_gadget,
        )
        .unwrap();

    if !cs.is_satisfied() {
        println!("Unsatisfied constraint: {}", cs.which_is_unsatisfied().unwrap());
    }
    assert!(cs.is_satisfied());
}

fn update_merkle_tree<P: MerkleParameters, F: PrimeField, HG: CRHGadget<P::H, F>>(leaves: &[[u8; 30]]) {
    let merkle_parameters = Arc::new(P::default());
    let tree = MerkleTree::<P>::new(merkle_parameters.clone(), &leaves[..]).unwrap();
    let root = tree.root();

    let mut satisfied = true;
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.generate_proof(i, &leaf).unwrap();
        assert!(proof.verify(&root, &leaf).unwrap());

        let mut updated_leaves = leaves.to_vec();
        updated_leaves[i] = [u8::MAX; 30];

        let new_tree = MerkleTree::<P>::new(merkle_parameters.clone(), &updated_leaves[..]).unwrap();
        let new_proof = new_tree.generate_proof(i, &updated_leaves[i]).unwrap();
        let new_root = new_tree.root();

        assert!(new_proof.verify(&new_root, &updated_leaves[i]).unwrap());

        let mut cs = TestConstraintSystem::<F>::new();

        let crh = HG::alloc(&mut cs.ns(|| "crh"), || Ok(merkle_parameters.crh())).unwrap();

        // Allocate Merkle tree root
        let root = <HG as CRHGadget<_, _>>::OutputGadget::alloc(&mut cs.ns(|| "root"), || Ok(root.clone())).unwrap();

        // Allocate new Merkle tree root
        let new_root =
            <HG as CRHGadget<_, _>>::OutputGadget::alloc(&mut cs.ns(|| "new_root"), || Ok(new_root.clone())).unwrap();

        let path = MerklePathGadget::<_, HG, _>::alloc(&mut cs.ns(|| "path"), || Ok(proof)).unwrap();

        let leaf_gadget = UInt8::alloc_vec(cs.ns(|| "alloc_leaf"), &leaves[i]).unwrap();
        let new_leaf_gadget = UInt8::alloc_vec(cs.ns(|| "alloc_new_leaf"), &updated_leaves[i]).unwrap();

        path.update_and_check(
            cs.ns(|| "update_and_check"),
            &crh,
            &root,
            &new_root,
            &leaf_gadget,
            &new_leaf_gadget,
        )
        .unwrap();

        if !cs.is_satisfied() {
            satisfied = false;
            println!("Unsatisfied constraint: {}", cs.which_is_unsatisfied().unwrap());
        }
    }

    assert!(satisfied);
}

mod merkle_tree_pedersen_crh_on_projective {
    use super::*;

    define_masked_merkle_tree_parameters!(EdwardsMerkleParameters, H, 4);

    type H = PedersenCRH<EdwardsProjective, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>;
    type HG = PedersenCRHGadget<EdwardsProjective, Fr, EdwardsBls12Gadget, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>;

    #[test]
    fn good_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, false);
    }

    #[should_panic]
    #[test]
    fn bad_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, true);
    }

    #[test]
    fn update_merkle_tree_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        update_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves);
    }
}

mod merkle_tree_compressed_pedersen_crh_on_projective {
    use super::*;

    define_masked_merkle_tree_parameters!(EdwardsMerkleParameters, H, 4);

    type H = PedersenCompressedCRH<EdwardsProjective, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>;
    type HG = PedersenCompressedCRHGadget<
        EdwardsProjective,
        Fr,
        EdwardsBls12Gadget,
        PEDERSEN_NUM_WINDOWS,
        PEDERSEN_WINDOW_SIZE,
    >;

    #[test]
    fn good_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, false);
    }

    #[should_panic]
    #[test]
    fn bad_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, true);
    }

    #[test]
    fn good_masked_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_masked_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, false);
    }

    #[should_panic]
    #[test]
    fn bad_masked_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_masked_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, true);
    }

    #[test]
    fn update_merkle_tree_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        update_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves);
    }
}

mod merkle_tree_bowe_hopwood_pedersen_compressed_crh_on_projective {
    use super::*;

    define_masked_merkle_tree_parameters!(EdwardsMerkleParameters, H, 4);

    type H = BoweHopwoodPedersenCompressedCRH<EdwardsProjective, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>;
    type HG = BoweHopwoodPedersenCompressedCRHGadget<
        EdwardsProjective,
        Fr,
        EdwardsBls12Gadget,
        BHP_NUM_WINDOWS,
        BHP_WINDOW_SIZE,
    >;

    #[test]
    fn good_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, false);
    }

    #[should_panic]
    #[test]
    fn bad_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, true);
    }

    #[test]
    fn update_merkle_tree_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        update_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves);
    }
}

mod merkle_tree_poseidon {
    use super::*;
    use crate::algorithms::crypto_hash::PoseidonCryptoHashGadget;
    use snarkvm_algorithms::crypto_hash::PoseidonCryptoHash;

    define_masked_merkle_tree_parameters!(EdwardsMerkleParameters, H, 4);

    type H = PoseidonCryptoHash<Fr, 4, false>;
    type HG = PoseidonCryptoHashGadget<Fr, 4, false>;

    #[test]
    fn good_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, false);
    }

    #[should_panic]
    #[test]
    fn bad_root_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        generate_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves, true);
    }

    #[test]
    fn update_merkle_tree_test() {
        let mut leaves = Vec::new();
        for i in 0..1 << EdwardsMerkleParameters::DEPTH {
            let input = [i; 30];
            leaves.push(input);
        }
        update_merkle_tree::<EdwardsMerkleParameters, Fr, HG>(&leaves);
    }
}
