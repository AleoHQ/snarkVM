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

use rand::{Rng, SeedableRng};
use rand_xorshift::XorShiftRng;

use snarkvm_algorithms::{
    commitment::PedersenCompressedCommitment,
    commitment_tree::*,
    crh::BoweHopwoodPedersenCompressedCRH,
    traits::{CommitmentScheme, CRH},
};
use snarkvm_curves::{bls12_377::Fr, edwards_bls12::EdwardsProjective as EdwardsBls};
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};
use snarkvm_utilities::rand::UniformRand;

use crate::{
    algorithms::{
        commitment::PedersenCompressedCommitmentGadget,
        commitment_tree::*,
        crh::BoweHopwoodPedersenCompressedCRHGadget,
    },
    curves::edwards_bls12::EdwardsBls12Gadget,
    traits::{
        algorithms::{CRHGadget, CommitmentGadget},
        alloc::AllocGadget,
    },
};

const CRH_NUM_WINDOWS: usize = 16;
const CRH_WINDOW_SIZE: usize = 32;

const COMMITMENT_NUM_WINDOWS: usize = 8;
const COMMITMENT_WINDOW_SIZE: usize = 32;

pub type H = BoweHopwoodPedersenCompressedCRH<EdwardsBls, CRH_NUM_WINDOWS, CRH_WINDOW_SIZE>;
pub type HG =
    BoweHopwoodPedersenCompressedCRHGadget<EdwardsBls, Fr, EdwardsBls12Gadget, CRH_NUM_WINDOWS, CRH_WINDOW_SIZE>;

pub type C = PedersenCompressedCommitment<EdwardsBls, COMMITMENT_NUM_WINDOWS, COMMITMENT_WINDOW_SIZE>;
pub type CG = PedersenCompressedCommitmentGadget<
    EdwardsBls,
    Fr,
    EdwardsBls12Gadget,
    COMMITMENT_NUM_WINDOWS,
    COMMITMENT_WINDOW_SIZE,
>;

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

fn commitment_tree_test<
    C: CommitmentScheme,
    H: CRH,
    CG: CommitmentGadget<C, F>,
    HG: CRHGadget<H, F>,
    F: PrimeField,
    R: Rng,
>(
    use_bad_root: bool,
    setup_message: &str,
    rng: &mut R,
) {
    let commitment = C::setup(&format!("{} for commitment", setup_message));
    let crh = H::setup(&format!("{} for crh", setup_message));

    let merkle_tree = generate_merkle_tree(&commitment, &crh, rng);

    let mut satisfied = true;
    for (i, leaf) in merkle_tree.leaves().iter().enumerate() {
        let proof = merkle_tree.generate_proof(&leaf).unwrap();
        assert!(proof.verify(&crh, &merkle_tree.root(), &leaf).unwrap());

        let mut num_constraints = 0;

        let mut cs = TestConstraintSystem::<F>::new();

        // Allocate Merkle tree root
        let root_gadget =
            <HG as CRHGadget<H, _>>::OutputGadget::alloc(&mut cs.ns(|| format!("new_root_{}", i)), || {
                if use_bad_root {
                    Ok(<H as CRH>::Output::default())
                } else {
                    Ok(merkle_tree.root())
                }
            })
            .unwrap();

        println!("constraints from root: {}", cs.num_constraints() - num_constraints);
        num_constraints = cs.num_constraints();

        // Allocate CRH
        let crh_parameters = HG::alloc(&mut cs.ns(|| format!("new_crh_parameters_{}", i)), || Ok(crh.clone())).unwrap();

        println!(
            "constraints from crh parameters: {}",
            cs.num_constraints() - num_constraints
        );
        num_constraints = cs.num_constraints();

        // Allocate Leaf
        let leaf_gadget =
            <CG as CommitmentGadget<_, _>>::OutputGadget::alloc(&mut cs.ns(|| format!("leaf_{}", i)), || Ok(leaf))
                .unwrap();

        println!("constraints from leaf: {}", cs.num_constraints() - num_constraints);
        num_constraints = cs.num_constraints();

        // Allocate Merkle tree path
        let commitment_witness =
            CommitmentMerklePathGadget::<_, _, CG, HG, _>::alloc(&mut cs.ns(|| format!("new_witness_{}", i)), || {
                Ok(proof)
            })
            .unwrap();

        println!("constraints from path: {}", cs.num_constraints() - num_constraints);
        num_constraints = cs.num_constraints();

        commitment_witness
            .check_membership(
                &mut cs.ns(|| format!("new_witness_check_{}", i)),
                &crh_parameters,
                &root_gadget,
                &leaf_gadget,
            )
            .unwrap();

        if !cs.is_satisfied() {
            satisfied = false;
            println!("Unsatisfied constraint: {}", cs.which_is_unsatisfied().unwrap());
        }

        println!(
            "constraints from witness_check: {}",
            cs.num_constraints() - num_constraints
        );
    }

    assert!(satisfied);
}

#[test]
fn commitment_tree_good_root_test() {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);

    commitment_tree_test::<C, H, CG, HG, _, _>(false, "commitment_tree_good_root_test", rng);
}

#[should_panic]
#[test]
fn commitment_tree_bad_root_test() {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);

    commitment_tree_test::<C, H, CG, HG, _, _>(true, "commitment_tree_bad_root_test", rng);
}
