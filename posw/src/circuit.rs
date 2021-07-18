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

//! Implements a Proof of Succinct work circuit. The inputs are opaque leaves,
//! which are then used to build a tree instantiated with a masked Pedersen hash. The prover
//! inputs a mask computed as Blake2s(nonce || root), which the verifier also checks.
use std::{marker::PhantomData, sync::Arc};

use snarkvm_algorithms::traits::{MaskedMerkleParameters, CRH};
use snarkvm_fields::PrimeField;
use snarkvm_gadgets::{
    algorithms::merkle_tree::compute_root,
    integers::uint::UInt8,
    traits::{algorithms::MaskedCRHGadget, alloc::AllocGadget, eq::EqGadget},
};
use snarkvm_r1cs::{errors::SynthesisError, Assignment, ConstraintSynthesizer, ConstraintSystem};

/// Enforces sizes of the mask and leaves.
pub trait POSWCircuitParameters {
    const MASK_LENGTH: usize;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct POSWCircuit<
    F: PrimeField,
    M: MaskedMerkleParameters,
    HG: MaskedCRHGadget<M::H, F>,
    CP: POSWCircuitParameters,
> {
    pub leaves: Vec<Option<<M::H as CRH>::Output>>,
    pub merkle_parameters: Arc<M>,
    pub mask: Option<Vec<u8>>,
    pub root: Option<<M::H as CRH>::Output>,

    pub field_type: PhantomData<F>,
    pub crh_gadget_type: PhantomData<HG>,
    pub circuit_parameters_type: PhantomData<CP>,
}

impl<F: PrimeField, M: MaskedMerkleParameters, HG: MaskedCRHGadget<M::H, F>, CP: POSWCircuitParameters>
    ConstraintSynthesizer<F> for POSWCircuit<F, M, HG, CP>
{
    fn generate_constraints<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        // Compute the mask if it exists.
        let mask = self.mask.clone().unwrap_or_else(|| vec![0; CP::MASK_LENGTH]);
        if mask.len() != CP::MASK_LENGTH {
            return Err(SynthesisError::Unsatisfiable);
        }
        let mask_bytes = UInt8::alloc_input_vec_le(cs.ns(|| "mask"), &mask)?;

        let crh_parameters = HG::alloc(&mut cs.ns(|| "new_parameters"), || Ok(self.merkle_parameters.crh()))?;
        let mask_crh_parameters = <HG as MaskedCRHGadget<M::H, F>>::MaskParametersGadget::alloc(
            &mut cs.ns(|| "new_mask_parameters"),
            || {
                let crh_parameters = self.merkle_parameters.mask_parameters();
                Ok(crh_parameters)
            },
        )?;
        let leaves_number = 2u32.pow(M::DEPTH as u32) as usize;
        assert!(self.leaves.len() <= leaves_number);

        // Initialize the leaves.
        let mut leaf_gadgets = self
            .leaves
            .iter()
            .enumerate()
            .map(|(i, l)| HG::OutputGadget::alloc(cs.ns(|| format!("leaf {}", i)), || l.as_ref().get()))
            .collect::<Result<Vec<_>, _>>()?;

        let empty_hash = self
            .merkle_parameters
            .hash_empty()
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        for i in leaf_gadgets.len()..leaves_number {
            leaf_gadgets.push(HG::OutputGadget::alloc(cs.ns(|| format!("leaf {}", i)), || {
                Ok(empty_hash.clone())
            })?);
        }

        // Compute the root using the masked tree.
        let computed_root = compute_root::<M::H, HG, _, _, _>(
            cs.ns(|| "compute masked root"),
            &crh_parameters,
            &mask_crh_parameters,
            &mask_bytes,
            &leaf_gadgets,
        )?;

        // Enforce the input root is the same as the computed root.
        let public_computed_root =
            HG::OutputGadget::alloc_input(cs.ns(|| "public computed root"), || self.root.as_ref().get())?;
        computed_root.enforce_equal(cs.ns(|| "inputize computed root"), &public_computed_root)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::{marker::PhantomData, sync::Arc};

    use blake2::{digest::Digest, Blake2s};
    use rand::thread_rng;

    use snarkvm_algorithms::{
        crh::PedersenCompressedCRH,
        define_masked_merkle_tree_parameters,
        snark::gm17::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof},
    };
    use snarkvm_curves::{
        bls12_377::{Bls12_377, Fr},
        edwards_bls12::{EdwardsProjective as Edwards, Fq},
    };
    use snarkvm_fields::ToConstraintField;
    use snarkvm_gadgets::{algorithms::crh::PedersenCompressedCRHGadget, curves::edwards_bls12::EdwardsBls12Gadget};
    use snarkvm_utilities::ToBytes;

    use super::{POSWCircuit, POSWCircuitParameters};

    // We'll use 32 byte masks in this test
    struct TestPOSWCircuitParameters;
    impl POSWCircuitParameters for TestPOSWCircuitParameters {
        const MASK_LENGTH: usize = 32;
    }

    const NUM_WINDOWS: usize = 256;
    const WINDOW_SIZE: usize = 4;

    // We use a small tree in this test
    define_masked_merkle_tree_parameters!(EdwardsMaskedMerkleParameters, PedersenCompressedCRH<Edwards, NUM_WINDOWS, WINDOW_SIZE>, 4);

    type HashGadget = PedersenCompressedCRHGadget<Edwards, Fq, EdwardsBls12Gadget, NUM_WINDOWS, WINDOW_SIZE>;
    type EdwardsMaskedMerkleTree = MerkleTree<EdwardsMaskedMerkleParameters>;

    #[test]
    fn test_tree_proof() {
        let mut rng = thread_rng();

        let parameters = EdwardsMaskedMerkleParameters::setup("test_tree_proof");
        let params = generate_random_parameters::<Bls12_377, _, _>(
            &POSWCircuit::<_, EdwardsMaskedMerkleParameters, HashGadget, TestPOSWCircuitParameters> {
                leaves: vec![None; 7],
                merkle_parameters: Arc::new(parameters.clone()),
                mask: None,
                root: None,
                field_type: PhantomData,
                crh_gadget_type: PhantomData,
                circuit_parameters_type: PhantomData,
            },
            &mut rng,
        )
        .unwrap();

        let nonce = [1; 32];
        let leaves = vec![vec![3u8; 32]; 7];
        let tree = EdwardsMaskedMerkleTree::new(Arc::new(parameters.clone()), &leaves[..]).unwrap();
        let root = tree.root();
        let mut root_bytes = [0; 32];
        root.write_le(&mut root_bytes[..]).unwrap();

        let mut h = Blake2s::new();
        h.update(nonce.as_ref());
        h.update(root_bytes.as_ref());
        let mask = h.finalize().to_vec();

        let snark_leaves = tree.hashed_leaves().to_vec().into_iter().map(Some).collect();
        let proof = create_random_proof(
            &POSWCircuit::<_, EdwardsMaskedMerkleParameters, HashGadget, TestPOSWCircuitParameters> {
                leaves: snark_leaves,
                merkle_parameters: Arc::new(parameters),
                mask: Some(mask.clone()),
                root: Some(root),
                field_type: PhantomData,
                crh_gadget_type: PhantomData,
                circuit_parameters_type: PhantomData,
            },
            &params,
            &mut rng,
        )
        .unwrap();

        let inputs = [ToConstraintField::<Fr>::to_field_elements(&mask[..]).unwrap(), vec![
            root,
        ]]
        .concat();

        assert!(verify_proof(&prepare_verifying_key(params.vk), &proof, &inputs,).unwrap());
    }
}
