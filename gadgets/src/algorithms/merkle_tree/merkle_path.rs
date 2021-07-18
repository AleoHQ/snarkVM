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

use itertools::Itertools;
use std::borrow::Borrow;

use snarkvm_algorithms::{
    merkle_tree::MerklePath,
    traits::{MerkleParameters, CRH},
};
use snarkvm_fields::PrimeField;
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};

use crate::{
    bits::{boolean::Boolean, ToBytesGadget},
    traits::{algorithms::CRHGadget, alloc::AllocGadget, eq::ConditionalEqGadget, select::CondSelectGadget},
    EqGadget,
};

pub struct MerklePathGadget<P: MerkleParameters, HG: CRHGadget<P::H, F>, F: PrimeField> {
    /// `traversal[i]` is 0 (false) iff ith node from bottom to top is left.
    traversal: Vec<Boolean>,
    /// `path[i]` is the entry of sibling of ith node from bottom to top.
    path: Vec<HG::OutputGadget>,
}

impl<P: MerkleParameters, HG: CRHGadget<P::H, F>, F: PrimeField> MerklePathGadget<P, HG, F> {
    pub fn calculate_root<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        crh: &HG,
        leaf: impl ToBytesGadget<F>,
    ) -> Result<HG::OutputGadget, SynthesisError> {
        let leaf_bytes = leaf.to_bytes(&mut cs.ns(|| "leaf_to_bytes"))?;
        let mut curr_hash = crh.check_evaluation_gadget(cs.ns(|| "leaf_hash"), leaf_bytes)?;

        // To traverse up a MT, we iterate over the path from bottom to top

        // At any given bit, the bit being 0 indicates our currently hashed value is the left,
        // and the bit being 1 indicates our currently hashed value is on the right.
        // Thus `left_hash` is the sibling if bit is 1, and it's the computed hash if bit is 0
        for (i, (bit, sibling)) in self.traversal.iter().zip_eq(self.path.iter()).enumerate() {
            let left_hash = HG::OutputGadget::conditionally_select(
                cs.ns(|| format!("cond_select_left_{}", i)),
                &bit,
                &sibling,
                &curr_hash,
            )?;
            let right_hash = HG::OutputGadget::conditionally_select(
                cs.ns(|| format!("cond_select_right_{}", i)),
                &bit,
                &curr_hash,
                &sibling,
            )?;

            curr_hash = hash_inner_node_gadget::<P::H, HG, F, _>(
                &mut cs.ns(|| format!("hash_inner_node_{}", i)),
                crh,
                &left_hash,
                &right_hash,
            )?;
        }

        Ok(curr_hash)
    }

    pub fn update_leaf<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        crh: &HG,
        old_root: &HG::OutputGadget,
        old_leaf: impl ToBytesGadget<F>,
        new_leaf: impl ToBytesGadget<F>,
    ) -> Result<HG::OutputGadget, SynthesisError> {
        self.check_membership(cs.ns(|| "check_membership"), &crh, &old_root, &old_leaf)?;
        Ok(self.calculate_root(cs.ns(|| "calculate_root"), &crh, &new_leaf)?)
    }

    pub fn update_and_check<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        crh: &HG,
        old_root: &HG::OutputGadget,
        new_root: &HG::OutputGadget,
        old_leaf: impl ToBytesGadget<F>,
        new_leaf: impl ToBytesGadget<F>,
    ) -> Result<(), SynthesisError> {
        let actual_new_root = self.update_leaf(cs.ns(|| "check_membership"), &crh, &old_root, &old_leaf, &new_leaf)?;

        actual_new_root.enforce_equal(cs.ns(|| "enforce_equal_roots"), &new_root)?;

        Ok(())
    }

    pub fn check_membership<CS: ConstraintSystem<F>>(
        &self,
        cs: CS,
        crh: &HG,
        root: &HG::OutputGadget,
        leaf: impl ToBytesGadget<F>,
    ) -> Result<(), SynthesisError> {
        self.conditionally_check_membership(cs, crh, root, leaf, &Boolean::Constant(true))
    }

    pub fn conditionally_check_membership<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        crh: &HG,
        root: &HG::OutputGadget,
        leaf: impl ToBytesGadget<F>,
        should_enforce: &Boolean,
    ) -> Result<(), SynthesisError> {
        let expected_root = self.calculate_root(cs.ns(|| "calculate_root"), crh, leaf)?;

        root.conditional_enforce_equal(&mut cs.ns(|| "root_is_eq"), &expected_root, should_enforce)
    }
}

pub(crate) fn hash_inner_node_gadget<H, HG, F, CS>(
    mut cs: CS,
    crh: &HG,
    left_child: &HG::OutputGadget,
    right_child: &HG::OutputGadget,
) -> Result<HG::OutputGadget, SynthesisError>
where
    F: PrimeField,
    CS: ConstraintSystem<F>,
    H: CRH,
    HG: CRHGadget<H, F>,
{
    let left_bytes = left_child.to_bytes(&mut cs.ns(|| "left_to_bytes"))?;
    let right_bytes = right_child.to_bytes(&mut cs.ns(|| "right_to_bytes"))?;
    let mut bytes = left_bytes;
    bytes.extend_from_slice(&right_bytes);

    crh.check_evaluation_gadget(cs, bytes)
}

impl<P, HGadget, F> AllocGadget<MerklePath<P>, F> for MerklePathGadget<P, HGadget, F>
where
    P: MerkleParameters,
    HGadget: CRHGadget<P::H, F>,
    F: PrimeField,
{
    fn alloc<Fn, T, CS: ConstraintSystem<F>>(mut cs: CS, value_gen: Fn) -> Result<Self, SynthesisError>
    where
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<MerklePath<P>>,
    {
        let merkle_path = value_gen()?.borrow().clone();

        let mut traversal = vec![];
        for (i, position) in merkle_path.position_list().enumerate() {
            traversal.push(Boolean::alloc(cs.ns(|| format!("alloc_position_{}", i)), || {
                Ok(position)
            })?);
        }

        let mut path = Vec::with_capacity(merkle_path.path.len());
        for (i, node) in merkle_path.path.iter().enumerate() {
            path.push(HGadget::OutputGadget::alloc(
                &mut cs.ns(|| format!("alloc_node_{}", i)),
                || Ok(node.clone()),
            )?);
        }

        Ok(MerklePathGadget { traversal, path })
    }

    fn alloc_input<Fn, T, CS: ConstraintSystem<F>>(mut cs: CS, value_gen: Fn) -> Result<Self, SynthesisError>
    where
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<MerklePath<P>>,
    {
        let merkle_path = value_gen()?.borrow().clone();

        let mut traversal = vec![];
        for (i, position) in merkle_path.position_list().enumerate() {
            traversal.push(Boolean::alloc_input(
                cs.ns(|| format!("alloc_input_position_{}", i)),
                || Ok(position),
            )?);
        }

        let mut path = Vec::with_capacity(merkle_path.path.len());
        for (i, node) in merkle_path.path.iter().enumerate() {
            path.push(HGadget::OutputGadget::alloc_input(
                &mut cs.ns(|| format!("alloc_input_node_{}", i)),
                || Ok(node.clone()),
            )?);
        }

        Ok(MerklePathGadget { traversal, path })
    }
}
