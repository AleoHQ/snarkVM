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

use core::borrow::Borrow;

use snarkvm_curves::PairingEngine;
use snarkvm_fields::ToConstraintField;
use snarkvm_gadgets::traits::{alloc::AllocGadget, curves::PairingGadget};
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};

use crate::{marlin_pc::PreparedCommitment, Vec};

/// Prepared gadget for an optionally hiding Marlin-KZG10 commitment.
/// shifted_comm is not prepared, due to the specific use case.
pub struct PreparedCommitmentVar<
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
> where
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    /// Prepared commitment.
    pub prepared_comm: Vec<PG::G1Gadget>,
    /// Shifted commitment.
    pub shifted_comm: Option<PG::G1Gadget>,
}

impl<TargetCurve, BaseCurve, PG> Clone for PreparedCommitmentVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    fn clone(&self) -> Self {
        Self {
            prepared_comm: self.prepared_comm.clone(),
            shifted_comm: self.shifted_comm.clone(),
        }
    }
}

impl<TargetCurve, BaseCurve, PG> AllocGadget<PreparedCommitment<TargetCurve>, <BaseCurve as PairingEngine>::Fr>
    for PreparedCommitmentVar<TargetCurve, BaseCurve, PG>
where
    TargetCurve: PairingEngine,
    BaseCurve: PairingEngine,
    PG: PairingGadget<TargetCurve, <BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G1Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
    <TargetCurve as PairingEngine>::G2Affine: ToConstraintField<<BaseCurve as PairingEngine>::Fr>,
{
    fn alloc_constant<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PreparedCommitment<TargetCurve>>,
        CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let obj = value_gen()?.borrow().clone();

        let mut prepared_comm = Vec::<PG::G1Gadget>::new();

        for (i, comm_elem) in obj.prepared_comm.0.iter().enumerate() {
            prepared_comm.push(<PG::G1Gadget as AllocGadget<
                <TargetCurve as PairingEngine>::G1Projective,
                <BaseCurve as PairingEngine>::Fr,
            >>::alloc_constant(
                cs.ns(|| format!("comm_elem_{}", i)),
                || {
                    Ok(<<TargetCurve as PairingEngine>::G1Projective as From<
                        <TargetCurve as PairingEngine>::G1Affine,
                    >>::from(*comm_elem))
                },
            )?);
        }

        let shifted_comm = if obj.shifted_comm.is_some() {
            Some(<PG::G1Gadget as AllocGadget<
                <TargetCurve as PairingEngine>::G1Projective,
                <BaseCurve as PairingEngine>::Fr,
            >>::alloc_constant(cs.ns(|| "shifted_comm"), || {
                Ok(<<TargetCurve as PairingEngine>::G1Projective as From<
                    <TargetCurve as PairingEngine>::G1Affine,
                >>::from(obj.shifted_comm.unwrap().0))
            })?)
        } else {
            None
        };

        Ok(Self {
            prepared_comm,
            shifted_comm,
        })
    }

    fn alloc<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PreparedCommitment<TargetCurve>>,
        CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let obj = value_gen()?.borrow().clone();

        let mut prepared_comm = Vec::<PG::G1Gadget>::new();

        for (i, comm_elem) in obj.prepared_comm.0.iter().enumerate() {
            prepared_comm.push(<PG::G1Gadget as AllocGadget<
                <TargetCurve as PairingEngine>::G1Projective,
                <BaseCurve as PairingEngine>::Fr,
            >>::alloc(cs.ns(|| format!("comm_elem_{}", i)), || {
                Ok(<<TargetCurve as PairingEngine>::G1Projective as From<
                    <TargetCurve as PairingEngine>::G1Affine,
                >>::from(*comm_elem))
            })?);
        }

        let shifted_comm = if obj.shifted_comm.is_some() {
            Some(<PG::G1Gadget as AllocGadget<
                <TargetCurve as PairingEngine>::G1Projective,
                <BaseCurve as PairingEngine>::Fr,
            >>::alloc(cs.ns(|| "shifted_comm"), || {
                Ok(<<TargetCurve as PairingEngine>::G1Projective as From<
                    <TargetCurve as PairingEngine>::G1Affine,
                >>::from(obj.shifted_comm.unwrap().0))
            })?)
        } else {
            None
        };

        Ok(Self {
            prepared_comm,
            shifted_comm,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PreparedCommitment<TargetCurve>>,
        CS: ConstraintSystem<<BaseCurve as PairingEngine>::Fr>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let obj = value_gen()?.borrow().clone();

        let mut prepared_comm = Vec::<PG::G1Gadget>::new();

        for (i, comm_elem) in obj.prepared_comm.0.iter().enumerate() {
            prepared_comm.push(<PG::G1Gadget as AllocGadget<
                <TargetCurve as PairingEngine>::G1Projective,
                <BaseCurve as PairingEngine>::Fr,
            >>::alloc_input(
                cs.ns(|| format!("comm_elem_{}", i)),
                || {
                    Ok(<<TargetCurve as PairingEngine>::G1Projective as From<
                        <TargetCurve as PairingEngine>::G1Affine,
                    >>::from(*comm_elem))
                },
            )?);
        }

        let shifted_comm = if obj.shifted_comm.is_some() {
            Some(<PG::G1Gadget as AllocGadget<
                <TargetCurve as PairingEngine>::G1Projective,
                <BaseCurve as PairingEngine>::Fr,
            >>::alloc_input(cs.ns(|| "shifted_comm"), || {
                Ok(<<TargetCurve as PairingEngine>::G1Projective as From<
                    <TargetCurve as PairingEngine>::G1Affine,
                >>::from(obj.shifted_comm.unwrap().0))
            })?)
        } else {
            None
        };

        Ok(Self {
            prepared_comm,
            shifted_comm,
        })
    }
}
