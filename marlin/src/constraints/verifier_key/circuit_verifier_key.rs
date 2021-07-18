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

use snarkvm_algorithms::fft::EvaluationDomain;
use snarkvm_fields::{PrimeField, ToConstraintField};
use snarkvm_gadgets::{
    fields::FpGadget,
    traits::alloc::AllocGadget,
    AllocBytesGadget,
    PrepareGadget,
    ToBytesGadget,
    ToConstraintFieldGadget,
    UInt8,
};
use snarkvm_polycommit::PCCheckVar;
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};

use crate::{
    constraints::{verifier::MarlinVerificationGadget, verifier_key::PreparedCircuitVerifyingKeyVar},
    marlin::CircuitVerifyingKey,
    FiatShamirRng,
    FiatShamirRngVar,
    PolynomialCommitment,
};
use snarkvm_algorithms::crypto_hash::PoseidonDefaultParametersField;
use snarkvm_utilities::{marker::PhantomData, to_bytes_le, FromBytes, ToBytes};

/// The circuit verifying key gadget
pub struct CircuitVerifyingKeyVar<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> {
    /// The original key
    pub origin_verifier_key: CircuitVerifyingKey<TargetField, PC>,
    /// The size of domain h
    pub domain_h_size: u64,
    /// The size of domain k
    pub domain_k_size: u64,
    /// The size of domain h in constraint form
    pub domain_h_size_gadget: FpGadget<BaseField>,
    /// The size of domain k in constraint form
    pub domain_k_size_gadget: FpGadget<BaseField>,
    /// The circuit commitments in constraint form
    pub index_comms: Vec<PCG::CommitmentVar>,
    /// The verifying key in constraint form
    pub verifier_key: PCG::VerifierKeyVar,
}

impl<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> Clone for CircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG>
{
    fn clone(&self) -> Self {
        Self {
            origin_verifier_key: self.origin_verifier_key.clone(),
            domain_h_size: self.domain_h_size,
            domain_k_size: self.domain_k_size,
            domain_h_size_gadget: self.domain_h_size_gadget.clone(),
            domain_k_size_gadget: self.domain_k_size_gadget.clone(),
            index_comms: self.index_comms.clone(),
            verifier_key: self.verifier_key.clone(),
        }
    }
}

impl<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> CircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG>
{
    /// Returns an iterator of the circuit commitments.
    pub fn iter(&self) -> impl Iterator<Item = &PCG::CommitmentVar> {
        self.index_comms.iter()
    }
}

impl<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> AllocGadget<CircuitVerifyingKey<TargetField, PC>, BaseField>
    for CircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG>
{
    #[inline]
    fn alloc_constant<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CircuitVerifyingKey<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let ivk = tmp.borrow();

        let mut index_comms = Vec::<PCG::CommitmentVar>::new();
        for (i, index_comm) in ivk.circuit_commitments.iter().enumerate() {
            index_comms.push(PCG::CommitmentVar::alloc_constant(
                cs.ns(|| format!("index_comm_{}", i)),
                || Ok(index_comm),
            )?);
        }

        let verifier_key = PCG::VerifierKeyVar::alloc_constant(cs.ns(|| "verifier_key"), || Ok(&ivk.verifier_key))?;

        let domain_h = EvaluationDomain::<TargetField>::new(ivk.circuit_info.num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_k = EvaluationDomain::<TargetField>::new(ivk.circuit_info.num_non_zero)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let domain_h_size_gadget = FpGadget::<BaseField>::alloc_constant(cs.ns(|| "domain_h_size_gadget"), || {
            Ok(BaseField::from(domain_h.size() as u128))
        })?;
        let domain_k_size_gadget = FpGadget::<BaseField>::alloc_constant(cs.ns(|| "domain_k_size_gadget"), || {
            Ok(BaseField::from(domain_k.size() as u128))
        })?;

        Ok(CircuitVerifyingKeyVar {
            origin_verifier_key: (*ivk).clone(),
            domain_h_size: domain_h.size() as u64,
            domain_k_size: domain_k.size() as u64,
            domain_h_size_gadget,
            domain_k_size_gadget,
            index_comms,
            verifier_key,
        })
    }

    #[inline]
    fn alloc<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CircuitVerifyingKey<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let ivk = tmp.borrow();

        let mut index_comms = Vec::<PCG::CommitmentVar>::new();
        for (i, index_comm) in ivk.circuit_commitments.iter().enumerate() {
            index_comms.push(PCG::CommitmentVar::alloc(
                cs.ns(|| format!("index_comm_{}", i)),
                || Ok(index_comm),
            )?);
        }

        let verifier_key = PCG::VerifierKeyVar::alloc(cs.ns(|| "verifier_key"), || Ok(&ivk.verifier_key))?;

        let domain_h = EvaluationDomain::<TargetField>::new(ivk.circuit_info.num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_k = EvaluationDomain::<TargetField>::new(ivk.circuit_info.num_non_zero)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let domain_h_size_gadget = FpGadget::<BaseField>::alloc(cs.ns(|| "domain_h_size_gadget"), || {
            Ok(BaseField::from(domain_h.size() as u128))
        })?;
        let domain_k_size_gadget = FpGadget::<BaseField>::alloc(cs.ns(|| "domain_k_size_gadget"), || {
            Ok(BaseField::from(domain_k.size() as u128))
        })?;

        Ok(CircuitVerifyingKeyVar {
            origin_verifier_key: (*ivk).clone(),
            domain_h_size: domain_h.size() as u64,
            domain_k_size: domain_k.size() as u64,
            domain_h_size_gadget,
            domain_k_size_gadget,
            index_comms,
            verifier_key,
        })
    }

    #[inline]
    fn alloc_input<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CircuitVerifyingKey<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let ivk = tmp.borrow();

        let mut index_comms = Vec::<PCG::CommitmentVar>::new();
        for (i, index_comm) in ivk.circuit_commitments.iter().enumerate() {
            index_comms.push(PCG::CommitmentVar::alloc_input(
                cs.ns(|| format!("index_comm_{}", i)),
                || Ok(index_comm),
            )?);
        }

        let verifier_key = PCG::VerifierKeyVar::alloc_input(cs.ns(|| "verifier_key"), || Ok(&ivk.verifier_key))?;

        let domain_h = EvaluationDomain::<TargetField>::new(ivk.circuit_info.num_constraints)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_k = EvaluationDomain::<TargetField>::new(ivk.circuit_info.num_non_zero)
            .ok_or(SynthesisError::PolynomialDegreeTooLarge)?;

        let domain_h_size_gadget = FpGadget::<BaseField>::alloc_input(cs.ns(|| "domain_h_size_gadget"), || {
            Ok(BaseField::from(domain_h.size() as u128))
        })?;
        let domain_k_size_gadget = FpGadget::<BaseField>::alloc_input(cs.ns(|| "domain_k_size_gadget"), || {
            Ok(BaseField::from(domain_k.size() as u128))
        })?;

        Ok(CircuitVerifyingKeyVar {
            origin_verifier_key: (*ivk).clone(),
            domain_h_size: domain_h.size() as u64,
            domain_k_size: domain_k.size() as u64,
            domain_h_size_gadget,
            domain_k_size_gadget,
            index_comms,
            verifier_key,
        })
    }
}

impl<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> ToConstraintFieldGadget<BaseField> for CircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG>
{
    fn to_constraint_field<CS: ConstraintSystem<BaseField>>(
        &self,
        mut cs: CS,
    ) -> Result<Vec<FpGadget<BaseField>>, SynthesisError> {
        let mut res = Vec::new();
        res.append(
            &mut self
                .domain_h_size_gadget
                .to_constraint_field(cs.ns(|| "domain_h_size_gadget"))?,
        );
        res.append(
            &mut self
                .domain_k_size_gadget
                .to_constraint_field(cs.ns(|| "domain_k_size_gadget"))?,
        );
        for (i, comm) in self.index_comms.iter().enumerate() {
            res.append(&mut comm.to_constraint_field(cs.ns(|| format!("index_comm_{}", i)))?);
        }
        // TODO: this overhead can be cut.
        res.append(&mut self.verifier_key.to_constraint_field(cs.ns(|| "verifier_key"))?);

        Ok(res)
    }
}

impl<TargetField, BaseField, PC, PCG, PR, R>
    PrepareGadget<PreparedCircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG, PR, R>, BaseField>
    for CircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG>
where
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
    PR: FiatShamirRng<TargetField, BaseField>,
    R: FiatShamirRngVar<TargetField, BaseField, PR>,
    PC::Commitment: ToConstraintField<BaseField>,
    PCG::VerifierKeyVar: ToConstraintFieldGadget<BaseField>,
    PCG::CommitmentVar: ToConstraintFieldGadget<BaseField>,
{
    /// Returns an instance of a `PreparedCircuitVerifyingKeyGadget`.
    fn prepare<CS: ConstraintSystem<BaseField>>(
        &self,
        mut cs: CS,
    ) -> Result<PreparedCircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG, PR, R>, SynthesisError> {
        let mut fs_rng_raw = PR::new();
        fs_rng_raw.absorb_bytes(&to_bytes_le![
            &MarlinVerificationGadget::<TargetField, BaseField, PC, PCG>::PROTOCOL_NAME
        ]?);

        let index_vk_hash = {
            let mut vk_hash_rng = PR::new();

            let mut vk_elems = Vec::<BaseField>::new();
            self.origin_verifier_key
                .circuit_commitments
                .iter()
                .for_each(|index_comm| {
                    vk_elems.append(&mut index_comm.to_field_elements().unwrap());
                });
            vk_hash_rng.absorb_native_field_elements(&vk_elems);
            vk_hash_rng.squeeze_native_field_elements(1).unwrap()
        };

        fs_rng_raw.absorb_native_field_elements(&index_vk_hash);

        let fs_rng = R::constant(cs.ns(|| "fs_rng_raw"), &fs_rng_raw);

        let mut prepared_index_comms = Vec::<PCG::PreparedCommitmentVar>::new();
        for (i, comm) in self.index_comms.iter().enumerate() {
            prepared_index_comms.push(comm.prepare(cs.ns(|| format!("prepare_{}", i)))?);
        }

        let prepared_verifier_key = self.verifier_key.prepare(cs.ns(|| "prepare_last"))?;

        Ok(
            PreparedCircuitVerifyingKeyVar::<TargetField, BaseField, PC, PCG, PR, R> {
                domain_h_size: self.domain_h_size,
                domain_k_size: self.domain_k_size,
                domain_h_size_gadget: self.domain_h_size_gadget.clone(),
                domain_k_size_gadget: self.domain_k_size_gadget.clone(),
                prepared_index_comms,
                prepared_verifier_key,
                fs_rng,
                pr: PhantomData,
            },
        )
    }
}

impl<
    TargetField: PrimeField,
    BaseField: PrimeField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
> ToBytesGadget<BaseField> for CircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG>
{
    fn to_bytes<CS: ConstraintSystem<BaseField>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        let mut res = Vec::<UInt8>::new();

        res.append(&mut self.domain_h_size_gadget.to_bytes(cs.ns(|| "domain_h_size_gadget"))?);
        res.append(&mut self.domain_k_size_gadget.to_bytes(cs.ns(|| "domain_k_size_gadget"))?);
        res.append(&mut self.verifier_key.to_bytes(cs.ns(|| "verifier_key"))?);

        for (i, comm) in self.index_comms.iter().enumerate() {
            res.append(&mut comm.to_bytes(cs.ns(|| format!("commitment_{}", i)))?);
        }

        Ok(res)
    }

    fn to_bytes_strict<CS: ConstraintSystem<BaseField>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        let mut res = Vec::<UInt8>::new();
        res.append(&mut self.domain_h_size_gadget.to_bytes(cs.ns(|| "domain_h_size_gadget"))?);
        res.append(&mut self.domain_k_size_gadget.to_bytes(cs.ns(|| "domain_k_size_gadget"))?);
        res.append(&mut self.verifier_key.to_bytes(cs.ns(|| "verifier_key"))?);

        for (i, comm) in self.index_comms.iter().enumerate() {
            res.append(&mut comm.to_bytes(cs.ns(|| format!("commitment_{}", i)))?);
        }

        Ok(res)
    }
}

impl<TargetField, BaseField, PC, PCG> AllocBytesGadget<Vec<u8>, BaseField>
    for CircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG>
where
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
    PC::VerifierKey: ToConstraintField<BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
    PCG::VerifierKeyVar: ToConstraintFieldGadget<BaseField>,
    PCG::CommitmentVar: ToConstraintFieldGadget<BaseField>,
{
    #[inline]
    fn alloc_bytes<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Vec<u8>>,
    {
        value_gen().and_then(|vk_bytes| {
            let circuit_vk: CircuitVerifyingKey<TargetField, PC> = FromBytes::read_le(&vk_bytes.borrow()[..])?;

            CircuitVerifyingKeyVar::<TargetField, BaseField, PC, PCG>::alloc(cs.ns(|| "unprepared_vk"), || {
                Ok(circuit_vk)
            })
        })
    }

    #[inline]
    fn alloc_input_bytes<FN, T, CS: ConstraintSystem<BaseField>>(
        mut cs: CS,
        value_gen: FN,
    ) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Vec<u8>>,
    {
        value_gen().and_then(|vk_bytes| {
            let circuit_vk: CircuitVerifyingKey<TargetField, PC> = FromBytes::read_le(&vk_bytes.borrow()[..])?;

            CircuitVerifyingKeyVar::<TargetField, BaseField, PC, PCG>::alloc_input(cs.ns(|| "unprepared_vk"), || {
                Ok(circuit_vk)
            })
        })
    }
}

#[cfg(test)]
mod test {
    use core::ops::MulAssign;

    use blake2::Blake2s;

    use snarkvm_curves::{
        bls12_377::{Bls12_377, Fq, Fr},
        bw6_761::BW6_761,
    };
    use snarkvm_gadgets::{curves::bls12_377::PairingGadget as Bls12_377PairingGadget, traits::eq::EqGadget};
    use snarkvm_polycommit::marlin_pc::{marlin_kzg10::MarlinKZG10Gadget, MarlinKZG10};
    use snarkvm_r1cs::TestConstraintSystem;
    use snarkvm_utilities::rand::{test_rng, UniformRand};

    use crate::{
        fiat_shamir::FiatShamirChaChaRng,
        marlin::{tests::Circuit, MarlinSNARK, MarlinTestnet1Mode},
    };

    use super::*;

    type MultiPC = MarlinKZG10<Bls12_377>;
    type MarlinInst = MarlinSNARK<Fr, Fq, MultiPC, FiatShamirChaChaRng<Fr, Fq, Blake2s>, MarlinTestnet1Mode>;

    type MultiPCVar = MarlinKZG10Gadget<Bls12_377, BW6_761, Bls12_377PairingGadget>;

    #[test]
    fn test_alloc() {
        let rng = &mut test_rng();

        let cs = &mut TestConstraintSystem::<Fq>::new();

        let num_constraints = 25;
        let num_variables = 25;

        // Construct the circuit verifier key.

        let universal_srs = MarlinInst::universal_setup(100, 25, 100, rng).unwrap();

        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        let mut c = a;
        c.mul_assign(&b);
        let mut d = c;
        d.mul_assign(&b);

        let circ = Circuit {
            a: Some(a),
            b: Some(b),
            num_constraints,
            num_variables,
        };

        let (_circuit_pk, circuit_vk) = MarlinInst::circuit_setup(&universal_srs, &circ).unwrap();

        // Allocate the circuit vk gadget.
        let circuit_vk_gadget =
            CircuitVerifyingKeyVar::<_, _, _, MultiPCVar>::alloc(cs.ns(|| "alloc_vk"), || Ok(circuit_vk.clone()))
                .unwrap();

        // Enforce that the native vk and vk gadget elements are equivalent.

        for (i, (commitment, commitment_gadget)) in circuit_vk
            .circuit_commitments
            .iter()
            .zip(circuit_vk_gadget.index_comms)
            .enumerate()
        {
            let expected_commitment_gadget = <MultiPCVar as PCCheckVar<_, _, _>>::CommitmentVar::alloc(
                cs.ns(|| format!("alloc_commitment_{}", i)),
                || Ok(commitment),
            )
            .unwrap();

            commitment_gadget
                .comm
                .enforce_equal(
                    cs.ns(|| format!("enforce_equal_comm_{}", i)),
                    &expected_commitment_gadget.comm,
                )
                .unwrap();
        }

        assert!(cs.is_satisfied());
    }
}
