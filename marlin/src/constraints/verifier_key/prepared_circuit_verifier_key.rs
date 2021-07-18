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
use std::marker::PhantomData;

use snarkvm_algorithms::Prepare;
use snarkvm_fields::{PrimeField, ToConstraintField};
use snarkvm_gadgets::{
    fields::FpGadget,
    traits::{alloc::AllocGadget, fields::ToConstraintFieldGadget},
};
use snarkvm_polycommit::PCCheckVar;
use snarkvm_r1cs::{ConstraintSystem, SynthesisError};
use snarkvm_utilities::{to_bytes_le, ToBytes};

use crate::{
    constraints::verifier::MarlinVerificationGadget,
    marlin::{CircuitVerifyingKey, PreparedCircuitVerifyingKey},
    FiatShamirRng,
    FiatShamirRngVar,
    PolynomialCommitment,
};
use snarkvm_algorithms::crypto_hash::PoseidonDefaultParametersField;

/// The prepared circuit verifying key gadget
pub struct PreparedCircuitVerifyingKeyVar<
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
    PR: FiatShamirRng<TargetField, BaseField>,
    R: FiatShamirRngVar<TargetField, BaseField, PR>,
> {
    /// The size of domain h
    pub domain_h_size: u64,
    /// The size of domain k
    pub domain_k_size: u64,
    /// The size of domain h in constraint form
    pub domain_h_size_gadget: FpGadget<BaseField>,
    /// The size of domain k in constraint form
    pub domain_k_size_gadget: FpGadget<BaseField>,
    /// The prepared circuit commitments in constraint form
    pub prepared_index_comms: Vec<PCG::PreparedCommitmentVar>,
    /// The prepared verifying key in constraint form
    pub prepared_verifier_key: PCG::PreparedVerifierKeyVar,
    /// The Fiat-Shamir Rng
    pub fs_rng: R,

    pub pr: PhantomData<PR>,
}

impl<
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
    PR: FiatShamirRng<TargetField, BaseField>,
    R: FiatShamirRngVar<TargetField, BaseField, PR>,
> Clone for PreparedCircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG, PR, R>
{
    fn clone(&self) -> Self {
        PreparedCircuitVerifyingKeyVar {
            domain_h_size: self.domain_h_size,
            domain_k_size: self.domain_k_size,
            domain_h_size_gadget: self.domain_h_size_gadget.clone(),
            domain_k_size_gadget: self.domain_k_size_gadget.clone(),
            prepared_index_comms: self.prepared_index_comms.clone(),
            prepared_verifier_key: self.prepared_verifier_key.clone(),
            fs_rng: self.fs_rng.clone(),
            pr: PhantomData,
        }
    }
}

impl<TargetField, BaseField, PC, PCG, PR, R> AllocGadget<PreparedCircuitVerifyingKey<TargetField, PC>, BaseField>
    for PreparedCircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG, PR, R>
where
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
    PR: FiatShamirRng<TargetField, BaseField>,
    R: FiatShamirRngVar<TargetField, BaseField, PR>,
    PC::VerifierKey: ToConstraintField<BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
    PCG::VerifierKeyVar: ToConstraintFieldGadget<BaseField>,
    PCG::CommitmentVar: ToConstraintFieldGadget<BaseField>,
{
    #[inline]
    fn alloc_constant<FN, T, CS: ConstraintSystem<BaseField>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PreparedCircuitVerifyingKey<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let obj = tmp.borrow();

        let mut prepared_index_comms = Vec::<PCG::PreparedCommitmentVar>::new();
        for (i, index_comm) in obj.prepared_index_comms.iter().enumerate() {
            prepared_index_comms.push(PCG::PreparedCommitmentVar::alloc_constant(
                cs.ns(|| format!("alloc_constant_index_commitment_{}", i)),
                || Ok(index_comm),
            )?);
        }

        let prepared_verifier_key =
            PCG::PreparedVerifierKeyVar::alloc_constant(cs.ns(|| "alloc_constant_pvk"), || {
                Ok(&obj.prepared_verifier_key)
            })?;

        let mut vk_elems = Vec::<BaseField>::new();
        obj.orig_vk.circuit_commitments.iter().for_each(|index_comm| {
            vk_elems.append(&mut index_comm.to_field_elements().unwrap());
        });

        let index_vk_hash = {
            let mut vk_hash_rng = PR::new();

            vk_hash_rng.absorb_native_field_elements(&vk_elems);
            FpGadget::<BaseField>::alloc_constant(cs.ns(|| "alloc_constant_vk_hash"), || {
                Ok(vk_hash_rng.squeeze_native_field_elements(1).unwrap()[0])
            })?
        };

        let mut fs_rng_raw = PR::new();
        fs_rng_raw.absorb_bytes(&to_bytes_le![
            &MarlinVerificationGadget::<TargetField, BaseField, PC, PCG>::PROTOCOL_NAME
        ]?);

        let fs_rng = {
            let mut fs_rng = R::constant(cs.ns(|| "fs_rng_raw"), &fs_rng_raw);
            fs_rng.absorb_native_field_elements(cs.ns(|| "absorb"), &[index_vk_hash])?;
            fs_rng
        };

        let domain_h_size_gadget = FpGadget::<BaseField>::alloc_constant(cs.ns(|| "domain_h_size_gadget"), || {
            Ok(BaseField::from(obj.domain_h_size as u128))
        })?;
        let domain_k_size_gadget = FpGadget::<BaseField>::alloc_constant(cs.ns(|| "domain_k_size_gadget"), || {
            Ok(BaseField::from(obj.domain_k_size as u128))
        })?;

        Ok(Self {
            domain_h_size: obj.domain_h_size,
            domain_k_size: obj.domain_k_size,
            domain_h_size_gadget,
            domain_k_size_gadget,
            prepared_index_comms,
            prepared_verifier_key,
            fs_rng,
            pr: PhantomData,
        })
    }

    #[inline]
    fn alloc<FN, T, CS: ConstraintSystem<BaseField>>(_cs: CS, _value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PreparedCircuitVerifyingKey<TargetField, PC>>,
    {
        unimplemented!();
        // the overhead is not worthwhile
    }

    #[inline]
    fn alloc_input<FN, T, CS: ConstraintSystem<BaseField>>(_cs: CS, _value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<PreparedCircuitVerifyingKey<TargetField, PC>>,
    {
        unimplemented!();
        // the overhead is not worthwhile
    }
}

impl<TargetField, BaseField, PC, PCG, PR, R> AllocGadget<CircuitVerifyingKey<TargetField, PC>, BaseField>
    for PreparedCircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG, PR, R>
where
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
    PR: FiatShamirRng<TargetField, BaseField>,
    R: FiatShamirRngVar<TargetField, BaseField, PR>,
    PC::VerifierKey: ToConstraintField<BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
    PCG::VerifierKeyVar: ToConstraintFieldGadget<BaseField>,
    PCG::CommitmentVar: ToConstraintFieldGadget<BaseField>,
{
    #[inline]
    fn alloc_constant<FN, T, CS: ConstraintSystem<BaseField>>(cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CircuitVerifyingKey<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let vk = tmp.borrow();
        let prepared_vk = vk.prepare();

        Self::alloc_constant(cs, || Ok(prepared_vk))
    }

    #[inline]
    #[inline]
    fn alloc<FN, T, CS: ConstraintSystem<BaseField>>(cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CircuitVerifyingKey<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let vk = tmp.borrow();
        let prepared_vk = vk.prepare();

        Self::alloc(cs, || Ok(prepared_vk))
    }

    #[inline]
    fn alloc_input<FN, T, CS: ConstraintSystem<BaseField>>(cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<CircuitVerifyingKey<TargetField, PC>>,
    {
        let tmp = value_gen()?;
        let vk = tmp.borrow();
        let prepared_vk = vk.prepare();

        Self::alloc_input(cs, || Ok(prepared_vk))
    }
}

#[cfg(test)]
mod test {
    use core::ops::MulAssign;

    use snarkvm_curves::{
        bls12_377::{Bls12_377, Fq, Fr},
        bw6_761::BW6_761,
    };
    use snarkvm_gadgets::{
        curves::bls12_377::PairingGadget as Bls12_377PairingGadget,
        traits::eq::EqGadget,
        PrepareGadget,
    };
    use snarkvm_polycommit::marlin_pc::{marlin_kzg10::MarlinKZG10Gadget, MarlinKZG10};
    use snarkvm_r1cs::TestConstraintSystem;
    use snarkvm_utilities::rand::{test_rng, UniformRand};

    use crate::{
        marlin::{tests::Circuit, MarlinSNARK, MarlinTestnet1Mode},
        FiatShamirAlgebraicSpongeRng,
        FiatShamirAlgebraicSpongeRngVar,
        PoseidonSponge,
        PoseidonSpongeVar,
    };

    use super::*;
    use crate::constraints::verifier_key::CircuitVerifyingKeyVar;

    type FS = FiatShamirAlgebraicSpongeRng<Fr, Fq, PoseidonSponge<Fq>>;
    type FSG = FiatShamirAlgebraicSpongeRngVar<Fr, Fq, PoseidonSponge<Fq>, PoseidonSpongeVar<Fq>>;

    type MultiPC = MarlinKZG10<Bls12_377>;
    type MarlinInst = MarlinSNARK<Fr, Fq, MultiPC, FS, MarlinTestnet1Mode>;

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

        let prepared_circuit_vk = circuit_vk.prepare();

        // Allocate the circuit vk gadget.
        let prepared_circuit_vk_gadget =
            PreparedCircuitVerifyingKeyVar::<_, _, _, MultiPCVar, FS, FSG>::alloc_constant(
                cs.ns(|| "alloc_prepared_vk"),
                || Ok(prepared_circuit_vk.clone()),
            )
            .unwrap();

        // Enforce that the native vk and vk gadget elements are equivalent.

        assert_eq!(
            prepared_circuit_vk.domain_h_size,
            prepared_circuit_vk_gadget.domain_h_size
        );
        assert_eq!(
            prepared_circuit_vk.domain_k_size,
            prepared_circuit_vk_gadget.domain_k_size
        );

        for (i, (prepared_commitment, prepared_commitment_gadget)) in prepared_circuit_vk
            .prepared_index_comms
            .iter()
            .zip(prepared_circuit_vk_gadget.prepared_index_comms)
            .enumerate()
        {
            let expected_prepared_commitment_gadget =
                <MultiPCVar as PCCheckVar<_, _, _>>::PreparedCommitmentVar::alloc(
                    cs.ns(|| format!("alloc_prepared_commitment_{}", i)),
                    || Ok(prepared_commitment),
                )
                .unwrap();

            for (j, (expected_comm, comm)) in expected_prepared_commitment_gadget
                .prepared_comm
                .iter()
                .zip(prepared_commitment_gadget.prepared_comm)
                .enumerate()
            {
                expected_comm
                    .enforce_equal(cs.ns(|| format!("enforce_equal_comm_{}_{}", i, j)), &comm)
                    .unwrap();
            }
        }

        assert!(cs.is_satisfied());
    }

    #[test]
    fn test_prepare() {
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

        let prepared_circuit_vk = circuit_vk.prepare();

        // Allocate the circuit vk gadget.
        let circuit_vk_gadget =
            CircuitVerifyingKeyVar::<_, _, _, MultiPCVar>::alloc(cs.ns(|| "alloc_vk"), || Ok(circuit_vk.clone()))
                .unwrap();

        let prepared_circuit_vk_gadget: PreparedCircuitVerifyingKeyVar<_, _, _, _, FS, FSG> =
            circuit_vk_gadget.prepare(cs.ns(|| "prepare")).unwrap();

        // Enforce that the native vk and vk gadget elements are equivalent.

        assert_eq!(
            prepared_circuit_vk.domain_h_size,
            prepared_circuit_vk_gadget.domain_h_size
        );
        assert_eq!(
            prepared_circuit_vk.domain_k_size,
            prepared_circuit_vk_gadget.domain_k_size
        );

        for (i, (prepared_commitment, prepared_commitment_gadget)) in prepared_circuit_vk
            .prepared_index_comms
            .iter()
            .zip(prepared_circuit_vk_gadget.prepared_index_comms)
            .enumerate()
        {
            let expected_prepared_commitment_gadget =
                <MultiPCVar as PCCheckVar<_, _, _>>::PreparedCommitmentVar::alloc(
                    cs.ns(|| format!("alloc_prepared_commitment_{}", i)),
                    || Ok(prepared_commitment),
                )
                .unwrap();

            for (j, (expected_comm, comm)) in expected_prepared_commitment_gadget
                .prepared_comm
                .iter()
                .zip(prepared_commitment_gadget.prepared_comm)
                .enumerate()
            {
                expected_comm
                    .enforce_equal(cs.ns(|| format!("enforce_equal_comm_{}_{}", i, j)), &comm)
                    .unwrap();
            }
        }

        assert!(cs.is_satisfied());
    }
}
