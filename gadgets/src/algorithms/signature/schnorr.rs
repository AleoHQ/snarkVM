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
    bits::{Boolean, ToBytesGadget},
    integers::uint::UInt8,
    traits::{
        algorithms::SignatureGadget,
        alloc::AllocGadget,
        curves::GroupGadget,
        eq::{ConditionalEqGadget, EqGadget},
        integers::Integer,
    },
    CryptoHashGadget,
    FpGadget,
    ToBitsLEGadget,
    ToConstraintFieldGadget,
};
use snarkvm_algorithms::{
    crypto_hash::PoseidonDefaultParametersField,
    signature::{Schnorr, SchnorrPublicKey, SchnorrSignature},
};
use snarkvm_curves::ProjectiveCurve;
use snarkvm_fields::{FieldParameters, PrimeField, ToConstraintField};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSystem};
use snarkvm_utilities::{
    serialize::{CanonicalDeserialize, CanonicalSerialize},
    to_bytes_le,
    FromBytes,
    ToBytes,
};

use crate::algorithms::crypto_hash::PoseidonCryptoHashGadget;
use itertools::Itertools;
use snarkvm_curves::AffineCurve;
use std::{borrow::Borrow, marker::PhantomData};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrPublicKeyGadget<G: ProjectiveCurve, F: PrimeField, GG: GroupGadget<G, F>> {
    pub(crate) public_key: GG,
    pub(crate) _group: PhantomData<G>,
    pub(crate) _engine: PhantomData<F>,
}

impl<G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize, F: PrimeField, GG: GroupGadget<G, F>>
    AllocGadget<SchnorrPublicKey<G>, F> for SchnorrPublicKeyGadget<G, F, GG>
{
    fn alloc<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<SchnorrPublicKey<G>>, CS: ConstraintSystem<F>>(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            public_key: GG::alloc_checked(cs, || f().map(|pk| pk.borrow().0.into_projective()))?,
            _engine: PhantomData,
            _group: PhantomData,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<SchnorrPublicKey<G>>,
        CS: ConstraintSystem<F>,
    >(
        cs: CS,
        f: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            public_key: GG::alloc_input(cs, || f().map(|pk| pk.borrow().0.into_projective()))?,
            _engine: PhantomData,
            _group: PhantomData,
        })
    }
}

impl<G: ProjectiveCurve, F: PrimeField, GG: GroupGadget<G, F>> ConditionalEqGadget<F>
    for SchnorrPublicKeyGadget<G, F, GG>
{
    #[inline]
    fn conditional_enforce_equal<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        other: &Self,
        condition: &Boolean,
    ) -> Result<(), SynthesisError> {
        self.public_key.conditional_enforce_equal(
            &mut cs.ns(|| "conditional_enforce_equal"),
            &other.public_key,
            condition,
        )?;
        Ok(())
    }

    fn cost() -> usize {
        <GG as ConditionalEqGadget<F>>::cost()
    }
}

impl<G: ProjectiveCurve, F: PrimeField, GG: GroupGadget<G, F>> EqGadget<F> for SchnorrPublicKeyGadget<G, F, GG> {}

impl<G: ProjectiveCurve, F: PrimeField, GG: GroupGadget<G, F>> ToBytesGadget<F> for SchnorrPublicKeyGadget<G, F, GG> {
    fn to_bytes<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        self.public_key.to_bytes(&mut cs.ns(|| "to_bytes"))
    }

    fn to_bytes_strict<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        self.public_key.to_bytes_strict(&mut cs.ns(|| "to_bytes_strict"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrSignatureGadget<G: ProjectiveCurve, F: PrimeField> {
    pub(crate) prover_response: FpGadget<F>,
    pub(crate) verifier_challenge: FpGadget<F>,
    pub(crate) _group: PhantomData<*const G>,
}

impl<G: ProjectiveCurve, F: PrimeField> AllocGadget<SchnorrSignature<G>, F> for SchnorrSignatureGadget<G, F> {
    fn alloc<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<SchnorrSignature<G>>, CS: ConstraintSystem<F>>(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let value = value_gen()?;
        let schnorr_output = value.borrow().clone();

        // TODO (raychu86): Check that this conversion is valid.
        //  This will work for EdwardsBls Fr and Bls12_377 Fr because they are both represented with Fp256.
        // Cast <G as Group>::ScalarField as F.
        let prover_response: F = FromBytes::read_le(&to_bytes_le![schnorr_output.prover_response]?[..])?;
        let verifier_challenge: F = FromBytes::read_le(&to_bytes_le![schnorr_output.verifier_challenge]?[..])?;

        let prover_response = FpGadget::<F>::alloc(cs.ns(|| "alloc_prover_response"), || Ok(&prover_response))?;
        let verifier_challenge =
            FpGadget::<F>::alloc(cs.ns(|| "alloc_verifier_challenge"), || Ok(&verifier_challenge))?;

        Ok(Self {
            prover_response,
            verifier_challenge,
            _group: PhantomData,
        })
    }

    fn alloc_input<
        Fn: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<SchnorrSignature<G>>,
        CS: ConstraintSystem<F>,
    >(
        mut cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        let value = value_gen()?;
        let schnorr_output = value.borrow().clone();

        // Cast <G as Group>::ScalarField as F.
        let prover_response: F = FromBytes::read_le(&to_bytes_le![schnorr_output.prover_response]?[..])?;
        let verifier_challenge: F = FromBytes::read_le(&to_bytes_le![schnorr_output.verifier_challenge]?[..])?;

        let prover_response =
            FpGadget::<F>::alloc_input(cs.ns(|| "alloc_input_prover_response"), || Ok(&prover_response))?;
        let verifier_challenge =
            FpGadget::<F>::alloc_input(cs.ns(|| "alloc_input_verifier_challenge"), || Ok(&verifier_challenge))?;

        Ok(Self {
            prover_response,
            verifier_challenge,
            _group: PhantomData,
        })
    }
}

impl<G: ProjectiveCurve, F: PrimeField> ConditionalEqGadget<F> for SchnorrSignatureGadget<G, F> {
    #[inline]
    fn conditional_enforce_equal<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        other: &Self,
        condition: &Boolean,
    ) -> Result<(), SynthesisError> {
        self.prover_response.conditional_enforce_equal(
            &mut cs.ns(|| "prover_response_conditional_enforce_equal"),
            &other.prover_response,
            condition,
        )?;
        self.verifier_challenge.conditional_enforce_equal(
            &mut cs.ns(|| "verifier_challenge_conditional_enforce_equal"),
            &other.verifier_challenge,
            condition,
        )?;
        Ok(())
    }

    fn cost() -> usize {
        <FpGadget<F> as ConditionalEqGadget<F>>::cost() * 2
    }
}

impl<G: ProjectiveCurve, F: PrimeField> EqGadget<F> for SchnorrSignatureGadget<G, F> {}

impl<G: ProjectiveCurve, F: PrimeField> ToBytesGadget<F> for SchnorrSignatureGadget<G, F> {
    fn to_bytes<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        let mut result = Vec::new();

        result.extend(
            self.prover_response
                .to_bytes(&mut cs.ns(|| "prover_response_to_bytes"))?,
        );
        result.extend(
            self.verifier_challenge
                .to_bytes(&mut cs.ns(|| "verifier_challenge_to_bytes"))?,
        );

        Ok(result)
    }

    fn to_bytes_strict<CS: ConstraintSystem<F>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        let mut result = Vec::new();

        result.extend(
            self.prover_response
                .to_bytes_strict(&mut cs.ns(|| "prover_response_to_bytes_strict"))?,
        );
        result.extend(
            self.verifier_challenge
                .to_bytes_strict(&mut cs.ns(|| "verifier_challenge_to_bytes_strict"))?,
        );

        Ok(result)
    }
}

pub struct SchnorrGadget<
    G: ProjectiveCurve,
    F: PrimeField + PoseidonDefaultParametersField,
    GG: GroupGadget<G, F> + ToConstraintFieldGadget<F>,
> {
    pub(crate) signature: Schnorr<G>,
    pub(crate) _group_gadget: PhantomData<*const GG>,
    pub(crate) _engine: PhantomData<*const F>,
}

impl<
    G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize,
    GG: GroupGadget<G, F> + ToConstraintFieldGadget<F>,
    F: PrimeField + PoseidonDefaultParametersField,
> AllocGadget<Schnorr<G>, F> for SchnorrGadget<G, F, GG>
where
    <G::Affine as AffineCurve>::BaseField: PoseidonDefaultParametersField,
    G: ToConstraintField<<G::Affine as AffineCurve>::BaseField>,
{
    fn alloc<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<Schnorr<G>>, CS: ConstraintSystem<F>>(
        _cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            signature: value_gen()?.borrow().clone(),
            _group_gadget: PhantomData,
            _engine: PhantomData,
        })
    }

    fn alloc_input<Fn: FnOnce() -> Result<T, SynthesisError>, T: Borrow<Schnorr<G>>, CS: ConstraintSystem<F>>(
        _cs: CS,
        value_gen: Fn,
    ) -> Result<Self, SynthesisError> {
        Ok(Self {
            signature: value_gen()?.borrow().clone(),
            _group_gadget: PhantomData,
            _engine: PhantomData,
        })
    }
}

impl<
    G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize,
    GG: GroupGadget<G, F> + ToConstraintFieldGadget<F>,
    F: PrimeField + PoseidonDefaultParametersField,
> SignatureGadget<Schnorr<G>, F> for SchnorrGadget<G, F, GG>
where
    <G::Affine as AffineCurve>::BaseField: PoseidonDefaultParametersField,
    G: ToConstraintField<<G::Affine as AffineCurve>::BaseField>,
    G::Affine: ToConstraintField<<G::Affine as AffineCurve>::BaseField>,
{
    type PublicKeyGadget = SchnorrPublicKeyGadget<G, F, GG>;
    type SignatureGadget = SchnorrSignatureGadget<G, F>;

    fn randomize_public_key<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        public_key: &Self::PublicKeyGadget,
        randomizer: &[UInt8],
    ) -> Result<Self::PublicKeyGadget, SynthesisError> {
        let randomness = randomizer.iter().flat_map(|b| b.to_bits_le()).collect::<Vec<_>>();

        let mut randomized_public_key = GG::zero(cs.ns(|| "zero"))?;
        randomized_public_key.scalar_multiplication(
            cs.ns(|| "check_randomization_gadget"),
            randomness.iter().zip_eq(&self.signature.generator_powers),
        )?;
        randomized_public_key = randomized_public_key.add(cs.ns(|| "pk + rG"), &public_key.public_key)?;

        Ok(SchnorrPublicKeyGadget {
            public_key: randomized_public_key,
            _group: PhantomData,
            _engine: PhantomData,
        })
    }

    // TODO (raychu86): Make the blake2s usage generic for all PRFs.
    fn verify<CS: ConstraintSystem<F>>(
        &self,
        mut cs: CS,
        public_key: &Self::PublicKeyGadget,
        message: &[UInt8],
        signature: &Self::SignatureGadget,
    ) -> Result<Boolean, SynthesisError> {
        let zero_group_gadget = GG::zero(cs.ns(|| "zero"))?;

        let prover_response_bytes = signature
            .prover_response
            .to_bytes(cs.ns(|| "prover_response_to_bytes"))?;

        let prover_response_bits = prover_response_bytes
            .iter()
            .flat_map(|byte| byte.to_bits_le())
            .collect::<Vec<_>>();
        let verifier_challenge_bits = signature
            .verifier_challenge
            .to_bits_le(cs.ns(|| "verifier_challenge_to_bits"))?;

        let mut claimed_prover_commitment = GG::zero(cs.ns(|| "zero_claimed_prover_commitment"))?;
        for (i, (bit, base_power)) in prover_response_bits
            .iter()
            .zip_eq(&self.signature.generator_powers)
            .enumerate()
        {
            let added =
                claimed_prover_commitment.add_constant(cs.ns(|| format!("add_base_power_{}", i)), base_power)?;

            claimed_prover_commitment = GG::conditionally_select(
                cs.ns(|| format!("cond_select_{}", i)),
                &bit,
                &added,
                &claimed_prover_commitment,
            )?;
        }

        let public_key_times_verifier_challenge = public_key.public_key.mul_bits(
            cs.ns(|| "record_view_key"),
            &zero_group_gadget,
            verifier_challenge_bits.into_iter(),
        )?;

        claimed_prover_commitment = claimed_prover_commitment.add(
            cs.ns(|| "claimed_prover_commitment_plus_public_key_times_verifier_challenge"),
            &public_key_times_verifier_challenge,
        )?;

        // Construct the hash
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(
            &claimed_prover_commitment
                .to_constraint_field(cs.ns(|| "convert claimed_prover_commitment into field elements"))?,
        );
        hash_input.extend_from_slice(
            &public_key
                .public_key
                .to_constraint_field(cs.ns(|| "convert public key into field elements"))?,
        );
        hash_input.push(FpGadget::<F>::Constant(F::from(message.len() as u128)));
        hash_input.extend_from_slice(&message.to_constraint_field(cs.ns(|| "convert message into field elements"))?);

        // Compute the hash on the base field
        let raw_hash =
            PoseidonCryptoHashGadget::<F, 4, false>::check_evaluation_gadget(cs.ns(|| "poseidon"), &hash_input)?;

        // Bit decompose the raw_hash
        let mut raw_hash_bits = raw_hash.to_bits_le(cs.ns(|| "convert the hash into bits"))?;
        raw_hash_bits.resize(
            <G::ScalarField as PrimeField>::Parameters::CAPACITY as usize,
            Boolean::Constant(false),
        );

        let hash = Boolean::le_bits_to_fp_var(cs.ns(|| "obtain the truncated hash"), &raw_hash_bits)?;
        let result = signature
            .verifier_challenge
            .is_eq(cs.ns(|| "check verifier challenge"), &hash)?;

        return Ok(result);
    }
}
