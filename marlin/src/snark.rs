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

//! Marlin adapted for the SnarkOS SNARK trait
use snarkvm_errors::{algorithms::SNARKError, serialization::SerializationError};
use snarkvm_models::{
    algorithms::SNARK,
    curves::{to_field_vec::ToConstraintField, AffineCurve, PairingEngine},
    gadgets::r1cs::ConstraintSynthesizer,
};
use snarkvm_profiler::{end_timer, start_timer};
use snarkvm_utilities::{
    bytes::{FromBytes, ToBytes},
    error,
    io,
    serialize::*,
};

pub use snarkvm_polycommit::{marlin_pc::MarlinKZG10 as MultiPC, PCCommitment};

use blake2::Blake2s;
use derivative::Derivative;
use rand_core::RngCore;
use rayon::prelude::*;
use std::{
    io::{Read, Write},
    marker::PhantomData,
};

// Instantiated type aliases for convenience
/// A structured reference string which will be used to derive a circuit-specific
/// common reference string
pub type SRS<E> = crate::UniversalSRS<<E as PairingEngine>::Fr, MultiPC<E>>;

/// Type alias for a Marlin instance using the KZG10 polynomial commitment and Blake2s
pub type Marlin<E> = crate::Marlin<<E as PairingEngine>::Fr, MultiPC<E>, Blake2s>;

type VerifierKey<E, C> = crate::IndexVerifierKey<<E as PairingEngine>::Fr, MultiPC<E>, C>;
type ProverKey<'a, E, C> = crate::IndexProverKey<'a, <E as PairingEngine>::Fr, MultiPC<E>, C>;
type Proof<E, C> = crate::Proof<<E as PairingEngine>::Fr, MultiPC<E>, C>;

/// SnarkOS-compatible Marlin
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarlinSnark<'a, E, C, V>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    V: ToConstraintField<E::Fr>,
{
    _engine: PhantomData<E>,
    _circuit: PhantomData<C>,
    _verifier_input: PhantomData<V>,
    _key_lifetime: PhantomData<&'a ProverKey<'a, E, C>>,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "C: 'a"))]
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
/// The public parameters used for the circuit's instantiation.
/// Generating the parameters is done via the `setup` function of the SNARK trait
/// by providing it the previously generated universal srs.
pub struct Parameters<'a, E, C>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
{
    /// The proving key
    pub prover_key: ProverKey<'a, E, C>,
    /// The verifying key
    pub verifier_key: VerifierKey<E, C>,
}

impl<'a, E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> FromBytes for Parameters<'a, E, C> {
    fn read<R: Read>(mut r: R) -> io::Result<Self> {
        use snarkvm_utilities::{PROCESSING_SNARK_PARAMS, SNARK_PARAMS_AFFINE_COUNT};
        use std::sync::atomic::{self, AtomicU64};

        // signal that the SNARK params are being processed in order for the validation of affine values to be
        // deferred, while ensuring that this method is not called recursively; the expected number of entries is
        // counted with a thread-local SNARK_PARAMS_AFFINE_COUNT, which does not support recursion in its current form
        let only_entry = PROCESSING_SNARK_PARAMS
            .with(|p| p.compare_exchange(false, true, atomic::Ordering::Relaxed, atomic::Ordering::Relaxed));
        debug_assert_eq!(only_entry, Ok(false), "recursive deserialization of Parameters");

        // perform the deserialization which will initially omit the validation of affine values
        let ret: Self =
            CanonicalDeserialize::deserialize(&mut r).map_err(|_| error("could not deserialize parameters"))?;

        // signal that all the other affine validation should be performed eagerly back again
        PROCESSING_SNARK_PARAMS.with(|p| p.store(false, atomic::Ordering::Relaxed));

        // retrieve the thread-local SNARK_PARAMS_AFFINE_COUNT and make it rayon-friendly
        let num_affines_to_verify =
            AtomicU64::new(SNARK_PARAMS_AFFINE_COUNT.with(|p| p.load(atomic::Ordering::Relaxed)));

        // check the affine values for the CommitterKey
        let ck = &ret.prover_key.committer_key;

        ck.powers.par_iter().try_for_each(|p| {
            num_affines_to_verify.fetch_sub(1, atomic::Ordering::Relaxed);
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                Err(error("invalid parameter data"))
            } else {
                Ok(())
            }
        })?;

        if let Some(shifted_powers) = &ck.shifted_powers {
            shifted_powers.par_iter().try_for_each(|p| {
                num_affines_to_verify.fetch_sub(1, atomic::Ordering::Relaxed);
                if !p.is_in_correct_subgroup_assuming_on_curve() {
                    Err(error("invalid parameter data"))
                } else {
                    Ok(())
                }
            })?;
        }

        ck.powers_of_gamma_g.par_iter().try_for_each(|p| {
            num_affines_to_verify.fetch_sub(1, atomic::Ordering::Relaxed);
            if !p.is_in_correct_subgroup_assuming_on_curve() {
                Err(error("invalid parameter data"))
            } else {
                Ok(())
            }
        })?;

        // there are 2 IndexVerifierKeys in the Parameters
        for vk in &[&ret.prover_key.index_vk, &ret.verifier_key] {
            // check the affine values for marlin::IndexVerifierKey
            for comm in &vk.index_comms {
                num_affines_to_verify.fetch_sub(1, atomic::Ordering::Relaxed);
                if !comm.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(error("invalid parameter data"));
                }

                if comm.has_degree_bound() {
                    num_affines_to_verify.fetch_sub(1, atomic::Ordering::Relaxed);
                }
            }

            // check the affine values for marlin_pc::VerifierKey
            if let Some(dbasp) = &vk.verifier_key.degree_bounds_and_shift_powers {
                for (_, p) in dbasp {
                    num_affines_to_verify.fetch_sub(1, atomic::Ordering::Relaxed);
                    if !p.is_in_correct_subgroup_assuming_on_curve() {
                        return Err(error("invalid parameter data"));
                    }
                }
            }

            // check the affine values for kzg10::VerifierKey
            for g in &[vk.verifier_key.vk.g, vk.verifier_key.vk.gamma_g] {
                num_affines_to_verify.fetch_sub(1, atomic::Ordering::Relaxed);
                if !g.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(error("invalid parameter data"));
                }
            }
            for h in &[vk.verifier_key.vk.h, vk.verifier_key.vk.beta_h] {
                num_affines_to_verify.fetch_sub(1, atomic::Ordering::Relaxed);
                if !h.is_in_correct_subgroup_assuming_on_curve() {
                    return Err(error("invalid parameter data"));
                }
            }
        }

        // this check ensures that all the deferred validation has been accounted for, i.e. that
        // there were no affine values belonging to the Parameters object that were not validated
        debug_assert_eq!(num_affines_to_verify.load(atomic::Ordering::Relaxed), 0);

        Ok(ret)
    }
}

impl<'a, E: PairingEngine, C: ConstraintSynthesizer<E::Fr>> ToBytes for Parameters<'a, E, C> {
    fn write<W: Write>(&self, mut w: W) -> io::Result<()> {
        CanonicalSerialize::serialize(self, &mut w).map_err(|_| error("could not serialize parameters"))
    }
}

impl<'a, E, C> Parameters<'a, E, C>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
{
    /// Creates a new Parameters instance from a previously computed universal SRS
    pub fn new(circuit: &C, universal_srs: &SRS<E>) -> Result<Self, SNARKError> {
        let (prover_key, verifier_key) = Marlin::index(universal_srs, circuit)
            .map_err(|error| SNARKError::Crate("marlin", format!("could not index: {:?}", error)))?;
        Ok(Self {
            prover_key,
            verifier_key,
        })
    }
}

impl<'a, E, C> From<Parameters<'a, E, C>> for VerifierKey<E, C>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
{
    fn from(params: Parameters<'a, E, C>) -> Self {
        params.verifier_key
    }
}

impl<'a, E, C, V> SNARK for MarlinSnark<'a, E, C, V>
where
    E: PairingEngine,
    C: ConstraintSynthesizer<E::Fr>,
    V: ToConstraintField<E::Fr>,
{
    type AssignedCircuit = C;
    type Circuit = (C, SRS<E>);
    // Abuse the Circuit type to pass the SRS as well.
    type PreparedVerificationParameters = VerifierKey<E, C>;
    type Proof = Proof<E, C>;
    type ProvingParameters = Parameters<'a, E, C>;
    type VerificationParameters = VerifierKey<E, C>;
    type VerifierInput = V;

    fn setup<R: RngCore>(
        (circuit, srs): &Self::Circuit,
        _rng: &mut R, // The Marlin Setup is deterministic
    ) -> Result<(Self::ProvingParameters, Self::PreparedVerificationParameters), SNARKError> {
        let setup_time = start_timer!(|| "{Marlin}::Setup");
        let parameters = Parameters::<E, C>::new(circuit, srs)?;
        end_timer!(setup_time);
        let verifier_key = parameters.verifier_key.clone();
        Ok((parameters, verifier_key))
    }

    fn prove<R: RngCore>(
        pp: &Self::ProvingParameters,
        circuit: &Self::AssignedCircuit,
        rng: &mut R,
    ) -> Result<Self::Proof, SNARKError> {
        let proving_time = start_timer!(|| "{Marlin}::Proving");
        let proof = Marlin::prove(&pp.prover_key, circuit, rng)
            .map_err(|_| SNARKError::Crate("marlin", "Could not generate proof".to_owned()))?;
        end_timer!(proving_time);
        Ok(proof)
    }

    fn verify(
        vk: &Self::PreparedVerificationParameters,
        input: &Self::VerifierInput,
        proof: &Self::Proof,
    ) -> Result<bool, SNARKError> {
        let verification_time = start_timer!(|| "{Marlin}::Verifying");
        let res = Marlin::verify(&vk, &input.to_field_elements()?, &proof, &mut rand_core::OsRng)
            .map_err(|_| SNARKError::Crate("marlin", "Could not verify proof".to_owned()))?;
        end_timer!(verification_time);

        Ok(res)
    }
}
