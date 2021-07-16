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

use super::{PreparedVerifyingKey, Proof, VerifyingKey};
use snarkvm_curves::traits::{PairingCurve, PairingEngine};
use snarkvm_r1cs::errors::SynthesisError;

use core::ops::{AddAssign, Mul, Neg};
use rand::RngCore;
use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::One;
use snarkvm_utilities::UniformRand;

pub fn prepare_verifying_key<E: PairingEngine>(vk: VerifyingKey<E>) -> PreparedVerifyingKey<E> {
    let alpha_g1_beta_g2 = E::pairing(vk.alpha_g1, vk.beta_g2);
    let gamma_g2_neg_pc = vk.gamma_g2.neg().prepare();
    let delta_g2_neg_pc = vk.delta_g2.neg().prepare();

    PreparedVerifyingKey {
        vk,
        alpha_g1_beta_g2,
        gamma_g2_neg_pc,
        delta_g2_neg_pc,
    }
}

pub fn verify_proof<E: PairingEngine>(
    pvk: &PreparedVerifyingKey<E>,
    proof: &Proof<E>,
    public_inputs: &[E::Fr],
) -> Result<bool, SynthesisError> {
    if (public_inputs.len() + 1) != pvk.gamma_abc_g1().len() {
        return Err(SynthesisError::MalformedVerifyingKey);
    }

    let mut g_ic = pvk.gamma_abc_g1()[0].into_projective();
    for (i, b) in public_inputs.iter().zip(pvk.gamma_abc_g1().iter().skip(1)) {
        g_ic.add_assign(b.into_projective().mul(*i));
    }

    let qap = E::miller_loop(
        [
            (&proof.a.prepare(), &proof.b.prepare()),
            (&g_ic.into_affine().prepare(), &pvk.gamma_g2_neg_pc),
            (&proof.c.prepare(), &pvk.delta_g2_neg_pc),
        ]
        .iter()
        .copied(),
    );

    let test = E::final_exponentiation(&qap).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test == pvk.alpha_g1_beta_g2)
}

pub fn batch_verify_proof<E: PairingEngine, R: RngCore>(
    pvk: &PreparedVerifyingKey<E>,
    proofs: &[Proof<E>],
    public_inputs: &[Vec<E::Fr>],
    mut rng: R,
) -> Result<bool, SynthesisError> {
    assert_eq!(proofs.len(), public_inputs.len());

    let mut r_powers = Vec::with_capacity(proofs.len());
    for _ in 0..proofs.len() {
        let challenge: E::Fr = u128::rand(&mut rng).into();
        r_powers.push(challenge);
    }

    let combined_inputs = {
        let randomized_inputs = public_inputs
            .iter()
            .zip(&r_powers)
            .map(|(input, r)| {
                let mut g_ic = pvk.vk.gamma_abc_g1[0].into_projective();
                for (i, b) in input.iter().zip(pvk.vk.gamma_abc_g1.iter().skip(1)) {
                    g_ic += &b.into_projective().mul(*i);
                }
                g_ic.mul(*r)
            })
            .collect::<Vec<E::G1Projective>>();

        let mut combined_inputs = randomized_inputs[0];
        for randomized_input in randomized_inputs.iter().skip(1) {
            combined_inputs += randomized_input;
        }
        combined_inputs
    };

    let combined_proof_a_s = proofs
        .iter()
        .zip(&r_powers)
        .map(|(proof, r)| proof.a.into_projective().mul(*r))
        .collect::<Vec<_>>();
    let combined_proof_a_s = E::G1Projective::batch_normalization_into_affine(combined_proof_a_s);
    let ml_inputs = proofs
        .iter()
        .zip(&combined_proof_a_s)
        .map(|(proof, a)| ((*a).prepare(), proof.b.prepare()))
        .collect::<Vec<_>>();
    let ml_inputs_ref = ml_inputs.iter().map(|(a, b)| (a, b)).collect::<Vec<_>>();
    let a_r_times_b = E::miller_loop(ml_inputs_ref.iter().cloned());

    let combined_c_s = {
        let randomized_cs = proofs
            .iter()
            .zip(&r_powers)
            .map(|(proof, r)| proof.c.into_projective().mul(*r))
            .collect::<Vec<E::G1Projective>>();

        let mut combined_c_s = randomized_cs[0];
        for randomized_c in randomized_cs.iter().skip(1) {
            combined_c_s += randomized_c;
        }
        combined_c_s
    };

    let sum_of_rs = (&r_powers).iter().copied().sum::<E::Fr>();
    let combined_alpha = -pvk.vk.alpha_g1.mul(sum_of_rs);
    let qap = E::miller_loop(
        [
            (&combined_alpha.prepare(), &pvk.vk.beta_g2.prepare()),
            (&combined_inputs.into_affine().prepare(), &pvk.gamma_g2_neg_pc),
            (&combined_c_s.into_affine().prepare(), &pvk.delta_g2_neg_pc),
        ]
        .iter()
        .cloned(),
    );

    let test = E::final_exponentiation(&(qap * &a_r_times_b)).ok_or(SynthesisError::UnexpectedIdentity)?;

    Ok(test == E::Fqk::one())
}
