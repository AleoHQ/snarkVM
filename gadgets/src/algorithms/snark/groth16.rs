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

use std::{borrow::Borrow, marker::PhantomData};

use snarkvm_algorithms::snark::groth16::{Groth16, Proof, VerifyingKey};
use snarkvm_curves::traits::{AffineCurve, PairingEngine};
use snarkvm_fields::{Field, ToConstraintField};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSynthesizer, ConstraintSystem};
use snarkvm_utilities::FromBytes;

use crate::{
    bits::{Boolean, ToBitsBEGadget, ToBytesGadget},
    integers::uint::UInt8,
    traits::{
        algorithms::snark::SNARKVerifierGadget,
        alloc::{AllocBytesGadget, AllocGadget},
        curves::{GroupGadget, PairingGadget},
        eq::EqGadget,
    },
};

#[derive(Derivative)]
#[derivative(Clone(bound = "P::G1Gadget: Clone, P::G2Gadget: Clone"))]
pub struct ProofGadget<PairingE: PairingEngine, ConstraintF: Field, P: PairingGadget<PairingE, ConstraintF>> {
    pub a: P::G1Gadget,
    pub b: P::G2Gadget,
    pub c: P::G1Gadget,
}

#[derive(Derivative)]
#[derivative(Clone(bound = "P::G1Gadget: Clone, P::GTGadget: Clone, P::G1PreparedGadget: Clone, \
             P::G2PreparedGadget: Clone, "))]
pub struct VerifyingKeyGadget<PairingE: PairingEngine, ConstraintF: Field, P: PairingGadget<PairingE, ConstraintF>> {
    pub alpha_g1: P::G1Gadget,
    pub beta_g2: P::G2Gadget,
    pub gamma_g2: P::G2Gadget,
    pub delta_g2: P::G2Gadget,
    pub gamma_abc_g1: Vec<P::G1Gadget>,
}

impl<PairingE: PairingEngine, ConstraintF: Field, P: PairingGadget<PairingE, ConstraintF>>
    VerifyingKeyGadget<PairingE, ConstraintF, P>
{
    pub fn prepare<CS: ConstraintSystem<ConstraintF>>(
        &self,
        mut cs: CS,
    ) -> Result<PreparedVerifyingKeyGadget<PairingE, ConstraintF, P>, SynthesisError> {
        let mut cs = cs.ns(|| "Preparing verifying key");
        let alpha_g1_pc = P::prepare_g1(&mut cs.ns(|| "Prepare alpha_g1"), self.alpha_g1.clone())?;
        let beta_g2_pc = P::prepare_g2(&mut cs.ns(|| "Prepare beta_g2"), self.beta_g2.clone())?;

        let alpha_g1_beta_g2 = P::pairing(
            &mut cs.ns(|| "Precompute e(alpha_g1, beta_g2)"),
            alpha_g1_pc,
            beta_g2_pc,
        )?;

        let gamma_g2_neg = self.gamma_g2.negate(&mut cs.ns(|| "Negate gamma_g2"))?;
        let gamma_g2_neg_pc = P::prepare_g2(&mut cs.ns(|| "Prepare gamma_g2_neg"), gamma_g2_neg)?;

        let delta_g2_neg = self.delta_g2.negate(&mut cs.ns(|| "Negate delta_g2"))?;
        let delta_g2_neg_pc = P::prepare_g2(&mut cs.ns(|| "Prepare delta_g2_neg"), delta_g2_neg)?;

        Ok(PreparedVerifyingKeyGadget {
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
            gamma_abc_g1: self.gamma_abc_g1.clone(),
        })
    }
}

#[derive(Derivative)]
#[derivative(Clone(
    bound = "P::G1Gadget: Clone, P::GTGadget: Clone, P::G1PreparedGadget: Clone, P::G2PreparedGadget: Clone"
))]
pub struct PreparedVerifyingKeyGadget<
    PairingE: PairingEngine,
    ConstraintF: Field,
    P: PairingGadget<PairingE, ConstraintF>,
> {
    pub alpha_g1_beta_g2: P::GTGadget,
    pub gamma_g2_neg_pc: P::G2PreparedGadget,
    pub delta_g2_neg_pc: P::G2PreparedGadget,
    pub gamma_abc_g1: Vec<P::G1Gadget>,
}

pub struct Groth16VerifierGadget<PairingE, ConstraintF, P>
where
    PairingE: PairingEngine,
    ConstraintF: Field,
    P: PairingGadget<PairingE, ConstraintF>,
{
    _pairing_engine: PhantomData<PairingE>,
    _engine: PhantomData<ConstraintF>,
    _pairing_gadget: PhantomData<P>,
}

impl<PairingE, ConstraintF, P, C, V> SNARKVerifierGadget<Groth16<PairingE, C, V>, ConstraintF>
    for Groth16VerifierGadget<PairingE, ConstraintF, P>
where
    PairingE: PairingEngine,
    ConstraintF: Field,
    C: ConstraintSynthesizer<PairingE::Fr>,
    V: ToConstraintField<PairingE::Fr>,
    P: PairingGadget<PairingE, ConstraintF>,
{
    type Input = Vec<Boolean>;
    type ProofGadget = ProofGadget<PairingE, ConstraintF, P>;
    type VerificationKeyGadget = VerifyingKeyGadget<PairingE, ConstraintF, P>;

    fn check_verify<CS: ConstraintSystem<ConstraintF>, I: Iterator<Item = Self::Input>>(
        mut cs: CS,
        vk: &Self::VerificationKeyGadget,
        mut public_inputs: I,
        proof: &Self::ProofGadget,
    ) -> Result<(), SynthesisError> {
        let pvk = vk.prepare(&mut cs.ns(|| "Prepare vk"))?;

        let PreparedVerifyingKeyGadget {
            alpha_g1_beta_g2,
            gamma_g2_neg_pc,
            delta_g2_neg_pc,
            mut gamma_abc_g1,
        } = pvk;

        let mut gamma_abc_g1_iter = gamma_abc_g1.iter_mut();

        let g_ic = {
            let mut cs = cs.ns(|| "Process input");
            let mut g_ic = gamma_abc_g1_iter.next().cloned().unwrap();
            let mut input_len = 1;
            for (i, (input, b)) in public_inputs.by_ref().zip(gamma_abc_g1_iter).enumerate() {
                let input_bits = input.to_bits_be(cs.ns(|| format!("Input {}", i)))?;
                g_ic = b.mul_bits(cs.ns(|| format!("Mul {}", i)), &g_ic, input_bits.into_iter())?;
                input_len += 1;
            }
            // Check that the input and the query in the verification are of the
            // same length.
            assert!(input_len == gamma_abc_g1.len() && public_inputs.next().is_none());
            g_ic
        };

        let test_exp = {
            let proof_a_prep = P::prepare_g1(cs.ns(|| "Prepare proof a"), proof.a.clone())?;
            let proof_b_prep = P::prepare_g2(cs.ns(|| "Prepare proof b"), proof.b.clone())?;
            let proof_c_prep = P::prepare_g1(cs.ns(|| "Prepare proof c"), proof.c.clone())?;

            let g_ic_prep = P::prepare_g1(cs.ns(|| "Prepare g_ic"), g_ic)?;

            P::miller_loop(
                cs.ns(|| "Miller loop 1"),
                &[proof_a_prep, g_ic_prep, proof_c_prep],
                &[proof_b_prep, gamma_g2_neg_pc, delta_g2_neg_pc],
            )?
        };

        let test = P::final_exponentiation(cs.ns(|| "Final Exp"), &test_exp).unwrap();

        test.enforce_equal(cs.ns(|| "Test 1"), &alpha_g1_beta_g2)?;
        Ok(())
    }
}

impl<PairingE, ConstraintF, P> AllocGadget<VerifyingKey<PairingE>, ConstraintF>
    for VerifyingKeyGadget<PairingE, ConstraintF, P>
where
    PairingE: PairingEngine,
    ConstraintF: Field,
    P: PairingGadget<PairingE, ConstraintF>,
{
    #[inline]
    fn alloc<FN, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<VerifyingKey<PairingE>>,
    {
        value_gen().and_then(|vk| {
            let VerifyingKey {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            } = vk.borrow();
            let alpha_g1 = P::G1Gadget::alloc(cs.ns(|| "alpha_g1"), || Ok(alpha_g1.into_projective()))?;
            let beta_g2 = P::G2Gadget::alloc(cs.ns(|| "beta_g2"), || Ok(beta_g2.into_projective()))?;
            let gamma_g2 = P::G2Gadget::alloc(cs.ns(|| "gamma_g2"), || Ok(gamma_g2.into_projective()))?;
            let delta_g2 = P::G2Gadget::alloc(cs.ns(|| "delta_g2"), || Ok(delta_g2.into_projective()))?;

            let gamma_abc_g1 = gamma_abc_g1
                .iter()
                .enumerate()
                .map(|(i, gamma_abc_i)| {
                    P::G1Gadget::alloc(cs.ns(|| format!("gamma_abc_{}", i)), || {
                        Ok(gamma_abc_i.into_projective())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Self {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            })
        })
    }

    #[inline]
    fn alloc_input<FN, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<VerifyingKey<PairingE>>,
    {
        value_gen().and_then(|vk| {
            let VerifyingKey {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            } = vk.borrow();
            let alpha_g1 = P::G1Gadget::alloc_input(cs.ns(|| "alpha_g1"), || Ok(alpha_g1.into_projective()))?;
            let beta_g2 = P::G2Gadget::alloc_input(cs.ns(|| "beta_g2"), || Ok(beta_g2.into_projective()))?;
            let gamma_g2 = P::G2Gadget::alloc_input(cs.ns(|| "gamma_g2"), || Ok(gamma_g2.into_projective()))?;
            let delta_g2 = P::G2Gadget::alloc_input(cs.ns(|| "delta_g2"), || Ok(delta_g2.into_projective()))?;

            let gamma_abc_g1 = gamma_abc_g1
                .iter()
                .enumerate()
                .map(|(i, gamma_abc_i)| {
                    P::G1Gadget::alloc_input(cs.ns(|| format!("gamma_abc_{}", i)), || {
                        Ok(gamma_abc_i.into_projective())
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            Ok(Self {
                alpha_g1,
                beta_g2,
                gamma_g2,
                delta_g2,
                gamma_abc_g1,
            })
        })
    }
}

impl<PairingE, ConstraintF, P> AllocBytesGadget<Vec<u8>, ConstraintF> for VerifyingKeyGadget<PairingE, ConstraintF, P>
where
    PairingE: PairingEngine,
    ConstraintF: Field,
    P: PairingGadget<PairingE, ConstraintF>,
{
    #[inline]
    fn alloc_bytes<FN, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Vec<u8>>,
    {
        value_gen().and_then(|vk_bytes| {
            let vk: VerifyingKey<PairingE> = FromBytes::read_le(&vk_bytes.borrow()[..])?;

            Self::alloc(cs.ns(|| "alloc_bytes"), || Ok(vk))
        })
    }

    #[inline]
    fn alloc_input_bytes<FN, T, CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        value_gen: FN,
    ) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Vec<u8>>,
    {
        value_gen().and_then(|vk_bytes| {
            let vk: VerifyingKey<PairingE> = FromBytes::read_le(&vk_bytes.borrow()[..])?;

            Self::alloc_input(cs.ns(|| "alloc_input_bytes"), || Ok(vk))
        })
    }
}

impl<PairingE, ConstraintF, P> AllocGadget<Proof<PairingE>, ConstraintF> for ProofGadget<PairingE, ConstraintF, P>
where
    PairingE: PairingEngine,
    ConstraintF: Field,
    P: PairingGadget<PairingE, ConstraintF>,
{
    #[inline]
    fn alloc<FN, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Proof<PairingE>>,
    {
        value_gen().and_then(|proof| {
            let Proof { a, b, c, .. } = proof.borrow();
            let a = P::G1Gadget::alloc_checked(cs.ns(|| "a"), || Ok(a.into_projective()))?;
            let b = P::G2Gadget::alloc_checked(cs.ns(|| "b"), || Ok(b.into_projective()))?;
            let c = P::G1Gadget::alloc_checked(cs.ns(|| "c"), || Ok(c.into_projective()))?;
            Ok(Self { a, b, c })
        })
    }

    #[inline]
    fn alloc_input<FN, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Proof<PairingE>>,
    {
        value_gen().and_then(|proof| {
            let Proof { a, b, c, .. } = proof.borrow();
            // We don't need to check here because the prime order check can be performed
            // in plain.
            let a = P::G1Gadget::alloc_input(cs.ns(|| "a"), || Ok(a.into_projective()))?;
            let b = P::G2Gadget::alloc_input(cs.ns(|| "b"), || Ok(b.into_projective()))?;
            let c = P::G1Gadget::alloc_input(cs.ns(|| "c"), || Ok(c.into_projective()))?;
            Ok(Self { a, b, c })
        })
    }
}

impl<PairingE, ConstraintF, P> AllocBytesGadget<Vec<u8>, ConstraintF> for ProofGadget<PairingE, ConstraintF, P>
where
    PairingE: PairingEngine,
    ConstraintF: Field,
    P: PairingGadget<PairingE, ConstraintF>,
{
    #[inline]
    fn alloc_bytes<FN, T, CS: ConstraintSystem<ConstraintF>>(mut cs: CS, value_gen: FN) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Vec<u8>>,
    {
        value_gen().and_then(|proof_bytes| {
            let proof: Proof<PairingE> = FromBytes::read_le(&proof_bytes.borrow()[..])?;

            Self::alloc(cs.ns(|| "alloc_bytes"), || Ok(proof))
        })
    }

    #[inline]
    fn alloc_input_bytes<FN, T, CS: ConstraintSystem<ConstraintF>>(
        mut cs: CS,
        value_gen: FN,
    ) -> Result<Self, SynthesisError>
    where
        FN: FnOnce() -> Result<T, SynthesisError>,
        T: Borrow<Vec<u8>>,
    {
        value_gen().and_then(|proof_bytes| {
            let proof: Proof<PairingE> = FromBytes::read_le(&proof_bytes.borrow()[..])?;

            Self::alloc_input(cs.ns(|| "alloc_input_bytes"), || Ok(proof))
        })
    }
}

impl<PairingE, ConstraintF, P> ToBytesGadget<ConstraintF> for VerifyingKeyGadget<PairingE, ConstraintF, P>
where
    PairingE: PairingEngine,
    ConstraintF: Field,
    P: PairingGadget<PairingE, ConstraintF>,
{
    #[inline]
    fn to_bytes<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.alpha_g1.to_bytes(&mut cs.ns(|| "alpha_g1 to bytes"))?);
        bytes.extend_from_slice(&self.beta_g2.to_bytes(&mut cs.ns(|| "beta_g2 to bytes"))?);
        bytes.extend_from_slice(&self.gamma_g2.to_bytes(&mut cs.ns(|| "gamma_g2 to bytes"))?);
        bytes.extend_from_slice(&self.delta_g2.to_bytes(&mut cs.ns(|| "delta_g2 to bytes"))?);
        bytes.extend_from_slice(&UInt8::alloc_vec(
            &mut cs.ns(|| "gamma_abc_g1_length"),
            &(self.gamma_abc_g1.len() as u32).to_le_bytes()[..],
        )?);
        for (i, g) in self.gamma_abc_g1.iter().enumerate() {
            let mut cs = cs.ns(|| format!("Iteration {}", i));
            bytes.extend_from_slice(&g.to_bytes(&mut cs.ns(|| "g"))?);
        }
        Ok(bytes)
    }

    #[inline]
    fn to_bytes_strict<CS: ConstraintSystem<ConstraintF>>(&self, mut cs: CS) -> Result<Vec<UInt8>, SynthesisError> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.alpha_g1.to_bytes_strict(&mut cs.ns(|| "alpha_g1 to bytes"))?);
        bytes.extend_from_slice(&self.beta_g2.to_bytes_strict(&mut cs.ns(|| "beta_g2 to bytes"))?);
        bytes.extend_from_slice(&self.gamma_g2.to_bytes_strict(&mut cs.ns(|| "gamma_g2 to bytes"))?);
        bytes.extend_from_slice(&self.delta_g2.to_bytes_strict(&mut cs.ns(|| "delta_g2 to bytes"))?);
        bytes.extend_from_slice(&UInt8::alloc_vec(
            &mut cs.ns(|| "gamma_abc_g1_length"),
            &(self.gamma_abc_g1.len() as u32).to_le_bytes()[..],
        )?);
        for (i, g) in self.gamma_abc_g1.iter().enumerate() {
            let mut cs = cs.ns(|| format!("Iteration {}", i));
            bytes.extend_from_slice(&g.to_bytes_strict(&mut cs.ns(|| "g"))?);
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use rand::Rng;

    use snarkvm_algorithms::snark::groth16::*;
    use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
    use snarkvm_fields::PrimeField;
    use snarkvm_r1cs::{ConstraintSynthesizer, ConstraintSystem, TestConstraintSystem};
    use snarkvm_utilities::{test_rng, to_bytes_le, BitIteratorBE, ToBytes};

    use crate::{bits::Boolean, curves::bls12_377::PairingGadget as Bls12_377PairingGadget};

    use super::*;

    type TestProofSystem = Groth16<Bls12_377, Bench<Fr>, Fr>;
    type TestVerifierGadget = Groth16VerifierGadget<Bls12_377, Fq, Bls12_377PairingGadget>;
    type TestProofGadget = ProofGadget<Bls12_377, Fq, Bls12_377PairingGadget>;
    type TestVkGadget = VerifyingKeyGadget<Bls12_377, Fq, Bls12_377PairingGadget>;

    struct Bench<F: Field> {
        inputs: Vec<Option<F>>,
        num_constraints: usize,
    }

    impl<F: Field> ConstraintSynthesizer<F> for Bench<F> {
        fn generate_constraints<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
            assert!(self.inputs.len() >= 2);
            assert!(self.num_constraints >= self.inputs.len());

            let mut variables: Vec<_> = Vec::with_capacity(self.inputs.len());
            for (i, input) in self.inputs.iter().cloned().enumerate() {
                let input_var = cs.alloc_input(
                    || format!("Input {}", i),
                    || input.ok_or(SynthesisError::AssignmentMissing),
                )?;
                variables.push((input, input_var));
            }

            for i in 0..self.num_constraints {
                let new_entry = {
                    let (input_1_val, input_1_var) = variables[i];
                    let (input_2_val, input_2_var) = variables[i + 1];
                    let result_val = input_1_val.and_then(|input_1| input_2_val.map(|input_2| input_1 * input_2));
                    let result_var = cs.alloc(
                        || format!("Result {}", i),
                        || result_val.ok_or(SynthesisError::AssignmentMissing),
                    )?;
                    cs.enforce(
                        || format!("Enforce constraint {}", i),
                        |lc| lc + input_1_var,
                        |lc| lc + input_2_var,
                        |lc| lc + result_var,
                    );
                    (result_val, result_var)
                };
                variables.push(new_entry);
            }
            Ok(())
        }
    }

    #[test]
    fn groth16_verifier_test() {
        let num_inputs = 100;
        let num_constraints = num_inputs;
        let rng = &mut test_rng();
        let mut inputs: Vec<Option<Fr>> = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            inputs.push(Some(rng.gen()));
        }
        let params = {
            let c = Bench::<Fr> {
                inputs: vec![None; num_inputs],
                num_constraints,
            };

            generate_random_parameters(&c, rng).unwrap()
        };

        {
            let proof = {
                // Create an instance of our circuit (with the
                // witness)
                let c = Bench {
                    inputs: inputs.clone(),
                    num_constraints,
                };
                // Create a groth16 proof with our parameters.
                create_random_proof(&c, &params, rng).unwrap()
            };

            // assert!(!verify_proof(&pvk, &proof, &[a]).unwrap());
            let mut cs = TestConstraintSystem::<Fq>::new();

            let inputs = inputs.into_iter().map(|input| input.unwrap());
            let mut input_gadgets = Vec::new();

            {
                let mut cs = cs.ns(|| "Allocate Input");
                for (i, input) in inputs.enumerate() {
                    let mut input_bits = BitIteratorBE::new(input.to_repr()).collect::<Vec<_>>();
                    // Input must be in little-endian, but BitIterator outputs in big-endian.
                    input_bits.reverse();

                    let input_bits =
                        Vec::<Boolean>::alloc_input(cs.ns(|| format!("Input {}", i)), || Ok(input_bits)).unwrap();
                    input_gadgets.push(input_bits);
                }
            }

            let vk_gadget = TestVkGadget::alloc_input(cs.ns(|| "Vk"), || Ok(&params.vk)).unwrap();
            let proof_gadget = TestProofGadget::alloc(cs.ns(|| "Proof"), || Ok(proof.clone())).unwrap();
            println!("Time to verify!\n\n\n\n");
            <TestVerifierGadget as SNARKVerifierGadget<TestProofSystem, Fq>>::check_verify(
                cs.ns(|| "Verify"),
                &vk_gadget,
                input_gadgets.iter().cloned(),
                &proof_gadget,
            )
            .unwrap();
            if !cs.is_satisfied() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{:?}", cs.which_is_unsatisfied().unwrap());
                println!("=========================================================");
            }

            // cs.print_named_objects();
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn groth16_verifier_bytes_test() {
        let num_inputs = 100;
        let num_constraints = num_inputs;
        let rng = &mut test_rng();
        let mut inputs: Vec<Option<Fr>> = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            inputs.push(Some(rng.gen()));
        }
        let params = {
            let c = Bench::<Fr> {
                inputs: vec![None; num_inputs],
                num_constraints,
            };

            generate_random_parameters::<Bls12_377, _, _>(&c, rng).unwrap()
        };

        {
            let proof = {
                // Create an instance of our circuit (with the
                // witness)
                let c = Bench {
                    inputs: inputs.clone(),
                    num_constraints,
                };
                // Create a groth16 proof with our parameters.
                create_random_proof(&c, &params, rng).unwrap()
            };

            // assert!(!verify_proof(&pvk, &proof, &[a]).unwrap());
            let mut cs = TestConstraintSystem::<Fq>::new();

            let inputs: Vec<_> = inputs.into_iter().map(|input| input.unwrap()).collect();
            let mut input_gadgets = Vec::new();

            {
                let mut cs = cs.ns(|| "Allocate Input");
                for (i, input) in inputs.into_iter().enumerate() {
                    let mut input_bits = BitIteratorBE::new(input.to_repr()).collect::<Vec<_>>();
                    // Input must be in little-endian, but BitIterator outputs in big-endian.
                    input_bits.reverse();

                    let input_bits =
                        Vec::<Boolean>::alloc_input(cs.ns(|| format!("Input {}", i)), || Ok(input_bits)).unwrap();
                    input_gadgets.push(input_bits);
                }
            }

            let vk_bytes = to_bytes_le![params.vk].unwrap();
            let proof_bytes = to_bytes_le![proof].unwrap();

            let vk_gadget = TestVkGadget::alloc_input_bytes(cs.ns(|| "Vk"), || Ok(vk_bytes)).unwrap();
            let proof_gadget = TestProofGadget::alloc_bytes(cs.ns(|| "Proof"), || Ok(proof_bytes)).unwrap();
            println!("Time to verify!\n\n\n\n");
            <TestVerifierGadget as SNARKVerifierGadget<TestProofSystem, Fq>>::check_verify(
                cs.ns(|| "Verify"),
                &vk_gadget,
                input_gadgets.iter().cloned(),
                &proof_gadget,
            )
            .unwrap();
            if !cs.is_satisfied() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{:?}", cs.which_is_unsatisfied().unwrap());
                println!("=========================================================");
            }

            // cs.print_named_objects();
            assert!(cs.is_satisfied());
        }
    }

    #[test]
    fn groth16_verifier_num_constraints_test() {
        let num_inputs = 100;
        let num_constraints = num_inputs;
        let rng = &mut test_rng();
        let mut inputs: Vec<Option<Fr>> = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            inputs.push(Some(rng.gen()));
        }
        let params = {
            let c = Bench::<Fr> {
                inputs: vec![None; num_inputs],
                num_constraints,
            };

            generate_random_parameters(&c, rng).unwrap()
        };

        {
            let proof = {
                // Create an instance of our circuit (with the
                // witness)
                let c = Bench {
                    inputs: inputs.clone(),
                    num_constraints,
                };
                // Create a groth16 proof with our parameters.
                create_random_proof(&c, &params, rng).unwrap()
            };

            // assert!(!verify_proof(&pvk, &proof, &[a]).unwrap());
            let mut cs = TestConstraintSystem::<Fq>::new();

            let inputs = inputs.into_iter().map(|input| input.unwrap());
            let mut input_gadgets = Vec::new();

            {
                let mut cs = cs.ns(|| "Allocate Input");
                for (i, input) in inputs.enumerate() {
                    let mut input_bits = BitIteratorBE::new(input.to_repr()).collect::<Vec<_>>();
                    // Input must be in little-endian, but BitIterator outputs in big-endian.
                    input_bits.reverse();

                    let input_bits =
                        Vec::<Boolean>::alloc_input(cs.ns(|| format!("Input {}", i)), || Ok(input_bits)).unwrap();
                    input_gadgets.push(input_bits);
                }
            }

            let input_gadget_constraints = cs.num_constraints();

            let vk_gadget = TestVkGadget::alloc_input(cs.ns(|| "Vk"), || Ok(&params.vk)).unwrap();

            let vk_gadget_constraints = cs.num_constraints() - input_gadget_constraints;

            let proof_gadget = TestProofGadget::alloc(cs.ns(|| "Proof"), || Ok(proof.clone())).unwrap();

            let proof_gadget_constraints = cs.num_constraints() - vk_gadget_constraints;

            <TestVerifierGadget as SNARKVerifierGadget<TestProofSystem, Fq>>::check_verify(
                cs.ns(|| "Verify"),
                &vk_gadget,
                input_gadgets.iter().cloned(),
                &proof_gadget,
            )
            .unwrap();

            let verifier_gadget_constraints = cs.num_constraints() - proof_gadget_constraints;

            if !cs.is_satisfied() {
                println!("=========================================================");
                println!("Unsatisfied constraints:");
                println!("{:?}", cs.which_is_unsatisfied().unwrap());
                println!("=========================================================");
            }

            // cs.print_named_objects();
            assert!(cs.is_satisfied());

            println!("input_gadget_constraints : {:?}", input_gadget_constraints);
            println!("vk_gadget_constraints : {:?}", vk_gadget_constraints);
            println!("proof_gadget_constraints : {:?}", proof_gadget_constraints);
            println!("verifier_gadget_constraints : {:?}", verifier_gadget_constraints);

            const INPUT_GADGET_CONSTRAINTS: usize = 25600;
            const VK_GADGET_CONSTRAINTS: usize = 105;
            const PROOF_GADGET_CONSTRAINTS: usize = 30199;
            const VERIFIER_GADGET_CONSTRAINTS: usize = 316635;

            assert_eq!(input_gadget_constraints, INPUT_GADGET_CONSTRAINTS);
            assert_eq!(vk_gadget_constraints, VK_GADGET_CONSTRAINTS);
            assert_eq!(proof_gadget_constraints, PROOF_GADGET_CONSTRAINTS);
            assert_eq!(verifier_gadget_constraints, VERIFIER_GADGET_CONSTRAINTS);
        }
    }
}
