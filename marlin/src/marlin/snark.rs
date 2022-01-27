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

use rand::{CryptoRng, Rng};

use crate::{
    fiat_shamir::FiatShamirRng,
    marlin::{CircuitProvingKey, CircuitVerifyingKey, MarlinMode, PreparedCircuitVerifyingKey, Proof},
};
use core::sync::atomic::AtomicBool;
use snarkvm_algorithms::{crypto_hash::PoseidonDefaultParametersField, SNARKError, SNARK, SRS};
use snarkvm_fields::{PrimeField, ToConstraintField};
use snarkvm_polycommit::PolynomialCommitment;
use snarkvm_r1cs::ConstraintSynthesizer;

impl<TargetField, BaseField, PC, FS, MM, Input> SNARK
    for crate::marlin::MarlinSNARK<TargetField, BaseField, PC, FS, MM, Input>
where
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField, BaseField>,
    FS: FiatShamirRng<TargetField, BaseField>,
    MM: MarlinMode,
    Input: ToConstraintField<TargetField>,
{
    type BaseField = BaseField;
    type PreparedVerifyingKey = PreparedCircuitVerifyingKey<TargetField, BaseField, PC, MM>;
    type Proof = Proof<TargetField, BaseField, PC>;
    type ProvingKey = CircuitProvingKey<TargetField, BaseField, PC, MM>;
    type ScalarField = TargetField;
    type UniversalSetupConfig = usize;
    type UniversalSetupParameters = crate::marlin::UniversalSRS<TargetField, BaseField, PC>;
    type VerifierInput = Input;
    type VerifyingKey = CircuitVerifyingKey<TargetField, BaseField, PC, MM>;

    fn universal_setup<R: Rng + CryptoRng>(
        max_degree: &Self::UniversalSetupConfig,
        rng: &mut R,
    ) -> Result<Self::UniversalSetupParameters, SNARKError> {
        let setup_time = start_timer!(|| "{Marlin}::Setup");
        let srs = Self::universal_setup(*max_degree, rng)?;
        end_timer!(setup_time);

        Ok(srs)
    }

    fn setup<C: ConstraintSynthesizer<TargetField>, R: Rng + CryptoRng>(
        circuit: &C,
        srs: &mut SRS<R, Self::UniversalSetupParameters>,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), SNARKError> {
        match srs {
            SRS::CircuitSpecific(rng) => Self::circuit_specific_setup(circuit, rng),
            SRS::Universal(srs) => Self::circuit_setup(srs, circuit),
        }
        .map_err(SNARKError::from)
    }

    fn prove_with_terminator<C: ConstraintSynthesizer<TargetField>, R: Rng + CryptoRng>(
        parameters: &Self::ProvingKey,
        circuit: &C,
        terminator: &AtomicBool,
        rng: &mut R,
    ) -> Result<Self::Proof, SNARKError> {
        Self::prove_with_terminator(parameters, circuit, terminator, rng).map_err(SNARKError::from)
    }

    fn verify_prepared(
        prepared_verifying_key: &Self::PreparedVerifyingKey,
        input: &Self::VerifierInput,
        proof: &Self::Proof,
    ) -> Result<bool, SNARKError> {
        Self::prepared_verify(prepared_verifying_key, &input.to_field_elements()?, proof).map_err(SNARKError::from)
    }
}

#[cfg(test)]
pub mod test {
    use core::ops::MulAssign;

    use super::*;
    use crate::{
        fiat_shamir::{FiatShamirAlgebraicSpongeRng, PoseidonSponge},
        marlin::{MarlinRecursiveMode, MarlinSNARK},
    };
    use snarkvm_algorithms::SRS;
    use snarkvm_curves::bls12_377::{Bls12_377, Fq, Fr};
    use snarkvm_fields::Field;
    use snarkvm_polycommit::sonic_pc::SonicKZG10;
    use snarkvm_r1cs::{ConstraintSystem, SynthesisError};
    use snarkvm_utilities::{test_rng, UniformRand};

    const ITERATIONS: usize = 10;

    #[derive(Copy, Clone)]
    pub struct Circuit<F: Field> {
        pub a: Option<F>,
        pub b: Option<F>,
        pub num_constraints: usize,
        pub num_variables: usize,
    }

    impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for Circuit<ConstraintF> {
        fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
            let a = cs.alloc(|| "a", || self.a.ok_or(SynthesisError::AssignmentMissing))?;
            let b = cs.alloc(|| "b", || self.b.ok_or(SynthesisError::AssignmentMissing))?;
            let c = cs.alloc_input(
                || "c",
                || {
                    let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
                    let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

                    a.mul_assign(&b);
                    Ok(a)
                },
            )?;

            for i in 0..(self.num_variables - 3) {
                let _ = cs.alloc(
                    || format!("var {}", i),
                    || self.a.ok_or(SynthesisError::AssignmentMissing),
                )?;
            }

            for i in 0..(self.num_constraints - 1) {
                cs.enforce(|| format!("constraint {}", i), |lc| lc + a, |lc| lc + b, |lc| lc + c);
            }

            Ok(())
        }
    }

    type PC = SonicKZG10<Bls12_377>;
    type FS = FiatShamirAlgebraicSpongeRng<Fr, Fq, PoseidonSponge<Fq, 6, 1>>;
    type TestSNARK = MarlinSNARK<Fr, Fq, PC, FS, MarlinRecursiveMode, Vec<Fr>>;

    #[test]
    fn marlin_snark_test() {
        let mut rng = test_rng();

        for _ in 0..ITERATIONS {
            // Construct the circuit.

            let a = Fr::rand(&mut rng);
            let b = Fr::rand(&mut rng);
            let mut c = a;
            c.mul_assign(&b);

            let circ = Circuit {
                a: Some(a),
                b: Some(b),
                num_constraints: 100,
                num_variables: 25,
            };

            // Generate the circuit parameters.

            let (pk, vk) = TestSNARK::setup(&circ, &mut SRS::CircuitSpecific(&mut rng)).unwrap();

            // Test native proof and verification.

            let proof = TestSNARK::prove(&pk, &circ, &mut rng).unwrap();

            assert!(
                TestSNARK::verify(&vk.clone(), &[c], &proof).unwrap(),
                "The native verification check fails."
            );
        }
    }
}

// #[cfg(test)]
// #[allow(clippy::upper_case_acronyms)]
// pub mod multiple_input_tests {
//     use core::ops::MulAssign;

//     use super::*;
//     use crate::{
//         constraints::{
//             proof::ProofVar,
//             snark::MarlinSNARK,
//             verifier::MarlinVerificationGadget,
//             verifier_key::CircuitVerifyingKeyVar,
//         },
//         fiat_shamir::{
//             FiatShamirAlgebraicSpongeRng,
//             FiatShamirAlgebraicSpongeRngVar,
//             PoseidonSponge,
//             PoseidonSpongeGadget as PoseidonSpongeVar,
//         },
//         marlin::MarlinRecursiveMode,
//         FiatShamirRngVar,
//     };
//     use snarkvm_algorithms::SRS;
//     use snarkvm_curves::{
//         bls12_377::{Bls12_377, Fq, Fr},
//         bw6_761::BW6_761,
//     };
//     use snarkvm_fields::Field;
//     use snarkvm_gadgets::{
//         curves::bls12_377::PairingGadget as Bls12_377PairingGadget,
//         nonnative::NonNativeFieldInputVar,
//         traits::{alloc::AllocGadget, eq::EqGadget},
//         Boolean,
//         SNARKVerifierGadget,
//     };
//     use snarkvm_polycommit::{
//         sonic_pc::{sonic_kzg10::SonicKZG10Gadget, SonicKZG10},
//         PCCheckVar,
//     };
//     use snarkvm_r1cs::{ConstraintSystem, SynthesisError, TestConstraintSystem};
//     use snarkvm_utilities::{test_rng, UniformRand};

//     const ITERATIONS: usize = 10;

//     #[derive(Copy, Clone)]
//     pub struct Circuit<F: Field> {
//         pub a: Option<F>,
//         pub b: Option<F>,
//         pub num_constraints: usize,
//         pub num_variables: usize,
//     }

//     impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for Circuit<ConstraintF> {
//         fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
//             let a = cs.alloc(|| "a", || self.a.ok_or(SynthesisError::AssignmentMissing))?;
//             let b = cs.alloc(|| "b", || self.b.ok_or(SynthesisError::AssignmentMissing))?;
//             let c = cs.alloc_input(
//                 || "c",
//                 || {
//                     let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
//                     let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

//                     a.mul_assign(&b);
//                     Ok(a)
//                 },
//             )?;

//             let d = cs.alloc_input(
//                 || "d",
//                 || {
//                     let mut a = self.a.ok_or(SynthesisError::AssignmentMissing)?;
//                     let b = self.b.ok_or(SynthesisError::AssignmentMissing)?;

//                     a.mul_assign(&b);
//                     Ok(a)
//                 },
//             )?;

//             for i in 0..(self.num_variables - 3) {
//                 let _ = cs.alloc(
//                     || format!("var {}", i),
//                     || self.a.ok_or(SynthesisError::AssignmentMissing),
//                 )?;
//             }

//             for i in 0..(self.num_constraints - 1) {
//                 cs.enforce(|| format!("constraint {}", i), |lc| lc + a, |lc| lc + b, |lc| lc + c);
//             }

//             for i in 0..(self.num_constraints - 1) {
//                 cs.enforce(|| format!("constraint 2 {}", i), |lc| lc + a, |lc| lc + b, |lc| lc + d);
//             }

//             Ok(())
//         }
//     }

//     pub struct VerifierCircuit<
//         F: PrimeField,
//         ConstraintF: PrimeField + PoseidonDefaultParametersField,
//         PC: PolynomialCommitment<F, ConstraintF>,
//         FS: FiatShamirRng<F, ConstraintF>,
//         MM: MarlinMode,
//         PCG: PCCheckVar<F, PC, ConstraintF>,
//         FSG: FiatShamirRngVar<F, ConstraintF, FS>,
//     > {
//         pub c: F,
//         pub verifying_key: CircuitVerifyingKey<F, ConstraintF, PC, MM>,
//         pub proof: Proof<F, ConstraintF, PC>,
//         _f: PhantomData<ConstraintF>,
//         _fs: PhantomData<FS>,
//         _marlin_mode: PhantomData<MM>,
//         _pcg: PhantomData<PCG>,
//         _fsg: PhantomData<FSG>,
//     }

//     impl<
//         F: PrimeField,
//         ConstraintF: PrimeField + PoseidonDefaultParametersField,
//         PC: PolynomialCommitment<F, ConstraintF>,
//         FS: FiatShamirRng<F, ConstraintF>,
//         MM: MarlinMode,
//         PCG: PCCheckVar<F, PC, ConstraintF>,
//         FSG: FiatShamirRngVar<F, ConstraintF, FS>,
//     > ConstraintSynthesizer<ConstraintF> for VerifierCircuit<F, ConstraintF, PC, FS, MM, PCG, FSG>
//     {
//         fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
//             let vk_gadget = CircuitVerifyingKeyVar::<F, ConstraintF, PC, PCG, MM>::alloc(cs.ns(|| "vk"), || {
//                 Ok(self.verifying_key.clone())
//             })?;

//             let proof_gadget =
//                 ProofVar::<F, ConstraintF, PC, PCG>::alloc(cs.ns(|| "proof"), || Ok(self.proof.clone()))?;

//             let input_gadget =
//                 NonNativeFieldInputVar::<F, ConstraintF>::alloc(cs.ns(|| "input 2"), || Ok(vec![self.c, self.c]))?;

//             let output = MarlinVerificationGadget::<F, ConstraintF, PC, PCG, MM>::verify::<_, FS, FSG>(
//                 cs.ns(|| "verify"),
//                 &vk_gadget,
//                 &input_gadget.val,
//                 &proof_gadget,
//             )
//             .unwrap();

//             let expected = Boolean::Constant(true);

//             output.enforce_equal(cs.ns(|| "valid_verification"), &expected)?;

//             Ok(())
//         }
//     }

//     type PC = SonicKZG10<Bls12_377>;
//     type PCGadget = SonicKZG10Gadget<Bls12_377, BW6_761, Bls12_377PairingGadget>;

//     type FS = FiatShamirAlgebraicSpongeRng<Fr, Fq, PoseidonSponge<Fq, 6, 1>>;
//     type FSG = FiatShamirAlgebraicSpongeRngVar<Fr, Fq, PoseidonSponge<Fq, 6, 1>, PoseidonSpongeVar<Fq, 6, 1>>;

//     type TestSNARK = MarlinSNARK<Fr, Fq, PC, FS, MarlinRecursiveMode, Vec<Fr>>;
//     type TestSNARKGadget = MarlinVerificationGadget<Fr, Fq, PC, PCGadget, MarlinRecursiveMode>;

//     #[test]
//     fn two_input_marlin_snark_test() {
//         let mut rng = test_rng();

//         for _ in 0..ITERATIONS {
//             // Construct the circuit.

//             let a = Fr::rand(&mut rng);
//             let b = Fr::rand(&mut rng);
//             let mut c = a;
//             c.mul_assign(&b);

//             let circ = Circuit {
//                 a: Some(a),
//                 b: Some(b),
//                 num_constraints: 100,
//                 num_variables: 25,
//             };

//             // Generate the circuit parameters.

//             let (pk, vk) = TestSNARK::setup(&circ, &mut SRS::CircuitSpecific(&mut rng)).unwrap();

//             // Test native proof and verification.

//             let proof = TestSNARK::prove(&pk, &circ, &mut rng).unwrap();

//             assert!(
//                 TestSNARK::verify(&vk.clone(), &[c, c].to_vec(), &proof).unwrap(),
//                 "The native verification check fails."
//             );

//             // Initialize constraint system.
//             let mut cs = TestConstraintSystem::<Fq>::new();

//             let input_gadget = <TestSNARKGadget as SNARKVerifierGadget<TestSNARK>>::InputGadget::alloc_input(
//                 cs.ns(|| "alloc_input_gadget"),
//                 || Ok(vec![c, c]),
//             )
//             .unwrap();

//             let proof_gadget = <TestSNARKGadget as SNARKVerifierGadget<TestSNARK>>::ProofGadget::alloc(
//                 cs.ns(|| "alloc_proof"),
//                 || Ok(proof),
//             )
//             .unwrap();

//             let vk_gadget = <TestSNARKGadget as SNARKVerifierGadget<TestSNARK>>::VerificationKeyGadget::alloc(
//                 cs.ns(|| "alloc_vk"),
//                 || Ok(vk.clone()),
//             )
//             .unwrap();

//             assert!(
//                 cs.is_satisfied(),
//                 "Constraints not satisfied: {}",
//                 cs.which_is_unsatisfied().unwrap()
//             );

//             <TestSNARKGadget as SNARKVerifierGadget<TestSNARK>>::check_verify(
//                 cs.ns(|| "marlin_verify"),
//                 &vk_gadget,
//                 &input_gadget,
//                 &proof_gadget,
//             )
//             .unwrap();

//             assert!(
//                 cs.is_satisfied(),
//                 "Constraints not satisfied: {}",
//                 cs.which_is_unsatisfied().unwrap()
//             );

//             assert!(
//                 cs.is_satisfied(),
//                 "Constraints not satisfied: {}",
//                 cs.which_is_unsatisfied().unwrap()
//             );
//         }
//     }

//     #[test]
//     fn marlin_nested_verification_gadget_test() {
//         let mut rng = test_rng();

//         for _ in 0..ITERATIONS {
//             // Construct the circuit.

//             let a = Fr::rand(&mut rng);
//             let b = Fr::rand(&mut rng);
//             let mut c = a;
//             c.mul_assign(&b);

//             let circ = Circuit {
//                 a: Some(a),
//                 b: Some(b),
//                 num_constraints: 100,
//                 num_variables: 25,
//             };

//             // Generate the circuit parameters.

//             let (pk, vk) = TestSNARK::setup(&circ, &mut SRS::CircuitSpecific(&mut rng)).unwrap();

//             // Test native proof and verification.

//             let proof = TestSNARK::prove(&pk, &circ, &mut rng).unwrap();

//             assert!(
//                 TestSNARK::verify(&vk.clone(), &[c, c].to_vec(), &proof).unwrap(),
//                 "The native verification check fails."
//             );

//             // Initialize constraint system.
//             let mut cs = TestConstraintSystem::<Fq>::new();

//             let circuit = VerifierCircuit::<Fr, Fq, PC, FS, MarlinRecursiveMode, PCGadget, FSG> {
//                 c,
//                 verifying_key: vk,
//                 proof,
//                 _f: PhantomData,
//                 _fs: PhantomData,
//                 _marlin_mode: PhantomData,
//                 _pcg: PhantomData,
//                 _fsg: PhantomData,
//             };

//             circuit
//                 .generate_constraints(&mut cs.ns(|| "verify_within_gadget"))
//                 .unwrap();

//             assert!(
//                 cs.is_satisfied(),
//                 "Constraints not satisfied: {}",
//                 cs.which_is_unsatisfied().unwrap()
//             );
//         }
//     }

//     #[test]
//     fn marlin_test_nested_snark() {
//         let mut rng = test_rng();

//         // Construct the circuit.

//         let a = Fr::rand(&mut rng);
//         let b = Fr::rand(&mut rng);
//         let mut c = a;
//         c.mul_assign(&b);

//         let circ = Circuit {
//             a: Some(a),
//             b: Some(b),
//             num_constraints: 100,
//             num_variables: 25,
//         };

//         // Generate the circuit parameters.

//         let (pk, vk) = TestSNARK::setup(&circ, &mut SRS::CircuitSpecific(&mut rng)).unwrap();

//         // Test native proof and verification.

//         let proof = TestSNARK::prove(&pk, &circ, &mut rng).unwrap();

//         assert!(
//             TestSNARK::verify(&vk, &[c, c].to_vec(), &proof).unwrap(),
//             "The native verification check fails."
//         );

//         // Initialize constraint system.
//         let nested_circuit = VerifierCircuit::<Fr, Fq, PC, FS, MarlinRecursiveMode, PCGadget, FSG> {
//             c,
//             verifying_key: vk,
//             proof,
//             _f: PhantomData,
//             _fs: PhantomData,
//             _marlin_mode: PhantomData,
//             _pcg: PhantomData,
//             _fsg: PhantomData,
//         };

//         use snarkvm_algorithms::snark::groth16::Groth16;
//         type NestedSNARK = Groth16<BW6_761, Vec<Fq>>;

//         let (nested_pk, nested_vk) = NestedSNARK::setup(&nested_circuit, &mut SRS::CircuitSpecific(&mut rng)).unwrap();

//         // Test native proof and verification.

//         let nested_proof = NestedSNARK::prove(&nested_pk, &nested_circuit, &mut rng).unwrap();

//         assert!(
//             NestedSNARK::verify(&nested_vk, &vec![], &nested_proof).unwrap(),
//             "The native verification check fails."
//         );
//     }
// }
