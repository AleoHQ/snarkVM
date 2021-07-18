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

use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use rand::{CryptoRng, Rng, RngCore};

use snarkvm_algorithms::{crypto_hash::PoseidonDefaultParametersField, Prepare, SNARKError, SNARK};
use snarkvm_fields::{PrimeField, ToConstraintField};
use snarkvm_gadgets::{
    bits::Boolean,
    nonnative::NonNativeFieldInputVar,
    traits::{algorithms::SNARKGadget, fields::ToConstraintFieldGadget},
};
use snarkvm_polycommit::{PCCheckVar, PolynomialCommitment};
use snarkvm_r1cs::{ConstraintSynthesizer, ConstraintSystem, LinearCombination, SynthesisError, Variable};

use crate::{
    constraints::{
        error::MarlinConstraintsError,
        proof::ProofVar,
        verifier::MarlinVerificationGadget,
        verifier_key::{CircuitVerifyingKeyVar, PreparedCircuitVerifyingKeyVar},
        UniversalSRS,
    },
    fiat_shamir::FiatShamirRng,
    marlin::{
        CircuitProvingKey,
        CircuitVerifyingKey,
        MarlinError,
        MarlinMode,
        MarlinSNARK as MarlinCore,
        PreparedCircuitVerifyingKey,
        Proof,
    },
    FiatShamirRngVar,
};

/// Marlin bound.
#[derive(Clone, PartialEq, PartialOrd)]
pub struct MarlinBound {
    /// Maximum degree for universal setup.
    pub max_degree: usize,
}

impl Default for MarlinBound {
    fn default() -> Self {
        Self { max_degree: 200000 }
    }
}

impl Debug for MarlinBound {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.max_degree)
    }
}

/// The Marlin proof system.
pub struct MarlinSNARK<
    F: PrimeField,
    FSF: PrimeField,
    PC: PolynomialCommitment<F>,
    FS: FiatShamirRng<F, FSF>,
    MC: MarlinMode,
    C: ConstraintSynthesizer<F>,
    V: ToConstraintField<F>,
> {
    f_phantom: PhantomData<F>,
    fsf_phantom: PhantomData<FSF>,
    pc_phantom: PhantomData<PC>,
    fs_phantom: PhantomData<FS>,
    mc_phantom: PhantomData<MC>,
    c_phantom: PhantomData<C>,
    v_phantom: PhantomData<V>,
}

impl<TargetField, BaseField, PC, FS, MM, C, V> MarlinSNARK<TargetField, BaseField, PC, FS, MM, C, V>
where
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    FS: FiatShamirRng<TargetField, BaseField>,
    MM: MarlinMode,
    PC::VerifierKey: ToConstraintField<BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
    C: ConstraintSynthesizer<TargetField>,
    V: ToConstraintField<TargetField>,
{
    /// Generates the universal proving and verifying keys for the argument system.
    pub fn universal_setup<R: Rng>(
        bound: &MarlinBound,
        rng: &mut R,
    ) -> Result<(MarlinBound, UniversalSRS<TargetField, PC>), Box<MarlinConstraintsError>> {
        let MarlinBound { max_degree } = bound;

        match MarlinCore::<TargetField, BaseField, PC, FS, MM>::universal_setup(1, 1, (max_degree + 5) / 3, rng) {
            Ok(res) => Ok((bound.clone(), res)),
            Err(e) => Err(Box::new(MarlinConstraintsError::from(e))),
        }
    }

    /// Generates the circuit proving and verifying keys.
    /// This is a deterministic algorithm that anyone can rerun.
    #[allow(clippy::type_complexity)]
    pub fn index<R: RngCore>(
        crs: &(MarlinBound, UniversalSRS<TargetField, PC>),
        circuit: C,
        _rng: &mut R,
    ) -> Result<(<Self as SNARK>::ProvingKey, <Self as SNARK>::VerifyingKey), Box<MarlinConstraintsError>> {
        let index_res = MarlinCore::<TargetField, BaseField, PC, FS, MM>::circuit_setup(&crs.1, &circuit);
        match index_res {
            Ok(res) => Ok(res),
            Err(e) => Err(Box::new(MarlinError::from(e).into())),
        }
    }

    /// Generate the index-specific (i.e., circuit-specific) prover and verifier
    /// keys. This is a trusted setup.
    pub fn circuit_specific_setup<R: RngCore + CryptoRng>(
        circuit: C,
        rng: &mut R,
    ) -> Result<(CircuitProvingKey<TargetField, PC>, CircuitVerifyingKey<TargetField, PC>), Box<MarlinConstraintsError>>
    {
        Ok(MarlinCore::<TargetField, BaseField, PC, FS, MM>::circuit_specific_setup(&circuit, rng).unwrap())
    }

    /// Prepare the verifying key.
    pub fn process_vk(
        vk: &CircuitVerifyingKey<TargetField, PC>,
    ) -> Result<PreparedCircuitVerifyingKey<TargetField, PC>, Box<MarlinConstraintsError>> {
        Ok(vk.prepare())
    }

    /// Verify the proof with the prepared verifying key.
    pub fn verify_with_processed_vk(
        pvk: &PreparedCircuitVerifyingKey<TargetField, PC>,
        x: &[TargetField],
        proof: &Proof<TargetField, PC>,
    ) -> Result<bool, Box<MarlinConstraintsError>> {
        match MarlinCore::<TargetField, BaseField, PC, FS, MM>::prepared_verify(pvk, x, proof) {
            Ok(res) => Ok(res),
            Err(e) => Err(Box::new(MarlinError::from(e).into())),
        }
    }
}

impl<TargetField, BaseField, PC, FS, MM, C, V> SNARK for MarlinSNARK<TargetField, BaseField, PC, FS, MM, C, V>
where
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    FS: FiatShamirRng<TargetField, BaseField>,
    MM: MarlinMode,
    PC::VerifierKey: ToConstraintField<BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
    C: ConstraintSynthesizer<TargetField>,
    V: ToConstraintField<TargetField>,
{
    type AllocatedCircuit = C;
    type Circuit = (C, UniversalSRS<TargetField, PC>);
    type PreparedVerifyingKey = PreparedCircuitVerifyingKey<TargetField, PC>;
    type Proof = Proof<TargetField, PC>;
    type ProvingKey = CircuitProvingKey<TargetField, PC>;
    type VerifierInput = V;
    type VerifyingKey = CircuitVerifyingKey<TargetField, PC>;

    fn setup<R: RngCore>(
        (circuit, _srs): &Self::Circuit,
        rng: &mut R,
    ) -> Result<(Self::ProvingKey, Self::VerifyingKey), SNARKError> {
        // TODO: This is a trusted setup.
        let (circuit_proving_key, circuit_verifier_key) =
            MarlinCore::<TargetField, BaseField, PC, FS, MM>::circuit_specific_setup(circuit, rng).unwrap();

        Ok((circuit_proving_key, circuit_verifier_key))
    }

    fn prove<R: Rng>(
        parameters: &Self::ProvingKey,
        circuit: &Self::AllocatedCircuit,
        rng: &mut R,
    ) -> Result<Self::Proof, SNARKError> {
        match MarlinCore::<TargetField, BaseField, PC, FS, MM>::prove(&parameters, circuit, rng) {
            Ok(res) => Ok(res),
            Err(e) => Err(SNARKError::from(e)),
        }
    }

    fn verify_prepared(
        verifying_key: &Self::PreparedVerifyingKey,
        input: &Self::VerifierInput,
        proof: &Self::Proof,
    ) -> Result<bool, SNARKError> {
        match MarlinCore::<TargetField, BaseField, PC, FS, MM>::prepared_verify(
            verifying_key,
            &input.to_field_elements()?,
            proof,
        ) {
            Ok(res) => Ok(res),
            Err(e) => Err(SNARKError::from(e)),
        }
    }
}

/// The Marlin proof system gadget.
pub struct MarlinSNARKGadget<F, FSF, PC, FS, MM, PCG, FSG>
where
    F: PrimeField,
    FSF: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<F>,
    FS: FiatShamirRng<F, FSF>,
    MM: MarlinMode,
    PCG: PCCheckVar<F, PC, FSF>,
    FSG: FiatShamirRngVar<F, FSF, FS>,
{
    f_phantom: PhantomData<F>,
    fsf_phantom: PhantomData<FSF>,
    pc_phantom: PhantomData<PC>,
    fs_phantom: PhantomData<FS>,
    mm_phantom: PhantomData<MM>,
    pcg_phantom: PhantomData<PCG>,
    fsg_phantom: PhantomData<FSG>,
}

impl<TargetField, BaseField, PC, FS, MM, PCG, FSG, C, V>
    SNARKGadget<TargetField, BaseField, MarlinSNARK<TargetField, BaseField, PC, FS, MM, C, V>>
    for MarlinSNARKGadget<TargetField, BaseField, PC, FS, MM, PCG, FSG>
where
    TargetField: PrimeField,
    BaseField: PrimeField + PoseidonDefaultParametersField,
    PC: PolynomialCommitment<TargetField>,
    FS: FiatShamirRng<TargetField, BaseField>,
    MM: MarlinMode,
    PCG: PCCheckVar<TargetField, PC, BaseField>,
    FSG: FiatShamirRngVar<TargetField, BaseField, FS>,
    PC::VerifierKey: ToConstraintField<BaseField>,
    PC::Commitment: ToConstraintField<BaseField>,
    PCG::VerifierKeyVar: ToConstraintFieldGadget<BaseField>,
    PCG::CommitmentVar: ToConstraintFieldGadget<BaseField>,
    C: ConstraintSynthesizer<TargetField>,
    V: ToConstraintField<TargetField>,
{
    type InputVar = NonNativeFieldInputVar<TargetField, BaseField>;
    type PreparedVerifyingKeyVar = PreparedCircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG, FS, FSG>;
    type ProofVar = ProofVar<TargetField, BaseField, PC, PCG>;
    type VerifierSize = usize;
    type VerifyingKeyVar = CircuitVerifyingKeyVar<TargetField, BaseField, PC, PCG>;

    fn verifier_size(
        circuit_vk: &<MarlinSNARK<TargetField, BaseField, PC, FS, MM, C, V> as SNARK>::VerifyingKey,
    ) -> Self::VerifierSize {
        circuit_vk.circuit_info.num_variables
    }

    fn verify_with_processed_vk<CS: ConstraintSystem<BaseField>>(
        mut cs: CS,
        circuit_pvk: &Self::PreparedVerifyingKeyVar,
        x: &Self::InputVar,
        proof: &Self::ProofVar,
    ) -> Result<Boolean, SynthesisError> {
        Ok(
            MarlinVerificationGadget::<TargetField, BaseField, PC, PCG>::prepared_verify(
                cs.ns(|| "prepared_verify"),
                &circuit_pvk,
                &x.val,
                proof,
            )
            .unwrap(),
        )
    }

    fn verify<CS: ConstraintSystem<BaseField>>(
        mut cs: CS,
        circuit_vk: &Self::VerifyingKeyVar,
        x: &Self::InputVar,
        proof: &Self::ProofVar,
    ) -> Result<Boolean, SynthesisError> {
        Ok(
            MarlinVerificationGadget::<TargetField, BaseField, PC, PCG>::verify::<_, FS, FSG>(
                cs.ns(|| "verify"),
                circuit_vk,
                &x.val,
                proof,
            )
            .unwrap(),
        )
    }
}

/// Circuit representing the `MarlinBound`
#[derive(Clone)]
pub struct MarlinBoundCircuit<F: PrimeField> {
    /// The Marlin bound.
    pub bound: MarlinBound,
    _fsf_phantom: PhantomData<F>,
}

impl<F: PrimeField> From<MarlinBound> for MarlinBoundCircuit<F> {
    fn from(bound: MarlinBound) -> Self {
        Self {
            bound,
            _fsf_phantom: PhantomData,
        }
    }
}

impl<F: PrimeField> ConstraintSynthesizer<F> for MarlinBoundCircuit<F> {
    fn generate_constraints<CS: ConstraintSystem<F>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
        let MarlinBound { max_degree } = self.bound;

        let num_variables = max_degree / 3;
        let num_constraints = max_degree / 3;

        let mut vars: Vec<Variable> = vec![];
        for i in 0..num_variables - 1 {
            let var_i = cs.alloc(|| format!("var_i_{}", i), || Ok(F::zero()))?;
            vars.push(var_i);
        }

        let mut rng = snarkvm_utilities::test_rng();

        let mut non_zero_remaining = (max_degree + 5) / 3;
        for i in 0..num_constraints {
            if non_zero_remaining > 0 {
                let num_for_this_constraint = std::cmp::min(non_zero_remaining, num_variables - 1);

                let mut lc_a = LinearCombination::zero();
                let mut lc_b = LinearCombination::zero();
                let mut lc_c = LinearCombination::zero();

                for var in vars.iter().take(num_for_this_constraint) {
                    lc_a += (F::rand(&mut rng), *var);
                    lc_b += (F::rand(&mut rng), *var);
                    lc_c += (F::rand(&mut rng), *var);
                }

                cs.enforce(|| format!("enforce_constraint_{}", i), |_| lc_a, |_| lc_b, |_| lc_c);

                non_zero_remaining -= num_for_this_constraint;
            } else {
                cs.enforce(|| format!("enforce_constraint_{}", i), |lc| lc, |lc| lc, |lc| lc);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
pub mod test {
    use core::ops::MulAssign;

    use snarkvm_curves::{
        bls12_377::{Bls12_377, Fq, Fr},
        bw6_761::BW6_761,
    };
    use snarkvm_fields::Field;
    use snarkvm_gadgets::{
        curves::bls12_377::PairingGadget as Bls12_377PairingGadget,
        traits::{alloc::AllocGadget, eq::EqGadget},
    };
    use snarkvm_polycommit::marlin_pc::{marlin_kzg10::MarlinKZG10Gadget, MarlinKZG10};
    use snarkvm_r1cs::TestConstraintSystem;
    use snarkvm_utilities::{test_rng, UniformRand};

    use crate::{
        constraints::snark::{MarlinSNARK, MarlinSNARKGadget},
        fiat_shamir::{
            FiatShamirAlgebraicSpongeRng,
            FiatShamirAlgebraicSpongeRngVar,
            PoseidonSponge,
            PoseidonSpongeVar,
        },
        marlin::MarlinRecursiveMode,
    };

    use super::*;

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

    type PC = MarlinKZG10<Bls12_377>;
    type PCGadget = MarlinKZG10Gadget<Bls12_377, BW6_761, Bls12_377PairingGadget>;

    type FS = FiatShamirAlgebraicSpongeRng<Fr, Fq, PoseidonSponge<Fq>>;
    type FSG = FiatShamirAlgebraicSpongeRngVar<Fr, Fq, PoseidonSponge<Fq>, PoseidonSpongeVar<Fq>>;

    type TestSNARK = MarlinSNARK<Fr, Fq, PC, FS, MarlinRecursiveMode, Circuit<Fr>, Vec<Fr>>;
    type TestSNARKGadget = MarlinSNARKGadget<Fr, Fq, PC, FS, MarlinRecursiveMode, PCGadget, FSG>;

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

            let (pk, vk) = TestSNARK::circuit_specific_setup(circ, &mut rng).unwrap();

            // Test native proof and verification.

            let proof = TestSNARK::prove(&pk, &circ, &mut rng).unwrap();

            assert!(
                TestSNARK::verify(&vk.clone().into(), &vec![c], &proof).unwrap(),
                "The native verification check fails."
            );

            // Initialize constraint system.
            let mut cs = TestConstraintSystem::<Fq>::new();

            let input_gadget = <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::InputVar::alloc_input(
                cs.ns(|| "alloc_input_gadget"),
                || Ok(vec![c]),
            )
            .unwrap();

            let proof_gadget =
                <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::ProofVar::alloc(cs.ns(|| "alloc_proof"), || {
                    Ok(proof)
                })
                .unwrap();

            let vk_gadget = <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::VerifyingKeyVar::alloc(
                cs.ns(|| "alloc_vk"),
                || Ok(vk.clone()),
            )
            .unwrap();

            assert!(
                cs.is_satisfied(),
                "Constraints not satisfied: {}",
                cs.which_is_unsatisfied().unwrap()
            );

            let verification_result = <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::verify(
                cs.ns(|| "marlin_verify"),
                &vk_gadget,
                &input_gadget,
                &proof_gadget,
            )
            .unwrap();

            assert!(
                cs.is_satisfied(),
                "Constraints not satisfied: {}",
                cs.which_is_unsatisfied().unwrap()
            );

            verification_result
                .enforce_equal(cs.ns(|| "enforce_equal_verification"), &Boolean::Constant(true))
                .unwrap();

            assert!(
                cs.is_satisfied(),
                "Constraints not satisfied: {}",
                cs.which_is_unsatisfied().unwrap()
            );
        }
    }

    #[test]
    fn marlin_verifier_num_constraints_test() {
        let mut rng = test_rng();

        // Construct the circuit.

        let a = Fr::rand(&mut rng);
        let b = Fr::rand(&mut rng);
        let mut c = a;
        c.mul_assign(&b);

        let circ = Circuit {
            a: Some(a),
            b: Some(b),
            num_constraints: rng.gen_range(1000..100000),
            num_variables: rng.gen_range(100..1000),
        };

        // Generate the circuit parameters.

        let (pk, vk) = TestSNARK::circuit_specific_setup(circ, &mut rng).unwrap();

        // Test native proof and verification.

        let proof = TestSNARK::prove(&pk, &circ, &mut rng).unwrap();

        assert!(
            TestSNARK::verify(&vk.clone().into(), &vec![c], &proof).unwrap(),
            "The native verification check fails."
        );

        // Initialize constraint system.
        let mut cs = TestConstraintSystem::<Fq>::new();

        let input_gadget = <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::InputVar::alloc_input(
            cs.ns(|| "alloc_input_gadget"),
            || Ok(vec![c]),
        )
        .unwrap();

        let input_gadget_constraints = cs.num_constraints();

        let proof_gadget =
            <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::ProofVar::alloc(cs.ns(|| "alloc_proof"), || Ok(proof))
                .unwrap();

        let proof_gadget_constraints = cs.num_constraints() - input_gadget_constraints;

        let vk_gadget =
            <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::VerifyingKeyVar::alloc(cs.ns(|| "alloc_vk"), || {
                Ok(vk.clone())
            })
            .unwrap();

        let vk_gadget_constraints = cs.num_constraints() - input_gadget_constraints;

        let verification_result = <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::verify(
            cs.ns(|| "marlin_verify"),
            &vk_gadget,
            &input_gadget,
            &proof_gadget,
        )
        .unwrap();

        let verifier_gadget_constraints = cs.num_constraints() - proof_gadget_constraints;

        verification_result
            .enforce_equal(cs.ns(|| "enforce_equal_verification"), &Boolean::Constant(true))
            .unwrap();

        assert!(
            cs.is_satisfied(),
            "Constraints not satisfied: {}",
            cs.which_is_unsatisfied().unwrap()
        );

        const INPUT_GADGET_CONSTRAINTS: usize = 383;
        const PROOF_GADGET_CONSTRAINTS: usize = 56;
        const VK_GADGET_CONSTRAINTS: usize = 140;
        const VERIFIER_GADGET_CONSTRAINTS: usize = 150594;

        assert_eq!(input_gadget_constraints, INPUT_GADGET_CONSTRAINTS);
        assert_eq!(proof_gadget_constraints, PROOF_GADGET_CONSTRAINTS);
        assert_eq!(vk_gadget_constraints, VK_GADGET_CONSTRAINTS);
        assert_eq!(verifier_gadget_constraints, VERIFIER_GADGET_CONSTRAINTS);
    }
}

#[cfg(test)]
pub mod multiple_input_tests {
    use core::ops::MulAssign;

    use snarkvm_curves::{
        bls12_377::{Bls12_377, Fq, Fr},
        bw6_761::BW6_761,
    };
    use snarkvm_fields::Field;
    use snarkvm_gadgets::{
        curves::bls12_377::PairingGadget as Bls12_377PairingGadget,
        traits::{alloc::AllocGadget, eq::EqGadget},
    };
    use snarkvm_polycommit::marlin_pc::{marlin_kzg10::MarlinKZG10Gadget, MarlinKZG10};
    use snarkvm_r1cs::TestConstraintSystem;
    use snarkvm_utilities::{test_rng, UniformRand};

    use crate::{
        constraints::snark::{MarlinSNARK, MarlinSNARKGadget},
        fiat_shamir::{
            FiatShamirAlgebraicSpongeRng,
            FiatShamirAlgebraicSpongeRngVar,
            PoseidonSponge,
            PoseidonSpongeVar,
        },
        marlin::MarlinRecursiveMode,
    };

    use super::*;

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

            let d = cs.alloc_input(
                || "d",
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

            for i in 0..(self.num_constraints - 1) {
                cs.enforce(|| format!("constraint 2 {}", i), |lc| lc + a, |lc| lc + b, |lc| lc + d);
            }

            Ok(())
        }
    }

    pub struct VerifierCircuit<
        F: PrimeField,
        ConstraintF: PrimeField + PoseidonDefaultParametersField,
        PC: PolynomialCommitment<F>,
        FS: FiatShamirRng<F, ConstraintF>,
        MM: MarlinMode,
        PCG: PCCheckVar<F, PC, ConstraintF>,
        FSG: FiatShamirRngVar<F, ConstraintF, FS>,
    >
    where
        PC::VerifierKey: ToConstraintField<ConstraintF>,
        PC::Commitment: ToConstraintField<ConstraintF>,
        PCG::VerifierKeyVar: ToConstraintFieldGadget<ConstraintF>,
        PCG::CommitmentVar: ToConstraintFieldGadget<ConstraintF>,
    {
        pub c: F,
        pub verifying_key: CircuitVerifyingKey<F, PC>,
        pub proof: Proof<F, PC>,
        _f: PhantomData<ConstraintF>,
        _fs: PhantomData<FS>,
        _marlin_mode: PhantomData<MM>,
        _pcg: PhantomData<PCG>,
        _fsg: PhantomData<FSG>,
    }

    impl<
        F: PrimeField,
        ConstraintF: PrimeField + PoseidonDefaultParametersField,
        PC: PolynomialCommitment<F>,
        FS: FiatShamirRng<F, ConstraintF>,
        MM: MarlinMode,
        PCG: PCCheckVar<F, PC, ConstraintF>,
        FSG: FiatShamirRngVar<F, ConstraintF, FS>,
    > ConstraintSynthesizer<ConstraintF> for VerifierCircuit<F, ConstraintF, PC, FS, MM, PCG, FSG>
    where
        PC::VerifierKey: ToConstraintField<ConstraintF>,
        PC::Commitment: ToConstraintField<ConstraintF>,
        PCG::VerifierKeyVar: ToConstraintFieldGadget<ConstraintF>,
        PCG::CommitmentVar: ToConstraintFieldGadget<ConstraintF>,
    {
        fn generate_constraints<CS: ConstraintSystem<ConstraintF>>(&self, cs: &mut CS) -> Result<(), SynthesisError> {
            let vk_gadget = CircuitVerifyingKeyVar::<F, ConstraintF, PC, PCG>::alloc(cs.ns(|| "vk"), || {
                Ok(self.verifying_key.clone())
            })?;

            let proof_gadget =
                ProofVar::<F, ConstraintF, PC, PCG>::alloc(cs.ns(|| "proof"), || Ok(self.proof.clone()))?;

            let input_gadget = NonNativeFieldInputVar::<F, ConstraintF>::alloc(cs.ns(|| "input 2"), || {
                Ok(vec![self.c.clone(), self.c.clone()])
            })?;

            let output = MarlinVerificationGadget::<F, ConstraintF, PC, PCG>::verify::<_, FS, FSG>(
                cs.ns(|| "verify"),
                &vk_gadget,
                &input_gadget.val,
                &proof_gadget,
            )
            .unwrap();

            let expected = Boolean::Constant(true);

            output.enforce_equal(cs.ns(|| "valid_verification"), &expected)?;

            Ok(())
        }
    }

    type PC = MarlinKZG10<Bls12_377>;
    type PCGadget = MarlinKZG10Gadget<Bls12_377, BW6_761, Bls12_377PairingGadget>;

    type FS = FiatShamirAlgebraicSpongeRng<Fr, Fq, PoseidonSponge<Fq>>;
    type FSG = FiatShamirAlgebraicSpongeRngVar<Fr, Fq, PoseidonSponge<Fq>, PoseidonSpongeVar<Fq>>;

    type TestSNARK = MarlinSNARK<Fr, Fq, PC, FS, MarlinRecursiveMode, Circuit<Fr>, Vec<Fr>>;
    type TestSNARKGadget = MarlinSNARKGadget<Fr, Fq, PC, FS, MarlinRecursiveMode, PCGadget, FSG>;

    #[test]
    fn two_input_marlin_snark_test() {
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

            let (pk, vk) = TestSNARK::circuit_specific_setup(circ, &mut rng).unwrap();

            // Test native proof and verification.

            let proof = TestSNARK::prove(&pk, &circ, &mut rng).unwrap();

            assert!(
                TestSNARK::verify(&vk.clone().into(), &[c.clone(), c].to_vec(), &proof).unwrap(),
                "The native verification check fails."
            );

            // Initialize constraint system.
            let mut cs = TestConstraintSystem::<Fq>::new();

            let input_gadget = <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::InputVar::alloc_input(
                cs.ns(|| "alloc_input_gadget"),
                || Ok(vec![c.clone(), c]),
            )
            .unwrap();

            let proof_gadget =
                <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::ProofVar::alloc(cs.ns(|| "alloc_proof"), || {
                    Ok(proof)
                })
                .unwrap();

            let vk_gadget = <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::VerifyingKeyVar::alloc(
                cs.ns(|| "alloc_vk"),
                || Ok(vk.clone()),
            )
            .unwrap();

            assert!(
                cs.is_satisfied(),
                "Constraints not satisfied: {}",
                cs.which_is_unsatisfied().unwrap()
            );

            let verification_result = <TestSNARKGadget as SNARKGadget<Fr, Fq, TestSNARK>>::verify(
                cs.ns(|| "marlin_verify"),
                &vk_gadget,
                &input_gadget,
                &proof_gadget,
            )
            .unwrap();

            assert!(
                cs.is_satisfied(),
                "Constraints not satisfied: {}",
                cs.which_is_unsatisfied().unwrap()
            );

            verification_result
                .enforce_equal(cs.ns(|| "enforce_equal_verification"), &Boolean::Constant(true))
                .unwrap();

            assert!(
                cs.is_satisfied(),
                "Constraints not satisfied: {}",
                cs.which_is_unsatisfied().unwrap()
            );
        }
    }

    #[test]
    fn marlin_nested_verification_gadget_test() {
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

            let (pk, vk) = TestSNARK::circuit_specific_setup(circ, &mut rng).unwrap();

            // Test native proof and verification.

            let proof = TestSNARK::prove(&pk, &circ, &mut rng).unwrap();

            assert!(
                TestSNARK::verify(&vk.clone().into(), &[c.clone(), c].to_vec(), &proof).unwrap(),
                "The native verification check fails."
            );

            // Initialize constraint system.
            let mut cs = TestConstraintSystem::<Fq>::new();

            let circuit = VerifierCircuit::<Fr, Fq, PC, FS, MarlinRecursiveMode, PCGadget, FSG> {
                c: c.clone(),
                verifying_key: vk,
                proof,
                _f: PhantomData,
                _fs: PhantomData,
                _marlin_mode: PhantomData,
                _pcg: PhantomData,
                _fsg: PhantomData,
            };

            circuit
                .generate_constraints(&mut cs.ns(|| "verify_within_gadget"))
                .unwrap();

            assert!(
                cs.is_satisfied(),
                "Constraints not satisfied: {}",
                cs.which_is_unsatisfied().unwrap()
            );
        }
    }

    #[test]
    fn marlin_test_nested_snark() {
        let mut rng = test_rng();

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

        let (pk, vk) = TestSNARK::circuit_specific_setup(circ, &mut rng).unwrap();

        // Test native proof and verification.

        let proof = TestSNARK::prove(&pk, &circ, &mut rng).unwrap();

        assert!(
            TestSNARK::verify(&vk.clone().into(), &[c.clone(), c].to_vec(), &proof).unwrap(),
            "The native verification check fails."
        );

        // Initialize constraint system.
        let nested_circuit = VerifierCircuit::<Fr, Fq, PC, FS, MarlinRecursiveMode, PCGadget, FSG> {
            c: c.clone(),
            verifying_key: vk,
            proof,
            _f: PhantomData,
            _fs: PhantomData,
            _marlin_mode: PhantomData,
            _pcg: PhantomData,
            _fsg: PhantomData,
        };

        use snarkvm_algorithms::snark::groth16::Groth16;
        type NestedSNARK =
            Groth16<BW6_761, VerifierCircuit<Fr, Fq, PC, FS, MarlinRecursiveMode, PCGadget, FSG>, Vec<Fq>>;

        let (nested_pk, nested_vk) = NestedSNARK::setup(&nested_circuit, &mut rng).unwrap();

        // Test native proof and verification.

        let nested_proof = NestedSNARK::prove(&nested_pk, &nested_circuit, &mut rng).unwrap();

        assert!(
            NestedSNARK::verify(&nested_vk.clone().into(), &vec![], &nested_proof).unwrap(),
            "The native verification check fails."
        );
    }
}
