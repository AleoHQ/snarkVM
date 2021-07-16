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

use snarkvm_fields::{Field, Zero};
use snarkvm_r1cs::{errors::SynthesisError, ConstraintSynthesizer, ConstraintSystem};

struct MySillyCircuit<F: Field> {
    a: Option<F>,
    b: Option<F>,
}

impl<ConstraintF: Field> ConstraintSynthesizer<ConstraintF> for MySillyCircuit<ConstraintF> {
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

        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);
        cs.enforce(|| "a*b=c", |lc| lc + a, |lc| lc + b, |lc| lc + c);

        Ok(())
    }
}

mod bls12_377 {
    use super::*;
    use crate::snark::groth16::{
        batch_verify_proof,
        create_random_proof,
        generate_random_parameters,
        prepare_verifying_key,
        verify_proof,
    };
    use core::ops::MulAssign;
    use snarkvm_curves::bls12_377::{Bls12_377, Fr};
    use snarkvm_utilities::rand::{test_rng, UniformRand};

    #[test]
    fn prove_and_verify() {
        let rng = &mut test_rng();

        let parameters =
            generate_random_parameters::<Bls12_377, _, _>(&MySillyCircuit { a: None, b: None }, rng).unwrap();

        for _ in 0..100 {
            let a = Fr::rand(rng);
            let b = Fr::rand(rng);
            let mut c = a;
            c.mul_assign(&b);

            let proof = create_random_proof(&MySillyCircuit { a: Some(a), b: Some(b) }, &parameters, rng).unwrap();
            let pvk = prepare_verifying_key::<Bls12_377>(parameters.vk.clone());

            assert!(verify_proof(&pvk, &proof, &[c]).unwrap());
            assert!(!verify_proof(&pvk, &proof, &[a]).unwrap());
        }
    }

    #[test]
    fn batch_prove_and_verify() {
        let rng = &mut test_rng();

        let parameters =
            generate_random_parameters::<Bls12_377, _, _>(&MySillyCircuit { a: None, b: None }, rng).unwrap();

        let pvk = prepare_verifying_key::<Bls12_377>(parameters.vk.clone());

        let mut proofs = Vec::new();
        let mut inputs = Vec::new();
        for _ in 0..100 {
            let a = Fr::rand(rng);
            let b = Fr::rand(rng);
            let mut c = a;
            c.mul_assign(&b);

            proofs.push(create_random_proof(&MySillyCircuit { a: Some(a), b: Some(b) }, &parameters, rng).unwrap());
            inputs.push(vec![c]);
        }
        assert!(batch_verify_proof(&pvk, &proofs, &inputs, rng).unwrap());
    }
}

mod bw6_761 {
    use super::*;
    use crate::snark::groth16::{create_random_proof, generate_random_parameters, prepare_verifying_key, verify_proof};

    use snarkvm_curves::bw6_761::{Fr, BW6_761};
    use snarkvm_utilities::rand::{test_rng, UniformRand};

    #[test]
    fn prove_and_verify() {
        let rng = &mut test_rng();

        let parameters =
            generate_random_parameters::<BW6_761, _, _>(&MySillyCircuit { a: None, b: None }, rng).unwrap();

        let a = Fr::rand(rng);
        let b = Fr::rand(rng);
        let c = a * b;

        let proof = create_random_proof(&MySillyCircuit { a: Some(a), b: Some(b) }, &parameters, rng).unwrap();
        let pvk = prepare_verifying_key::<BW6_761>(parameters.vk);

        assert!(verify_proof(&pvk, &proof, &[c]).unwrap());
        assert!(!verify_proof(&pvk, &proof, &[Fr::zero()]).unwrap());
    }
}

mod serialization {
    use super::*;
    use crate::snark::groth16::{create_random_proof, generate_random_parameters, Proof};
    use snarkvm_curves::bls12_377::{Bls12_377, Fr};
    use snarkvm_utilities::{
        rand::{test_rng, UniformRand},
        FromBytes,
        ToBytes,
    };

    #[test]
    fn test_compressed_proof_serialization() {
        let rng = &mut test_rng();

        let parameters =
            generate_random_parameters::<Bls12_377, _, _>(&MySillyCircuit { a: None, b: None }, rng).unwrap();

        let a = Fr::rand(rng);
        let b = Fr::rand(rng);

        let proof = create_random_proof(&MySillyCircuit { a: Some(a), b: Some(b) }, &parameters, rng).unwrap();

        let compressed_serialization = proof.to_bytes_le().unwrap();

        assert_eq!(
            Proof::<Bls12_377>::compressed_proof_size().unwrap(),
            compressed_serialization.len()
        );
        assert!(Proof::<Bls12_377>::read_uncompressed(&compressed_serialization[..]).is_err());

        let recovered_proof: Proof<Bls12_377> = FromBytes::read_le(&compressed_serialization[..]).unwrap();
        assert_eq!(recovered_proof.compressed, true);
    }

    #[test]
    fn test_uncompressed_proof_serialization() {
        let rng = &mut test_rng();

        let parameters =
            generate_random_parameters::<Bls12_377, _, _>(&MySillyCircuit { a: None, b: None }, rng).unwrap();

        let a = Fr::rand(rng);
        let b = Fr::rand(rng);

        let proof = create_random_proof(&MySillyCircuit { a: Some(a), b: Some(b) }, &parameters, rng).unwrap();

        let mut uncompressed_serialization = Vec::new();
        proof.write_uncompressed(&mut uncompressed_serialization).unwrap();

        assert_eq!(
            Proof::<Bls12_377>::uncompressed_proof_size().unwrap(),
            uncompressed_serialization.len()
        );
        assert!(Proof::<Bls12_377>::read_compressed(&uncompressed_serialization[..]).is_err());

        let recovered_proof: Proof<Bls12_377> = FromBytes::read_le(&uncompressed_serialization[..]).unwrap();
        assert_eq!(recovered_proof.compressed, false);
    }
}
