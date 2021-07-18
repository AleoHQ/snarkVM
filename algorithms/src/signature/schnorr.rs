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
    crypto_hash::{PoseidonCryptoHash, PoseidonDefaultParametersField},
    hash_to_curve::hash_to_curve,
    CryptoHash,
    SignatureError,
    SignatureScheme,
};
use snarkvm_curves::{AffineCurve, Group, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, Field, FieldParameters, PrimeField, ToConstraintField};
use snarkvm_utilities::{
    bytes::{from_bytes_le_to_bits_le, FromBytes, ToBytes},
    errors::SerializationError,
    rand::UniformRand,
    serialize::*,
    to_bytes_le,
    FromBits,
    ToBits,
};

use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::{
    hash::Hash,
    io::{Read, Result as IoResult, Write},
};

#[derive(Derivative)]
#[derivative(
    Clone(bound = "G: ProjectiveCurve"),
    Debug(bound = "G: ProjectiveCurve"),
    Default(bound = "G: ProjectiveCurve"),
    PartialEq(bound = "G: ProjectiveCurve"),
    Eq(bound = "G: ProjectiveCurve")
)]
pub struct SchnorrSignature<G: ProjectiveCurve> {
    pub prover_response: <G as Group>::ScalarField,
    pub verifier_challenge: <G as Group>::ScalarField,
}

impl<G: ProjectiveCurve> ToBytes for SchnorrSignature<G> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.prover_response.write_le(&mut writer)?;
        self.verifier_challenge.write_le(&mut writer)
    }
}

impl<G: ProjectiveCurve> FromBytes for SchnorrSignature<G> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let prover_response = <G as Group>::ScalarField::read_le(&mut reader)?;
        let verifier_challenge = <G as Group>::ScalarField::read_le(&mut reader)?;
        Ok(Self {
            prover_response,
            verifier_challenge,
        })
    }
}

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Copy(bound = "G: ProjectiveCurve"),
    Clone(bound = "G: ProjectiveCurve"),
    PartialEq(bound = "G: ProjectiveCurve"),
    Eq(bound = "G: ProjectiveCurve"),
    Debug(bound = "G: ProjectiveCurve"),
    Hash(bound = "G: ProjectiveCurve"),
    Default(bound = "G: ProjectiveCurve")
)]
pub struct SchnorrPublicKey<G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize>(pub G::Affine);

impl<G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize> ToBytes for SchnorrPublicKey<G> {
    /// Writes the x-coordinate of the encryption public key.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        let x_coordinate = self.0.to_x_coordinate();
        x_coordinate.write_le(&mut writer)
    }
}

impl<G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize> FromBytes for SchnorrPublicKey<G> {
    /// Reads the x-coordinate of the encryption public key.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let x_coordinate = <G::Affine as AffineCurve>::BaseField::read_le(&mut reader)?;

        if let Some(element) = <G::Affine as AffineCurve>::from_x_coordinate(x_coordinate, true) {
            if element.is_in_correct_subgroup_assuming_on_curve() {
                return Ok(Self(element));
            }
        }

        if let Some(element) = <G::Affine as AffineCurve>::from_x_coordinate(x_coordinate, false) {
            if element.is_in_correct_subgroup_assuming_on_curve() {
                return Ok(Self(element));
            }
        }

        Err(SignatureError::Message("Failed to read signature public key".into()).into())
    }
}

impl<F: Field, G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize + ToConstraintField<F>>
    ToConstraintField<F> for SchnorrPublicKey<G>
where
    G::Affine: ToConstraintField<F>,
{
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        self.0.to_field_elements()
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "G: ProjectiveCurve"),
    Debug(bound = "G: ProjectiveCurve"),
    PartialEq(bound = "G: ProjectiveCurve"),
    Eq(bound = "G: ProjectiveCurve")
)]
pub struct Schnorr<G: ProjectiveCurve> {
    pub generator_powers: Vec<G>,
}

impl<G: ProjectiveCurve + Hash + CanonicalSerialize + CanonicalDeserialize> SignatureScheme for Schnorr<G>
where
    <G::Affine as AffineCurve>::BaseField: PoseidonDefaultParametersField,
    G: ToConstraintField<<G::Affine as AffineCurve>::BaseField>,
    G::Affine: ToConstraintField<<G::Affine as AffineCurve>::BaseField>,
{
    type Parameters = Vec<G>;
    type PrivateKey = <G as Group>::ScalarField;
    type PublicKey = SchnorrPublicKey<G>;
    type RandomizedPrivateKey = <G as Group>::ScalarField;
    type Randomizer = [u8; 32];
    type Signature = SchnorrSignature<G>;

    fn setup(message: &str) -> Self {
        assert!(
            <<G as Group>::ScalarField as PrimeField>::Parameters::CAPACITY
                < <<G::Affine as AffineCurve>::BaseField as PrimeField>::Parameters::CAPACITY
        );

        let setup_time = start_timer!(|| "SchnorrSignature::setup");
        // Round to the closest multiple of 64 to factor bit and byte encoding differences.
        let private_key_size_in_bits = Self::PrivateKey::size_in_bits();
        assert!(private_key_size_in_bits < usize::MAX - 63);
        let num_powers = (private_key_size_in_bits + 63) & !63usize;

        let mut generator_powers = Vec::with_capacity(num_powers);
        let (base, _, _) = hash_to_curve::<G::Affine>(message);
        let mut generator = base.into_projective();
        for _ in 0..num_powers {
            generator_powers.push(generator);
            generator.double_in_place();
        }
        end_timer!(setup_time);

        Self { generator_powers }
    }

    fn parameters(&self) -> &Self::Parameters {
        &self.generator_powers
    }

    fn generate_private_key<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<Self::PrivateKey, SignatureError> {
        let keygen_time = start_timer!(|| "SchnorrSignature::generate_private_key");
        let private_key = <G as Group>::ScalarField::rand(rng);
        end_timer!(keygen_time);
        Ok(private_key)
    }

    fn generate_public_key(&self, private_key: &Self::PrivateKey) -> Result<Self::PublicKey, SignatureError> {
        let keygen_time = start_timer!(|| "SchnorrSignature::generate_public_key");

        let mut public_key = G::zero();
        for (bit, base_power) in from_bytes_le_to_bits_le(&to_bytes_le![private_key]?).zip_eq(&self.generator_powers) {
            if bit {
                public_key += base_power;
            }
        }
        end_timer!(keygen_time);

        Ok(SchnorrPublicKey(public_key.into_affine()))
    }

    fn randomize_private_key(
        &self,
        private_key: &Self::PrivateKey,
        randomizer: &Self::Randomizer,
    ) -> Result<Self::RandomizedPrivateKey, SignatureError> {
        let timer = start_timer!(|| "SchnorrSignature::randomize_private_key");
        let randomized_private_key = *private_key + G::ScalarField::from_le_bytes_mod_order(randomizer);
        end_timer!(timer);
        Ok(randomized_private_key)
    }

    fn randomize_public_key(
        &self,
        public_key: &Self::PublicKey,
        randomizer: &Self::Randomizer,
    ) -> Result<Self::PublicKey, SignatureError> {
        let timer = start_timer!(|| "SchnorrSignature::randomize_public_key");
        let group_randomizer = self.generate_public_key(&G::ScalarField::from_le_bytes_mod_order(randomizer))?;
        let randomized_public_key = public_key.0 + group_randomizer.0;
        end_timer!(timer);
        Ok(SchnorrPublicKey::<G>(randomized_public_key))
    }

    fn sign<R: Rng + CryptoRng>(
        &self,
        private_key: &Self::PrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, SignatureError> {
        let sign_time = start_timer!(|| "SchnorrSignature::sign");
        // (k, e);

        // Sample a random scalar `k` from the prime scalar field.
        let random_scalar: <G as Group>::ScalarField = <G as Group>::ScalarField::rand(rng);
        // Commit to the random scalar via r := k · g.
        // This is the prover's first msg in the Sigma protocol.
        let mut prover_commitment = G::zero();
        for (bit, base_power) in from_bytes_le_to_bits_le(&to_bytes_le![random_scalar]?).zip_eq(&self.generator_powers)
        {
            if bit {
                prover_commitment += base_power;
            }
        }

        // Derive the public key.
        let public_key = self.generate_public_key(private_key)?;

        // Hash everything to get verifier challenge.
        let mut hash_input = Vec::<<G::Affine as AffineCurve>::BaseField>::new();
        hash_input.extend_from_slice(&prover_commitment.to_field_elements().unwrap());
        hash_input.extend_from_slice(&public_key.to_field_elements().unwrap());
        hash_input.push(<G::Affine as AffineCurve>::BaseField::from(message.len() as u128));
        hash_input.extend_from_slice(&message.to_field_elements().unwrap());

        let raw_hash =
            PoseidonCryptoHash::<<G::Affine as AffineCurve>::BaseField, 4, false>::evaluate(&hash_input).unwrap();

        // Bit decompose the raw_hash
        let mut raw_hash_bits = raw_hash.to_repr().to_bits_le();
        raw_hash_bits.resize(
            <<G as Group>::ScalarField as PrimeField>::Parameters::CAPACITY as usize,
            false,
        );
        raw_hash_bits.reverse();

        // Compute the supposed verifier response: e := H(r || pubkey || msg);
        let verifier_challenge = <<G as Group>::ScalarField as PrimeField>::from_repr(
            <<G as Group>::ScalarField as PrimeField>::BigInteger::from_bits_be(&raw_hash_bits),
        )
        .unwrap();

        // k - xe;
        let prover_response = random_scalar - (verifier_challenge * private_key);
        let signature = SchnorrSignature {
            prover_response,
            verifier_challenge,
        };

        end_timer!(sign_time);
        Ok(signature)
    }

    fn sign_randomized<R: Rng + CryptoRng>(
        &self,
        randomized_private_key: &Self::RandomizedPrivateKey,
        message: &[u8],
        rng: &mut R,
    ) -> Result<Self::Signature, SignatureError> {
        let timer = start_timer!(|| "SchnorrSignature::sign_randomized");
        let randomized_signature = self.sign(randomized_private_key, message, rng)?;
        end_timer!(timer);
        Ok(randomized_signature)
    }

    fn verify(
        &self,
        public_key: &Self::PublicKey,
        message: &[u8],
        signature: &Self::Signature,
    ) -> Result<bool, SignatureError> {
        let verify_time = start_timer!(|| "SchnorrSignature::verify");

        let SchnorrSignature {
            prover_response,
            verifier_challenge,
        } = signature;

        let mut claimed_prover_commitment = G::zero();
        for (bit, base_power) in
            from_bytes_le_to_bits_le(&to_bytes_le![prover_response]?).zip_eq(&self.generator_powers)
        {
            if bit {
                claimed_prover_commitment += base_power;
            }
        }

        let public_key_times_verifier_challenge = public_key.0.into_projective().mul(*verifier_challenge);
        claimed_prover_commitment += public_key_times_verifier_challenge;

        // Hash everything to get verifier challenge.
        let mut hash_input = Vec::<<G::Affine as AffineCurve>::BaseField>::new();
        hash_input.extend_from_slice(&claimed_prover_commitment.to_field_elements().unwrap());
        hash_input.extend_from_slice(&public_key.to_field_elements().unwrap());
        hash_input.push(<G::Affine as AffineCurve>::BaseField::from(message.len() as u128));
        hash_input.extend_from_slice(&message.to_field_elements().unwrap());

        let raw_hash =
            PoseidonCryptoHash::<<G::Affine as AffineCurve>::BaseField, 4, false>::evaluate(&hash_input).unwrap();

        // Bit decompose the raw_hash
        let mut raw_hash_bits = raw_hash.to_repr().to_bits_le();
        raw_hash_bits.resize(
            <<G as Group>::ScalarField as PrimeField>::Parameters::CAPACITY as usize,
            false,
        );
        raw_hash_bits.reverse();

        // Compute the supposed verifier response: e := H(r || pubkey || msg);
        let obtained_verifier_challenge = <<G as Group>::ScalarField as PrimeField>::from_repr(
            <<G as Group>::ScalarField as PrimeField>::BigInteger::from_bits_be(&raw_hash_bits),
        )
        .unwrap();

        end_timer!(verify_time);
        Ok(verifier_challenge == &obtained_verifier_challenge)
    }
}

impl<G: ProjectiveCurve> From<Vec<G>> for Schnorr<G> {
    fn from(generator_powers: Vec<G>) -> Self {
        Self { generator_powers }
    }
}

impl<G: ProjectiveCurve> ToBytes for Schnorr<G> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (self.generator_powers.len() as u32).write_le(&mut writer)?;
        for g in &self.generator_powers {
            g.write_le(&mut writer)?;
        }
        Ok(())
    }
}

impl<G: ProjectiveCurve> FromBytes for Schnorr<G> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let generator_powers_length: u32 = FromBytes::read_le(&mut reader)?;
        let mut generator_powers = Vec::with_capacity(generator_powers_length as usize);
        for _ in 0..generator_powers_length {
            let g: G = FromBytes::read_le(&mut reader)?;
            generator_powers.push(g);
        }

        Ok(Self { generator_powers })
    }
}

impl<F: Field, G: ProjectiveCurve + ToConstraintField<F>> ToConstraintField<F> for Schnorr<G> {
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        Ok(Vec::new())
    }
}
