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

use crate::{hash_to_curve::hash_to_curve, EncryptionError, EncryptionScheme};
use snarkvm_curves::traits::{AffineCurve, Group, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, Field, One, PrimeField, ToConstraintField, Zero};
use snarkvm_utilities::{
    errors::SerializationError,
    from_bytes_le_to_bits_le,
    rand::UniformRand,
    serialize::*,
    FromBytes,
    ToBytes,
};

use itertools::Itertools;
use rand::{CryptoRng, Rng};
use std::io::{Read, Result as IoResult, Write};

#[derive(Derivative, CanonicalSerialize, CanonicalDeserialize)]
#[derivative(
    Copy(bound = "G: ProjectiveCurve"),
    Clone(bound = "G: ProjectiveCurve"),
    PartialEq(bound = "G: ProjectiveCurve"),
    Eq(bound = "G: ProjectiveCurve"),
    Debug(bound = "G: ProjectiveCurve"),
    Hash(bound = "G: ProjectiveCurve")
)]
pub struct GroupEncryptionPublicKey<G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize>(pub G);

impl<G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize> ToBytes for GroupEncryptionPublicKey<G> {
    /// Writes the x-coordinate of the encryption public key.
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        let affine = self.0.into_affine();
        let x_coordinate = affine.to_x_coordinate();
        x_coordinate.write_le(&mut writer)
    }
}

impl<G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize> FromBytes for GroupEncryptionPublicKey<G> {
    /// Reads the x-coordinate of the encryption public key.
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let x_coordinate = <G::Affine as AffineCurve>::BaseField::read_le(&mut reader)?;

        if let Some(element) = <G::Affine as AffineCurve>::from_x_coordinate(x_coordinate, true) {
            if element.is_in_correct_subgroup_assuming_on_curve() {
                return Ok(Self(element.into_projective()));
            }
        }

        if let Some(element) = <G::Affine as AffineCurve>::from_x_coordinate(x_coordinate, false) {
            if element.is_in_correct_subgroup_assuming_on_curve() {
                return Ok(Self(element.into_projective()));
            }
        }

        Err(EncryptionError::Message("Failed to read encryption public key".into()).into())
    }
}

impl<G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize> Default for GroupEncryptionPublicKey<G> {
    fn default() -> Self {
        Self(G::default())
    }
}

#[derive(Derivative)]
#[derivative(
    Clone(bound = "G: ProjectiveCurve"),
    Debug(bound = "G: ProjectiveCurve"),
    PartialEq(bound = "G: ProjectiveCurve"),
    Eq(bound = "G: ProjectiveCurve")
)]
pub struct GroupEncryption<G: ProjectiveCurve> {
    pub generator_powers: Vec<G>,
}

impl<G: ProjectiveCurve + CanonicalSerialize + CanonicalDeserialize> EncryptionScheme for GroupEncryption<G> {
    type BlindingExponent = <G as Group>::ScalarField;
    type Parameters = Vec<G>;
    type PrivateKey = <G as Group>::ScalarField;
    type PublicKey = GroupEncryptionPublicKey<G>;
    type Randomness = <G as Group>::ScalarField;
    type Text = G;

    fn setup(message: &str) -> Self {
        // Round to the closest multiple of 64 to factor bit and byte encoding differences.
        let private_key_size_in_bits = <Self as EncryptionScheme>::PrivateKey::size_in_bits();
        assert!(private_key_size_in_bits < usize::MAX - 63);
        let num_powers = (private_key_size_in_bits + 63) & !63usize;

        let mut generator_powers = Vec::with_capacity(num_powers);
        let (base, _, _) = hash_to_curve::<G::Affine>(message);
        let mut generator = base.into_projective();
        for _ in 0..num_powers {
            generator_powers.push(generator);
            generator.double_in_place();
        }

        Self { generator_powers }
    }

    fn generate_private_key<R: Rng + CryptoRng>(&self, rng: &mut R) -> <Self as EncryptionScheme>::PrivateKey {
        let keygen_time = start_timer!(|| "GroupEncryption::generate_private_key");
        let private_key = <G as Group>::ScalarField::rand(rng);
        end_timer!(keygen_time);

        private_key
    }

    fn generate_public_key(
        &self,
        private_key: &<Self as EncryptionScheme>::PrivateKey,
    ) -> Result<<Self as EncryptionScheme>::PublicKey, EncryptionError> {
        let keygen_time = start_timer!(|| "GroupEncryption::generate_public_key");

        let mut public_key = G::zero();
        for (bit, base_power) in from_bytes_le_to_bits_le(&private_key.to_bytes_le()?).zip_eq(&self.generator_powers) {
            if bit {
                public_key += base_power;
            }
        }
        end_timer!(keygen_time);

        Ok(GroupEncryptionPublicKey(public_key))
    }

    fn generate_randomness<R: Rng + CryptoRng>(
        &self,
        public_key: &<Self as EncryptionScheme>::PublicKey,
        rng: &mut R,
    ) -> Result<Self::Randomness, EncryptionError> {
        let mut y = Self::Randomness::zero();
        let mut z_bytes = vec![];

        while Self::Randomness::read_le(&z_bytes[..]).is_err() {
            y = Self::Randomness::rand(rng);

            let affine = public_key.0.mul(y).into_affine();
            debug_assert!(affine.is_in_correct_subgroup_assuming_on_curve());
            z_bytes = affine.to_x_coordinate().to_bytes_le()?;
        }

        Ok(y)
    }

    fn generate_blinding_exponents(
        &self,
        public_key: &<Self as EncryptionScheme>::PublicKey,
        randomness: &Self::Randomness,
        message_length: usize,
    ) -> Result<Vec<Self::BlindingExponent>, EncryptionError> {
        let record_view_key = public_key.0.mul(*randomness);

        let affine = record_view_key.into_affine();
        debug_assert!(affine.is_in_correct_subgroup_assuming_on_curve());
        let z_bytes = affine.to_x_coordinate().to_bytes_le()?;

        let z = Self::Randomness::read_le(&z_bytes[..])?;

        let one = Self::Randomness::one();
        let mut i = Self::Randomness::one();

        let mut blinding_exponents = vec![];
        for _ in 0..message_length {
            // 1 [/] (z [+] i)
            match (z + i).inverse() {
                Some(val) => blinding_exponents.push(val),
                None => return Err(EncryptionError::MissingInverse),
            };

            i += one;
        }

        Ok(blinding_exponents)
    }

    fn encrypt(
        &self,
        public_key: &<Self as EncryptionScheme>::PublicKey,
        randomness: &Self::Randomness,
        message: &[Self::Text],
    ) -> Result<Vec<Self::Text>, EncryptionError> {
        let record_view_key = public_key.0.mul(*randomness);

        let mut c_0 = G::zero();
        for (bit, base_power) in from_bytes_le_to_bits_le(&randomness.to_bytes_le()?).zip_eq(&self.generator_powers) {
            if bit {
                c_0 += base_power;
            }
        }
        let mut ciphertext = vec![c_0];

        let one = Self::Randomness::one();
        let mut i = Self::Randomness::one();

        let blinding_exponents = self.generate_blinding_exponents(public_key, randomness, message.len())?;

        for (m_i, blinding_exp) in message.iter().zip_eq(blinding_exponents) {
            // h_i <- 1 [/] (z [+] i) * record_view_key
            let h_i = record_view_key.mul(blinding_exp);

            // c_i <- h_i + m_i
            let c_i = h_i + m_i;

            ciphertext.push(c_i);
            i += one;
        }

        Ok(ciphertext)
    }

    fn decrypt(
        &self,
        private_key: &<Self as EncryptionScheme>::PrivateKey,
        ciphertext: &[Self::Text],
    ) -> Result<Vec<Self::Text>, EncryptionError> {
        assert!(!ciphertext.is_empty());
        let c_0 = &ciphertext[0];

        let record_view_key = c_0.mul(*private_key);

        let affine = record_view_key.into_affine();
        debug_assert!(affine.is_in_correct_subgroup_assuming_on_curve());
        let z_bytes = affine.to_x_coordinate().to_bytes_le()?;

        let z = Self::Randomness::read_le(&z_bytes[..])?;

        let one = Self::Randomness::one();
        let mut plaintext = Vec::with_capacity(ciphertext.len().saturating_sub(1));
        let mut i = Self::Randomness::one();

        for c_i in ciphertext.iter().skip(1) {
            // h_i <- 1 [/] (z [+] i) * record_view_key
            let h_i = match &(z + i).inverse() {
                Some(val) => record_view_key.mul(*val),
                None => return Err(EncryptionError::MissingInverse),
            };

            // m_i <- c_i - h_i
            let m_i = *c_i - h_i;

            plaintext.push(m_i);
            i += one;
        }

        Ok(plaintext)
    }

    fn parameters(&self) -> &<Self as EncryptionScheme>::Parameters {
        &self.generator_powers
    }

    fn private_key_size_in_bits() -> usize {
        <Self as EncryptionScheme>::PrivateKey::size_in_bits()
    }
}

impl<G: ProjectiveCurve> From<Vec<G>> for GroupEncryption<G> {
    fn from(generator_powers: Vec<G>) -> Self {
        Self { generator_powers }
    }
}

impl<G: ProjectiveCurve> ToBytes for GroupEncryption<G> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (self.generator_powers.len() as u32).write_le(&mut writer)?;
        for g in &self.generator_powers {
            g.write_le(&mut writer)?;
        }
        Ok(())
    }
}

impl<G: ProjectiveCurve> FromBytes for GroupEncryption<G> {
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

impl<F: Field, G: ProjectiveCurve + ToConstraintField<F>> ToConstraintField<F> for GroupEncryption<G> {
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        Ok(Vec::new())
    }
}
