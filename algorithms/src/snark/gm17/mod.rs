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

//! An implementation of the [Groth-Maller][GM17] simulation extractable zkSNARK.
//! [GM17]: https://eprint.iacr.org/2017/540

use snarkvm_curves::traits::pairing_engine::{AffineCurve, PairingCurve, PairingEngine};
use snarkvm_r1cs::errors::SynthesisResult;
use snarkvm_utilities::{errors::SerializationError, serialize::*, FromBytes, ToBytes};

use std::io::{
    Read,
    Result as IoResult,
    Write,
    {self},
};

/// GM17 zkSNARK construction.
pub mod snark;
pub use snark::*;

/// Reduce an R1CS instance to a *Square Arithmetic Program* instance.
mod r1cs_to_sap;

/// Generate public parameters for the GM17 zkSNARK construction.
mod generator;

/// Create proofs for the GM17 zkSNARK construction.
mod prover;

/// Verify proofs for the GM17 zkSNARK construction.
mod verifier;

#[cfg(test)]
mod tests;

pub use generator::*;
pub use prover::*;
pub use verifier::*;

/// A proof in the GM17 SNARK.
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof<E: PairingEngine> {
    pub a: E::G1Affine,
    pub b: E::G2Affine,
    pub c: E::G1Affine,
    pub(crate) compressed: bool,
}

impl<E: PairingEngine> ToBytes for Proof<E> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self.compressed {
            true => self.write_compressed(&mut writer),
            false => self.write_uncompressed(&mut writer),
        }
    }
}

impl<E: PairingEngine> FromBytes for Proof<E> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        Self::read(&mut reader)
    }
}

impl<E: PairingEngine> PartialEq for Proof<E> {
    fn eq(&self, other: &Self) -> bool {
        self.a == other.a && self.b == other.b && self.c == other.c
    }
}

impl<E: PairingEngine> Default for Proof<E> {
    fn default() -> Self {
        Self {
            a: E::G1Affine::default(),
            b: E::G2Affine::default(),
            c: E::G1Affine::default(),
            compressed: true,
        }
    }
}

impl<E: PairingEngine> Proof<E> {
    /// Serialize the proof into bytes in compressed form, for storage
    /// on disk or transmission over the network.
    pub fn write_compressed<W: Write>(&self, mut writer: W) -> IoResult<()> {
        CanonicalSerialize::serialize(self, &mut writer)?;

        Ok(())
    }

    /// Serialize the proof into bytes in uncompressed form, for storage
    /// on disk or transmission over the network.
    pub fn write_uncompressed<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.a.write_le(&mut writer)?;
        self.b.write_le(&mut writer)?;
        self.c.write_le(&mut writer)
    }

    /// Deserialize the proof from compressed bytes.
    pub fn read_compressed<R: Read>(mut reader: R) -> IoResult<Self> {
        Ok(CanonicalDeserialize::deserialize(&mut reader)?)
    }

    /// Deserialize the proof from uncompressed bytes.
    pub fn read_uncompressed<R: Read>(mut reader: R) -> IoResult<Self> {
        let a: E::G1Affine = FromBytes::read_le(&mut reader)?;
        let b: E::G2Affine = FromBytes::read_le(&mut reader)?;
        let c: E::G1Affine = FromBytes::read_le(&mut reader)?;

        Ok(Self {
            a,
            b,
            c,
            compressed: false,
        })
    }

    /// Deserialize a proof from compressed or uncompressed bytes.
    pub fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        // Construct the compressed reader.
        let compressed_proof_size = Self::compressed_proof_size()?;
        let mut proof_reader = vec![0u8; compressed_proof_size];
        reader.read_exact(&mut proof_reader)?;

        // Attempt to read the compressed proof.
        if let Ok(proof) = Self::read_compressed(&proof_reader[..]) {
            return Ok(proof);
        }

        // Construct the uncompressed reader.
        let uncompressed_proof_size = Self::uncompressed_proof_size()?;
        proof_reader.resize(uncompressed_proof_size, 0);
        reader.read_exact(&mut proof_reader[compressed_proof_size..])?;

        // Attempt to read the uncompressed proof.
        Self::read_uncompressed(&proof_reader[..])
    }

    /// Returns the number of bytes in a compressed proof serialization.
    pub fn compressed_proof_size() -> IoResult<usize> {
        let mut buffer = Vec::new();
        Self::default().write_compressed(&mut buffer)?;
        Ok(buffer.len())
    }

    /// Returns the number of bytes in an uncompressed proof serialization.
    pub fn uncompressed_proof_size() -> IoResult<usize> {
        let mut buffer = Vec::new();
        Self::default().write_uncompressed(&mut buffer)?;
        Ok(buffer.len())
    }
}

/// A verifying key in the GM17 SNARK.
#[derive(Clone, Debug, Eq)]
pub struct VerifyingKey<E: PairingEngine> {
    pub h_g2: E::G2Affine,
    pub g_alpha_g1: E::G1Affine,
    pub h_beta_g2: E::G2Affine,
    pub g_gamma_g1: E::G1Affine,
    pub h_gamma_g2: E::G2Affine,
    pub query: Vec<E::G1Affine>,
}

impl<E: PairingEngine> ToBytes for VerifyingKey<E> {
    /// Writes the verifying key into little-endian bytes,
    /// for storage on disk or transmission over the network.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.h_g2.write_le(&mut writer)?;
        self.g_alpha_g1.write_le(&mut writer)?;
        self.h_beta_g2.write_le(&mut writer)?;
        self.g_gamma_g1.write_le(&mut writer)?;
        self.h_gamma_g2.write_le(&mut writer)?;
        (self.query.len() as u32).write_le(&mut writer)?;
        for q in &self.query {
            q.write_le(&mut writer)?;
        }
        Ok(())
    }
}

impl<E: PairingEngine> FromBytes for VerifyingKey<E> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        Self::read(&mut reader)
    }
}

impl<E: PairingEngine> Default for VerifyingKey<E> {
    fn default() -> Self {
        Self {
            h_g2: E::G2Affine::default(),
            g_alpha_g1: E::G1Affine::default(),
            h_beta_g2: E::G2Affine::default(),
            g_gamma_g1: E::G1Affine::default(),
            h_gamma_g2: E::G2Affine::default(),
            query: Vec::new(),
        }
    }
}

impl<E: PairingEngine> PartialEq for VerifyingKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.h_g2 == other.h_g2
            && self.g_alpha_g1 == other.g_alpha_g1
            && self.h_beta_g2 == other.h_beta_g2
            && self.g_gamma_g1 == other.g_gamma_g1
            && self.h_gamma_g2 == other.h_gamma_g2
            && self.query == other.query
    }
}

impl<E: PairingEngine> VerifyingKey<E> {
    /// Deserialize the verifying key from bytes.
    pub fn read<R: Read>(mut reader: R) -> IoResult<Self> {
        let h_g2: E::G2Affine = FromBytes::read_le(&mut reader)?;
        let g_alpha_g1: E::G1Affine = FromBytes::read_le(&mut reader)?;
        let h_beta_g2: E::G2Affine = FromBytes::read_le(&mut reader)?;
        let g_gamma_g1: E::G1Affine = FromBytes::read_le(&mut reader)?;
        let h_gamma_g2: E::G2Affine = FromBytes::read_le(&mut reader)?;

        let query_len: u32 = FromBytes::read_le(&mut reader)?;
        let mut query: Vec<E::G1Affine> = Vec::with_capacity(query_len as usize);
        for _ in 0..query_len {
            let query_element: E::G1Affine = FromBytes::read_le(&mut reader)?;
            query.push(query_element);
        }

        Ok(Self {
            h_g2,
            g_alpha_g1,
            h_beta_g2,
            g_gamma_g1,
            h_gamma_g2,
            query,
        })
    }
}

/// Full public (prover and verifier) parameters for the GM17 zkSNARK.
#[derive(Clone, Debug, Eq)]
pub struct ProvingKey<E: PairingEngine> {
    pub vk: VerifyingKey<E>,
    pub a_query: Vec<E::G1Affine>,
    pub b_query: Vec<E::G2Affine>,
    pub c_query_1: Vec<E::G1Affine>,
    pub c_query_2: Vec<E::G1Affine>,
    pub g_gamma_z: E::G1Affine,
    pub h_gamma_z: E::G2Affine,
    pub g_ab_gamma_z: E::G1Affine,
    pub g_gamma2_z2: E::G1Affine,
    pub g_gamma2_z_t: Vec<E::G1Affine>,
}

impl<E: PairingEngine> PartialEq for ProvingKey<E> {
    fn eq(&self, other: &Self) -> bool {
        self.vk == other.vk
            && self.a_query == other.a_query
            && self.b_query == other.b_query
            && self.c_query_1 == other.c_query_1
            && self.c_query_2 == other.c_query_2
            && self.g_gamma_z == other.g_gamma_z
            && self.h_gamma_z == other.h_gamma_z
            && self.g_ab_gamma_z == other.g_ab_gamma_z
            && self.g_gamma2_z2 == other.g_gamma2_z2
            && self.g_gamma2_z_t == other.g_gamma2_z_t
    }
}

impl<E: PairingEngine> ToBytes for ProvingKey<E> {
    /// Serialize the parameters to little-endian bytes.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.vk.write_le(&mut writer)?;

        (self.a_query.len() as u32).write_le(&mut writer)?;
        for g in &self.a_query[..] {
            g.write_le(&mut writer)?;
        }

        (self.b_query.len() as u32).write_le(&mut writer)?;
        for g in &self.b_query[..] {
            g.write_le(&mut writer)?;
        }

        (self.c_query_1.len() as u32).write_le(&mut writer)?;
        for g in &self.c_query_1[..] {
            g.write_le(&mut writer)?;
        }

        (self.c_query_2.len() as u32).write_le(&mut writer)?;
        for g in &self.c_query_2[..] {
            g.write_le(&mut writer)?;
        }

        self.g_gamma_z.write_le(&mut writer)?;

        self.h_gamma_z.write_le(&mut writer)?;

        self.g_ab_gamma_z.write_le(&mut writer)?;

        self.g_gamma2_z2.write_le(&mut writer)?;

        (self.g_gamma2_z_t.len() as u32).write_le(&mut writer)?;
        for g in &self.g_gamma2_z_t[..] {
            g.write_le(&mut writer)?;
        }

        Ok(())
    }
}

impl<E: PairingEngine> FromBytes for ProvingKey<E> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        Self::read(&mut reader, false)
    }
}

impl<E: PairingEngine> From<ProvingKey<E>> for VerifyingKey<E> {
    fn from(other: ProvingKey<E>) -> Self {
        other.vk
    }
}

impl<E: PairingEngine> From<ProvingKey<E>> for PreparedVerifyingKey<E> {
    fn from(other: ProvingKey<E>) -> Self {
        prepare_verifying_key(other.vk)
    }
}

impl<E: PairingEngine> ProvingKey<E> {
    /// Deserialize the public parameters from bytes.
    pub fn read<R: Read>(mut reader: R, checked: bool) -> IoResult<Self> {
        let read_g1_affine = |mut reader: &mut R| -> IoResult<E::G1Affine> {
            let g1_affine: E::G1Affine = FromBytes::read_le(&mut reader)?;

            if checked && !g1_affine.is_in_correct_subgroup_assuming_on_curve() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "point is not in the correct subgroup",
                ));
            }

            Ok(g1_affine)
        };

        let read_g2_affine = |mut reader: &mut R| -> IoResult<E::G2Affine> {
            let g2_affine: E::G2Affine = FromBytes::read_le(&mut reader)?;

            if checked && !g2_affine.is_in_correct_subgroup_assuming_on_curve() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "point is not in the correct subgroup",
                ));
            }

            Ok(g2_affine)
        };

        let vk = VerifyingKey::<E>::read(&mut reader)?;

        let a_query_len: u32 = FromBytes::read_le(&mut reader)?;
        let mut a_query = Vec::with_capacity(a_query_len as usize);
        for _ in 0..a_query_len {
            a_query.push(read_g1_affine(&mut reader)?);
        }

        let b_query_len: u32 = FromBytes::read_le(&mut reader)?;
        let mut b_query = Vec::with_capacity(b_query_len as usize);
        for _ in 0..b_query_len {
            b_query.push(read_g2_affine(&mut reader)?);
        }

        let c_query_1_len: u32 = FromBytes::read_le(&mut reader)?;
        let mut c_query_1 = Vec::with_capacity(c_query_1_len as usize);
        for _ in 0..c_query_1_len {
            c_query_1.push(read_g1_affine(&mut reader)?);
        }

        let c_query_2_len: u32 = FromBytes::read_le(&mut reader)?;
        let mut c_query_2 = Vec::with_capacity(c_query_2_len as usize);
        for _ in 0..c_query_2_len {
            c_query_2.push(read_g1_affine(&mut reader)?);
        }

        let g_gamma_z: E::G1Affine = FromBytes::read_le(&mut reader)?;
        let h_gamma_z: E::G2Affine = FromBytes::read_le(&mut reader)?;
        let g_ab_gamma_z: E::G1Affine = FromBytes::read_le(&mut reader)?;
        let g_gamma2_z2: E::G1Affine = FromBytes::read_le(&mut reader)?;

        let g_gamma2_z_t_len: u32 = FromBytes::read_le(&mut reader)?;
        let mut g_gamma2_z_t = Vec::with_capacity(g_gamma2_z_t_len as usize);
        for _ in 0..g_gamma2_z_t_len {
            g_gamma2_z_t.push(read_g1_affine(&mut reader)?);
        }

        Ok(Self {
            vk,
            a_query,
            b_query,
            c_query_1,
            c_query_2,
            g_gamma_z,
            h_gamma_z,
            g_ab_gamma_z,
            g_gamma2_z2,
            g_gamma2_z_t,
        })
    }
}

/// Preprocessed verifying key parameters that enable faster verification
/// at the expense of larger size in memory.
#[derive(Clone, Debug)]
pub struct PreparedVerifyingKey<E: PairingEngine> {
    pub vk: VerifyingKey<E>,
    pub g_alpha: E::G1Affine,
    pub h_beta: E::G2Affine,
    pub g_alpha_h_beta_ml: E::Fqk,
    pub g_gamma_pc: <E::G1Affine as PairingCurve>::Prepared,
    pub h_gamma_pc: <E::G2Affine as PairingCurve>::Prepared,
    pub h_pc: <E::G2Affine as PairingCurve>::Prepared,
}

impl<E: PairingEngine> PreparedVerifyingKey<E> {
    fn query(&self) -> &[E::G1Affine] {
        &self.vk.query
    }
}

impl<E: PairingEngine> From<PreparedVerifyingKey<E>> for VerifyingKey<E> {
    fn from(other: PreparedVerifyingKey<E>) -> Self {
        other.vk
    }
}

impl<E: PairingEngine> From<VerifyingKey<E>> for PreparedVerifyingKey<E> {
    fn from(other: VerifyingKey<E>) -> Self {
        prepare_verifying_key(other)
    }
}

impl<E: PairingEngine> Default for PreparedVerifyingKey<E> {
    fn default() -> Self {
        Self {
            vk: VerifyingKey::default(),
            g_alpha: E::G1Affine::default(),
            h_beta: E::G2Affine::default(),
            g_alpha_h_beta_ml: E::Fqk::default(),
            g_gamma_pc: <E::G1Affine as PairingCurve>::Prepared::default(),
            h_gamma_pc: <E::G2Affine as PairingCurve>::Prepared::default(),
            h_pc: <E::G2Affine as PairingCurve>::Prepared::default(),
        }
    }
}

impl<E: PairingEngine> ToBytes for PreparedVerifyingKey<E> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.vk.write_le(&mut writer)?;
        self.g_alpha.write_le(&mut writer)?;
        self.h_beta.write_le(&mut writer)?;
        self.g_alpha_h_beta_ml.write_le(&mut writer)?;
        self.g_gamma_pc.write_le(&mut writer)?;
        self.h_gamma_pc.write_le(&mut writer)?;
        self.h_pc.write_le(&mut writer)?;
        for q in self.query() {
            q.write_le(&mut writer)?;
        }
        Ok(())
    }
}

type AffinePair<'a, T> = (&'a [T], &'a [T]);

impl<E: PairingEngine> ProvingKey<E> {
    pub fn get_vk(&self, _: usize) -> SynthesisResult<VerifyingKey<E>> {
        Ok(self.vk.clone())
    }

    pub fn get_a_query(&self, num_inputs: usize) -> SynthesisResult<AffinePair<E::G1Affine>> {
        Ok((&self.a_query[1..num_inputs], &self.a_query[num_inputs..]))
    }

    pub fn get_b_query(&self, num_inputs: usize) -> SynthesisResult<AffinePair<E::G2Affine>> {
        Ok((&self.b_query[1..num_inputs], &self.b_query[num_inputs..]))
    }

    pub fn get_c_query_1(&self, num_inputs: usize) -> SynthesisResult<AffinePair<E::G1Affine>> {
        Ok((&self.c_query_1[0..num_inputs], &self.c_query_1[num_inputs..]))
    }

    pub fn get_c_query_2(&self, num_inputs: usize) -> SynthesisResult<AffinePair<E::G1Affine>> {
        Ok((&self.c_query_2[1..num_inputs], &self.c_query_2[num_inputs..]))
    }

    pub fn get_g_gamma_z(&self) -> SynthesisResult<E::G1Affine> {
        Ok(self.g_gamma_z)
    }

    pub fn get_h_gamma_z(&self) -> SynthesisResult<E::G2Affine> {
        Ok(self.h_gamma_z)
    }

    pub fn get_g_ab_gamma_z(&self) -> SynthesisResult<E::G1Affine> {
        Ok(self.g_ab_gamma_z)
    }

    pub fn get_g_gamma2_z2(&self) -> SynthesisResult<E::G1Affine> {
        Ok(self.g_gamma2_z2)
    }

    pub fn get_g_gamma2_z_t(&self, num_inputs: usize) -> SynthesisResult<AffinePair<E::G1Affine>> {
        Ok((&self.g_gamma2_z_t[0..num_inputs], &self.g_gamma2_z_t[num_inputs..]))
    }

    pub fn get_a_query_full(&self) -> SynthesisResult<&[E::G1Affine]> {
        Ok(&self.a_query)
    }

    pub fn get_b_query_full(&self) -> SynthesisResult<&[E::G2Affine]> {
        Ok(&self.b_query)
    }

    pub fn get_c_query_1_full(&self) -> SynthesisResult<&[E::G1Affine]> {
        Ok(&self.c_query_1)
    }

    pub fn get_c_query_2_full(&self) -> SynthesisResult<&[E::G1Affine]> {
        Ok(&self.c_query_2)
    }

    pub fn get_g_gamma2_z_t_full(&self) -> SynthesisResult<&[E::G1Affine]> {
        Ok(&self.g_gamma2_z_t)
    }
}
