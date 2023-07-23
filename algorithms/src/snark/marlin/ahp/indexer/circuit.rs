// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use core::marker::PhantomData;

use crate::{
    fft::{
        domain::{FFTPrecomputation, IFFTPrecomputation},
        EvaluationDomain,
    },
    polycommit::sonic_pc::LabeledPolynomial,
    r1cs::LookupTable,
    snark::marlin::{ahp::matrices::MatrixArithmetization, AHPForR1CS, CircuitInfo, MarlinMode, Matrix, TableInfo},
};
use blake2::Digest;
use hex::FromHex;
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{serialize::*, SerializationError};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, CanonicalSerialize, CanonicalDeserialize)]
pub struct CircuitId(pub [u8; 32]);

impl std::fmt::Display for CircuitId {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl CircuitId {
    pub fn from_witness_label(witness_label: &str) -> Self {
        CircuitId(
            <[u8; 32]>::from_hex(witness_label.split('_').collect::<Vec<&str>>()[1])
                .expect("Decoding circuit_id failed"),
        )
    }
}

/// The indexed version of the constraint system.
/// This struct contains the following kinds of objects:
/// 1) `index_info` is information about the index, such as the size of the
///     public input
/// 3) `table_info` is information about the index regarding lookups, such as the
///     defined lookup tables
/// 4) `{a,b,c}` are the matrices defining the R1CS instance
/// 5) `{a,b,c}_arith` are structs containing information about the arithmetized matrices
/// 6) `s_mul and s_lookup` are selectors used to distinguish between mul and lookup constraints
#[derive(Clone, Debug)]
pub struct Circuit<F: PrimeField, MM: MarlinMode> {
    /// Information about the indexed circuit.
    pub index_info: CircuitInfo,
    /// Optional information about the lookup tables in the circuit.
    pub table_info: Option<TableInfo<F>>,

    /// The A matrix for the R1CS instance
    pub a: Matrix<F>,
    /// The B matrix for the R1CS instance
    pub b: Matrix<F>,
    /// The C matrix for the R1CS instance
    pub c: Matrix<F>,

    /// Joint arithmetization of the A, B, and C matrices.
    pub a_arith: MatrixArithmetization<F>,
    pub b_arith: MatrixArithmetization<F>,
    pub c_arith: MatrixArithmetization<F>,

    pub fft_precomputation: FFTPrecomputation<F>,
    pub ifft_precomputation: IFFTPrecomputation<F>,

    /// Selectors, only used when lookups are activated
    pub s_mul: Option<LabeledPolynomial<F>>,
    pub s_lookup: Option<LabeledPolynomial<F>>, // TODO: re-evaluate if storing s_lookup_evals saves so much compute
    pub s_lookup_evals: Option<Vec<F>>,

    pub(crate) _mode: PhantomData<MM>,
    pub(crate) id: CircuitId,
}

impl<F: PrimeField, MM: MarlinMode> Eq for Circuit<F, MM> {}
impl<F: PrimeField, MM: MarlinMode> PartialEq for Circuit<F, MM> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<F: PrimeField, MM: MarlinMode> Ord for Circuit<F, MM> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.id.cmp(&other.id)
    }
}

impl<F: PrimeField, MM: MarlinMode> PartialOrd for Circuit<F, MM> {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl<F: PrimeField, MM: MarlinMode> Circuit<F, MM> {
    pub fn hash(
        index_info: &CircuitInfo,
        table_info: &Option<&Vec<LookupTable<F>>>,
        a: &Matrix<F>,
        b: &Matrix<F>,
        c: &Matrix<F>,
        s_mul: &Option<&Vec<F>>,
        s_lookup: &Option<&Vec<F>>,
    ) -> Result<CircuitId, SerializationError> {
        let mut blake2 = blake2::Blake2s256::new();
        index_info.serialize_uncompressed(&mut blake2)?;
        a.serialize_uncompressed(&mut blake2)?;
        b.serialize_uncompressed(&mut blake2)?;
        c.serialize_uncompressed(&mut blake2)?;
        if table_info.is_some() {
            table_info.as_ref().unwrap().serialize_uncompressed(&mut blake2)?;
            s_mul.as_ref().unwrap().serialize_uncompressed(&mut blake2)?;
            s_lookup.as_ref().unwrap().serialize_uncompressed(&mut blake2)?;
        }
        Ok(CircuitId(blake2.finalize().into()))
    }

    /// The maximum degree required to represent polynomials of this index.
    pub fn max_degree(&self) -> usize {
        self.index_info.max_degree::<F, MM>()
    }

    /// The size of the constraint domain in this R1CS instance.
    pub fn constraint_domain_size(&self) -> usize {
        crate::fft::EvaluationDomain::<F>::new(self.index_info.num_constraints).unwrap().size()
    }

    /// The size of the variable domain in this R1CS instance.
    pub fn variable_domain_size(&self) -> usize {
        crate::fft::EvaluationDomain::<F>::new(self.index_info.num_variables).unwrap().size()
    }

    /// Iterate over the indexed polynomials.
    pub fn iter(&self) -> impl Iterator<Item = &LabeledPolynomial<F>> {
        assert_eq!(self.s_lookup.is_some(), self.s_mul.is_some());
        assert_eq!(self.s_lookup.is_some(), self.s_lookup_evals.is_some());
        assert_eq!(self.s_lookup.is_some(), self.table_info.is_some());
        // Alphabetical order of their labels
        [
            &self.a_arith.col,
            &self.b_arith.col,
            &self.c_arith.col,
            &self.a_arith.row,
            &self.b_arith.row,
            &self.c_arith.row,
            &self.a_arith.row_col,
            &self.b_arith.row_col,
            &self.c_arith.row_col,
            &self.a_arith.row_col_val,
            &self.b_arith.row_col_val,
            &self.c_arith.row_col_val,
        ]
        .into_iter()
        .chain(self.s_lookup.as_ref())
        .chain(self.s_mul.as_ref())
        .chain(self.table_info.is_some().then(|| self.table_info.as_ref().unwrap().iter()).into_iter().flatten())
        // .chain([&self.a_arith.row_col_val, &self.b_arith.row_col_val, &self.c_arith.row_col_val])
    }

    /// After indexing, we drop these evaluations to save space in the ProvingKey.
    pub fn prune_row_col_evals(&mut self) {
        self.a_arith.evals_on_K.row_col = None;
        self.b_arith.evals_on_K.row_col = None;
        self.c_arith.evals_on_K.row_col = None;
    }
}

impl<F: PrimeField, MM: MarlinMode> CanonicalSerialize for Circuit<F, MM> {
    #[allow(unused_mut, unused_variables)]
    fn serialize_with_mode<W: Write>(&self, mut writer: W, compress: Compress) -> Result<(), SerializationError> {
        self.index_info.serialize_with_mode(&mut writer, compress)?;
        self.table_info.serialize_with_mode(&mut writer, compress)?;
        self.a.serialize_with_mode(&mut writer, compress)?;
        self.b.serialize_with_mode(&mut writer, compress)?;
        self.c.serialize_with_mode(&mut writer, compress)?;
        self.a_arith.serialize_with_mode(&mut writer, compress)?;
        self.b_arith.serialize_with_mode(&mut writer, compress)?;
        self.c_arith.serialize_with_mode(&mut writer, compress)?;
        self.s_mul.serialize_with_mode(&mut writer, compress)?;
        self.s_lookup.serialize_with_mode(&mut writer, compress)?;
        self.s_lookup_evals.serialize_with_mode(&mut writer, compress)?;
        Ok(())
    }

    #[allow(unused_mut, unused_variables)]
    fn serialized_size(&self, mode: Compress) -> usize {
        let mut size = 0;
        size += self.index_info.serialized_size(mode);
        size += self.table_info.serialized_size(mode);
        size += self.a.serialized_size(mode);
        size += self.b.serialized_size(mode);
        size += self.c.serialized_size(mode);
        size += self.a_arith.serialized_size(mode);
        size += self.b_arith.serialized_size(mode);
        size += self.c_arith.serialized_size(mode);
        size += self.s_mul.serialized_size(mode);
        size += self.s_lookup.serialized_size(mode);
        size += self.s_lookup_evals.serialized_size(mode);
        size
    }
}

impl<F: PrimeField, MM: MarlinMode> snarkvm_utilities::Valid for Circuit<F, MM> {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }

    fn batch_check<'a>(_batch: impl Iterator<Item = &'a Self> + Send) -> Result<(), SerializationError>
    where
        Self: 'a,
    {
        Ok(())
    }
}

impl<F: PrimeField, MM: MarlinMode> CanonicalDeserialize for Circuit<F, MM> {
    fn deserialize_with_mode<R: Read>(
        mut reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        let index_info: CircuitInfo = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let table_info: Option<TableInfo<F>> =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let constraint_domain_size = EvaluationDomain::<F>::compute_size_of_domain(index_info.num_constraints)
            .ok_or(SerializationError::InvalidData)?;
        let variable_domain_size = EvaluationDomain::<F>::compute_size_of_domain(index_info.num_variables)
            .ok_or(SerializationError::InvalidData)?;
        let non_zero_a_domain_size = EvaluationDomain::<F>::compute_size_of_domain(index_info.num_non_zero_a)
            .ok_or(SerializationError::InvalidData)?;
        let non_zero_b_domain_size = EvaluationDomain::<F>::compute_size_of_domain(index_info.num_non_zero_b)
            .ok_or(SerializationError::InvalidData)?;
        let non_zero_c_domain_size = EvaluationDomain::<F>::compute_size_of_domain(index_info.num_non_zero_c)
            .ok_or(SerializationError::InvalidData)?;

        let (fft_precomputation, ifft_precomputation) = AHPForR1CS::<F, MM>::fft_precomputation(
            variable_domain_size,
            constraint_domain_size,
            non_zero_a_domain_size,
            non_zero_b_domain_size,
            non_zero_c_domain_size,
        )
        .ok_or(SerializationError::InvalidData)?;
        let a = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let b = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let c = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;

        let a_arith = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let b_arith = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let c_arith = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;

        let s_mul: Option<LabeledPolynomial<F>> =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let s_lookup = CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let s_lookup_evals: Option<Vec<F>> =
            CanonicalDeserialize::deserialize_with_mode(&mut reader, compress, validate)?;
        let constraint_domain = EvaluationDomain::new(constraint_domain_size).ok_or(SerializationError::InvalidData)?;
        let s_mul_evals = s_mul.is_some().then(|| {
            s_mul
                .as_ref()
                .unwrap()
                .polynomial()
                .as_dense()
                .unwrap()
                .evaluate_over_domain_by_ref(constraint_domain)
                .evaluations
        });
        let lookup_tables = table_info.is_some().then(|| &table_info.as_ref().unwrap().lookup_tables);

        let id = Self::hash(&index_info, &lookup_tables, &a, &b, &c, &s_mul_evals.as_ref(), &s_lookup_evals.as_ref())?;
        Ok(Circuit {
            index_info,
            table_info,
            a,
            b,
            c,
            a_arith,
            b_arith,
            c_arith,
            fft_precomputation,
            ifft_precomputation,
            s_mul,
            s_lookup,
            s_lookup_evals,
            _mode: PhantomData,
            id,
        })
    }
}
