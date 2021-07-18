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
    crypto_hash::{CryptographicSponge, DuplexSpongeMode, PoseidonGrainLFSR},
    CryptoHash,
    CryptoHashError,
};
use snarkvm_fields::{
    Fp256,
    Fp256Parameters,
    Fp384,
    Fp384Parameters,
    Fp768,
    Fp768Parameters,
    PoseidonDefaultParameters,
    PrimeField,
};
use snarkvm_utilities::{FromBytes, ToBytes};

use std::io::{Read, Result as IoResult, Write};

/// Parameters and RNG used
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PoseidonParameters<F: PrimeField> {
    /// number of rounds in a full-round operation
    pub full_rounds: usize,
    /// number of rounds in a partial-round operation
    pub partial_rounds: usize,
    /// Exponent used in S-boxes
    pub alpha: u64,
    /// Additive Round keys. These are added before each MDS matrix application to make it an affine shift.
    /// They are indexed by `ark[round_num][state_element_index]`
    pub ark: Vec<Vec<F>>,
    /// Maximally Distance Separating Matrix.
    pub mds: Vec<Vec<F>>,
    /// the rate (in terms of number of field elements)
    pub rate: usize,
    /// the capacity (in terms of number of field elements)
    pub capacity: usize,
}

impl<F: PrimeField> PoseidonParameters<F> {
    /// Initialize the parameter for Poseidon Sponge.
    pub fn new(
        full_rounds: usize,
        partial_rounds: usize,
        alpha: u64,
        mds: Vec<Vec<F>>,
        ark: Vec<Vec<F>>,
        rate: usize,
        capacity: usize,
    ) -> Self {
        assert_eq!(ark.len(), full_rounds + partial_rounds);
        for item in &ark {
            assert_eq!(item.len(), rate + capacity);
        }
        assert_eq!(mds.len(), rate + capacity);
        for item in &mds {
            assert_eq!(item.len(), rate + capacity);
        }
        Self {
            full_rounds,
            partial_rounds,
            alpha,
            mds,
            ark,
            rate,
            capacity,
        }
    }
}

impl<F: PrimeField> ToBytes for PoseidonParameters<F> {
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        (self.full_rounds as u32).write_le(&mut writer)?;
        (self.partial_rounds as u32).write_le(&mut writer)?;
        self.alpha.write_le(&mut writer)?;

        (self.ark.len() as u32).write_le(&mut writer)?;
        for fields in &self.ark {
            (fields.len() as u32).write_le(&mut writer)?;
            for field in fields {
                field.write_le(&mut writer)?;
            }
        }

        (self.mds.len() as u32).write_le(&mut writer)?;
        for fields in &self.mds {
            (fields.len() as u32).write_le(&mut writer)?;
            for field in fields {
                field.write_le(&mut writer)?;
            }
        }

        (self.rate as u32).write_le(&mut writer)?;
        (self.capacity as u32).write_le(&mut writer)
    }
}

impl<F: PrimeField> FromBytes for PoseidonParameters<F> {
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let full_rounds: u32 = FromBytes::read_le(&mut reader)?;
        let partial_rounds: u32 = FromBytes::read_le(&mut reader)?;
        let alpha: u64 = FromBytes::read_le(&mut reader)?;

        let ark_length: u32 = FromBytes::read_le(&mut reader)?;
        let mut ark = Vec::with_capacity(ark_length as usize);
        for _ in 0..ark_length {
            let num_fields: u32 = FromBytes::read_le(&mut reader)?;
            let mut fields = Vec::with_capacity(num_fields as usize);

            for _ in 0..num_fields {
                let field: F = FromBytes::read_le(&mut reader)?;
                fields.push(field);
            }
            ark.push(fields);
        }

        let mds_length: u32 = FromBytes::read_le(&mut reader)?;
        let mut mds = Vec::with_capacity(mds_length as usize);
        for _ in 0..mds_length {
            let num_fields: u32 = FromBytes::read_le(&mut reader)?;
            let mut fields = Vec::with_capacity(num_fields as usize);

            for _ in 0..num_fields {
                let field: F = FromBytes::read_le(&mut reader)?;
                fields.push(field);
            }
            mds.push(fields);
        }

        let rate: u32 = FromBytes::read_le(&mut reader)?;
        let capacity: u32 = FromBytes::read_le(&mut reader)?;

        Ok(Self::new(
            full_rounds as usize,
            partial_rounds as usize,
            alpha,
            mds,
            ark,
            rate as usize,
            capacity as usize,
        ))
    }
}

#[derive(Clone)]
/// A duplex sponge based using the Poseidon permutation.
///
/// This implementation of Poseidon is entirely from Fractal's implementation in [COS20][cos]
/// with small syntax changes.
///
/// [cos]: https://eprint.iacr.org/2019/1076
pub struct PoseidonSponge<F: PrimeField> {
    // Sponge Parameters
    pub parameters: PoseidonParameters<F>,

    // Sponge State
    /// current sponge's state (current elements in the permutation block)
    pub state: Vec<F>,
    /// current mode (whether its absorbing or squeezing)
    pub mode: DuplexSpongeMode,
}

impl<F: PrimeField> PoseidonSponge<F> {
    fn apply_s_box(&self, state: &mut [F], is_full_round: bool) {
        // Full rounds apply the S Box (x^alpha) to every element of state
        if is_full_round {
            for elem in state {
                *elem = elem.pow(&[self.parameters.alpha]);
            }
        }
        // Partial rounds apply the S Box (x^alpha) to just the first element of state
        else {
            state[0] = state[0].pow(&[self.parameters.alpha]);
        }
    }

    fn apply_ark(&self, state: &mut [F], round_number: usize) {
        for (i, state_elem) in state.iter_mut().enumerate() {
            state_elem.add_assign(&self.parameters.ark[round_number][i]);
        }
    }

    fn apply_mds(&self, state: &mut [F]) {
        let mut new_state = Vec::new();
        for i in 0..state.len() {
            let mut cur = F::zero();
            for (j, state_elem) in state.iter().enumerate() {
                let term = state_elem.mul(&self.parameters.mds[i][j]);
                cur.add_assign(&term);
            }
            new_state.push(cur);
        }

        state.clone_from_slice(&new_state[..state.len()])
    }

    fn permute(&mut self) {
        let full_rounds_over_2 = self.parameters.full_rounds / 2;
        let mut state = self.state.clone();
        for i in 0..full_rounds_over_2 {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }

        for i in full_rounds_over_2..(full_rounds_over_2 + self.parameters.partial_rounds) {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, false);
            self.apply_mds(&mut state);
        }

        for i in (full_rounds_over_2 + self.parameters.partial_rounds)
            ..(self.parameters.partial_rounds + self.parameters.full_rounds)
        {
            self.apply_ark(&mut state, i);
            self.apply_s_box(&mut state, true);
            self.apply_mds(&mut state);
        }
        self.state = state;
    }

    // Absorbs everything in elements, this does not end in an absorbtion.
    fn absorb_internal(&mut self, mut rate_start_index: usize, elements: &[F]) {
        if elements.len() == 0 {
            return;
        }

        let mut remaining_elements = elements;

        loop {
            // if we can finish in this call
            if rate_start_index + remaining_elements.len() <= self.parameters.rate {
                for (i, element) in remaining_elements.iter().enumerate() {
                    self.state[self.parameters.capacity + i + rate_start_index] += element;
                }
                self.mode = DuplexSpongeMode::Absorbing {
                    next_absorb_index: rate_start_index + remaining_elements.len(),
                };

                return;
            }
            // otherwise absorb (rate - rate_start_index) elements
            let num_elements_absorbed = self.parameters.rate - rate_start_index;
            for (i, element) in remaining_elements.iter().enumerate().take(num_elements_absorbed) {
                self.state[self.parameters.capacity + i + rate_start_index] += element;
            }
            self.permute();
            // the input elements got truncated by num elements absorbed
            remaining_elements = &remaining_elements[num_elements_absorbed..];
            rate_start_index = 0;
        }
    }

    // Squeeze |output| many elements. This does not end in a squeeze
    fn squeeze_internal(&mut self, mut rate_start_index: usize, output: &mut [F]) {
        let mut output_remaining = output;
        loop {
            // if we can finish in this call
            if rate_start_index + output_remaining.len() <= self.parameters.rate {
                output_remaining.clone_from_slice(
                    &self.state[self.parameters.capacity + rate_start_index
                        ..(self.parameters.capacity + output_remaining.len() + rate_start_index)],
                );
                self.mode = DuplexSpongeMode::Squeezing {
                    next_squeeze_index: rate_start_index + output_remaining.len(),
                };
                return;
            }
            // otherwise squeeze (rate - rate_start_index) elements
            let num_elements_squeezed = self.parameters.rate - rate_start_index;
            output_remaining[..num_elements_squeezed].clone_from_slice(
                &self.state[self.parameters.capacity + rate_start_index
                    ..(self.parameters.capacity + num_elements_squeezed + rate_start_index)],
            );

            // Unless we are done with squeezing in this call, permute.
            if output_remaining.len() != self.parameters.rate {
                self.permute();
            }
            // Repeat with updated output slices
            output_remaining = &mut output_remaining[num_elements_squeezed..];
            rate_start_index = 0;
        }
    }
}

impl<F: PrimeField> CryptographicSponge<F> for PoseidonSponge<F> {
    type Parameters = PoseidonParameters<F>;

    fn new(parameters: &Self::Parameters) -> Self {
        let state = vec![F::zero(); parameters.rate + parameters.capacity];
        let mode = DuplexSpongeMode::Absorbing { next_absorb_index: 0 };

        Self {
            parameters: parameters.clone(),
            state,
            mode,
        }
    }

    fn absorb(&mut self, input: &[F]) {
        if input.len() == 0 {
            return;
        }

        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index } => {
                let mut absorb_index = next_absorb_index;
                if absorb_index == self.parameters.rate {
                    self.permute();
                    absorb_index = 0;
                }
                self.absorb_internal(absorb_index, input);
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index: _ } => {
                self.permute();
                self.absorb_internal(0, input);
            }
        };
    }

    fn squeeze_field_elements(&mut self, num_elements: usize) -> Vec<F> {
        let mut squeezed_elems = vec![F::zero(); num_elements];
        match self.mode {
            DuplexSpongeMode::Absorbing { next_absorb_index: _ } => {
                self.permute();
                self.squeeze_internal(0, &mut squeezed_elems);
            }
            DuplexSpongeMode::Squeezing { next_squeeze_index } => {
                let mut squeeze_index = next_squeeze_index;
                if squeeze_index == self.parameters.rate {
                    self.permute();
                    squeeze_index = 0;
                }
                self.squeeze_internal(squeeze_index, &mut squeezed_elems);
            }
        };

        squeezed_elems
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoseidonCryptoHash<
    F: PrimeField + PoseidonDefaultParametersField,
    const RATE: usize,
    const OPTIMIZED_FOR_WEIGHTS: bool,
> {
    pub parameters: PoseidonParameters<F>,
}

impl<F: PrimeField + PoseidonDefaultParametersField, const RATE: usize, const OPTIMIZED_FOR_WEIGHTS: bool> CryptoHash
    for PoseidonCryptoHash<F, RATE, OPTIMIZED_FOR_WEIGHTS>
{
    type Input = F;
    type Output = F;

    fn evaluate(input: &[Self::Input]) -> Result<Self::Output, CryptoHashError> {
        let params = F::get_default_poseidon_parameters(RATE, OPTIMIZED_FOR_WEIGHTS).unwrap();
        let mut sponge = PoseidonSponge::<F>::new(&params);
        sponge.absorb(input);
        let res = sponge.squeeze_field_elements(1);
        Ok(res[0].clone())
    }
}

impl<F: PrimeField + PoseidonDefaultParametersField, const RATE: usize, const OPTIMIZED_FOR_WEIGHTS: bool> ToBytes
    for PoseidonCryptoHash<F, RATE, OPTIMIZED_FOR_WEIGHTS>
{
    #[inline]
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        self.parameters.write_le(&mut writer)
    }
}

impl<F: PrimeField + PoseidonDefaultParametersField, const RATE: usize, const OPTIMIZED_FOR_WEIGHTS: bool> FromBytes
    for PoseidonCryptoHash<F, RATE, OPTIMIZED_FOR_WEIGHTS>
{
    #[inline]
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        let parameters: PoseidonParameters<F> = FromBytes::read_le(&mut reader)?;

        Ok(Self { parameters })
    }
}

/// A field with Poseidon parameters associated
pub trait PoseidonDefaultParametersField: PrimeField {
    /// Obtain the default Poseidon parameters for this rate and for this prime field,
    /// with a specific optimization goal.
    fn get_default_poseidon_parameters(rate: usize, optimized_for_weights: bool) -> Option<PoseidonParameters<Self>>;
}

/// Internal function that uses the `PoseidonDefaultParameters` to compute the Poseidon parameters.
pub fn get_default_poseidon_parameters_internal<F: PrimeField, P: PoseidonDefaultParameters>(
    rate: usize,
    optimized_for_weights: bool,
) -> Option<PoseidonParameters<F>> {
    let params_set = if !optimized_for_weights {
        P::PARAMS_OPT_FOR_CONSTRAINTS
    } else {
        P::PARAMS_OPT_FOR_WEIGHTS
    };

    for param in params_set.iter() {
        if param.rate == rate {
            let (ark, mds) = find_poseidon_ark_and_mds::<F>(
                P::MODULUS_BITS as u64,
                rate,
                param.full_rounds as u64,
                param.partial_rounds as u64,
                param.skip_matrices as u64,
            );

            return Some(PoseidonParameters {
                full_rounds: param.full_rounds,
                partial_rounds: param.partial_rounds,
                alpha: param.alpha as u64,
                ark,
                mds,
                rate: param.rate,
                capacity: 1,
            });
        }
    }

    None
}

/// Internal function that computes the ark and mds from the Poseidon Grain LFSR.
pub fn find_poseidon_ark_and_mds<F: PrimeField>(
    prime_bits: u64,
    rate: usize,
    full_rounds: u64,
    partial_rounds: u64,
    skip_matrices: u64,
) -> (Vec<Vec<F>>, Vec<Vec<F>>) {
    let mut lfsr = PoseidonGrainLFSR::new(false, prime_bits, (rate + 1) as u64, full_rounds, partial_rounds);

    let mut ark = Vec::<Vec<F>>::new();
    for _ in 0..(full_rounds + partial_rounds) {
        ark.push(lfsr.get_field_elements_rejection_sampling(rate + 1));
    }

    let mut mds = Vec::<Vec<F>>::new();
    mds.resize(rate + 1, vec![F::zero(); rate + 1]);
    for _ in 0..skip_matrices {
        let _ = lfsr.get_field_elements_mod_p::<F>(2 * (rate + 1));
    }

    // a qualifying matrix must satisfy the following requirements
    // - there is no duplication among the elements in x or y
    // - there is no i and j such that x[i] + y[j] = p
    // - the resultant MDS passes all the three tests

    let xs = lfsr.get_field_elements_mod_p::<F>(rate + 1);
    let ys = lfsr.get_field_elements_mod_p::<F>(rate + 1);

    for i in 0..(rate + 1) {
        for j in 0..(rate + 1) {
            mds[i][j] = (xs[i] + &ys[j]).inverse().unwrap();
        }
    }

    (ark, mds)
}

macro_rules! impl_poseidon_default_parameters_field {
    ($field: ident, $params: ident) => {
        impl<P: $params + PoseidonDefaultParameters> PoseidonDefaultParametersField for $field<P> {
            fn get_default_poseidon_parameters(
                rate: usize,
                optimized_for_weights: bool,
            ) -> Option<PoseidonParameters<Self>> {
                get_default_poseidon_parameters_internal::<Self, P>(rate, optimized_for_weights)
            }
        }
    };
}

impl_poseidon_default_parameters_field!(Fp256, Fp256Parameters);
impl_poseidon_default_parameters_field!(Fp384, Fp384Parameters);
impl_poseidon_default_parameters_field!(Fp768, Fp768Parameters);
