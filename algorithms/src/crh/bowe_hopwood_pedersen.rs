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

use crate::{crh::PedersenCRH, hash_to_curve::hash_to_curve, CRHError, CRH};
use snarkvm_curves::{AffineCurve, ProjectiveCurve};
use snarkvm_fields::{ConstraintFieldError, Field, PrimeField, ToConstraintField};
use snarkvm_utilities::{BigInteger, FromBytes, ToBytes};

use bitvec::{order::Lsb0, view::BitView};
use once_cell::sync::OnceCell;
use std::{
    fmt::Debug,
    io::{Read, Result as IoResult, Write},
};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

// we cant use these in array sizes since they are from a trait (and cant be refered to at const time)
const MAX_WINDOW_SIZE: usize = 256;
const MAX_NUM_WINDOWS: usize = 4096;

pub const BOWE_HOPWOOD_CHUNK_SIZE: usize = 3;
pub const BOWE_HOPWOOD_LOOKUP_SIZE: usize = 2usize.pow(BOWE_HOPWOOD_CHUNK_SIZE as u32);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoweHopwoodPedersenCRH<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> {
    pub crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>,
    base_lookup: OnceCell<Vec<Vec<[G; BOWE_HOPWOOD_LOOKUP_SIZE]>>>,
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> CRH
    for BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    type Output = G::Affine;
    type Parameters = PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>;

    const INPUT_SIZE_BITS: usize = PedersenCRH::<G, NUM_WINDOWS, WINDOW_SIZE>::INPUT_SIZE_BITS;

    fn setup(message: &str) -> Self {
        fn calculate_num_chunks_in_segment<F: PrimeField>() -> usize {
            let upper_limit = F::modulus_minus_one_div_two();
            let mut c = 0;
            let mut range = F::BigInteger::from(2_u64);
            while range < upper_limit {
                range.muln(4);
                c += 1;
            }

            c
        }

        let maximum_num_chunks_in_segment = calculate_num_chunks_in_segment::<G::ScalarField>();
        if WINDOW_SIZE > maximum_num_chunks_in_segment {
            panic!(
                "Bowe-Hopwood hash must have a window size resulting in scalars < (p-1)/2, \
                 maximum segment size is {}",
                maximum_num_chunks_in_segment
            );
        }

        let time = start_timer!(|| format!(
            "BoweHopwoodPedersenCRH::Setup: {} segments of {} 3-bit chunks; {{0,1}}^{{{}}} -> G",
            NUM_WINDOWS,
            WINDOW_SIZE,
            WINDOW_SIZE * NUM_WINDOWS * BOWE_HOPWOOD_CHUNK_SIZE
        ));
        let bases = Self::create_generators(message);
        end_timer!(time);

        Self {
            crh: bases.into(),
            base_lookup: OnceCell::new(),
        }
    }

    fn hash(&self, input: &[u8]) -> Result<Self::Output, CRHError> {
        let eval_time = start_timer!(|| "BoweHopwoodPedersenCRH::Eval");

        if (input.len() * 8) > WINDOW_SIZE * NUM_WINDOWS {
            return Err(CRHError::IncorrectInputLength(input.len(), WINDOW_SIZE, NUM_WINDOWS));
        }
        assert!(WINDOW_SIZE <= MAX_WINDOW_SIZE);
        assert!(NUM_WINDOWS <= MAX_NUM_WINDOWS);

        // overzealous but stack allocation
        let mut buffer = [0u8; MAX_WINDOW_SIZE * MAX_NUM_WINDOWS / 8 + BOWE_HOPWOOD_CHUNK_SIZE + 1];
        buffer[..input.len()].copy_from_slice(input);
        let buf_slice = (&buffer[..]).view_bits::<Lsb0>();

        let mut bit_len = WINDOW_SIZE * NUM_WINDOWS;
        if bit_len % BOWE_HOPWOOD_CHUNK_SIZE != 0 {
            bit_len += BOWE_HOPWOOD_CHUNK_SIZE - (bit_len % BOWE_HOPWOOD_CHUNK_SIZE);
        }

        assert_eq!(bit_len % BOWE_HOPWOOD_CHUNK_SIZE, 0);

        assert_eq!(
            self.crh.bases.len(),
            NUM_WINDOWS,
            "Incorrect pp of size {:?} for window params {:?}x{:?}x{}",
            self.crh.bases.len(),
            WINDOW_SIZE,
            NUM_WINDOWS,
            BOWE_HOPWOOD_CHUNK_SIZE,
        );
        assert_eq!(self.crh.bases.len(), NUM_WINDOWS);
        for bases in self.crh.bases.iter() {
            assert_eq!(bases.len(), WINDOW_SIZE);
        }
        let base_lookup = self.base_lookup(&self.crh);
        assert_eq!(base_lookup.len(), NUM_WINDOWS);
        for bases in base_lookup.iter() {
            assert_eq!(bases.len(), WINDOW_SIZE);
        }
        assert_eq!(BOWE_HOPWOOD_CHUNK_SIZE, 3);

        // Compute sum of h_i^{sum of
        // (1-2*c_{i,j,2})*(1+c_{i,j,0}+2*c_{i,j,1})*2^{4*(j-1)} for all j in segment}
        // for all i. Described in section 5.4.1.7 in the Zcash protocol
        // specification.
        let result = buf_slice[..bit_len]
            .chunks(WINDOW_SIZE * BOWE_HOPWOOD_CHUNK_SIZE)
            .zip(base_lookup)
            .map(|(segment_bits, segment_generators)| {
                segment_bits
                    .chunks(BOWE_HOPWOOD_CHUNK_SIZE)
                    .zip(segment_generators)
                    .map(|(chunk_bits, generator)| {
                        &generator
                            [(chunk_bits[0] as usize) | (chunk_bits[1] as usize) << 1 | (chunk_bits[2] as usize) << 2]
                    })
                    .fold(G::zero(), |a, b| a + b)
            })
            .fold(G::zero(), |a, b| a + b);

        end_timer!(eval_time);

        Ok(result.into_affine())
    }

    fn parameters(&self) -> &Self::Parameters {
        &self.crh
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    pub fn create_generators(message: &str) -> Vec<Vec<G>> {
        let mut generators = Vec::with_capacity(NUM_WINDOWS);
        for index in 0..NUM_WINDOWS {
            // Construct an indexed message to attempt to sample a base.
            let indexed_message = format!("{} at {}", message, index);
            let (generator, _, _) = hash_to_curve::<G::Affine>(&indexed_message);
            let mut base = generator.into_projective();
            // Compute the generators for the sampled base.
            let mut generators_for_segment = Vec::with_capacity(WINDOW_SIZE);
            for _ in 0..WINDOW_SIZE {
                generators_for_segment.push(base);
                for _ in 0..4 {
                    base.double_in_place();
                }
            }
            generators.push(generators_for_segment);
        }
        generators
    }

    pub fn base_lookup(
        &self,
        input: &PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>,
    ) -> &Vec<Vec<[G; BOWE_HOPWOOD_LOOKUP_SIZE]>> {
        self.base_lookup
            .get_or_try_init::<_, ()>(|| {
                Ok(cfg_iter!(input.bases)
                    .map(|x| {
                        x.iter()
                            .map(|g| {
                                let mut out = [G::zero(); BOWE_HOPWOOD_LOOKUP_SIZE];
                                for i in 0..BOWE_HOPWOOD_LOOKUP_SIZE {
                                    let mut encoded = *g;
                                    if (i & 0x01) != 0 {
                                        encoded += g;
                                    }
                                    if (i & 0x02) != 0 {
                                        encoded += g.double();
                                    }
                                    if (i & 0x04) != 0 {
                                        encoded = encoded.neg();
                                    }
                                    out[i] = encoded;
                                }
                                out
                            })
                            .collect()
                    })
                    .collect())
            })
            .expect("failed to init BoweHopwoodPedersenCRHParameters")
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    From<PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>> for BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from(crh: PedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>) -> Self {
        Self {
            crh,
            base_lookup: OnceCell::new(),
        }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> From<Vec<Vec<G>>>
    for BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn from(bases: Vec<Vec<G>>) -> Self {
        Self {
            crh: bases.into(),
            base_lookup: OnceCell::new(),
        }
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> ToBytes
    for BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    fn write_le<W: Write>(&self, writer: W) -> IoResult<()> {
        self.crh.write_le(writer)
    }
}

impl<G: ProjectiveCurve, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize> FromBytes
    for BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn read_le<R: Read>(reader: R) -> IoResult<Self> {
        Ok(PedersenCRH::read_le(reader)?.into())
    }
}

impl<F: Field, G: ProjectiveCurve + ToConstraintField<F>, const NUM_WINDOWS: usize, const WINDOW_SIZE: usize>
    ToConstraintField<F> for BoweHopwoodPedersenCRH<G, NUM_WINDOWS, WINDOW_SIZE>
{
    #[inline]
    fn to_field_elements(&self) -> Result<Vec<F>, ConstraintFieldError> {
        self.crh.to_field_elements()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_curves::edwards_bls12::EdwardsProjective;

    const NUM_WINDOWS: usize = 8;
    const WINDOW_SIZE: usize = 32;

    #[test]
    fn test_bowe_pedersen() {
        let crh =
            <BoweHopwoodPedersenCRH<EdwardsProjective, NUM_WINDOWS, WINDOW_SIZE> as CRH>::setup("test_bowe_pedersen");
        let input = vec![127u8; 32];

        let output = crh.hash(&input).unwrap();
        assert_eq!(
            &*output.to_string(),
            "Affine(x=2591648422993904809826711498838675948697848925001720514073745852367402669969, y=3090936323959984371620829350469190013004970213099218155955516230575434312314)"
        );
    }
}
