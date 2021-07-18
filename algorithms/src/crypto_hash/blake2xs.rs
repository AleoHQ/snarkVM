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

///!
///! Blake2Xs function
///!
///! This implementation is based on the BLAKE2Xs specification in Section 2 of:
///! https://www.blake2.net/blake2x.pdf
///!
use blake2::VarBlake2s;
use digest::{Update, VariableOutput};

#[rustfmt::skip]
#[macro_export]
macro_rules! const_assert {
    ($x:expr $(,)*) => {
        pub const ASSERT: [(); 1] = [()];
        pub const fn bool_assert(x: bool) -> bool { x }
        let _ = ASSERT[!bool_assert($x) as usize];
    };
}

/// Converts a string of 8 characters into a `u64` for personalization in Blake2Xs.
#[macro_export]
macro_rules! personalization {
    ( $persona: expr ) => {{
        // panic!("Personalization must be exactly 8 characters")
        const_assert!($persona.len() == 8);
        let p = $persona.as_bytes();
        u64::from_le_bytes([p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]])
    }};
}

pub struct Blake2Xs;

impl Blake2Xs {
    /// Returns the BLAKE2Xs digest given:
    ///  - `input` is an input message as a slice of bytes,
    ///  - `XOF_DIGEST_LENGTH` is a `u16` set to the length of the final output digest in bytes,
    ///  - `PERSONALIZATION` is a `u64` representing a UTF-8 string of 8 characters.
    #[rustfmt::skip]
    pub fn evaluate(input: &[u8], xof_digest_length: u16, persona: &[u8]) -> Vec<u8> {
        debug_assert!(xof_digest_length > 0, "Output digest must be of non-zero length");
        debug_assert!(persona.len() <= 8, "Personalization may be at most 8 characters");

        // Start by computing the digest of the input bytes.
        let xof_digest_length_node_offset = (xof_digest_length as u64) << 32;
        let input_digest = blake2s_simd::Params::new()
            .hash_length(32)
            .node_offset(xof_digest_length_node_offset)
            .personal(persona)
            .hash(&input)
            .as_bytes()
            .to_vec();

        let mut output = vec![];

        let num_rounds = (xof_digest_length + 31) / 32;
        for node_offset in 0..num_rounds {
            // Calculate the digest length for this round.
            let is_final_round = node_offset == num_rounds - 1;
            let has_remainder =  xof_digest_length % 32 != 0;
            let digest_length = match is_final_round && has_remainder {
                true => (xof_digest_length % 32) as usize,
                false => 32
            };

            // Compute the next part of the output digest.
            output.extend_from_slice(&blake2s_simd::Params::new()
                .hash_length(digest_length)
                .fanout(0)
                .max_depth(0)
                .max_leaf_length(32)
                .node_offset(xof_digest_length_node_offset | (node_offset as u64))
                .inner_hash_length(32)
                .personal(persona)
                .hash(&input_digest)
                .as_bytes());
        }

        output
    }

    #[rustfmt::skip]
    pub fn evaluate_blake2s(input: &[u8], persona: u64) -> [u8; 32] {
        let mut h = VarBlake2s::with_parameter_block(&Self::blake2s_parameter_block(persona));
        let mut output = [0u8; 32];
        h.update(input);
        h.finalize_variable(|buffer| output.copy_from_slice(buffer));
        output
    }

    /// Returns the parameter block for BLAKE2Xs where:
    ///  - `DIGEST_LENGTH` is a `u8` set to the expected output length of this evaluation of Blake2Xs,
    ///  - `NODE_OFFSET` is a `u32` representing the current multiple of the digest length (starting from 0),
    ///  - `XOF_DIGEST_LENGTH` is a `u16` set to the length of the final output digest in bytes,
    ///  - `PERSONALIZATION` is a `u64` representing a UTF-8 string of 8 characters.
    #[rustfmt::skip]
    pub fn blake2xs_parameter_block(digest_length: u8, node_offset: u32, xof_digest_length: u16, persona: u64) -> [u32; 8] {
        // • “Key length” is set to 0 (even if the root hash was keyed)
        const KEY_LENGTH: u8 = 0u8;
        // • “Fanout” is set to 0 (unlimited)
        const FANOUT: u8 = 0u8;
        // • “Maximal depth” is set to 0
        const DEPTH: u8 = 0u8;
        // • “Leaf maximal byte length” is set to 32 for BLAKE2Xs, and 64 for BLAKE2Xb
        const LEAF_LENGTH: u32 = 32u32;
        // • “Node depth” is set to 0 (leaves)
        const NODE_DEPTH: u8 = 0u8;
        // • “Inner hash byte length” is set to 32 for BLAKE2Xs and 64 for BLAKE2Xb
        const INNER_LENGTH: u8 = 32u8;
        // • Other fields are left to the same values as in the underlying BLAKE2 instance
        const SALT: u64 = 0u64;

        Self::parameter_block::<KEY_LENGTH, FANOUT, DEPTH, LEAF_LENGTH, NODE_DEPTH, INNER_LENGTH, SALT>(
            digest_length,
            node_offset,
            xof_digest_length,
            persona,
        )
    }

    /// Returns the parameter block for BLAKE2s.
    #[rustfmt::skip]
    pub const fn blake2s_parameter_block(persona: u64) -> [u32; 8] {
        Self::parameter_block::<0u8, 1u8, 1u8, 0u32, 0u8, 0u8, 0u64>(32u8, 0u32, 0u16, persona)
    }

    /// Returns the parameter block for BLAKE2 where:
    ///  - `DIGEST_LENGTH` is a `u8` set to the expected output length of this evaluation,
    ///  - `NODE_OFFSET` is a `u32` representing the current multiple of the digest length (starting from 0),
    ///  - `XOF_DIGEST_LENGTH` is a `u16` set to the length of the final output digest in bytes,
    ///  - `PERSONALIZATION` is a `u64` representing a UTF-8 string of 8 characters.
    #[rustfmt::skip]
    pub const fn parameter_block<
        const KEY_LENGTH: u8,
        const FANOUT: u8,
        const DEPTH: u8,
        const LEAF_LENGTH: u32,
        const NODE_DEPTH: u8,
        const INNER_LENGTH: u8,
        const SALT: u64,
    >(digest_length: u8, node_offset: u32, xof_digest_length: u16, persona: u64) -> [u32; 8] {
        [
            // Offset 0 - Digest length || Key length || Fanout || Depth
            u32::from_le_bytes([digest_length, KEY_LENGTH, FANOUT, DEPTH]),
            // Offset 4 - Leaf length
            LEAF_LENGTH,
            // Offset 8 - Node offset
            node_offset,
            // Offset 12 - XOF digest length || Node depth || Inner length
            u32::from_le_bytes([xof_digest_length as u8, (xof_digest_length >> 8) as u8, NODE_DEPTH, INNER_LENGTH]),
            // Offset 16 - Salt
            u32::from_le_bytes([SALT as u8, (SALT >> 8) as u8, (SALT >> 16) as u8, (SALT >> 24) as u8]),
            // Offset 20 - Salt (continued)
            u32::from_le_bytes([(SALT >> 32) as u8, (SALT >> 40) as u8, (SALT >> 48) as u8, (SALT >> 56) as u8]),
            // Offset 24 - Personalization
            u32::from_le_bytes([persona as u8, (persona >> 8) as u8, (persona >> 16) as u8, (persona >> 24) as u8]),
            // Offset 24 - Personalization (continued)
            u32::from_le_bytes([(persona >> 32) as u8, (persona >> 40) as u8, (persona >> 48) as u8, (persona >> 56) as u8]),
        ]
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto_hash::Blake2Xs;

    use blake2::{Blake2s, VarBlake2s};
    use rand::{Rng, SeedableRng};
    use rand_chacha::ChaChaRng;
    use serde::Deserialize;

    const ITERATIONS: usize = 10_000;

    #[derive(Deserialize)]
    struct Case {
        hash: String,
        #[serde(rename = "in")]
        input: String,
        key: String,
        #[serde(rename = "out")]
        output: String,
    }

    #[test]
    fn test_aleo_personalization() {
        const ALEO_PERSONA: u64 = personalization!("AleoB2Xs");

        assert_eq!(8311448373230398529, ALEO_PERSONA);
        assert_eq!(ALEO_PERSONA, u64::from_le_bytes(ALEO_PERSONA.to_le_bytes()));
        assert_eq!([65, 108, 101, 111, 66, 50, 88, 115], ALEO_PERSONA.to_le_bytes());
        assert_eq!("AleoB2Xs".as_bytes(), ALEO_PERSONA.to_le_bytes());
        assert_eq!("AleoB2Xs", std::str::from_utf8(&ALEO_PERSONA.to_le_bytes()).unwrap());
    }

    #[test]
    fn test_blake2xs() {
        // Run test vector cases.
        let vectors: Vec<Case> = serde_json::from_str(include_str!("./resources/blake2-kat.json")).unwrap();
        for case in vectors.iter().filter(|v| &v.hash == "blake2xs" && v.key.is_empty()) {
            let input = hex::decode(case.input.as_bytes()).unwrap();
            let xof_digest_length = case.output.len() as u16 / 2;
            let output = hex::encode(Blake2Xs::evaluate(&input, xof_digest_length, "".as_bytes()));
            assert_eq!(output, case.output);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn test_blake2s() {
        // Run test vector cases.
        let vectors: Vec<Case> = serde_json::from_str(include_str!("./resources/blake2-kat.json")).unwrap();
        for case in vectors.iter().filter(|v| &v.hash == "blake2s" && v.key.is_empty()) {            
            let input = hex::decode(case.input.as_bytes()).unwrap();
            let output = hex::encode(Blake2Xs::evaluate_blake2s(&input, 0u64));
            assert_eq!(output, case.output);
        }
    }

    #[rustfmt::skip]
    #[test]
    fn test_blake2s_parameter_block_correctness() {
        use digest::generic_array::typenum::{Unsigned, U32};

        fn evaluate_blake2s(mut h: Blake2s, input: [u8; 32]) -> Vec<u8> {
            use digest::Digest;

            h.update(input.as_ref());

            let mut output = [0u8; 32];
            output.copy_from_slice(&h.finalize());
            output.to_vec()
        }

        fn evaluate_varblake2s(mut h: VarBlake2s, input: [u8; 32]) -> Vec<u8> {
            use digest::{Update, VariableOutput};

            h.update(input.as_ref());

            let mut output = vec![0u8; digest::VariableOutput::output_size(&h)];
            h.finalize_variable(|buffer| output.copy_from_slice(buffer));
            assert_eq!(32, output.len());
            output
        }

        fn u32_params_to_parameter_block(key: &[u8], salt: &[u8], persona: &[u8]) -> [u32; 8] {
            use digest::generic_array::{typenum::{U4, Unsigned}, GenericArray};
            use core::{convert::TryInto, ops::Div};

            let kk = key.len();
            assert!(kk <= U32::to_usize());
            assert!(32 <= U32::to_usize());

            // The number of bytes needed to express two words.
            let length = U32::to_usize()/4;
            assert!(salt.len() <= length);
            assert!(persona.len() <= length);

            // Build a parameter block
            let mut p = [0u32; 8];
            p[0] = 0x0101_0000 ^ ((kk as u32) << 8) ^ 32u32;

            // salt is two words long
            if salt.len() < length {
                let mut padded_salt = GenericArray::<u8, <U32 as Div<U4>>::Output>::default();
                for i in 0..salt.len() {
                    padded_salt[i] = salt[i];
                }
                p[4] = u32::from_le_bytes(padded_salt[0 .. length/2].try_into().unwrap());
                p[5] = u32::from_le_bytes(padded_salt[length/2 .. padded_salt.len()].try_into().unwrap());
            } else {
                p[4] = u32::from_le_bytes(salt[0 .. salt.len()/2].try_into().unwrap());
                p[5] = u32::from_le_bytes(salt[salt.len()/2 .. salt.len()].try_into().unwrap());
            }

            // persona is also two words long
            if persona.len() < length {
                let mut padded_persona = GenericArray::<u8, <U32 as Div<U4>>::Output>::default();
                for i in 0..persona.len() {
                    padded_persona[i] = persona[i];
                }
                p[6] = u32::from_le_bytes(padded_persona[0 .. length/2].try_into().unwrap());
                p[7] = u32::from_le_bytes(padded_persona[length/2 .. padded_persona.len()].try_into().unwrap());
            } else {
                p[6] = u32::from_le_bytes(persona[0 .. length/2].try_into().unwrap());
                p[7] = u32::from_le_bytes(persona[length/2 .. persona.len()].try_into().unwrap());
            }
            p
        }

        // Initialize a random number generator.
        let rng = &mut ChaChaRng::seed_from_u64(123456789u64);
        
        // Initialize the reference salt and persona.
        const REFERENCE_SALT: [u8; 8] = [0u8; 8];
        const REFERENCE_PERSONA: [u8; 8] = 0u64.to_le_bytes();
        
        // Run evaluations and enforce equality.
        for _ in 0..ITERATIONS {
            
            // Initialize a reference implementation of Blake2s.
            let reference_a = Blake2s::with_params(&[], &REFERENCE_SALT, &REFERENCE_PERSONA);

            // Initialize a reference implementation of VarBlake2s.
            let reference_b = VarBlake2s::with_params(&[], &REFERENCE_SALT, &REFERENCE_PERSONA, U32::to_usize());

            // Initialize a reference implementation of VarBlake2s from a parameter block.
            let reference_c = VarBlake2s::with_parameter_block(&u32_params_to_parameter_block(&[], &REFERENCE_SALT, &REFERENCE_PERSONA));

            // Initialize a candidate implementation of Blake2s from the parameter block.
            let candidate = VarBlake2s::with_parameter_block(&Blake2Xs::blake2s_parameter_block(0u64));
            
            // Sample a new input.
            let input: [u8; 32] = rng.gen();
            
            // Compare the evaluation of the implementations.
            assert_eq!(evaluate_blake2s(reference_a, input), evaluate_varblake2s(reference_b.clone(), input));
            assert_eq!(evaluate_varblake2s(reference_b, input), evaluate_varblake2s(reference_c.clone(), input));
            assert_eq!(evaluate_varblake2s(reference_c, input), evaluate_varblake2s(candidate, input));
        }
    }
}
