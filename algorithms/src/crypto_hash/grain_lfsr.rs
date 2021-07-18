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

#![allow(dead_code)]

use snarkvm_fields::{FieldParameters, PrimeField};
use snarkvm_utilities::{cmp::Ordering, vec::Vec, FromBits};

pub struct PoseidonGrainLFSR {
    pub prime_num_bits: u64,

    pub state: [bool; 80],
    pub head: usize,
}

impl PoseidonGrainLFSR {
    pub fn new(
        is_sbox_an_inverse: bool,
        prime_num_bits: u64,
        state_len: u64,
        num_full_rounds: u64,
        num_partial_rounds: u64,
    ) -> Self {
        let mut state = [false; 80];

        // b0, b1 describes the field
        state[1] = true;

        // b2, ..., b5 describes the S-BOX
        if is_sbox_an_inverse {
            state[5] = true;
        } else {
            state[5] = false;
        }

        // b6, ..., b17 are the binary representation of n (prime_num_bits)
        {
            let mut cur = prime_num_bits;
            for i in (6..=17).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b18, ..., b29 are the binary representation of t (state_len, rate + capacity)
        {
            let mut cur = state_len;
            for i in (18..=29).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b30, ..., b39 are the binary representation of R_F (the number of full rounds)
        {
            let mut cur = num_full_rounds;
            for i in (30..=39).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b40, ..., b49 are the binary representation of R_P (the number of partial rounds)
        {
            let mut cur = num_partial_rounds;
            for i in (40..=49).rev() {
                state[i] = cur & 1 == 1;
                cur >>= 1;
            }
        }

        // b50, ..., b79 are set to 1
        for i in 50..=79 {
            state[i] = true;
        }

        let head = 0;

        let mut res = Self {
            prime_num_bits,
            state,
            head,
        };
        res.init();
        res
    }

    pub fn get_bits(&mut self, num_bits: usize) -> Vec<bool> {
        let mut res = Vec::new();

        for _ in 0..num_bits {
            // Obtain the first bit
            let mut new_bit = self.update();

            // Loop until the first bit is true
            while new_bit == false {
                // Discard the second bit
                let _ = self.update();
                // Obtain another first bit
                new_bit = self.update();
            }

            // Obtain the second bit
            res.push(self.update());
        }

        res
    }

    pub fn get_field_elements_rejection_sampling<F: PrimeField>(&mut self, num_elems: usize) -> Vec<F> {
        assert_eq!(F::Parameters::MODULUS_BITS as u64, self.prime_num_bits);

        let mut res = Vec::new();
        for _ in 0..num_elems {
            // Perform rejection sampling
            loop {
                // Obtain n bits and make it most-significant-bit first
                let bits = self.get_bits(self.prime_num_bits as usize);

                // Construct the number
                let bigint = F::BigInteger::from_bits_be(&bits);

                if bigint.cmp(&F::Parameters::MODULUS) == Ordering::Less {
                    res.push(F::from_repr(bigint).unwrap());
                    break;
                }
            }
        }

        res
    }

    pub fn get_field_elements_mod_p<F: PrimeField>(&mut self, num_elems: usize) -> Vec<F> {
        assert_eq!(F::Parameters::MODULUS_BITS as u64, self.prime_num_bits);

        let mut res = Vec::new();
        for _ in 0..num_elems {
            // Obtain n bits and make it most-significant-bit first
            let mut bits = self.get_bits(self.prime_num_bits as usize);
            bits.reverse();

            let bytes = bits
                .chunks(8)
                .map(|chunk| {
                    let mut sum = chunk[0] as u8;
                    let mut cur = 1;
                    for i in chunk.iter().skip(1) {
                        cur *= 2;
                        sum += cur * (*i as u8);
                    }
                    sum
                })
                .collect::<Vec<u8>>();

            res.push(F::from_le_bytes_mod_order(&bytes));
        }

        res
    }

    #[inline]
    fn update(&mut self) -> bool {
        let new_bit = self.state[(self.head + 62) % 80]
            ^ self.state[(self.head + 51) % 80]
            ^ self.state[(self.head + 38) % 80]
            ^ self.state[(self.head + 23) % 80]
            ^ self.state[(self.head + 13) % 80]
            ^ self.state[self.head];
        self.state[self.head] = new_bit;
        self.head += 1;
        self.head %= 80;

        new_bit
    }

    fn init(&mut self) {
        for _ in 0..160 {
            let new_bit = self.state[(self.head + 62) % 80]
                ^ self.state[(self.head + 51) % 80]
                ^ self.state[(self.head + 38) % 80]
                ^ self.state[(self.head + 23) % 80]
                ^ self.state[(self.head + 13) % 80]
                ^ self.state[self.head];
            self.state[self.head] = new_bit;
            self.head += 1;
            self.head %= 80;
        }
    }
}
