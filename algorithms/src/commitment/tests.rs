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
    commitment::{PedersenCommitment, PedersenCompressedCommitment},
    traits::CommitmentScheme,
};
use snarkvm_curves::edwards_bls12::EdwardsProjective;
use snarkvm_utilities::{FromBytes, ToBytes};

use rand::SeedableRng;
use rand_xorshift::XorShiftRng;

const NUM_WINDOWS: usize = 8;
const WINDOW_SIZE: usize = 128;

fn commitment_parameters_serialization<C: CommitmentScheme>() {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);
    let commitment = C::setup(rng);

    let commitment_parameters_bytes = commitment.parameters().to_bytes_le().unwrap();

    let recovered_commitment_parameters =
        <C as CommitmentScheme>::Parameters::read_le(&commitment_parameters_bytes[..]).unwrap();

    assert_eq!(commitment.parameters(), &recovered_commitment_parameters);
}

#[test]
fn pedersen_commitment_parameters_serialization() {
    commitment_parameters_serialization::<PedersenCommitment<EdwardsProjective, NUM_WINDOWS, WINDOW_SIZE>>();
}

#[test]
fn pedersen_compressed_commitment_parameters_serialization() {
    commitment_parameters_serialization::<PedersenCompressedCommitment<EdwardsProjective, NUM_WINDOWS, WINDOW_SIZE>>();
}
