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

const NUM_WINDOWS: usize = 8;
const WINDOW_SIZE: usize = 128;

fn commitment_parameters_serialization<C: CommitmentScheme>() {
    let commitment = C::setup("commitment_parameters_serialization").to_bytes_le().unwrap();
    let recovered_commitment = C::read_le(&commitment[..]).unwrap();
    assert_eq!(commitment, recovered_commitment.to_bytes_le().unwrap());
}

#[test]
fn pedersen_commitment_parameters_serialization() {
    commitment_parameters_serialization::<PedersenCommitment<EdwardsProjective, NUM_WINDOWS, WINDOW_SIZE>>();
}

#[test]
fn pedersen_compressed_commitment_parameters_serialization() {
    commitment_parameters_serialization::<PedersenCompressedCommitment<EdwardsProjective, NUM_WINDOWS, WINDOW_SIZE>>();
}
