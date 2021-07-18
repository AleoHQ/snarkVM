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
    crh::{BoweHopwoodPedersenCRH, BoweHopwoodPedersenCompressedCRH, PedersenCRH, PedersenCompressedCRH},
    traits::CRH,
};
use snarkvm_curves::edwards_bls12::EdwardsProjective;
use snarkvm_utilities::FromBytes;

const PEDERSEN_NUM_WINDOWS: usize = 8;
const PEDERSEN_WINDOW_SIZE: usize = 128;

const BHP_NUM_WINDOWS: usize = 8;
const BHP_WINDOW_SIZE: usize = 63;

fn crh_serialization<C: CRH>() {
    let crh = C::setup("crh_serialization").to_bytes_le().unwrap();
    let recovered_crh: C = FromBytes::read_le(&crh[..]).unwrap();
    assert_eq!(crh, recovered_crh.to_bytes_le().unwrap());
}

#[test]
fn pedersen_crh_serialization() {
    crh_serialization::<PedersenCRH<EdwardsProjective, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>>();
}

#[test]
fn pedersen_compressed_crh_serialization() {
    crh_serialization::<PedersenCompressedCRH<EdwardsProjective, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>>();
}

#[test]
fn bowe_hopwood_crh_serialization() {
    crh_serialization::<BoweHopwoodPedersenCRH<EdwardsProjective, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>>();
}

#[test]
fn bowe_hopwood_compressed_crh_serialization() {
    crh_serialization::<BoweHopwoodPedersenCompressedCRH<EdwardsProjective, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>>();
}

#[test]
fn simple_bowe_hopwood_crh() {
    let crh =
        BoweHopwoodPedersenCRH::<EdwardsProjective, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>::setup("simple_bowe_hopwood_crh");
    crh.hash(&[1, 2, 3]).unwrap();
}
