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
use snarkvm_utilities::{FromBytes, ToBytes};

use rand::SeedableRng;
use rand_xorshift::XorShiftRng;

const PEDERSEN_NUM_WINDOWS: usize = 8;
const PEDERSEN_WINDOW_SIZE: usize = 128;

const BHP_NUM_WINDOWS: usize = 8;
const BHP_WINDOW_SIZE: usize = 63;

fn crh_parameters_serialization<C: CRH>() {
    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);

    let crh = C::setup(rng);
    let crh_parameters = crh.parameters();

    let crh_parameters_bytes = crh_parameters.to_bytes_le().unwrap();
    let recovered_crh_parameters: <C as CRH>::Parameters = FromBytes::read_le(&crh_parameters_bytes[..]).unwrap();

    assert_eq!(crh_parameters, &recovered_crh_parameters);
}

#[test]
fn pedersen_crh_parameters_serialization() {
    crh_parameters_serialization::<PedersenCRH<EdwardsProjective, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>>();
}

#[test]
fn pedersen_compressed_crh_parameters_serialization() {
    crh_parameters_serialization::<PedersenCompressedCRH<EdwardsProjective, PEDERSEN_NUM_WINDOWS, PEDERSEN_WINDOW_SIZE>>(
    );
}

#[test]
fn bowe_hopwood_crh_parameters_serialization() {
    crh_parameters_serialization::<BoweHopwoodPedersenCRH<EdwardsProjective, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>>();
}

#[test]
fn bowe_hopwood_compressed_crh_parameters_serialization() {
    crh_parameters_serialization::<BoweHopwoodPedersenCompressedCRH<EdwardsProjective, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>>(
    );
}

#[test]
fn simple_bowe_hopwood_crh() {
    type BoweHopwoodCRH = BoweHopwoodPedersenCRH<EdwardsProjective, BHP_NUM_WINDOWS, BHP_WINDOW_SIZE>;

    let rng = &mut XorShiftRng::seed_from_u64(1231275789u64);

    let parameters = BoweHopwoodCRH::setup(rng);

    BoweHopwoodCRH::hash(&parameters, &[1, 2, 3]).unwrap();
}
