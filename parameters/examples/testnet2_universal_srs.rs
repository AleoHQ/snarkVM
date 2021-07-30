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

use snarkvm_algorithms::{crh::sha256::sha256, SNARK};
use snarkvm_dpc::{errors::DPCError, testnet2::Testnet2Parameters, Parameters};
use snarkvm_utilities::ToBytes;

use rand::thread_rng;
use std::path::PathBuf;

mod utils;
use snarkvm_marlin::constraints::snark::MarlinBound;
use utils::store;

pub fn setup() -> Result<Vec<u8>, DPCError> {
    type C = Testnet2Parameters;
    let rng = &mut thread_rng();

    let bound = MarlinBound {
        max_degree: snarkvm_marlin::ahp::AHPForR1CS::<<C as Parameters>::InnerScalarField>::max_degree(
            10000, 10000, 10000,
        )
        .unwrap(),
    };

    let universal_srs = <<C as Parameters>::ProgramSNARK as SNARK>::universal_setup(&bound, rng)?;
    let universal_srs_bytes = universal_srs.to_bytes_le()?;

    println!("universal_srs.params\n\tsize - {}", universal_srs_bytes.len());
    Ok(universal_srs_bytes)
}

fn versioned_filename(checksum: &str) -> String {
    match checksum.get(0..7) {
        Some(sum) => format!("universal_srs-{}.params", sum),
        _ => "universal_srs.params".to_string(),
    }
}

pub fn main() {
    let universal_srs = setup().unwrap();
    let universal_srs_checksum = hex::encode(sha256(&universal_srs));
    store(
        &PathBuf::from(&versioned_filename(&universal_srs_checksum)),
        &PathBuf::from("universal_srs.checksum"),
        &universal_srs,
    )
    .unwrap();
}
