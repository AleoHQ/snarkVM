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

use snarkvm_algorithms::crh::sha256::sha256;
use snarkvm_dpc::{
    errors::DPCError,
    testnet2::{instantiated::Components, ProgramSNARKUniversalSRS, Testnet2Components},
};
use snarkvm_fields::ToConstraintField;
use snarkvm_marlin::PolynomialCommitment;
use snarkvm_utilities::ToBytes;

use rand::thread_rng;
use std::path::PathBuf;

mod utils;
use utils::store;

pub fn setup<C: Testnet2Components>() -> Result<Vec<u8>, DPCError>
where
    <C::PolynomialCommitment as PolynomialCommitment<C::InnerScalarField>>::VerifierKey:
        ToConstraintField<C::OuterScalarField>,
    <C::PolynomialCommitment as PolynomialCommitment<C::InnerScalarField>>::Commitment:
        ToConstraintField<C::OuterScalarField>,
{
    let rng = &mut thread_rng();

    let universal_srs = ProgramSNARKUniversalSRS::<C>::setup(rng)?;
    let universal_srs_bytes = universal_srs.0.to_bytes_le()?;

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
    let universal_srs = setup::<Components>().unwrap();
    let universal_srs_checksum = hex::encode(sha256(&universal_srs));
    store(
        &PathBuf::from(&versioned_filename(&universal_srs_checksum)),
        &PathBuf::from("universal_srs.checksum"),
        &universal_srs,
    )
    .unwrap();
}
