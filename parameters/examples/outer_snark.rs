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

use snarkvm_algorithms::{crh::sha256::sha256, traits::SNARK};
use snarkvm_dpc::{
    testnet1::{instantiated::Components, InnerCircuit, NoopProgram, OuterCircuit, Testnet1Components},
    DPCError,
    ProgramScheme,
};
use snarkvm_parameters::{
    testnet1::{InnerSNARKPKParameters, InnerSNARKVKParameters},
    traits::Parameter,
};
use snarkvm_utilities::{FromBytes, ToBytes};

use rand::thread_rng;
use std::{path::PathBuf, sync::Arc};

mod utils;
use utils::store;

pub fn setup<C: Testnet1Components>() -> Result<(Vec<u8>, Vec<u8>), DPCError> {
    let rng = &mut thread_rng();

    // TODO (howardwu): TEMPORARY - Resolve this inconsistency on import structure with a new model once MerkleParameters are refactored.
    let ledger_merkle_tree_parameters = Arc::new(C::ledger_merkle_tree_parameters().clone());

    let inner_snark_pk: <C::InnerSNARK as SNARK>::ProvingKey =
        <C::InnerSNARK as SNARK>::ProvingKey::read_le(InnerSNARKPKParameters::load_bytes()?.as_slice())?;

    let inner_snark_vk: <C::InnerSNARK as SNARK>::VerifyingKey =
        <C::InnerSNARK as SNARK>::VerifyingKey::read_le(InnerSNARKVKParameters::load_bytes()?.as_slice())?;

    let inner_snark_proof = C::InnerSNARK::prove(
        &inner_snark_pk,
        &InnerCircuit::blank(&ledger_merkle_tree_parameters),
        rng,
    )?;

    let noop_program = NoopProgram::<C>::load()?;

    let outer_snark_parameters = C::OuterSNARK::setup(
        &OuterCircuit::blank(
            ledger_merkle_tree_parameters,
            inner_snark_vk,
            inner_snark_proof,
            noop_program.execute_blank(rng)?,
        ),
        rng,
    )?;

    let outer_snark_pk = outer_snark_parameters.0.to_bytes_le()?;
    let outer_snark_vk: <C::OuterSNARK as SNARK>::VerifyingKey = outer_snark_parameters.1.into();
    let outer_snark_vk = outer_snark_vk.to_bytes_le()?;

    println!("outer_snark_pk.params\n\tsize - {}", outer_snark_pk.len());
    println!("outer_snark_vk.params\n\tsize - {}", outer_snark_vk.len());
    Ok((outer_snark_pk, outer_snark_vk))
}

fn versioned_filename(checksum: &str) -> String {
    match checksum.get(0..7) {
        Some(sum) => format!("outer_snark_pk-{}.params", sum),
        _ => "outer_snark_pk.params".to_string(),
    }
}

pub fn main() {
    let (outer_snark_pk, outer_snark_vk) = setup::<Components>().unwrap();
    let outer_snark_pk_checksum = hex::encode(sha256(&outer_snark_pk));
    store(
        &PathBuf::from(&versioned_filename(&outer_snark_pk_checksum)),
        &PathBuf::from("outer_snark_pk.checksum"),
        &outer_snark_pk,
    )
    .unwrap();
    store(
        &PathBuf::from("outer_snark_vk.params"),
        &PathBuf::from("outer_snark_vk.checksum"),
        &outer_snark_vk,
    )
    .unwrap();
}
