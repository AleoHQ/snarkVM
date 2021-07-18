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

use snarkvm_dpc::{
    testnet1::{instantiated::Components, NoopProgram, Testnet1Components},
    DPCError,
    ProgramScheme,
};
use snarkvm_utilities::ToBytes;

use rand::thread_rng;
use std::path::PathBuf;

mod utils;
use utils::store;

#[allow(deprecated)]
pub fn setup<C: Testnet1Components>() -> Result<(Vec<u8>, Vec<u8>), DPCError> {
    let rng = &mut thread_rng();
    let noop_program = NoopProgram::<C>::setup(rng)?;
    let (proving_key, verifying_key) = noop_program.to_snark_parameters();
    let noop_program_snark_pk = proving_key.to_bytes_le()?;
    let noop_program_snark_vk = verifying_key.to_bytes_le()?;

    println!("noop_program_snark_pk.params\n\tsize - {}", noop_program_snark_pk.len());
    println!("noop_program_snark_vk.params\n\tsize - {}", noop_program_snark_vk.len());
    Ok((noop_program_snark_pk, noop_program_snark_vk))
}

pub fn main() {
    let (program_snark_pk, program_snark_vk) = setup::<Components>().unwrap();
    store(
        &PathBuf::from("noop_program_snark_pk.params"),
        &PathBuf::from("noop_program_snark_pk.checksum"),
        &program_snark_pk,
    )
    .unwrap();
    store(
        &PathBuf::from("noop_program_snark_vk.params"),
        &PathBuf::from("noop_program_snark_vk.checksum"),
        &program_snark_vk,
    )
    .unwrap();
}
