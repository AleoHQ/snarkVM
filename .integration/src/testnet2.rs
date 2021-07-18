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

use crate::Ledger;
use snarkvm_dpc::{testnet2::instantiated::*, Account, DPCComponents, DPCScheme, Storage};

use rand::{CryptoRng, Rng};
use std::sync::Arc;

pub type MerkleTreeLedger<S> = Ledger<Testnet2Transaction, CommitmentMerkleTreeParameters, S>;

pub fn setup_or_load_parameters<R: Rng + CryptoRng, S: Storage>(
    verify_only: bool,
    rng: &mut R,
) -> (Arc<CommitmentMerkleTreeParameters>, Testnet2DPC) {
    // TODO (howardwu): TEMPORARY - Resolve this inconsistency on import structure with a new model once MerkleParameters are refactored.
    let ledger_merkle_tree_parameters = Arc::new(Components::ledger_merkle_tree_parameters().clone());

    // let dpc = match <InstantiatedDPC as DPCScheme<MerkleTreeLedger<S>>>::load(verify_only) {
    //     Ok(dpc) => dpc,
    //     Err(err) => {
    //         println!("error - {}, re-running parameter Setup", err);
    //         <InstantiatedDPC as DPCScheme<MerkleTreeLedger<S>>>::setup(&ledger_merkle_tree_parameters, rng)
    //             .expect("DPC setup failed")
    //     }
    // };

    let dpc = <Testnet2DPC as DPCScheme<MerkleTreeLedger<S>>>::setup(&ledger_merkle_tree_parameters, rng)
        .expect("DPC setup failed");

    (ledger_merkle_tree_parameters, dpc)
}

pub fn generate_test_accounts<R: Rng + CryptoRng, S: Storage>(
    dpc: &Testnet2DPC,
    rng: &mut R,
) -> [Account<Components>; 3] {
    // TODO (howardwu): Remove DPCScheme<MerkleTreeLedger<S>> usage after decoupling ledger.
    let genesis_account = <Testnet2DPC as DPCScheme<MerkleTreeLedger<S>>>::create_account(dpc, rng).unwrap();
    let account_1 = <Testnet2DPC as DPCScheme<MerkleTreeLedger<S>>>::create_account(dpc, rng).unwrap();
    let account_2 = <Testnet2DPC as DPCScheme<MerkleTreeLedger<S>>>::create_account(dpc, rng).unwrap();

    [genesis_account, account_1, account_2]
}
