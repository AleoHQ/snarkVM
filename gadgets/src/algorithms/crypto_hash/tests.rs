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
    algorithms::crypto_hash::{CryptographicSpongeVar, PoseidonSpongeGadget},
    AllocGadget,
    FieldGadget,
    FpGadget,
};
use snarkvm_algorithms::crypto_hash::{poseidon::PoseidonSponge, CryptographicSponge, PoseidonDefaultParametersField};
use snarkvm_curves::bls12_377::Fr;
use snarkvm_r1cs::{ConstraintSystem, TestConstraintSystem};
use snarkvm_utilities::{test_rng, UniformRand};

#[test]
fn absorb_test() {
    let mut rng = test_rng();

    let mut cs = TestConstraintSystem::<Fr>::new();

    let absorb: Vec<_> = (0..256).map(|_| Fr::rand(&mut rng)).collect();
    let absorb_var: Vec<_> = absorb
        .iter()
        .enumerate()
        .map(|(i, v)| FpGadget::<Fr>::alloc_input(cs.ns(|| format!("alloc input {}", i)), || Ok((*v).clone())).unwrap())
        .collect();

    let sponge_params = Fr::get_default_poseidon_parameters(2, false).unwrap();

    let mut native_sponge = PoseidonSponge::<Fr>::new(&sponge_params);
    let mut constraint_sponge = PoseidonSpongeGadget::<Fr>::new(cs.ns(|| "new sponge"), &sponge_params);

    native_sponge.absorb(&absorb);
    constraint_sponge.absorb(cs.ns(|| "absorb"), absorb_var.iter()).unwrap();

    let native_squeeze = native_sponge.squeeze_field_elements(1);
    let constraint_squeeze = constraint_sponge
        .squeeze_field_elements(cs.ns(|| "squeeze"), 1)
        .unwrap();

    assert_eq!(constraint_squeeze[0].get_value().unwrap(), native_squeeze[0]);
    assert!(cs.is_satisfied());
}
