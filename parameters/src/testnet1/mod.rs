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

pub mod genesis;
pub use genesis::*;

// POSW SNARK
impl_params_remote!(
    PoswSNARKPKParameters,
    posw_snark_pk_test,
    "https://s3-us-west-1.amazonaws.com/aleo.parameters",
    "./",
    "posw_snark_pk",
    162891216
);
impl_params_local!(PoswSNARKVKParameters, posw_snark_vk_test, "./", "posw_snark_vk", 40807);

// Program SNARK
impl_params_local!(
    NoopProgramSNARKPKParameters,
    noop_program_snark_pk_test,
    "./",
    "noop_program_snark_pk",
    348514
);
impl_params_local!(
    NoopProgramSNARKVKParameters,
    noop_program_snark_vk_test,
    "./",
    "noop_program_snark_vk",
    1068
);

// Inner SNARK
impl_params_remote!(
    InnerSNARKPKParameters,
    inner_snark_pk_test,
    "https://s3-us-west-1.amazonaws.com/aleo.parameters",
    "./",
    "inner_snark_pk",
    249864465
);
impl_params_local!(
    InnerSNARKVKParameters,
    inner_snark_vk_test,
    "./",
    "inner_snark_vk",
    2329
);

// Outer SNARK
impl_params_remote!(
    OuterSNARKPKParameters,
    outer_snark_pk_test,
    "https://s3-us-west-1.amazonaws.com/aleo.parameters",
    "./",
    "outer_snark_pk",
    502942005
);
impl_params_local!(
    OuterSNARKVKParameters,
    outer_snark_vk_test,
    "./",
    "outer_snark_vk",
    4443
);
