// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::collections::BTreeMap;

use crate::{
    fft::DensePolynomial,
    polycommit::sonic_pc::{LabeledPolynomial, PolynomialInfo, PolynomialLabel},
    snark::varuna::{ahp::AHPError, prover, AHPForR1CS, SNARKMode},
    AlgebraicSponge,
};

use itertools::Itertools;
use snarkvm_fields::PrimeField;
use snarkvm_utilities::{cfg_par_bridge, cfg_reduce};

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

impl<F: PrimeField, MM: SNARKMode> AHPForR1CS<F, MM> {
    /// Output the number of oracles sent by the prover in this round.
    pub const fn num_fifth_round_oracles() -> usize {
        1
    }

    /// Output the degree bounds of oracles in the last round.
    pub fn fifth_round_polynomial_info() -> BTreeMap<PolynomialLabel, PolynomialInfo> {
        [("h_2".into(), PolynomialInfo::new("h_2".into(), None, None))].into()
    }
}

impl<'a, F: PrimeField, MM: SNARKMode> prover::State<'a, F, MM> {
    pub fn fifth_round(&mut self) -> Result<prover::FifthOracles<F>, AHPError> {
        let verifier_state = self.verifier_state.as_ref().ok_or(anyhow::anyhow!("missing verifier state"))?;
        let verifier_fourth_message =
            verifier_state.fourth_round_message.clone().ok_or(anyhow::anyhow!("missing verifier message"))?;

        let lhs_sum: DensePolynomial<F> = cfg_reduce!(
            cfg_par_bridge!(verifier_fourth_message.into_iter().zip_eq(self.take_lhs_polys())).map(
                |(delta, mut lhs)| {
                    lhs *= delta;
                    lhs
                }
            ),
            || DensePolynomial::zero(),
            |mut a, mut b| {
                if b != DensePolynomial::zero() {
                    a += &std::mem::take(&mut b);
                }
                a
            }
        );
        let h_2 = LabeledPolynomial::new("h_2", lhs_sum, None, None);
        let oracles = prover::FifthOracles { h_2 };
        assert!(oracles.matches_info(&AHPForR1CS::<F, MM>::fifth_round_polynomial_info()));
        Ok(oracles)
    }

    pub fn verifier_fifth_round<Fq: PrimeField, R: AlgebraicSponge<Fq, 2>>(
        &mut self,
        fs_rng: &mut R,
    ) -> Result<(), AHPError> {
        self.verifier_state.as_mut().unwrap().fifth_round(fs_rng)?;
        Ok(())
    }
}
