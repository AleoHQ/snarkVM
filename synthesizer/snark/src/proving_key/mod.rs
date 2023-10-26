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

use super::*;

mod bytes;
mod parse;
mod serialize;

use parking_lot::RwLock;
use std::collections::BTreeMap;

#[derive(Clone)]
pub struct ProvingKey<N: Network> {
    /// The proving key for the function.
    proving_key: Arc<varuna::CircuitProvingKey<N::PairingCurve, varuna::VarunaHidingMode>>,
}

impl<N: Network> ProvingKey<N> {
    /// Initializes a new proving key.
    pub const fn new(proving_key: Arc<varuna::CircuitProvingKey<N::PairingCurve, varuna::VarunaHidingMode>>) -> Self {
        Self { proving_key }
    }

    /// Returns a proof for the given assignment on the circuit.
    pub fn prove<R: Rng + CryptoRng>(
        &self,
        srs: &UniversalSRS<N>,
        universal_prover: Arc<RwLock<UniversalProver<N>>>,
        function_name: &str,
        assignment: &circuit::Assignment<N::Field>,
        rng: &mut R,
    ) -> Result<Proof<N>> {
        #[cfg(feature = "aleo-cli")]
        let timer = std::time::Instant::now();

        // Retrieve the proving parameters.
        let degree_info = self.circuit.index_info.degree_info::<N::Field, varuna::VarunaHidingMode>();

        let fiat_shamir = N::varuna_fs_parameters();

        // Update the universal_prover and prevent other threads from writing to it
        let mut universal_prover = universal_prover.write();
        universal_prover.update(srs, degree_info)?;

        // Compute the proof.
        let proof = Proof::new(Varuna::<N>::prove(&universal_prover, fiat_shamir, self, assignment, rng)?);

        #[cfg(feature = "aleo-cli")]
        println!("{}", format!(" • Executed '{function_name}' (in {} ms)", timer.elapsed().as_millis()).dimmed());
        Ok(proof)
    }

    /// Returns a proof for the given batch of proving keys and assignments.
    #[allow(clippy::type_complexity)]
    pub fn prove_batch<R: Rng + CryptoRng>(
        srs: &UniversalSRS<N>,
        universal_prover: Arc<RwLock<UniversalProver<N>>>,
        locator: &str,
        assignments: &[(ProvingKey<N>, Vec<circuit::Assignment<N::Field>>)],
        rng: &mut R,
    ) -> Result<Proof<N>> {
        // Ensure that the assignments are not empty.
        ensure!(!assignments.is_empty(), "Cannot prove an empty batch");

        #[cfg(feature = "aleo-cli")]
        let timer = std::time::Instant::now();

        // Prepare the instances.
        let instances: BTreeMap<_, _> = assignments
            .iter()
            .map(|(proving_key, assignments)| (proving_key.deref(), assignments.as_slice()))
            .collect();

        // Retrieve the proving parameters.
        let mut degree_info: Option<DegreeInfo> = None;
        for (pk, _) in assignments {
            let degree_info_i = pk.circuit.index_info.degree_info::<N::Field, varuna::VarunaHidingMode>();
            degree_info = match degree_info {
                Some(degree_info) => Some(degree_info.union(&degree_info_i)),
                None => Some(degree_info_i),
            };
        }

        let fiat_shamir = N::varuna_fs_parameters();

        // Update the universal_prover and prevent other threads from writing to it
        let mut universal_prover = universal_prover.write();
        universal_prover.update(srs, degree_info.unwrap())?;

        // Compute the proof.
        let batch_proof = Proof::new(Varuna::<N>::prove_batch(&universal_prover, fiat_shamir, &instances, rng)?);

        #[cfg(feature = "aleo-cli")]
        println!("{}", format!(" • Executed '{locator}' (in {} ms)", timer.elapsed().as_millis()).dimmed());

        Ok(batch_proof)
    }
}

impl<N: Network> Deref for ProvingKey<N> {
    type Target = varuna::CircuitProvingKey<N::PairingCurve, varuna::VarunaHidingMode>;

    fn deref(&self) -> &Self::Target {
        &self.proving_key
    }
}
