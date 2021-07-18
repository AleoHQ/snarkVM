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
    testnet1::{Execution, LocalData, NoopCircuit, ProgramLocalData, Testnet1Components},
    DPCComponents,
    ProgramError,
    ProgramScheme,
    RecordScheme,
};
use snarkvm_algorithms::prelude::*;
use snarkvm_parameters::{
    testnet1::{NoopProgramSNARKPKParameters, NoopProgramSNARKVKParameters},
    Parameter,
};
use snarkvm_utilities::{to_bytes_le, FromBytes, ToBytes};

use rand::{CryptoRng, Rng};

#[derive(Derivative)]
#[derivative(Clone(bound = "C: Testnet1Components"), Debug(bound = "C: Testnet1Components"))]
pub struct NoopProgram<C: Testnet1Components> {
    #[derivative(Default(value = "vec![0u8; 48]"))]
    id: Vec<u8>,
    #[derivative(Debug = "ignore")]
    proving_key: <<C as Testnet1Components>::NoopProgramSNARK as SNARK>::ProvingKey,
    #[derivative(Debug = "ignore")]
    verifying_key: <<C as Testnet1Components>::NoopProgramSNARK as SNARK>::VerifyingKey,
}

impl<C: Testnet1Components> ProgramScheme for NoopProgram<C> {
    type Execution = Execution;
    type ID = Vec<u8>;
    type LocalData = LocalData<C>;
    type LocalDataCommitment = C::LocalDataCommitment;
    type ProgramIDCRH = C::ProgramIDCRH;
    type ProofSystem = <C as Testnet1Components>::NoopProgramSNARK;
    type ProvingKey = <Self::ProofSystem as SNARK>::ProvingKey;
    type PublicInput = ();
    type VerifyingKey = <Self::ProofSystem as SNARK>::VerifyingKey;

    /// Initializes a new instance of the noop program.
    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self, ProgramError> {
        let (proving_key, prepared_verifying_key) = <Self::ProofSystem as SNARK>::setup(&NoopCircuit::blank(), rng)?;
        let verifying_key: Self::VerifyingKey = prepared_verifying_key.into();

        // Compute the program ID.
        let id = <C as DPCComponents>::program_id_crh()
            .hash(&verifying_key.to_bytes_le()?)?
            .to_bytes_le()?;

        Ok(Self {
            id,
            proving_key,
            verifying_key,
        })
    }

    // TODO (howardwu): Why are we not preparing the VK here?
    /// Loads an instance of the noop program.
    fn load() -> Result<Self, ProgramError> {
        let proving_key: <Self::ProofSystem as SNARK>::ProvingKey =
            FromBytes::read_le(NoopProgramSNARKPKParameters::load_bytes()?.as_slice())?;
        let verifying_key = <Self::ProofSystem as SNARK>::VerifyingKey::read_le(
            NoopProgramSNARKVKParameters::load_bytes()?.as_slice(),
        )?;

        // Compute the program ID.
        let id = <C as DPCComponents>::program_id_crh()
            .hash(&verifying_key.to_bytes_le()?)?
            .to_bytes_le()?;

        Ok(Self {
            id,
            proving_key,
            verifying_key,
        })
    }

    fn execute<R: Rng + CryptoRng>(
        &self,
        local_data: &Self::LocalData,
        position: u8,
        rng: &mut R,
    ) -> Result<Self::Execution, ProgramError> {
        assert!((position as usize) < (local_data.old_records.len() + local_data.new_records.len()));

        let record = match (position as usize) < local_data.old_records.len() {
            true => &local_data.old_records[position as usize],
            false => &local_data.new_records[position as usize - local_data.old_records.len()],
        };

        match (position as usize) < C::NUM_INPUT_RECORDS {
            true => assert_eq!(self.id, record.death_program_id()),
            false => assert_eq!(self.id, record.birth_program_id()),
        };

        let local_data_root = local_data.local_data_merkle_tree.root();

        let proof = <Self::ProofSystem as SNARK>::prove(
            &self.proving_key,
            &NoopCircuit::<C>::new(&local_data_root, position),
            rng,
        )?;

        {
            let program_pub_input: ProgramLocalData<C> = ProgramLocalData {
                local_data_root,
                position,
            };
            assert!(<Self::ProofSystem as SNARK>::verify(
                &self.verifying_key.clone().into(),
                &program_pub_input,
                &proof
            )?);
        }

        Ok(Self::Execution {
            verifying_key: to_bytes_le![self.verifying_key]?,
            proof: to_bytes_le![proof]?,
        })
    }

    fn execute_blank<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<Self::Execution, ProgramError> {
        let proof = <Self::ProofSystem as SNARK>::prove(&self.proving_key, &NoopCircuit::<C>::blank(), rng)?;

        Ok(Self::Execution {
            verifying_key: to_bytes_le![self.verifying_key]?,
            proof: to_bytes_le![proof]?,
        })
    }

    fn evaluate(&self, _p: &Self::PublicInput, _w: &Self::Execution) -> bool {
        unimplemented!()
    }

    /// Returns the program ID.
    fn id(&self) -> Self::ID {
        self.id.clone()
    }
}

impl<C: Testnet1Components> NoopProgram<C> {
    #[deprecated]
    pub fn to_snark_parameters(
        &self,
    ) -> (
        <<C as Testnet1Components>::NoopProgramSNARK as SNARK>::ProvingKey,
        <<C as Testnet1Components>::NoopProgramSNARK as SNARK>::VerifyingKey,
    ) {
        (self.proving_key.clone(), self.verifying_key.clone())
    }
}
