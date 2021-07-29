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
    Execution,
    LocalData,
    Network,
    NoopCircuit,
    Parameters,
    ProgramError,
    ProgramLocalData,
    ProgramScheme,
    RecordScheme,
};
use snarkvm_algorithms::{merkle_tree::MerklePath, prelude::*};
use snarkvm_parameters::Parameter;
use snarkvm_r1cs::ToConstraintField;
use snarkvm_utilities::{FromBytes, ToBytes};

use rand::{CryptoRng, Rng};

#[derive(Derivative)]
#[derivative(Clone(bound = "C: Parameters"), Debug(bound = "C: Parameters"))]
pub struct NoopProgram<C: Parameters> {
    #[derivative(Default(value = "vec![0u8; 48]"))]
    id: Vec<u8>,
    #[derivative(Debug = "ignore")]
    proving_key: <C::ProgramSNARK as SNARK>::ProvingKey,
    #[derivative(Debug = "ignore")]
    verifying_key: <C::ProgramSNARK as SNARK>::VerifyingKey,
}

impl<C: Parameters> ProgramScheme for NoopProgram<C> {
    type Execution = Execution<C, Self::ProofSystem>;
    type ID = Vec<u8>;
    type LocalData = LocalData<C>;
    type LocalDataCommitment = C::LocalDataCommitmentScheme;
    type ProgramIDCRH = C::ProgramIDCRH;
    type ProgramSelectorTree = C::ProgramSelectorTreeParameters;
    type ProofSystem = C::ProgramSNARK;
    type ProvingKey = <Self::ProofSystem as SNARK>::ProvingKey;
    type PublicInput = ();
    type VerifyingKey = <Self::ProofSystem as SNARK>::VerifyingKey;

    /// Initializes a new instance of the noop program.
    fn setup<R: Rng + CryptoRng>(rng: &mut R) -> Result<Self, ProgramError> {
        let (proving_key, prepared_verifying_key) =
            <Self::ProofSystem as SNARK>::setup(&NoopCircuit::<C>::blank(), &mut C::program_srs::<R>(rng)?)?;
        let verifying_key: Self::VerifyingKey = prepared_verifying_key.into();

        let verifying_key_group_elements = verifying_key.to_field_elements()?;

        // Compute the program ID.
        let id = <C as Parameters>::program_id_crh()
            .hash_field_elements(&verifying_key_group_elements)?
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
        let proving_key: <Self::ProofSystem as SNARK>::ProvingKey = match Network::from_id(C::NETWORK_ID) {
            Network::Testnet1 => FromBytes::read_le(
                snarkvm_parameters::testnet1::NoopProgramSNARKPKParameters::load_bytes()?.as_slice(),
            )?,
            Network::Testnet2 => FromBytes::read_le(
                snarkvm_parameters::testnet2::NoopProgramSNARKPKParameters::load_bytes()?.as_slice(),
            )?,
            _ => {
                unimplemented!()
            }
        };

        let verifying_key = match Network::from_id(C::NETWORK_ID) {
            Network::Testnet1 => <Self::ProofSystem as SNARK>::VerifyingKey::read_le(
                snarkvm_parameters::testnet1::NoopProgramSNARKVKParameters::load_bytes()?.as_slice(),
            )?,
            Network::Testnet2 => <Self::ProofSystem as SNARK>::VerifyingKey::read_le(
                snarkvm_parameters::testnet2::NoopProgramSNARKVKParameters::load_bytes()?.as_slice(),
            )?,
            _ => {
                unimplemented!()
            }
        };

        let verifying_key_group_elements = verifying_key.to_field_elements()?;

        // Compute the program ID.
        let id = <C as Parameters>::program_id_crh()
            .hash_field_elements(&verifying_key_group_elements)?
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
        program_selector_path: MerklePath<Self::ProgramSelectorTree>,
        rng: &mut R,
    ) -> Result<Self::Execution, ProgramError> {
        assert!((position as usize) < (local_data.old_records.len() + local_data.new_records.len()));

        let record = match (position as usize) < local_data.old_records.len() {
            true => &local_data.old_records[position as usize],
            false => &local_data.new_records[position as usize - local_data.old_records.len()],
        };

        match (position as usize) < C::NUM_INPUT_RECORDS {
            true => assert_eq!(self.id, record.death_program_selector_root()),
            false => assert_eq!(self.id, record.birth_program_selector_root()),
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

        // TODO (raychu86): Extract the construction of the merkle tree.

        Ok(Self::Execution {
            verifying_key: self.verifying_key.clone(),
            proof,
            program_selector_path,
        })
    }

    fn execute_blank<R: Rng + CryptoRng>(&self, rng: &mut R) -> Result<Self::Execution, ProgramError> {
        let proof = <Self::ProofSystem as SNARK>::prove(&self.proving_key, &NoopCircuit::<C>::blank(), rng)?;
        let program_selector_path = MerklePath::<Self::ProgramSelectorTree>::default();

        Ok(Self::Execution {
            verifying_key: self.verifying_key.clone(),
            proof,
            program_selector_path,
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

impl<C: Parameters> NoopProgram<C> {
    #[deprecated]
    pub fn to_snark_parameters(
        &self,
    ) -> (
        <C::ProgramSNARK as SNARK>::ProvingKey,
        <C::ProgramSNARK as SNARK>::VerifyingKey,
    ) {
        (self.proving_key.clone(), self.verifying_key.clone())
    }
}
