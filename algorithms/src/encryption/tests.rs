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

mod ecies {
    use crate::{encryption::ECIESPoseidonEncryption, EncryptionScheme};
    use snarkvm_curves::edwards_bls12::EdwardsParameters;
    use snarkvm_utilities::{to_bytes_le, FromBytes, ToBytes, UniformRand};

    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    type TestEncryptionScheme = ECIESPoseidonEncryption<EdwardsParameters>;
    pub const ITERATIONS: usize = 1000;

    #[test]
    fn test_encrypt_and_decrypt() {
        let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);

        let encryption_scheme = TestEncryptionScheme::setup("simple_encryption");

        let private_key = encryption_scheme.generate_private_key(rng);
        let public_key = encryption_scheme.generate_public_key(&private_key).unwrap();

        let randomness = encryption_scheme.generate_randomness(&public_key, rng).unwrap();
        let message = (0..32).map(|_| u8::rand(rng)).collect::<Vec<u8>>();

        let ciphertext = encryption_scheme.encrypt(&public_key, &randomness, &message).unwrap();
        let decrypted_message = encryption_scheme.decrypt(&private_key, &ciphertext).unwrap();
        assert_eq!(message, decrypted_message);
    }

    #[test]
    fn test_encryption_public_key_to_bytes_le() {
        let rng = &mut ChaChaRng::seed_from_u64(1231275789u64);

        let encryption_scheme = TestEncryptionScheme::setup("encryption_public_key_serialization");

        for _ in 0..ITERATIONS {
            let private_key = encryption_scheme.generate_private_key(rng);
            let public_key = encryption_scheme.generate_public_key(&private_key).unwrap();

            let public_key_bytes = to_bytes_le![public_key].unwrap();
            let recovered_public_key =
                <TestEncryptionScheme as EncryptionScheme>::PublicKey::read_le(&public_key_bytes[..]).unwrap();
            assert_eq!(public_key, recovered_public_key);
        }
    }
}
