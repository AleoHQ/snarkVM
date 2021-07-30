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

use snarkvm_algorithms::crh::double_sha256;

fn merkle_round(hashes: &[[u8; 32]]) -> Vec<[u8; 32]> {
    let mut ret_len = hashes.len() / 2;
    if hashes.len() % 2 == 1 {
        ret_len += 1;
    };
    let mut ret = Vec::with_capacity(ret_len);

    // Duplicates the last element if there are an odd number of leaves
    for arr in hashes.chunks(2) {
        match arr {
            [h1, h2] => ret.push(merkle_hash(&h1[..], &h2[..])),
            [h] => ret.push(merkle_hash(&h[..], &h[..])),
            _ => unreachable!(),
        }
    }

    ret
}

/// Calculates a Merkle root and also returns the subroots at a desired depth. If the tree is too
/// shallow to have subroots at that depth, returns the root as a single subroot.
pub fn merkle_root_with_subroots(hashes: &[[u8; 32]], subroots_depth: usize) -> ([u8; 32], Vec<[u8; 32]>) {
    merkle_root_with_subroots_inner(hashes, &[], subroots_depth)
}

fn merkle_root_with_subroots_inner(
    hashes: &[[u8; 32]],
    subroots: &[[u8; 32]],
    subroots_depth: usize,
) -> ([u8; 32], Vec<[u8; 32]>) {
    if hashes.len() == 1 {
        // Tree was too shallow.
        let root = hashes[0];
        let subroots = if subroots.is_empty() {
            vec![root]
        } else {
            subroots.to_vec()
        };
        return (root, subroots);
    }

    let result = merkle_round(hashes);
    if result.len() == 1 << subroots_depth {
        merkle_root_with_subroots_inner(&result, &result, subroots_depth)
    } else {
        merkle_root_with_subroots_inner(&result, subroots, subroots_depth)
    }
}

/// Calculates the root of the Merkle tree
pub fn merkle_root(hashes: &[[u8; 32]]) -> [u8; 32] {
    if hashes.len() == 1 {
        return hashes[0];
    }

    let result = merkle_round(hashes);

    merkle_root(&result)
}

/// Calculate the Merkle tree hash by concatenating the left and right children nodes.
pub fn merkle_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 64];
    result[0..32].copy_from_slice(&left);
    result[32..64].copy_from_slice(&right);
    double_sha256(&result)
}

#[cfg(test)]
mod tests {
    use super::merkle_root;
    use std::convert::TryInto;

    // block 80_000
    // https://blockchain.info/block/000000000043a8c0fd1d6f726790caa2a406010d19efd2780db27bdbbd93baf6
    #[test]
    fn test_merkle_root_2_hashes() {
        let mut tx1 = hex::decode("c06fbab289f723c6261d3030ddb6be121f7d2508d77862bb1e484f5cd7f92b25").unwrap();
        let mut tx2 = hex::decode("5a4ebf66822b0b2d56bd9dc64ece0bc38ee7844a23ff1d7320a88c5fdb2ad3e2").unwrap();

        tx1.reverse();
        tx2.reverse();

        let result = merkle_root(&[tx1.as_slice().try_into().unwrap(), tx2.as_slice().try_into().unwrap()]);

        let mut expected = hex::decode("8fb300e3fdb6f30a4c67233b997f99fdd518b968b9a3fd65857bfe78b2600719").unwrap();
        expected.reverse();

        assert_eq!(&result[..], &expected[..]);
    }

    #[test]
    fn test_merkle_root_5_hashes() {
        let tx1 = hex::decode("1da63abbc8cc611334a753c4c31de14d19839c65b2b284202eaf3165861fb58d").unwrap();
        let tx2 = hex::decode("26c6a6f18d13d2f0787c1c0f3c5e23cf5bc8b3de685dd1923ae99f44c5341c0c").unwrap();
        let tx3 = hex::decode("513507fa209db823541caf7b9742bb9999b4a399cf604ba8da7037f3acced649").unwrap();
        let tx4 = hex::decode("6bf5d2e02b8432d825c5dff692d435b6c5f685d94efa6b3d8fb818f2ecdcfb66").unwrap();
        let tx5 = hex::decode("8a5ad423bc54fb7c76718371fd5a73b8c42bf27beaf2ad448761b13bcafb8895").unwrap();

        let vec: Vec<_> = vec![tx1, tx2, tx3, tx4, tx5]
            .iter_mut()
            .map(|tx| {
                tx.reverse();
                tx.as_slice().try_into().unwrap()
            })
            .collect();

        let result = merkle_root(&vec);

        let mut expected = hex::decode("3a432cd416ea05b1be4ec1e72d7952d08670eaa5505b6794a186ddb253aa62e6").unwrap();
        expected.reverse();

        assert_eq!(&result[..], &expected[..]);
    }
}
