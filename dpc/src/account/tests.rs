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
    account::{Account, Address, PrivateKey, ViewKey},
    testnet2::instantiated::Components,
    traits::AccountScheme,
};

use rand::thread_rng;
use std::str::FromStr;

#[test]
fn test_account_new() {
    let rng = &mut thread_rng();

    let account = Account::<Components>::new(rng);
    println!("{:?}", account);
    assert!(account.is_ok());
    println!("{}", account.unwrap());
}

#[test]
pub fn test_private_key_from_str() {
    let private_key_string = "APrivateKey1uaf51GJ6LuMzLi2jy9zJJC3doAtngx52WGFZrcvK6aBsEgo";
    let private_key = PrivateKey::<Components>::from_str(private_key_string);
    println!("{:?}", private_key);

    assert!(private_key.is_ok());
    assert_eq!(private_key_string, private_key.unwrap().to_string());
}

#[test]
pub fn test_view_key_from_str() {
    let view_key_string = "AViewKey1m8gvywHKHKfUzZiLiLoHedcdHEjKwo5TWo6efz8gK7wF";
    let view_key = ViewKey::<Components>::from_str(view_key_string);
    println!("{:?}", view_key);

    assert!(view_key.is_ok());
    assert_eq!(view_key_string, view_key.unwrap().to_string());
}

#[test]
pub fn test_address_from_str() {
    let address_string = "aleo1ag4alvc4g7d4apzgvr5f4jt44l0aezev2dx8m0klgwypnh9u5uxs42rclr";
    let address = Address::<Components>::from_str(address_string);
    assert!(address.is_ok());
    assert_eq!(address_string, address.unwrap().to_string());
}

#[test]
pub fn test_account_encryption_and_signature_compatibility() {
    let rng = &mut thread_rng();
    let message = "Hi, I am a Schnorr signature!".as_bytes();

    let account = Account::<Components>::new(rng).unwrap();
    let view_key = ViewKey::<Components>::from_private_key(&account.private_key).unwrap();

    let signature = view_key.sign(message, rng).unwrap();

    let verification = account.address.verify_signature(message, &signature).unwrap();

    assert!(verification);
}

#[test]
pub fn test_failed_account_encryption_and_signature_compatibility() {
    let rng = &mut thread_rng();
    let message = "Hi, I am a Schnorr signature!".as_bytes();
    let bad_message = "Bad Message".as_bytes();

    let account = Account::<Components>::new(rng).unwrap();
    let view_key = ViewKey::<Components>::from_private_key(&account.private_key).unwrap();

    let signature = view_key.sign(message, rng).unwrap();

    let verification = account.address.verify_signature(bad_message, &signature).unwrap();

    assert!(!verification);
}
