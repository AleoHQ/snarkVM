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

use super::ensure_map_is_empty;
use crate::helpers::NestedMap;

const NUM_ITEMS: usize = 10;
const NUM_TOTAL_ITEMS: usize = 20;

fn check_contains_and_remove_unique_maps(map: &impl for<'a> NestedMap<'a, usize, usize, String>) {
    ensure_map_is_empty(map);

    for i in 0..NUM_ITEMS {
        println!("insert({i})");

        assert!(!map.contains_map_confirmed(&i).unwrap());
        assert!(!map.contains_map_speculative(&i).unwrap());

        // Insert an item into the map.
        map.insert(i, i, i.to_string()).unwrap();

        assert!(map.contains_map_confirmed(&i).unwrap());
        assert!(map.contains_map_speculative(&i).unwrap());
    }

    /* test atomic insertions */

    {
        // Start an atomic write batch.
        map.start_atomic();

        for i in NUM_ITEMS..NUM_TOTAL_ITEMS {
            println!("insert({i}) [atomic]");

            assert!(!map.contains_map_confirmed(&i).unwrap());
            assert!(!map.contains_map_speculative(&i).unwrap());

            // Insert an item into the map.
            map.insert(i, i, i.to_string()).unwrap();

            assert!(!map.contains_map_confirmed(&i).unwrap());
            assert!(map.contains_map_speculative(&i).unwrap());
        }

        // Finish the current atomic write batch.
        map.finish_atomic().unwrap();
    }

    for i in 0..NUM_TOTAL_ITEMS {
        println!("remove_map({i})");

        assert!(map.contains_map_confirmed(&i).unwrap());
        assert!(map.contains_map_speculative(&i).unwrap());

        map.remove_map(&i).unwrap();

        assert!(!map.contains_map_confirmed(&i).unwrap());
        assert!(!map.contains_map_speculative(&i).unwrap());
    }

    ensure_map_is_empty(map);
}

fn check_contains_and_remove_same_map(map: &impl for<'a> NestedMap<'a, usize, usize, String>) {
    ensure_map_is_empty(map);

    const MAP: usize = 0;

    assert!(!map.contains_map_confirmed(&MAP).unwrap());
    assert!(!map.contains_map_speculative(&MAP).unwrap());

    for i in 0..NUM_ITEMS {
        println!("i: {}", i);

        // Insert an item into the map.
        map.insert(MAP, i, i.to_string()).unwrap();

        assert!(map.contains_map_confirmed(&MAP).unwrap());
        assert!(map.contains_map_speculative(&MAP).unwrap());
    }

    /* test atomic insertions */

    {
        // Start an atomic write batch.
        map.start_atomic();

        for i in NUM_ITEMS..NUM_TOTAL_ITEMS {
            println!("i: {}", i);

            assert!(map.contains_map_confirmed(&MAP).unwrap());
            assert!(map.contains_map_speculative(&MAP).unwrap());

            // Insert an item into the map.
            map.insert(MAP, i, i.to_string()).unwrap();

            assert!(map.contains_map_confirmed(&MAP).unwrap());
            assert!(map.contains_map_speculative(&MAP).unwrap());
        }

        // Finish the current atomic write batch.
        map.finish_atomic().unwrap();

        assert!(map.contains_map_confirmed(&MAP).unwrap());
        assert!(map.contains_map_speculative(&MAP).unwrap());
    }

    map.remove_map(&MAP).unwrap();

    assert!(!map.contains_map_confirmed(&MAP).unwrap());
    assert!(!map.contains_map_speculative(&MAP).unwrap());

    ensure_map_is_empty(map);
}

fn check_contains_map_by_removing_key_values(map: &impl for<'a> NestedMap<'a, usize, usize, String>) {
    ensure_map_is_empty(map);

    const MAP: usize = 0;

    assert!(!map.contains_map_confirmed(&MAP).unwrap());
    assert!(!map.contains_map_speculative(&MAP).unwrap());

    println!("Inserting all {NUM_TOTAL_ITEMS} items");

    for i in 0..NUM_TOTAL_ITEMS {
        println!("i: {}", i);

        // Insert an item into the map.
        map.insert(MAP, i, i.to_string()).unwrap();

        assert!(map.contains_map_confirmed(&MAP).unwrap());
        assert!(map.contains_map_speculative(&MAP).unwrap());
    }

    println!("Removing all {NUM_TOTAL_ITEMS} items");

    for i in 0..(NUM_TOTAL_ITEMS - 1) {
        println!("i: {}", i);

        assert!(map.contains_map_confirmed(&MAP).unwrap());
        assert!(map.contains_map_speculative(&MAP).unwrap());

        // Remove the item from the map.
        map.remove_key(&MAP, &i).unwrap();

        assert!(map.contains_map_confirmed(&MAP).unwrap());
        assert!(map.contains_map_speculative(&MAP).unwrap());
    }

    println!("i: {}", NUM_TOTAL_ITEMS - 1);

    // Remove the final item from the map.
    map.remove_key(&MAP, &(NUM_TOTAL_ITEMS - 1)).unwrap();

    assert!(!map.contains_map_confirmed(&MAP).unwrap());
    assert!(!map.contains_map_speculative(&MAP).unwrap());

    println!("Inserting all {NUM_TOTAL_ITEMS} items");

    for i in 0..NUM_TOTAL_ITEMS {
        println!("i: {}", i);

        // Insert an item into the map.
        map.insert(MAP, i, i.to_string()).unwrap();

        assert!(map.contains_map_confirmed(&MAP).unwrap());
        assert!(map.contains_map_speculative(&MAP).unwrap());
    }

    /* test atomic removals */

    println!("Removing all {NUM_TOTAL_ITEMS} items (atomically)");

    {
        // Start an atomic write batch.
        map.start_atomic();

        for i in 0..(NUM_TOTAL_ITEMS - 1) {
            println!("i: {}", i);

            assert!(map.contains_map_confirmed(&MAP).unwrap());
            assert!(map.contains_map_speculative(&MAP).unwrap());

            // Remove the item from the map.
            map.remove_key(&MAP, &i).unwrap();

            assert!(map.contains_map_confirmed(&MAP).unwrap());
            assert!(map.contains_map_speculative(&MAP).unwrap());
        }

        println!("i: {}", NUM_TOTAL_ITEMS - 1);

        // Remove the final item from the map.
        map.remove_key(&MAP, &(NUM_TOTAL_ITEMS - 1)).unwrap();

        assert!(map.contains_map_confirmed(&MAP).unwrap());
        assert!(!map.contains_map_speculative(&MAP).unwrap());

        // Finish the current atomic write batch.
        map.finish_atomic().unwrap();

        assert!(!map.contains_map_confirmed(&MAP).unwrap());
        assert!(!map.contains_map_speculative(&MAP).unwrap());
    }

    ensure_map_is_empty(map);
}

pub fn check_contains_and_remove_map(map: impl for<'a> NestedMap<'a, usize, usize, String>) {
    println!("Checking contains and remove unique maps");
    check_contains_and_remove_unique_maps(&map);

    println!("Checking contains and remove same map");
    check_contains_and_remove_same_map(&map);

    println!("Checking contains map by removing key-values, not remove map");
    check_contains_map_by_removing_key_values(&map);
}
