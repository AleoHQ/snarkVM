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

#![allow(clippy::redundant_closure)]

use console::{
    account::Address,
    network::Network,
    prelude::{cfg_into_iter, cfg_iter, cfg_reduce},
    program::{Identifier, Literal, Plaintext, Value},
    types::{Boolean, U64},
};
use ledger_committee::Committee;

use anyhow::{bail, ensure, Result};
use indexmap::{indexmap, IndexMap};
use std::str::FromStr;

#[cfg(not(feature = "serial"))]
use rayon::prelude::*;

/// Returns the committee given the committee map from finalize storage.
pub fn committee_map_into_committee<N: Network>(
    starting_round: u64,
    committee_map: Vec<(Plaintext<N>, Value<N>)>,
) -> Result<Committee<N>> {
    // Prepare the identifiers.
    let microcredits_identifier = Identifier::from_str("microcredits")?;
    let is_open_identifier = Identifier::from_str("is_open")?;
    let delegate_address_identifier = Identifier::from_str("delegate_address")?;

    // Extract the committee members.
    let committee_members = committee_map
        .iter()
        .map(|(key, value)| {
            // Extract the address from the key.
            let address = match key {
                Plaintext::Literal(Literal::Address(address), _) => address,
                _ => bail!("Invalid committee key (missing address) - {key}"),
            };
            // Extract the committee state from the value.
            match value {
                Value::Plaintext(Plaintext::Struct(state, _)) => {
                    // Extract the microcredits from the value.
                    let microcredits = match state.get(&microcredits_identifier) {
                        Some(Plaintext::Literal(Literal::U64(microcredits), _)) => **microcredits,
                        _ => bail!("Invalid committee state (missing microcredits) - {value}"),
                    };
                    // Extract the is_open flag from the value.
                    let is_open = match state.get(&is_open_identifier) {
                        Some(Plaintext::Literal(Literal::Boolean(is_open), _)) => **is_open,
                        _ => bail!("Invalid committee state (missing boolean) - {value}"),
                    };
                    let delegate_address = match state.get(&delegate_address_identifier) {
                        Some(Plaintext::Literal(Literal::Address(delegate_address), _)) => *delegate_address,
                        _ => bail!("Invalid committee state (missing delegate_address) - {value}"),
                    };
                    // Return the committee state.
                    Ok((*address, (microcredits, is_open, delegate_address)))
                }
                _ => bail!("Invalid committee value (missing struct) - {value}"),
            }
        })
        .collect::<Result<IndexMap<_, _>>>()?;

    // Return the committee.
    Committee::new(starting_round, committee_members)
}

/// Returns the stakers given the bonded map from finalize storage.
pub fn bonded_map_into_stakers<N: Network>(
    bonded_map: Vec<(Plaintext<N>, Value<N>)>,
) -> Result<IndexMap<Address<N>, (Address<N>, u64)>> {
    // Prepare the identifiers.
    let validator_identifier = Identifier::from_str("validator")?;
    let microcredits_identifier = Identifier::from_str("microcredits")?;

    // Convert the given key and value into a staker entry.
    let convert = |key, value| {
        // Extract the staker from the key.
        let address = match key {
            Plaintext::Literal(Literal::Address(address), _) => address,
            _ => bail!("Invalid bonded key (missing staker) - {key}"),
        };
        // Extract the bonded state from the value.
        match &value {
            Value::Plaintext(Plaintext::Struct(state, _)) => {
                // Extract the validator from the value.
                let validator = match state.get(&validator_identifier) {
                    Some(Plaintext::Literal(Literal::Address(validator), _)) => *validator,
                    _ => bail!("Invalid bonded state (missing validator) - {value}"),
                };
                // Extract the microcredits from the value.
                let microcredits = match state.get(&microcredits_identifier) {
                    Some(Plaintext::Literal(Literal::U64(microcredits), _)) => **microcredits,
                    _ => bail!("Invalid bonded state (missing microcredits) - {value}"),
                };
                // Return the bonded state.
                Ok((address, (validator, microcredits)))
            }
            _ => bail!("Invalid bonded value (missing struct) - {value}"),
        }
    };

    // Convert the bonded map into stakers.
    bonded_map.into_iter().map(|(key, value)| convert(key, value)).collect::<Result<IndexMap<_, _>>>()
}

/// Checks that the given committee from committee storage matches the given stakers.
pub fn ensure_stakers_matches<N: Network>(
    committee: &Committee<N>,
    stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
) -> Result<()> {
    // Construct the validator map.
    let validator_map: IndexMap<_, _> = cfg_reduce!(
        cfg_into_iter!(stakers).map(|(_, (validator, microcredits))| indexmap! {*validator => *microcredits}),
        || IndexMap::new(),
        |mut acc, e| {
            for (validator, microcredits) in e {
                let entry: &mut u64 = acc.entry(validator).or_default();
                *entry = entry.saturating_add(microcredits);
            }
            acc
        }
    );

    // Compute the total microcredits.
    let total_microcredits =
        cfg_reduce!(cfg_iter!(validator_map).map(|(_, microcredits)| *microcredits), || 0u64, |a, b| {
            // Add the staker's microcredits to the total microcredits.
            a.saturating_add(b)
        });

    // Ensure the committee and committee map match.
    ensure!(committee.members().len() == validator_map.len(), "Committee and validator map length do not match");
    // Ensure the total microcredits match.
    ensure!(committee.total_stake() == total_microcredits, "Committee and validator map total stake do not match");

    // Iterate over the committee and ensure the committee and validators match.
    for (validator, (microcredits, _, _)) in committee.members() {
        let candidate_microcredits = validator_map.get(validator);
        ensure!(candidate_microcredits.is_some(), "A validator is missing in finalize storage");
        ensure!(
            *microcredits == *candidate_microcredits.unwrap(),
            "Committee contains an incorrect 'microcredits' amount from stakers"
        );
    }

    Ok(())
}

/// Returns the next committee, given the current committee and stakers.
pub fn to_next_committee<N: Network>(
    current_committee: &Committee<N>,
    next_round: u64,
    next_stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
) -> Result<Committee<N>> {
    // Construct the validator map.
    let validator_map: IndexMap<_, _> = cfg_reduce!(
        cfg_into_iter!(next_stakers).map(|(_, (validator, microcredits))| indexmap! {*validator => *microcredits}),
        || IndexMap::new(),
        |mut acc, e| {
            for (validator, microcredits) in e {
                let entry: &mut u64 = acc.entry(validator).or_default();
                *entry = entry.saturating_add(microcredits);
            }
            acc
        }
    );

    // Initialize the members.
    let mut members = IndexMap::with_capacity(validator_map.len());
    // Iterate over the validators.
    for (validator, microcredits) in validator_map {
        members.insert(
            validator,
            (
                microcredits,
                current_committee.is_committee_member_open(validator),
                current_committee.get_committee_member_delegate_address(validator),
            ),
        );
    }
    // Return the next committee.
    Committee::new(next_round, members)
}

/// Returns the committee map and bonded map, given the committee and stakers.
pub fn to_next_commitee_map_and_bonded_map<N: Network>(
    next_committee: &Committee<N>,
    next_stakers: &IndexMap<Address<N>, (Address<N>, u64)>,
) -> (Vec<(Plaintext<N>, Value<N>)>, Vec<(Plaintext<N>, Value<N>)>) {
    // Prepare the identifiers.
    let validator_identifier = Identifier::from_str("validator").expect("Failed to parse 'validator'");
    let microcredits_identifier = Identifier::from_str("microcredits").expect("Failed to parse 'microcredits'");
    let is_open_identifier = Identifier::from_str("is_open").expect("Failed to parse 'is_open'");
    let delegate_address_identifier =
        Identifier::from_str("delegate_address").expect("Failed to parse 'delegate_address'");

    // Construct the committee map.
    let committee_map = cfg_iter!(next_committee.members())
        .map(|(validator, (microcredits, is_open, delegate_address))| {
            // Construct the committee state.
            let committee_state = indexmap! {
                microcredits_identifier => Plaintext::from(Literal::U64(U64::new(*microcredits))),
                is_open_identifier => Plaintext::from(Literal::Boolean(Boolean::new(*is_open))),
                delegate_address_identifier => Plaintext::from(Literal::Address(*delegate_address))
            };
            // Return the committee state.
            (
                Plaintext::from(Literal::Address(*validator)),
                Value::Plaintext(Plaintext::Struct(committee_state, Default::default())),
            )
        })
        .collect::<Vec<_>>();

    // Construct the bonded map.
    let bonded_map = cfg_iter!(next_stakers)
        .map(|(staker, (validator, microcredits))| {
            // Construct the bonded state.
            let bonded_state = indexmap! {
                validator_identifier => Plaintext::from(Literal::Address(*validator)),
                microcredits_identifier => Plaintext::from(Literal::U64(U64::new(*microcredits))),
            };
            // Return the bonded state.
            (
                Plaintext::from(Literal::Address(*staker)),
                Value::Plaintext(Plaintext::Struct(bonded_state, Default::default())),
            )
        })
        .collect::<Vec<_>>();

    (committee_map, bonded_map)
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use super::*;
    use crate::vm::TestRng;
    use ledger_committee::MIN_VALIDATOR_STAKE;

    use rand::{CryptoRng, Rng};

    /// Returns the stakers, given the map of `(validator, (microcredits, is_open))` entries.
    /// This method simulates the existence of delegators for the members.
    pub(crate) fn to_stakers<N: Network, R: Rng + CryptoRng>(
        members: &IndexMap<Address<N>, (u64, bool, Address<N>)>,
        rng: &mut R,
    ) -> IndexMap<Address<N>, (Address<N>, u64)> {
        members
            .into_iter()
            .flat_map(|(validator, (microcredits, _, _))| {
                // Keep a tally of the remaining microcredits.
                let remaining_microcredits = microcredits.saturating_sub(MIN_VALIDATOR_STAKE);
                // Set the staker amount to 10 credit.
                let staker_amount = 10_000_000;
                // Determine the number of iterations.
                let num_iterations = (remaining_microcredits / staker_amount).saturating_sub(1);

                // Construct the map of stakers.
                let rngs = (0..num_iterations).map(|_| TestRng::from_seed(rng.gen())).collect::<Vec<_>>();
                let mut stakers: IndexMap<_, _> = cfg_into_iter!(rngs)
                    .map(|mut rng| {
                        // Sample a random staker.
                        let staker = Address::<N>::new(rng.gen());
                        // Output the staker.
                        (staker, (*validator, staker_amount))
                    })
                    .collect();

                // Insert the validator.
                stakers.insert(*validator, (*validator, MIN_VALIDATOR_STAKE));

                // Insert the last staker.
                let final_amount = remaining_microcredits.saturating_sub(num_iterations * staker_amount);
                if final_amount > 0 {
                    let staker = Address::<N>::new(rng.gen());
                    stakers.insert(staker, (*validator, final_amount));
                }
                // Return the stakers.
                stakers
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::prelude::TestRng;

    #[allow(unused_imports)]
    use rayon::prelude::*;
    use std::str::FromStr;

    /// Returns the committee map, given the map of `(validator, (microcredits, is_open))` entries.
    fn to_committee_map<N: Network>(
        members: &IndexMap<Address<N>, (u64, bool, Address<N>)>,
    ) -> Vec<(Plaintext<N>, Value<N>)> {
        members
            .par_iter()
            .map(|(validator, (microcredits, is_open, _))| {
                let microcredits = U64::<N>::new(*microcredits);
                let is_open = Boolean::<N>::new(*is_open);
                (
                    Plaintext::from(Literal::Address(*validator)),
                    Value::from_str(&format!("{{ microcredits: {microcredits}, is_open: {is_open} }}")).unwrap(),
                )
            })
            .collect()
    }

    /// Returns the bonded map, given the staker, validator and microcredits.
    fn to_bonded_map<N: Network>(stakers: &IndexMap<Address<N>, (Address<N>, u64)>) -> Vec<(Plaintext<N>, Value<N>)> {
        // Prepare the identifiers.
        let validator_identifier = Identifier::from_str("validator").expect("Failed to parse 'validator'");
        let microcredits_identifier = Identifier::from_str("microcredits").expect("Failed to parse 'microcredits'");

        stakers
            .par_iter()
            .map(|(staker, (validator, microcredits))| {
                // Construct the bonded state.
                let bonded_state = indexmap! {
                    validator_identifier => Plaintext::from(Literal::Address(*validator)),
                    microcredits_identifier => Plaintext::from(Literal::U64(U64::new(*microcredits))),
                };
                // Return the bonded state.
                (
                    Plaintext::from(Literal::Address(*staker)),
                    Value::Plaintext(Plaintext::Struct(bonded_state, Default::default())),
                )
            })
            .collect()
    }

    #[test]
    fn test_committee_map_into_committee() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 100, rng);

        // Initialize the committee map.
        let committee_map = to_committee_map(committee.members());

        // Start a timer.
        let timer = std::time::Instant::now();
        // Convert the committee map into a committee.
        let candidate_committee = committee_map_into_committee(committee.starting_round(), committee_map).unwrap();
        println!("committee_map_into_committee: {}ms", timer.elapsed().as_millis());
        assert_eq!(candidate_committee, committee);
    }

    #[test]
    fn test_bonded_map_into_stakers() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 100, rng);
        // Convert the committee into stakers.
        let expected_stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);
        // Initialize the bonded map.
        let bonded_map = to_bonded_map(&expected_stakers);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Convert the bonded map into stakers.
        let candidate_stakers = bonded_map_into_stakers(bonded_map).unwrap();
        println!("bonded_map_into_stakers: {}ms", timer.elapsed().as_millis());
        assert_eq!(candidate_stakers.len(), expected_stakers.len());
        assert_eq!(candidate_stakers, expected_stakers);
    }

    #[test]
    fn test_ensure_stakers_matches() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 100, rng);
        // Convert the committee into stakers.
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Ensure the stakers matches.
        let result = ensure_stakers_matches(&committee, &stakers);
        println!("ensure_stakers_matches: {}ms", timer.elapsed().as_millis());
        assert!(result.is_ok());
    }

    #[test]
    fn test_to_next_committee() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = ledger_committee::test_helpers::sample_committee_for_round_and_size(1, 100, rng);
        // Convert the committee into stakers.
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Ensure the next committee matches the current committee.
        // Note: We can perform this check, in this specific case only, because we did not apply staking rewards.
        let next_committee = to_next_committee(&committee, committee.starting_round() + 1, &stakers).unwrap();
        println!("to_next_committee: {}ms", timer.elapsed().as_millis());
        assert_eq!(committee.starting_round() + 1, next_committee.starting_round());
        assert_eq!(committee.members(), next_committee.members());
    }

    #[test]
    fn test_to_next_commitee_map_and_bonded_map() {
        let rng = &mut TestRng::default();

        // Sample a committee.
        let committee = ledger_committee::test_helpers::sample_committee(rng);
        // Convert the committee into stakers.
        let stakers = crate::committee::test_helpers::to_stakers(committee.members(), rng);

        // Start a timer.
        let timer = std::time::Instant::now();
        // Ensure the next committee matches the current committee.
        // Note: We can perform this check, in this specific case only, because we did not apply staking rewards.
        let (committee_map, bonded_map) = to_next_commitee_map_and_bonded_map(&committee, &stakers);
        println!("to_next_commitee_map_and_bonded_map: {}ms", timer.elapsed().as_millis());
        assert_eq!(committee_map, to_committee_map(committee.members()));
        assert_eq!(bonded_map, to_bonded_map(&stakers));
    }
}
