// Copyright (C) 2019-2022 Aleo Systems Inc.
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

use super::*;

impl<N: Network, B: BlockStorage<N>, P: ProgramStorage<N>> Ledger<N, B, P> {
    /* Transaction */

    /// Returns an iterator over the transaction IDs, for all transactions in `self`.
    pub fn transaction_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, N::TransactionID>> {
        self.transactions.transaction_ids()
    }

    /// Returns an iterator over the program IDs, for all transactions in `self`.
    pub fn program_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, ProgramID<N>>> {
        self.transactions.program_ids()
    }

    /// Returns an iterator over the programs, for all transactions in `self`.
    pub fn programs(&self) -> impl '_ + Iterator<Item = Cow<'_, Program<N>>> {
        self.transactions.programs()
    }

    /* Transition */

    /// Returns an iterator over the transition IDs, for all transitions.
    pub fn transition_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, N::TransitionID>> {
        self.transitions.transition_ids()
    }

    /* Input */

    /// Returns an iterator over the input IDs, for all transition inputs.
    pub fn input_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.transitions.input_ids()
    }

    /// Returns an iterator over the serial numbers, for all transition inputs that are records.
    pub fn serial_numbers(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.transitions.serial_numbers()
    }

    /// Returns an iterator over the tags, for all transition inputs that are records.
    pub fn tags(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.transitions.tags()
    }

    /* Output */

    /// Returns an iterator over the output IDs, for all transition outputs that are records.
    pub fn output_ids(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.transitions.output_ids()
    }

    /// Returns an iterator over the commitments, for all transition outputs that are records.
    pub fn commitments(&self) -> impl '_ + Iterator<Item = Cow<'_, Field<N>>> {
        self.transitions.commitments()
    }

    /// Returns an iterator over the nonces, for all transition outputs that are records.
    pub fn nonces(&self) -> impl '_ + Iterator<Item = Cow<'_, Group<N>>> {
        self.transitions.nonces()
    }

    /// Returns an iterator over the `(commitment, record)` pairs, for all transition outputs that are records.
    pub fn records(&self) -> impl '_ + Iterator<Item = (Cow<'_, Field<N>>, Cow<'_, Record<N, Ciphertext<N>>>)> {
        self.transitions.records()
    }

    /* Metadata */

    /// Returns an iterator over the transition public keys, for all transactions.
    pub fn transition_public_keys(&self) -> impl '_ + Iterator<Item = Cow<'_, Group<N>>> {
        self.transitions.tpks()
    }
}
