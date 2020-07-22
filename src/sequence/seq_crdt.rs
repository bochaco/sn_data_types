// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::{Address, Entries, Entry, Index, Perm};
use crate::{Error, Result};
pub use crdts::{lseq::Op, Actor};
use crdts::{
    lseq::{ident::Identifier, Entry as LSeqEntry, LSeq},
    CmRDT,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fmt::{self, Display},
    hash::Hash,
};

/// Since in most of the cases it will be append operations, having a small
/// boundary will make the Identifiers' length to be shorter.
const LSEQ_BOUNDARY: u64 = 1;
/// Again, we are going to be dealing with append operations most of the time,
/// thus a large arity be benefitial to keep Identifiers' length short.
const LSEQ_TREE_BASE: u8 = 10; // arity of 1024 at root

/// CRDT Data operation applicable to other Sequence replica.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct CrdtDataOperation<A: Actor + Display + std::fmt::Debug, T> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The data operation to apply.
    pub crdt_op: Op<T, A>,
    /// The context (policy) this operation depends on
    pub ctx: Identifier<A>,
}

/// CRDT Policy operation applicable to other Sequence replica.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Eq, Hash)]
pub struct CrdtPolicyOperation<A: Actor + Display + std::fmt::Debug, P> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The policy operation to apply.
    pub crdt_op: Op<(P, Option<Identifier<A>>), A>,
    /// The context (data identifier) this operation depends on
    pub ctx: Option<Identifier<A>>,
}

/// Sequence data type as a CRDT with Access Control
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd)]
pub struct SequenceCrdt<A, P>
where
    A: Actor + Display + std::fmt::Debug,
    P: Perm + Hash + Clone,
{
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data, i.e. the items of the Sequence.
    /// We keep different LSeqs for each Policy, which allows us to create
    /// a (virtual) branch of items when data ops that depend on old policies are applied.
    data: BTreeMap<Identifier<A>, LSeq<Entry, A>>,
    /// History of the Policy matrix, each entry representing a version of the Policy matrix,
    /// mapping the Identifier of the data's entry when this policy change happened.
    policy: LSeq<(P, Option<Identifier<A>>), A>,
}

impl<A, P> Display for SequenceCrdt<A, P>
where
    A: Actor + Display + std::fmt::Debug,
    P: Perm + Hash + Clone,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[")?;
        /*for (i, entry) in self.data.iter().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "<{}>", String::from_utf8_lossy(&entry),)?;
        }*/
        write!(f, "]")
    }
}

impl<A, P> SequenceCrdt<A, P>
where
    A: Actor + Display + std::fmt::Debug,
    P: Perm + Hash + Clone,
{
    /// Constructs a new 'SequenceCrdt'.
    pub fn new(actor: A, address: Address) -> Self {
        Self {
            address,
            data: BTreeMap::default(),
            policy: LSeq::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY),
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the length of the sequence.
    pub fn len(&self) -> u64 {
        let (index, _) = self.walk_entries_main_branch(|_, _| false);
        index as u64
    }

    /// Returns the last policy index.
    pub fn policy_index(&self) -> u64 {
        self.policy.len() as u64
    }

    /// Append a new item to the SequenceCrdt.
    /// Returns the CRDT op and the context it depends on
    pub fn append(&mut self, entry: Entry) -> Result<CrdtDataOperation<A, Entry>> {
        let cur_policy = self.policy.last_entry().ok_or_else(|| {
            // There is no Policy set yet
            Error::InvalidOperation
        })?;

        // Retrieve the LSeq corresponding to the current Policy,
        // or create and insert one if not.
        let policy_id = cur_policy.id.clone();
        let actor = self.policy.actor();
        let cur_lseq = self
            .data
            .entry(policy_id.clone())
            .or_insert_with(|| LSeq::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY));

        // Append the entry to the LSeq corresponding to current Policy
        let crdt_op = cur_lseq.append(entry);

        // We return the operation as it may need to be broadcasted to other replicas
        Ok(CrdtDataOperation {
            address: *self.address(),
            crdt_op,
            ctx: policy_id,
        })
    }

    /// Apply a remote data CRDT operation to this replica of the Sequence.
    pub fn apply_data_op(&mut self, op: CrdtDataOperation<A, Entry>) -> Result<()> {
        let policy_id = op.ctx.clone();
        if self.policy.find(&policy_id).is_some() {
            // Retrieve the LSeq corresponding to the current Policy,
            // or create and insert one if not.
            let actor = self.policy.actor();
            let lseq = self
                .data
                .entry(policy_id)
                .or_insert_with(|| LSeq::new_with_args(actor, LSEQ_TREE_BASE, LSEQ_BOUNDARY));

            // Apply the CRDT operation to the LSeq data
            lseq.apply(op.crdt_op);
            Ok(())
        } else {
            // Operation is not causally ready as depends on a policy
            // version we aren't aware of yet.
            // Return error so sender can retry later and/or send the missing policy op/s
            // TODO: perhaps send the last Policy Identifier as a reference to the sender
            Err(Error::OpNotCausallyReady)
        }
    }

    /// Sets a new Policy keeping the current one in the history.
    pub fn set_policy(&mut self, policy: P) -> CrdtPolicyOperation<A, P> {
        let last_entry_id = self
            .policy
            .last_entry()
            .and_then(|policy| self.data.get(&policy.id))
            .and_then(|lseq| lseq.last_entry())
            .map(|entry| entry.id.clone());

        // Append the new Policy to the history
        let crdt_op = self.policy.append((policy, last_entry_id.clone()));
        let policy_id = crdt_op.id().clone();

        // Create a new LSeq for this new policy
        let new_lseq = LSeq::new_with_args(self.policy.actor(), LSEQ_TREE_BASE, LSEQ_BOUNDARY);
        let _ = self.data.insert(policy_id, new_lseq);

        // We return the operation as it may need to be broadcasted to other replicas
        CrdtPolicyOperation {
            address: *self.address(),
            crdt_op,
            ctx: last_entry_id,
        }
    }

    /// Apply a remote policy CRDT operation to this replica.
    pub fn apply_policy_op(&mut self, op: CrdtPolicyOperation<A, P>) -> Result<()> {
        /* TODO: verify it's causally ready
        if let Some(id_in_ctx) = op.ctx {
            // policy op has a context/causality info,
            // let's check it's ready for applying
            if ??? {
                // The policy is not causally ready, return an error
                // so the sender can retry later and/or send the missing ops
                return Err(Error::OpNotCausallyReady);
            }
        }*/

        // Apply the CRDT operation to the local replica of the policy
        self.policy.apply(op.crdt_op);

        Ok(())
    }

    /// Gets the entry at `index` if it exists.
    pub fn get(&self, index: Index) -> Option<&Entry> {
        let i = to_absolute_index(index, self.len() as usize)?;
        let (_, entry) = self.walk_entries_main_branch(|cur_index, _| cur_index == i);
        entry
    }

    /// Gets the last entry.
    pub fn last_entry(&self) -> Option<&Entry> {
        self.policy
            .last_entry()
            .and_then(|policy| self.data.get(&policy.id))
            .and_then(|lseq| lseq.last())
    }

    /// Gets a policy from the history at `index` if it exists.
    pub fn policy(&self, index: impl Into<Index>) -> Option<&P> {
        let index = to_absolute_index(index.into(), self.policy.len())?;
        self.policy.get(index).map(|(policy, _)| policy)
    }

    /// Gets a list of items which are within the given indices.
    pub fn in_range(&self, _start: Index, _end: Index) -> Option<Entries> {
        //let start_index = to_absolute_index(start, self.len() as usize)?;
        //let end_index = to_absolute_index(end, self.len() as usize)?;
        let entries = Entries::default();
        /*let _ = self.walk_entries_main_branch(|cur_index, cur_entry| {
            if cur_index < end_index {
                if cur_index >= start_index {
                    entries.push(cur_entry.clone())
                }
                false
            } else {
                true
            }
        });*/

        if entries.is_empty() {
            None
        } else {
            Some(entries)
        }
    }

    // Private helper to walk through the main branch of entries
    // TODO: transform this into an iterator
    // TODO: support walking through other branches based on a Policy
    fn walk_entries_main_branch<F>(&self, stop_fn: F) -> (usize, Option<&Entry>)
    where
        F: Fn(usize, &Entry) -> bool,
    {
        // We walk through the items ignoring branches of items
        // which were addded concurrently with new policies,
        // or those who were applied using an old policy as their context
        let mut cur_index = 0;
        let mut iter = self.policy.iter_entries().peekable();
        // Iterate through the history of policies from oldest to newest
        while let Some(LSeqEntry { id: policy_id, .. }) = iter.next() {
            // Find out what's the last entry with current Policy
            // to be considered prt of the main branch by peeking
            // subsequent Policy's causality info, i.e. linked entry id
            let ctx = iter.peek().and_then(|p| p.val.1.as_ref());

            // Retrieve the LSeq of items corresponding to current Policy
            if let Some(lseq) = self.data.get(policy_id) {
                // ...iterate through such entries
                for LSeqEntry {
                    id: entry_id, val, ..
                } in lseq.iter_entries()
                {
                    // if caller is interested in current index/entry
                    // we just stop here and return current entry
                    if stop_fn(cur_index, val) {
                        return (cur_index, Some(val));
                    }
                    cur_index += 1;

                    // If current entry is the last one bafore subsequent Policy
                    // was applied we then skip the rest of entries, and continue
                    // with entries corresponding to subsequent Policy
                    if let Some(id_ctx) = ctx {
                        if entry_id == id_ctx {
                            break;
                        }
                    }
                }
            }
        }

        (cur_index, None)
    }
}

// Private helpers

fn to_absolute_index(index: Index, count: usize) -> Option<usize> {
    match index {
        Index::FromStart(index) if index as usize <= count => Some(index as usize),
        Index::FromStart(_) => None,
        Index::FromEnd(index) => count.checked_sub(index as usize),
    }
}
