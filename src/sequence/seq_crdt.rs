// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use super::metadata::Entries;
use super::metadata::{Address, Entry, Index, Perm};
use crate::Signature;
use crate::{utils, Error, PublicKey, Result};
pub use crdts::merkle_reg::{Hash as NodeId, Node};
use crdts::{
    merkle_reg::{Content, MerkleReg},
    CmRDT,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt::{self, Debug, Display},
    hash::Hash,
};

/// CRDT Data operation applicable to other Sequence replica.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CrdtOperation<T> {
    /// Address of a Sequence object on the network.
    pub address: Address,
    /// The data operation to apply.
    pub crdt_op: Node<T>,
    /// The PublicKey of the entity that generated the operation
    pub source: PublicKey,
    /// The signature of source on the crdt_top, required to apply the op
    pub signature: Option<Signature>,
}

/// Sequence data type as a CRDT with Access Control
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd)]
pub struct SequenceCrdt<P>
where
    P: Perm + Hash + Clone + Serialize,
{
    /// Address on the network of this piece of data
    address: Address,
    /// CRDT to store the actual data, i.e. the items of the Sequence.
    data: MerkleReg<Entry>,
    /// The Policy matrix containing ownership and users permissions.
    policy: P,
}

impl<P> Display for SequenceCrdt<P>
where
    P: Perm + Hash + Clone + Serialize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(")?;
        for (i, entry) in self.data.read().values().enumerate() {
            if i > 0 {
                write!(f, ", ")?;
            }
            write!(f, "<{}>", String::from_utf8_lossy(&entry),)?;
        }
        write!(f, ")")
    }
}

impl<P> SequenceCrdt<P>
where
    P: Perm + Hash + Clone + Serialize,
{
    /// Constructs a new 'SequenceCrdt'.
    pub fn new(address: Address, policy: P) -> Self {
        Self {
            address,
            data: MerkleReg::new(),
            policy,
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        &self.address
    }

    /// Returns the length of the sequence.
    /// TODO: define the branching criteria for how this length is calculated
    pub fn len(&self) -> u64 {
        let (_, depth) = self.traverse_reg(None);
        depth
    }

    /// Create crdt op to append a new item to the SequenceCrdt
    pub fn create_append_op(
        &mut self,
        entry: Entry,
        parents: BTreeSet<NodeId>,
        source: PublicKey,
    ) -> Result<CrdtOperation<Entry>> {
        let address = *self.address();

        // Append the entry to the LSeq
        let crdt_op = self.data.write(entry, parents);
        self.data.apply(crdt_op.clone());

        // We return the operation as it may need to be broadcasted to other replicas
        Ok(CrdtOperation {
            address,
            crdt_op,
            source,
            signature: None,
        })
    }

    /// Apply a remote data CRDT operation to this replica of the Sequence.
    pub fn apply_op(&mut self, op: CrdtOperation<Entry>) -> Result<()> {
        // Let's first check the op is validly signed.
        // Note: Perms for the op are checked at the upper Sequence layer.

        let sig = op.signature.ok_or(Error::CrdtMissingOpSignature)?;
        let bytes_to_verify = utils::serialise(&op.crdt_op).map_err(|err| {
            Error::Serialisation(format!(
                "Could not serialise CRDT operation to verify signature: {}",
                err
            ))
        })?;
        op.source.verify(&sig, &bytes_to_verify)?;

        // Apply the CRDT operation to the LSeq data
        self.data.apply(op.crdt_op);

        Ok(())
    }

    /// Gets the entry at `index` if it exists.
    pub fn get(&self, index: Index) -> Option<Entry> {
        let i = to_absolute_index(index, self.len() as usize)?;
        let nodes = self.traverse_reg_rev(i);

        let entry = nodes.values().next().cloned();
        entry
    }

    /// Gets the last entry.
    pub fn last_entry(&self) -> Option<Entry> {
        // FIXME: if there are multiple branches, resolve which is the
        // preferred one
        let entry = self.data.read().values().next().cloned();
        entry
    }

    /// Gets the Policy of the object.
    pub fn policy(&self) -> &P {
        &self.policy
    }

    /// Gets a list of items which are within the given indices.
    /// Note the range of items is [start, end), i.e. the end index is not inclusive.
    pub fn in_range(&self, start: Index, end: Index) -> Option<Entries> {
        let count = self.len() as usize;
        let start_index = to_absolute_index(start, count)?;
        if start_index >= count {
            return None;
        }
        let end_index = to_absolute_index(end, count)?;
        let _items_to_take = end_index - start_index;

        /*
        let entries = self
            .data
            .iter()
            .skip(start_index)
            .take(items_to_take)
            .cloned()
            .collect::<Entries>();

        Some(entries)
        */

        //let (nodes, _) = self.traverse_reg(None);
        unimplemented!()
    }

    // Returns the depth of the found content after traversing up the branches.
    // If no 'stop_at' is provided it will return all entries that are the first
    // in the sequence which don't have any predecessor.
    // TODO: make this an iterator
    fn traverse_reg(&self, stop_at: Option<u64>) -> (Content<Entry>, u64) {
        let mut content = self.data.read();
        let mut depth = 0u64;
        let stop_at = stop_at.unwrap_or(u64::MAX);

        // FIXME: if there are multiple branches,
        // resolve which is the preferred one
        while let Some(hash) = content.hashes().iter().next() {
            content = self.data.parents(*hash);
            depth += 1;

            // stop at desired depth
            if depth == stop_at {
                break;
            }
        }

        (content, depth)
    }

    // Returns the content after traversing the branches in inverse order (from root nodes to leaves).
    // TODO: make this an iterator
    fn traverse_reg_rev(&self, _index: usize) -> Content<Entry> {
        unimplemented!();
        /*let mut content = self.data.read();

        // FIXME: if there are multiple branches,
        // resolve which is the preferred one
        while let Some(hash) = content.hashes().iter().next() {
            // stop at desired index
            if let Some(node) = self.data.node(*hash) {
                if node.height == index {
                    break;
                }
            }

            content = self.data.parents(*hash);
        }

        content*/
    }
}

// Private helpers

fn to_absolute_index(index: Index, count: usize) -> Option<usize> {
    match index {
        Index::FromStart(index) if (index as usize) <= count => Some(index as usize),
        Index::FromStart(_) => None,
        Index::FromEnd(index) => count.checked_sub(index as usize),
    }
}
