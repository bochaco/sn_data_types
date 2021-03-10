// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

//! SAFE network data types.

#![doc(
    html_logo_url = "https://raw.githubusercontent.com/maidsafe/QA/master/Images/maidsafe_logo.png",
    html_favicon_url = "https://maidsafe.net/img/favicon.ico",
    test(attr(forbid(warnings)))
)]
// For explanation of lint checks, run `rustc -W help`.
#![forbid(unsafe_code)]
#![warn(
    // TODO: add missing debug implementations for structs?
    // missing_debug_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unused_extern_crates,
    unused_import_braces,
    unused_qualifications,
    unused_results
)]

mod blob;
mod errors;
mod keys;
mod map;
mod register;
mod token;
mod transfer;
mod utils;

pub use blob::{
    Address as BlobAddress, Data as Blob, Kind as BlobKind, PrivateData as PrivateBlob,
    PublicData as PublicBlob, MAX_BLOB_SIZE_IN_BYTES,
};
pub use errors::{Error, Result};

pub use keys::{
    BlsKeypairShare, Keypair, NodeKeypairs, OwnerType, PublicKey, SecretKey, Signature,
    SignatureShare, Signing,
};
pub use map::{
    Action as MapAction, Address as MapAddress, Data as Map, Entries as MapEntries,
    EntryActions as MapEntryActions, Kind as MapKind, PermissionSet as MapPermissionSet,
    SeqData as SeqMap, SeqEntries as MapSeqEntries, SeqEntryAction as MapSeqEntryAction,
    SeqEntryActions as MapSeqEntryActions, SeqValue as MapSeqValue, UnseqData as UnseqMap,
    UnseqEntries as MapUnseqEntries, UnseqEntryAction as MapUnseqEntryAction,
    UnseqEntryActions as MapUnseqEntryActions, Value as MapValue, Values as MapValues,
};

pub use token::Token;

pub use register::{
    Action as RegisterAction, Address as RegisterAddress, Data as Register, DataOp as RegisterOp,
    Entries as RegisterEntries, Entry as RegisterEntry, Index as RegisterIndex,
    Kind as RegisterKind, NodeId as RegisterNodeId, Permissions as RegisterPermissions,
    Policy as RegisterPolicy, PrivatePermissions as RegisterPrivatePermissions,
    PrivatePolicy as RegisterPrivatePolicy, PrivateRegData,
    PublicPermissions as RegisterPublicPermissions, PublicPolicy as RegisterPublicPolicy,
    PublicRegData, User as RegisterUser,
};
pub use transfer::*;

use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use xor_name::XorName;

/// Object storing a data variant.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Data {
    /// Blob.
    Immutable(Blob),
    /// MutableData.
    Mutable(Map),
    /// Register.
    Register(Register),
}

impl Data {
    /// Returns true if public.
    pub fn is_public(&self) -> bool {
        match *self {
            Self::Immutable(ref idata) => idata.is_public(),
            Self::Mutable(_) => false,
            Self::Register(ref register) => register.is_public(),
        }
    }

    /// Returns true if private.
    pub fn is_private(&self) -> bool {
        !self.is_public()
    }
}

impl From<Blob> for Data {
    fn from(data: Blob) -> Self {
        Self::Immutable(data)
    }
}

impl From<Map> for Data {
    fn from(data: Map) -> Self {
        Self::Mutable(data)
    }
}

impl From<Register> for Data {
    fn from(data: Register) -> Self {
        Self::Register(data)
    }
}
