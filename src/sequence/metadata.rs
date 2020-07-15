// Copyright 2020 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::{utils, Error, PublicKey, Result, XorName};
use multibase::Decodable;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fmt::Debug, hash::Hash};

/// An action on Sequence data type.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Action {
    /// Read from the data.
    Read,
    /// Append to the data.
    Append,
    /// Manage permissions.
    Admin,
}

/// List of entries.
pub type Entries = Vec<Entry>;

/// An entry in a Sequence.
pub type Entry = Vec<u8>;

/// Address of a Sequence.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Address {
    /// Public sequence namespace.
    Public {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
    /// Private sequence namespace.
    Private {
        /// Name.
        name: XorName,
        /// Tag.
        tag: u64,
    },
}

impl Address {
    /// Constructs a new `Address` given `kind`, `name`, and `tag`.
    pub fn from_kind(kind: Kind, name: XorName, tag: u64) -> Self {
        match kind {
            Kind::Public => Address::Public { name, tag },
            Kind::Private => Address::Private { name, tag },
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        match self {
            Address::Public { .. } => Kind::Public,
            Address::Private { .. } => Kind::Private,
        }
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        match self {
            Address::Public { ref name, .. } | Address::Private { ref name, .. } => name,
        }
    }

    /// Returns the tag.
    pub fn tag(&self) -> u64 {
        match self {
            Address::Public { tag, .. } | Address::Private { tag, .. } => *tag,
        }
    }

    /// Returns true if public.
    pub fn is_pub(&self) -> bool {
        self.kind().is_pub()
    }

    /// Returns true if private.
    pub fn is_priv(&self) -> bool {
        self.kind().is_priv()
    }

    /// Returns the `Address` serialised and encoded in z-base-32.
    pub fn encode_to_zbase32(&self) -> String {
        utils::encode(&self)
    }

    /// Creates from z-base-32 encoded string.
    pub fn decode_from_zbase32<I: Decodable>(encoded: I) -> Result<Self> {
        utils::decode(encoded)
    }
}

/// Kind of a Sequence.
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub enum Kind {
    /// Public sequence.
    Public,
    /// Private sequence.
    Private,
}

impl Kind {
    /// Returns true if public.
    pub fn is_pub(self) -> bool {
        self == Kind::Public
    }

    /// Returns true if private.
    pub fn is_priv(self) -> bool {
        !self.is_pub()
    }
}

/// Index of some data.
#[derive(Copy, Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Index {
    /// Absolute index.
    FromStart(u64),
    /// Relative index - start counting from the end.
    FromEnd(u64),
}

impl From<u64> for Index {
    fn from(index: u64) -> Self {
        Index::FromStart(index)
    }
}

/// An owner could represent an individual user, or a group of users,
/// depending on the `public_key` type.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub struct Owner {
    /// Public key.
    pub public_key: PublicKey,
    /// The current index of the data when this ownership change happened
    pub entries_index: u64,
    /// The current index of the policy history when this ownership change happened
    pub policy_index: u64,
}

/// Set of public permissions for a user.
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PubPermissions {
    /// `Some(true)` if the user can append.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has permissions).
    /// Use permissions for `Anyone` if `None`.
    append: Option<bool>,
    /// `Some(true)` if the user can manage permissions.
    /// `Some(false)` explicitly denies this permission (even if `Anyone` has permissions).
    /// Use permissions for `Anyone` if `None`.
    admin: Option<bool>,
}

impl PubPermissions {
    /// Constructs a new public permission set.
    pub fn new(append: impl Into<Option<bool>>, manage_perms: impl Into<Option<bool>>) -> Self {
        Self {
            append: append.into(),
            admin: manage_perms.into(),
        }
    }

    /// Sets permissions.
    pub fn set_perms(&mut self, append: impl Into<Option<bool>>, admin: impl Into<Option<bool>>) {
        self.append = append.into();
        self.admin = admin.into();
    }

    /// Returns `Some(true)` if `action` is allowed and `Some(false)` if it's not permitted.
    /// `None` means that default permissions should be applied.
    pub fn is_allowed(self, action: Action) -> Option<bool> {
        match action {
            Action::Read => Some(true), // It's public data, so it's always allowed to read it.
            Action::Append => self.append,
            Action::Admin => self.admin,
        }
    }
}

/// Set of private permissions for a user.
#[derive(Copy, Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivPermissions {
    /// `true` if the user can read.
    read: bool,
    /// `true` if the user can append.
    append: bool,
    /// `true` if the user can manage permissions.
    admin: bool,
}

impl PrivPermissions {
    /// Constructs a new private permission set.
    pub fn new(read: bool, append: bool, manage_perms: bool) -> Self {
        Self {
            read,
            append,
            admin: manage_perms,
        }
    }

    /// Sets permissions.
    pub fn set_perms(&mut self, read: bool, append: bool, manage_perms: bool) {
        self.read = read;
        self.append = append;
        self.admin = manage_perms;
    }

    /// Returns `true` if `action` is allowed.
    pub fn is_allowed(self, action: Action) -> bool {
        match action {
            Action::Read => self.read,
            Action::Append => self.append,
            Action::Admin => self.admin,
        }
    }
}

/// User that can access Sequence.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Debug)]
pub enum User {
    /// Any user.
    Anyone,
    /// User identified by its public key.
    Key(PublicKey),
}

/// Published permissions.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PubPolicy {
    /// Map of users to their public permission set.
    pub permissions: BTreeMap<User, PubPermissions>,
    /// The current index of the data when this policy change happened.
    pub entries_index: u64,
    /// The current index of the owners history when this policy change happened.
    pub owners_index: u64,
}

impl PubPolicy {
    /// Returns `Some(true)` if `action` is allowed for the provided user and `Some(false)` if it's
    /// not permitted. `None` means that default permissions should be applied.
    fn is_action_allowed_by_user(&self, user: &User, action: Action) -> Option<bool> {
        self.permissions
            .get(user)
            .and_then(|perms| perms.is_allowed(action))
    }
}

/// Private permissions.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub struct PrivPolicy {
    /// Map of users to their private permission set.
    pub permissions: BTreeMap<PublicKey, PrivPermissions>,
    /// The current index of the data when this policy change happened.
    pub entries_index: u64,
    /// The current index of the owners history when this policy change happened.
    pub owners_index: u64,
}

pub trait Perm {
    /// Returns true if `action` is allowed for the provided user.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()>;
    /// Gets the permissions for a user if applicable.
    fn permissions(&self, user: User) -> Option<Permissions>;
    /// Gets the last entry index.
    fn entries_index(&self) -> u64;
    /// Gets the last owner index.
    fn owners_index(&self) -> u64;
}

impl Perm for PubPolicy {
    /// Returns `Ok(())` if `action` is allowed for the provided user and `Err(AccessDenied)` if
    /// this action is not permitted.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self
            .is_action_allowed_by_user(&User::Key(requester), action)
            .or_else(|| self.is_action_allowed_by_user(&User::Anyone, action))
        {
            Some(true) => Ok(()),
            Some(false) => Err(Error::AccessDenied),
            None => Err(Error::AccessDenied),
        }
    }

    /// Gets the permissions for a user if applicable.
    fn permissions(&self, user: User) -> Option<Permissions> {
        self.permissions.get(&user).map(|p| Permissions::Pub(*p))
    }

    /// Returns the last entry index.
    fn entries_index(&self) -> u64 {
        self.entries_index
    }

    /// Returns the last owners index.
    fn owners_index(&self) -> u64 {
        self.owners_index
    }
}

impl Perm for PrivPolicy {
    /// Returns `Ok(())` if `action` is allowed for the provided user and `Err(AccessDenied)` if
    /// this action is not permitted.
    fn is_action_allowed(&self, requester: PublicKey, action: Action) -> Result<()> {
        match self.permissions.get(&requester) {
            Some(perms) => {
                if perms.is_allowed(action) {
                    Ok(())
                } else {
                    Err(Error::AccessDenied)
                }
            }
            None => Err(Error::AccessDenied),
        }
    }

    /// Gets the permissions for a user if applicable.
    fn permissions(&self, user: User) -> Option<Permissions> {
        match user {
            User::Anyone => None,
            User::Key(key) => self.permissions.get(&key).map(|p| Permissions::Priv(*p)),
        }
    }

    /// Returns the last entry index.
    fn entries_index(&self) -> u64 {
        self.entries_index
    }

    /// Returns the last owners index.
    fn owners_index(&self) -> u64 {
        self.owners_index
    }
}

/// Wrapper type for permissions, which can be public or private.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum Policy {
    /// Public permissions.
    Pub(PubPolicy),
    /// Private permissions.
    Priv(PrivPolicy),
}

impl From<PrivPolicy> for Policy {
    fn from(policy: PrivPolicy) -> Self {
        Policy::Priv(policy)
    }
}

impl From<PubPolicy> for Policy {
    fn from(policy: PubPolicy) -> Self {
        Policy::Pub(policy)
    }
}

/// Wrapper type for permissions set, which can be public or private.
#[derive(Clone, Serialize, Deserialize, PartialEq, PartialOrd, Ord, Eq, Hash, Debug)]
pub enum Permissions {
    /// Public permissions set.
    Pub(PubPermissions),
    /// Private permissions set.
    Priv(PrivPermissions),
}

impl From<PrivPermissions> for Permissions {
    fn from(permission_set: PrivPermissions) -> Self {
        Permissions::Priv(permission_set)
    }
}

impl From<PubPermissions> for Permissions {
    fn from(permission_set: PubPermissions) -> Self {
        Permissions::Pub(permission_set)
    }
}
