// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

mod metadata;
mod reg_crdt;

use crate::{Error, PublicKey, Result};
pub use metadata::{
    Action, Address, Entries, Entry, Index, Kind, Perm, Permissions, Policy, PrivatePermissions,
    PrivatePolicy, PublicPermissions, PublicPolicy, User,
};
use reg_crdt::{CrdtOperation, NodeId, RegisterCrdt};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::{
    fmt::{self, Debug, Formatter},
    hash::Hash,
};
use xor_name::XorName;

/// Data mutation operation to apply to Register.
pub type DataOp<T> = CrdtOperation<T>;

/// Public Register.
pub type PublicRegData = RegisterCrdt<PublicPolicy>;
/// Private Register.
pub type PrivateRegData = RegisterCrdt<PrivatePolicy>;

impl Debug for PublicRegData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PubRegister {:?}", self.address().name())
    }
}

impl Debug for PrivateRegData {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        write!(formatter, "PrivRegister {:?}", self.address().name())
    }
}

/// Object storing a Register variant.
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
enum RegData {
    /// Public Register Data.
    Public(PublicRegData),
    /// Private Register Data.
    Private(PrivateRegData),
}

/// Object storing the Register
#[derive(Clone, Eq, PartialEq, PartialOrd, Hash, Serialize, Deserialize, Debug)]
pub struct Data {
    authority: PublicKey,
    data: RegData,
}

impl Data {
    /// Constructs a new Public Register Data.
    /// The 'authority' is assumed to be the PK which the messages were and will be
    /// signed with.
    /// If a policy is not provided, a default policy will be set where
    /// the 'authority' is the owner along with an empty users permissions set.
    pub fn new_public(
        authority: PublicKey,
        name: XorName,
        tag: u64,
        policy: Option<PublicPolicy>,
    ) -> Self {
        let policy = policy.unwrap_or(PublicPolicy {
            owner: authority,
            permissions: BTreeMap::new(),
        });

        Self {
            authority,
            data: RegData::Public(PublicRegData::new(Address::Public { name, tag }, policy)),
        }
    }

    /// Constructs a new Private Register Data.
    /// The 'authority' is assumed to be the PK which the messages were and will be
    /// signed with.
    /// If a policy is not provided, a default policy will be set where
    /// the 'authority' is the owner along with an empty users permissions set.
    pub fn new_private(
        authority: PublicKey,
        name: XorName,
        tag: u64,
        policy: Option<PrivatePolicy>,
    ) -> Self {
        let policy = policy.unwrap_or(PrivatePolicy {
            owner: authority,
            permissions: BTreeMap::new(),
        });

        Self {
            authority,
            data: RegData::Private(PrivateRegData::new(Address::Private { name, tag }, policy)),
        }
    }

    /// Returns the address.
    pub fn address(&self) -> &Address {
        match &self.data {
            RegData::Public(data) => data.address(),
            RegData::Private(data) => data.address(),
        }
    }

    /// Returns the kind.
    pub fn kind(&self) -> Kind {
        self.address().kind()
    }

    /// Returns the name.
    pub fn name(&self) -> &XorName {
        self.address().name()
    }

    /// Returns the tag.
    pub fn tag(&self) -> u64 {
        self.address().tag()
    }

    /// Returns `true` if public.
    pub fn is_public(&self) -> bool {
        self.kind().is_public()
    }

    /// Returns `true` if private.
    pub fn is_private(&self) -> bool {
        self.kind().is_private()
    }

    /// Returns the length of the register, optionally
    /// verifying read permissions if a pk is provided
    pub fn len(&self, requester: Option<PublicKey>) -> Result<u64> {
        self.check_permission(Action::Read, requester)?;

        Ok(match &self.data {
            RegData::Public(data) => data.len(),
            RegData::Private(data) => data.len(),
        })
    }

    /// Returns true if the register is empty.
    pub fn is_empty(&self, requester: Option<PublicKey>) -> Result<bool> {
        self.check_permission(Action::Read, requester)?;

        Ok(self.len(None)? == 0)
    }

    /// Gets a list of items which are within the given indices.
    /// Note the range of items is [start, end), i.e. the end index is not inclusive.
    pub fn in_range(
        &self,
        start: Index,
        end: Index,
        requester: Option<PublicKey>,
    ) -> Result<Option<Entries>> {
        self.check_permission(Action::Read, requester)?;

        let entries = match &self.data {
            RegData::Public(data) => data.in_range(start, end),
            RegData::Private(data) => data.in_range(start, end),
        };

        Ok(entries)
    }

    /// Returns a value at 'index', if present.
    pub fn get(&self, index: Index, requester: Option<PublicKey>) -> Result<Option<Entry>> {
        self.check_permission(Action::Read, requester)?;

        Ok(match &self.data {
            RegData::Public(data) => data.get(index),
            RegData::Private(data) => data.get(index),
        })
    }

    /// Returns the last entry, if it's not empty.
    pub fn last_entry(&self, requester: Option<PublicKey>) -> Result<Option<Entry>> {
        self.check_permission(Action::Read, requester)?;

        Ok(match &self.data {
            RegData::Public(data) => data.last_entry(),
            RegData::Private(data) => data.last_entry(),
        })
    }

    /// Generate unsigned crdt op, adding the new entry.
    pub fn create_unsigned_append_op(
        &mut self,
        entry: Entry,
        parents: BTreeSet<NodeId>,
    ) -> Result<DataOp<Entry>> {
        self.check_permission(Action::Append, None)?;

        match &mut self.data {
            RegData::Public(data) => data.create_append_op(entry, parents, self.authority),
            RegData::Private(data) => data.create_append_op(entry, parents, self.authority),
        }
    }

    /// Apply a signed data CRDT operation.
    pub fn apply_op(&mut self, op: DataOp<Entry>) -> Result<()> {
        self.check_permission(Action::Append, Some(op.source))?;

        match &mut self.data {
            RegData::Public(data) => data.apply_op(op),
            RegData::Private(data) => data.apply_op(op),
        }
    }

    /// Returns user permissions, if applicable.
    pub fn permissions(&self, user: User, requester: Option<PublicKey>) -> Result<Permissions> {
        self.check_permission(Action::Read, requester)?;

        let user_perm = match &self.data {
            RegData::Public(data) => data.policy().permissions(user).ok_or(Error::NoSuchEntry)?,
            RegData::Private(data) => data.policy().permissions(user).ok_or(Error::NoSuchEntry)?,
        };

        Ok(user_perm)
    }

    /// Returns the public policy, if applicable.
    pub fn public_policy(&self) -> Result<&PublicPolicy> {
        match &self.data {
            RegData::Public(data) => Ok(data.policy()),
            RegData::Private(_) => Err(Error::InvalidOperation),
        }
    }

    /// Returns the private policy, if applicable.
    pub fn private_policy(&self, requester: Option<PublicKey>) -> Result<&PrivatePolicy> {
        self.check_permission(Action::Read, requester)?;
        match &self.data {
            RegData::Private(data) => Ok(data.policy()),
            RegData::Public(_) => Err(Error::InvalidOperation),
        }
    }

    /// Helper to check permissions for given `action`
    /// for the given requester's public key.
    ///
    /// Returns:
    /// `Ok(())` if the permissions are valid,
    /// `Err::AccessDenied` if the action is not allowed.
    pub fn check_permission(&self, action: Action, requester: Option<PublicKey>) -> Result<()> {
        let requester = requester.unwrap_or(self.authority);
        match &self.data {
            RegData::Public(data) => data.policy().is_action_allowed(requester, action),
            RegData::Private(data) => data.policy().is_action_allowed(requester, action),
        }
    }

    /// Returns the owner of the data.
    pub fn owner(&self) -> PublicKey {
        match &self.data {
            RegData::Public(data) => data.policy().owner,
            RegData::Private(data) => data.policy().owner,
        }
    }

    /// Returns the PK which the messages are expected to be signed with by this replica.
    pub fn replica_authority(&self) -> PublicKey {
        self.authority
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        utils, Error, Keypair, Register, RegisterAddress, RegisterEntry, RegisterIndex,
        RegisterKind, RegisterOp, RegisterPermissions, RegisterPrivatePermissions,
        RegisterPrivatePolicy, RegisterPublicPermissions, RegisterPublicPolicy, RegisterUser,
        Result,
    };
    use anyhow::anyhow;
    use proptest::prelude::*;
    use rand::{rngs::OsRng, seq::SliceRandom};
    use std::{
        collections::{BTreeMap, BTreeSet},
        sync::Arc,
    };
    use xor_name::XorName;

    #[test]
    fn register_create_public() {
        let register_name = XorName::random();
        let register_tag = 43_000;
        let (_, register) = &gen_pub_reg_replicas(None, register_name, register_tag, None, 1)[0];

        assert_eq!(register.kind(), RegisterKind::Public);
        assert_eq!(*register.name(), register_name);
        assert_eq!(register.tag(), register_tag);
        assert!(register.is_public());
        assert!(!register.is_private());

        let register_address =
            RegisterAddress::from_kind(RegisterKind::Public, register_name, register_tag);
        assert_eq!(*register.address(), register_address);
    }

    #[test]
    fn register_create_private() {
        let register_name = XorName::random();
        let register_tag = 43_000;
        let (_, register) = &gen_priv_reg_replicas(None, register_name, register_tag, None, 1)[0];

        assert_eq!(register.kind(), RegisterKind::Private);
        assert_eq!(*register.name(), register_name);
        assert_eq!(register.tag(), register_tag);
        assert!(!register.is_public());
        assert!(register.is_private());

        let register_address =
            RegisterAddress::from_kind(RegisterKind::Private, register_name, register_tag);
        assert_eq!(*register.address(), register_address);
    }

    #[test]
    fn register_concurrent_append_ops() -> Result<()> {
        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let authority1 = authority_keypair1.public_key();
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();
        let register_name: XorName = rand::random();
        let register_tag = 43_000u64;

        // We'll have 'authority1' as the owner in both replicas and
        // grant permissions for Append to 'authority2' in both replicas
        let mut perms = BTreeMap::default();
        let user_perms = RegisterPublicPermissions::new(true);
        let _ = perms.insert(RegisterUser::Key(authority2), user_perms);

        // Instantiate the same Register on two replicas with the two diff authorities
        let mut replica1 = Register::new_public(
            authority1,
            register_name,
            register_tag,
            Some(RegisterPublicPolicy {
                owner: authority1,
                permissions: perms.clone(),
            }),
        );
        let mut replica2 = Register::new_public(
            authority2,
            register_name,
            register_tag,
            Some(RegisterPublicPolicy {
                owner: authority1,
                permissions: perms,
            }),
        );

        // And let's append an item to replica1 with autority1
        let item1 = b"item1";
        let append_op1 = sign_register_op(
            replica1.create_unsigned_append_op(item1.to_vec(), BTreeSet::new())?,
            &authority_keypair1,
        )?;
        replica1.apply_op(append_op1.clone())?;

        // Let's assert current state on both replicas
        assert_eq!(replica1.len(None)?, 1);
        assert_eq!(replica2.len(None)?, 0);

        // Concurrently append anoother item with authority2 on replica2
        let item2 = b"item2";
        let append_op2 = sign_register_op(
            replica2.create_unsigned_append_op(item2.to_vec(), BTreeSet::new())?,
            &authority_keypair2,
        )?;
        replica2.apply_op(append_op2.clone())?;

        // Item should be appended on replica2
        assert_eq!(replica2.len(None)?, 1);

        // Append operations are now broadcasted and applied to both replicas
        replica1.apply_op(append_op2)?;
        replica2.apply_op(append_op1)?;

        // Let's assert data convergence on both replicas
        verify_data_convergence(vec![replica1, replica2], 1)?;

        Ok(())
    }

    #[test]
    fn register_get_by_index() -> anyhow::Result<()> {
        let mut replicas = create_public_reg_replicas(1);
        let (authority_keypair, register) = &mut replicas[0];

        let entry1 = b"value0".to_vec();
        let entry2 = b"value1".to_vec();
        let entry3 = b"value2".to_vec();

        let op1 = sign_register_op(
            register.create_unsigned_append_op(entry1.clone(), BTreeSet::new())?,
            &authority_keypair,
        )?;
        register.apply_op(op1.clone())?;

        let op2 = sign_register_op(
            register.create_unsigned_append_op(entry2.clone(), BTreeSet::new())?,
            &authority_keypair,
        )?;
        register.apply_op(op2.clone())?;

        let parents = vec![op1.crdt_op.hash(), op2.crdt_op.hash()]
            .iter()
            .map(|hash| hash.clone())
            .collect();

        let op3 = sign_register_op(
            register.create_unsigned_append_op(entry3.clone(), parents)?,
            &authority_keypair,
        )?;
        register.apply_op(op3)?;

        assert_eq!(register.len(None)?, 2);

        let index_0 = RegisterIndex::FromStart(0);
        let first_entry = register.get(index_0, None)?;
        assert_eq!(first_entry, Some(entry1));

        let index_1 = RegisterIndex::FromStart(1);
        let second_entry = register.get(index_1, None)?;
        assert_eq!(second_entry, Some(entry3.clone()));
        /*
                let end_index = RegisterIndex::FromEnd(0);
                let second_entry = register.get(end_index, None)?;
                assert_eq!(second_entry, Some(entry3));
        */
        let index_beyond_end = RegisterIndex::FromStart(2);
        let not_found_entry = register.get(index_beyond_end, None)?;
        assert_eq!(not_found_entry, None);

        Ok(())
    }

    #[test]
    fn register_get_in_range() -> anyhow::Result<()> {
        let mut replicas = create_public_reg_replicas(1);
        let (authority_keypair, register) = &mut replicas[0];

        let entry1 = b"value0".to_vec();
        let entry2 = b"value1".to_vec();
        let entry3 = b"value2".to_vec();

        let op1 = sign_register_op(
            register.create_unsigned_append_op(entry1.clone(), BTreeSet::new())?,
            &authority_keypair,
        )?;
        register.apply_op(op1)?;

        let op2 = sign_register_op(
            register.create_unsigned_append_op(entry2.clone(), BTreeSet::new())?,
            &authority_keypair,
        )?;
        register.apply_op(op2)?;

        let op3 = sign_register_op(
            register.create_unsigned_append_op(entry3.clone(), BTreeSet::new())?,
            &authority_keypair,
        )?;
        register.apply_op(op3)?;

        assert_eq!(register.len(None)?, 3);

        let index_0 = RegisterIndex::FromStart(0);
        let index_1 = RegisterIndex::FromStart(1);
        let index_2 = RegisterIndex::FromStart(2);
        let end_index = RegisterIndex::FromEnd(0);

        let first_entry = register.in_range(index_0, index_1, None)?;
        assert_eq!(first_entry, Some(vec![entry1.clone()]));

        let all_entries = register.in_range(index_0, end_index, None)?;
        assert_eq!(
            all_entries,
            Some(vec![entry1, entry2.clone(), entry3.clone()])
        );

        let last_entry = register.in_range(index_2, end_index, None)?;
        assert_eq!(last_entry, Some(vec![entry3]));

        let second_entry = register.in_range(index_1, RegisterIndex::FromEnd(1), None)?;
        assert_eq!(second_entry, Some(vec![entry2]));

        let index_3 = RegisterIndex::FromStart(3);
        match register.in_range(index_3, index_3, None) {
            Ok(None) => Ok(()),
            Ok(Some(entries)) => Err(anyhow!(
                "Unexpectedly fetched entries from Register: {:?}",
                entries
            )),
            Err(err) => Err(anyhow!(
                "Unexpected error thrown when trying to fetch from Register with out of bound start index: {:?}",
                err
            )),
        }
    }

    #[test]
    fn register_query_public_policy() -> anyhow::Result<()> {
        // one replica will allow append ops to anyone
        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let owner1 = authority_keypair1.public_key();
        let mut perms1 = BTreeMap::default();
        let _ = perms1.insert(RegisterUser::Anyone, RegisterPublicPermissions::new(true));
        let replica1 = create_public_reg_replica_with(
            Some(authority_keypair1),
            Some(RegisterPublicPolicy {
                owner: owner1,
                permissions: perms1.clone(),
            }),
        );

        // the other replica will allow append ops to 'owner1' and 'authority2' only
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();
        let mut perms2 = BTreeMap::default();
        let _ = perms2.insert(
            RegisterUser::Key(owner1),
            RegisterPublicPermissions::new(true),
        );
        let replica2 = create_public_reg_replica_with(
            Some(authority_keypair2),
            Some(RegisterPublicPolicy {
                owner: authority2,
                permissions: perms2.clone(),
            }),
        );

        assert_eq!(replica1.owner(), owner1);
        assert_eq!(replica1.replica_authority(), owner1);
        assert_eq!(replica1.public_policy()?.permissions, perms1);
        assert_eq!(
            RegisterPermissions::Public(RegisterPublicPermissions::new(true)),
            replica1.permissions(RegisterUser::Anyone, None)?
        );

        assert_eq!(replica2.owner(), authority2);
        assert_eq!(replica2.replica_authority(), authority2);
        assert_eq!(replica2.public_policy()?.permissions, perms2);
        assert_eq!(
            RegisterPermissions::Public(RegisterPublicPermissions::new(true)),
            replica2.permissions(RegisterUser::Key(owner1), None)?
        );

        Ok(())
    }

    #[test]
    fn register_query_private_policy() -> anyhow::Result<()> {
        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let authority1 = authority_keypair1.public_key();
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();

        let mut perms1 = BTreeMap::default();
        let user_perms1 =
            RegisterPrivatePermissions::new(/*read*/ true, /*append*/ false);
        let _ = perms1.insert(authority1, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 = RegisterPrivatePermissions::new(/*read*/ true, /*append*/ true);
        let _ = perms2.insert(authority2, user_perms2);
        let user_perms2 =
            RegisterPrivatePermissions::new(/*read*/ false, /*append*/ true);
        let _ = perms2.insert(authority1, user_perms2);

        let replica1 = create_private_reg_replica_with(
            Some(authority_keypair1),
            Some(RegisterPrivatePolicy {
                owner: authority1,
                permissions: perms1.clone(),
            }),
        );

        let replica2 = create_private_reg_replica_with(
            Some(authority_keypair2),
            Some(RegisterPrivatePolicy {
                owner: authority2,
                permissions: perms2.clone(),
            }),
        );

        assert_eq!(replica1.owner(), authority1);
        assert_eq!(replica1.replica_authority(), authority1);
        assert_eq!(
            replica1.private_policy(Some(authority1))?.permissions,
            perms1
        );
        assert_eq!(
            RegisterPermissions::Private(RegisterPrivatePermissions::new(true, false)),
            replica1.permissions(RegisterUser::Key(authority1), None)?
        );

        assert_eq!(replica2.owner(), authority2);
        assert_eq!(replica2.replica_authority(), authority2);
        assert_eq!(
            replica2.private_policy(Some(authority2))?.permissions,
            perms2
        );
        assert_eq!(
            RegisterPermissions::Private(RegisterPrivatePermissions::new(true, true)),
            replica2.permissions(RegisterUser::Key(authority2), None)?
        );
        assert_eq!(
            RegisterPermissions::Private(RegisterPrivatePermissions::new(false, true)),
            replica2.permissions(RegisterUser::Key(authority1), None)?
        );

        Ok(())
    }

    #[test]
    fn register_public_append_fails_when_no_perms_for_authority() -> anyhow::Result<()> {
        // one replica will allow append ops to anyone
        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let owner1 = authority_keypair1.public_key();
        let mut perms1 = BTreeMap::default();
        let _ = perms1.insert(RegisterUser::Anyone, RegisterPublicPermissions::new(true));
        let mut replica1 = create_public_reg_replica_with(
            Some(authority_keypair1.clone()),
            Some(RegisterPublicPolicy {
                owner: owner1,
                permissions: perms1,
            }),
        );

        // the other replica will *not* allow append ops to 'owner1'
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();
        let mut perms2 = BTreeMap::default();
        let _ = perms2.insert(
            RegisterUser::Key(owner1),
            RegisterPublicPermissions::new(false),
        );
        let mut replica2 = create_public_reg_replica_with(
            Some(authority_keypair2.clone()),
            Some(RegisterPublicPolicy {
                owner: authority2,
                permissions: perms2,
            }),
        );

        // let's append to both replicas with one first item
        let item1 = b"item1";
        let item2 = b"item2";
        let append_op1 = sign_register_op(
            replica1.create_unsigned_append_op(item1.to_vec(), BTreeSet::new())?,
            &authority_keypair1,
        )?;
        replica1.apply_op(append_op1.clone())?;
        check_op_not_allowed_failure(replica2.apply_op(append_op1))?;

        let append_op2 = sign_register_op(
            replica2.create_unsigned_append_op(item2.to_vec(), BTreeSet::new())?,
            &authority_keypair2,
        )?;
        replica1.apply_op(append_op2.clone())?;
        replica2.apply_op(append_op2)?;

        assert_eq!(replica1.len(None)?, 2);
        assert_eq!(replica2.len(None)?, 1);

        Ok(())
    }

    #[test]
    fn register_private_append_fails_when_no_perms_for_authority() -> anyhow::Result<()> {
        let authority_keypair1 = Keypair::new_ed25519(&mut OsRng);
        let authority1 = authority_keypair1.public_key();
        let authority_keypair2 = Keypair::new_ed25519(&mut OsRng);
        let authority2 = authority_keypair2.public_key();

        let mut perms1 = BTreeMap::default();
        let user_perms1 =
            RegisterPrivatePermissions::new(/*read*/ false, /*append*/ true);
        let _ = perms1.insert(authority2, user_perms1);

        let mut perms2 = BTreeMap::default();
        let user_perms2 =
            RegisterPrivatePermissions::new(/*read*/ true, /*append*/ false);
        let _ = perms2.insert(authority1, user_perms2);

        let mut replica1 = create_private_reg_replica_with(
            Some(authority_keypair1.clone()),
            Some(RegisterPrivatePolicy {
                owner: authority1,
                permissions: perms1,
            }),
        );

        let mut replica2 = create_private_reg_replica_with(
            Some(authority_keypair2.clone()),
            Some(RegisterPrivatePolicy {
                owner: authority2,
                permissions: perms2,
            }),
        );

        // let's try to append to both registers
        let item1 = b"item1";
        let item2 = b"item2";
        let append_op1 = sign_register_op(
            replica1.create_unsigned_append_op(item1.to_vec(), BTreeSet::new())?,
            &authority_keypair1,
        )?;
        replica1.apply_op(append_op1.clone())?;
        check_op_not_allowed_failure(replica2.apply_op(append_op1))?;

        let append_op2 = sign_register_op(
            replica2.create_unsigned_append_op(item2.to_vec(), BTreeSet::new())?,
            &authority_keypair2,
        )?;
        replica1.apply_op(append_op2.clone())?;
        replica2.apply_op(append_op2)?;

        assert_eq!(replica1.len(None)?, 2);
        assert_eq!(replica2.len(None)?, 1);

        // Let's do some read permissions check now...

        // let's check authority1 can read from replica1 and replica2
        let data = replica1.get(RegisterIndex::FromStart(0), Some(authority1))?;
        let last_entry = replica1.last_entry(Some(authority1))?;
        let from_range = replica1.in_range(
            RegisterIndex::FromStart(0),
            RegisterIndex::FromStart(1),
            Some(authority1),
        )?;
        // since op2 is concurrent to op1, we don't know exactly
        // the order of items appended by op1 and op2 in replica1,
        // thus we assert for either case which are both valid
        if data == Some(item1.to_vec()) {
            assert_eq!(last_entry, Some(item2.to_vec()));
            assert_eq!(from_range, Some(vec![item1.to_vec()]));
        } else {
            assert_eq!(data, Some(item2.to_vec()));
            assert_eq!(last_entry, Some(item1.to_vec()));
            assert_eq!(from_range, Some(vec![item2.to_vec()]));
        }

        let data = replica2.get(RegisterIndex::FromStart(0), Some(authority1))?;
        let last_entry = replica2.last_entry(Some(authority1))?;
        let from_range = replica2.in_range(
            RegisterIndex::FromStart(0),
            RegisterIndex::FromStart(1),
            Some(authority1),
        )?;
        assert_eq!(data, Some(item2.to_vec()));
        assert_eq!(last_entry, Some(item2.to_vec()));
        assert_eq!(from_range, Some(vec![item2.to_vec()]));

        // authority2 cannot read from replica1
        check_op_not_allowed_failure(replica1.get(RegisterIndex::FromStart(0), Some(authority2)))?;
        check_op_not_allowed_failure(replica1.last_entry(Some(authority2)))?;
        check_op_not_allowed_failure(replica1.in_range(
            RegisterIndex::FromStart(0),
            RegisterIndex::FromStart(1),
            Some(authority2),
        ))?;

        // but authority2 can read from replica2
        let data = replica2.get(RegisterIndex::FromStart(0), Some(authority2))?;
        let last_entry = replica2.last_entry(Some(authority2))?;
        let from_range = replica2.in_range(
            RegisterIndex::FromStart(0),
            RegisterIndex::FromStart(1),
            Some(authority2),
        )?;
        assert_eq!(data, Some(item2.to_vec()));
        assert_eq!(last_entry, Some(item2.to_vec()));
        assert_eq!(from_range, Some(vec![item2.to_vec()]));

        Ok(())
    }

    // Helpers for tests

    fn sign_register_op(
        mut op: RegisterOp<RegisterEntry>,
        keypair: &Keypair,
    ) -> Result<RegisterOp<RegisterEntry>> {
        let bytes = utils::serialise(&op.crdt_op)?;
        let signature = keypair.sign(&bytes);
        op.signature = Some(signature);
        Ok(op)
    }

    fn gen_pub_reg_replicas(
        authority_keypair: Option<Keypair>,
        name: XorName,
        tag: u64,
        policy: Option<RegisterPublicPolicy>,
        count: usize,
    ) -> Vec<(Keypair, Register)> {
        let replicas: Vec<(Keypair, Register)> = (0..count)
            .map(|_| {
                let authority_keypair = authority_keypair
                    .clone()
                    .unwrap_or_else(|| Keypair::new_ed25519(&mut OsRng));
                let authority = authority_keypair.public_key();
                let register = Register::new_public(authority, name, tag, policy.clone());
                (authority_keypair, register)
            })
            .collect();

        assert_eq!(replicas.len(), count);
        replicas
    }

    fn gen_priv_reg_replicas(
        authority_keypair: Option<Keypair>,
        name: XorName,
        tag: u64,
        policy: Option<RegisterPrivatePolicy>,
        count: usize,
    ) -> Vec<(Keypair, Register)> {
        let replicas: Vec<(Keypair, Register)> = (0..count)
            .map(|_| {
                let authority_keypair = authority_keypair
                    .clone()
                    .unwrap_or_else(|| Keypair::new_ed25519(&mut OsRng));
                let authority = authority_keypair.public_key();
                let register = Register::new_private(authority, name, tag, policy.clone());
                (authority_keypair, register)
            })
            .collect();

        assert_eq!(replicas.len(), count);
        replicas
    }

    fn create_public_reg_replicas(count: usize) -> Vec<(Keypair, Register)> {
        let register_name = XorName::random();
        let register_tag = 43_000;

        gen_pub_reg_replicas(None, register_name, register_tag, None, count)
    }

    fn create_public_reg_replica_with(
        authority_keypair: Option<Keypair>,
        policy: Option<RegisterPublicPolicy>,
    ) -> Register {
        let register_name = XorName::random();
        let register_tag = 43_000;
        let replicas =
            gen_pub_reg_replicas(authority_keypair, register_name, register_tag, policy, 1);
        replicas[0].1.clone()
    }

    fn create_private_reg_replica_with(
        authority_keypair: Option<Keypair>,
        policy: Option<RegisterPrivatePolicy>,
    ) -> Register {
        let register_name = XorName::random();
        let register_tag = 43_000;
        let replicas =
            gen_priv_reg_replicas(authority_keypair, register_name, register_tag, policy, 1);
        replicas[0].1.clone()
    }

    // check it fails due to not having permissions
    fn check_op_not_allowed_failure<T>(result: Result<T>) -> anyhow::Result<()> {
        match result {
            Err(Error::AccessDenied(_)) => Ok(()),
            Err(err) => Err(anyhow!(
                "Error returned was the unexpected one for a non-allowed op: {}",
                err
            )),
            Ok(_) => Err(anyhow!(
                "Data operation succeded unexpectedly, an AccessDenied error was expected"
                    .to_string(),
            )),
        }
    }

    // verify data convergence on a set of replicas and with the expected length
    fn verify_data_convergence(replicas: Vec<Register>, expected_len: u64) -> Result<()> {
        // verify replicas have the expected length
        // also verify replicas failed to get with index beyond reported length
        let index_beyond_end = RegisterIndex::FromStart(expected_len);
        for r in &replicas {
            assert_eq!(r.len(None)?, expected_len);
            assert_eq!(r.get(index_beyond_end, None)?, None);
        }

        // now verify that the items are the same in all replicas
        for i in 0..expected_len {
            let index = RegisterIndex::FromStart(i);
            let r0_entry = replicas[0].get(index, None)?;
            for r in &replicas {
                assert_eq!(r0_entry, r.get(index, None)?);
            }
        }

        Ok(())
    }

    // Generate a vec of Register replicas of some length, with corresponding vec of keypairs for signing, and the overall owner of the register
    fn generate_replicas(
        max_quantity: usize,
    ) -> impl Strategy<Value = Result<(Vec<Register>, Arc<Keypair>)>> {
        let xorname = XorName::random();
        let tag = 45_000u64;

        let owner_keypair = Arc::new(Keypair::new_ed25519(&mut OsRng));
        let owner = owner_keypair.public_key();
        let policy = RegisterPublicPolicy {
            owner,
            permissions: BTreeMap::default(),
        };

        (1..max_quantity + 1).prop_map(move |quantity| {
            let mut replicas = Vec::with_capacity(quantity);
            for _ in 0..quantity {
                let actor = Keypair::new_ed25519(&mut OsRng).public_key();
                let replica = Register::new_public(actor, xorname, tag, Some(policy.clone()));

                replicas.push(replica);
            }

            Ok((replicas, owner_keypair.clone()))
        })
    }

    // Generate a Register entry
    fn generate_reg_entry() -> impl Strategy<Value = Vec<u8>> {
        "\\PC*".prop_map(|s| s.into_bytes())
    }

    // Generate a vec of Register entries
    fn generate_dataset(max_quantity: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
        prop::collection::vec(generate_reg_entry(), 1..max_quantity + 1)
    }

    // Generates a vec of Register entries each with a value suggesting
    // the delivery chance of the op that gets created with the entry
    fn generate_dataset_and_probability(
        max_quantity: usize,
    ) -> impl Strategy<Value = Vec<(Vec<u8>, u8)>> {
        prop::collection::vec((generate_reg_entry(), any::<u8>()), 1..max_quantity + 1)
    }

    proptest! {
        #[test]
        fn proptest_reg_doesnt_crash_with_random_data(
            data in generate_reg_entry()
        ) {
            // Instantiate the same Register on two replicas
            let register_name = XorName::random();
            let register_tag = 45_000u64;
            let owner_keypair = Keypair::new_ed25519(&mut OsRng);
            let policy = RegisterPublicPolicy {
                owner: owner_keypair.public_key(),
                permissions: BTreeMap::default(),
            };

            let mut replicas = gen_pub_reg_replicas(
                Some(owner_keypair.clone()),
                register_name,
                register_tag,
                Some(policy),
                2);
            let (_, mut replica1) = replicas.remove(0);
            let (_, mut replica2) = replicas.remove(0);

            // Append an item on replicas
            let append_op = sign_register_op(replica1.create_unsigned_append_op(data, BTreeSet::new())?, &owner_keypair)?;
            replica1.apply_op(append_op.clone())?;
            replica2.apply_op(append_op)?;

            verify_data_convergence(vec![replica1, replica2], 1)?;
        }

        #[test]
        fn proptest_reg_converge_with_many_random_data(
            dataset in generate_dataset(1000)
        ) {
            // Instantiate the same Register on two replicas
            let register_name = XorName::random();
            let register_tag = 43_001u64;
            let owner_keypair = Keypair::new_ed25519(&mut OsRng);
            let policy = RegisterPublicPolicy {
                owner: owner_keypair.public_key(),
                permissions: BTreeMap::default(),
            };

            // Instantiate the same Register on two replicas
            let mut replicas = gen_pub_reg_replicas(
                Some(owner_keypair.clone()),
                register_name,
                register_tag,
                Some(policy),
                2);
            let (_, mut replica1) = replicas.remove(0);
            let (_, mut replica2) = replicas.remove(0);

            let dataset_length = dataset.len() as u64;

            // insert our data at replicas
            for data in dataset {
                // Append an item on replica1
                let append_op = sign_register_op(replica1.create_unsigned_append_op(data, BTreeSet::new())?, &owner_keypair)?;
                replica1.apply_op(append_op.clone())?;
                // now apply that op to replica 2
                replica2.apply_op(append_op)?;
            }

            verify_data_convergence(vec![replica1, replica2], dataset_length)?;

        }

        #[test]
        fn proptest_reg_converge_with_many_random_data_across_arbitrary_number_of_replicas(
            dataset in generate_dataset(500),
            res in generate_replicas(50)
        ) {
            let (mut replicas, owner_keypair) = res?;
            let dataset_length = dataset.len() as u64;

            // insert our data at replicas
            for data in dataset {
                // first generate an op from one replica...
                let op = sign_register_op(replicas[0].create_unsigned_append_op(data, BTreeSet::new())?, &owner_keypair)?;

                // then apply this to all replicas
                for replica in &mut replicas {
                    replica.apply_op(op.clone())?;
                }
            }

            verify_data_convergence(replicas, dataset_length)?;

        }

        #[test]
        fn proptest_converge_with_shuffled_op_set_across_arbitrary_number_of_replicas(
            dataset in generate_dataset(100),
            res in generate_replicas(500)
        ) {
            let (mut replicas, owner_keypair) = res?;
            let dataset_length = dataset.len() as u64;

            // generate an ops set from one replica
            let mut ops = vec![];

            for data in dataset {
                let op = sign_register_op(replicas[0].create_unsigned_append_op(data, BTreeSet::new())?, &owner_keypair)?;
                replicas[0].apply_op(op.clone())?;
                ops.push(op);
            }

            // now we randomly shuffle ops and apply at each replica
            for replica in &mut replicas {
                let mut ops = ops.clone();
                ops.shuffle(&mut OsRng);

                for op in ops {
                    replica.apply_op(op)?;
                }
            }

            verify_data_convergence(replicas, dataset_length)?;
        }

        #[test]
        fn proptest_converge_with_shuffled_ops_from_many_replicas_across_arbitrary_number_of_replicas(
            dataset in generate_dataset(1000),
            res in generate_replicas(100)
        ) {
            let (mut replicas, owner_keypair) = res?;
            let dataset_length = dataset.len() as u64;

            // generate an ops set using random replica for each data
            let mut ops = vec![];
            for data in dataset {
                if let Some(replica) = replicas.choose_mut(&mut OsRng)
                {
                    let op = sign_register_op(replica.create_unsigned_append_op(data, BTreeSet::new())?, &owner_keypair)?;
                    replica.apply_op(op.clone())?;

                    ops.push(op);
                }
            }

            let opslen = ops.len() as u64;
            prop_assert_eq!(dataset_length, opslen);

            // now we randomly shuffle ops and apply at each replica
            for replica in &mut replicas {
                let mut ops = ops.clone();
                ops.shuffle(&mut OsRng);

                for op in ops {
                    replica.apply_op(op)?;
                }
            }

            verify_data_convergence(replicas, dataset_length)?;
        }

        #[test]
        fn proptest_dropped_data_can_be_reapplied_and_we_converge(
            dataset in generate_dataset_and_probability(1000),
        ) {
            // Instantiate the same Register on two replicas
            let register_name = XorName::random();
            let register_tag = 43_001u64;
            let owner_keypair = Keypair::new_ed25519(&mut OsRng);
            let policy = RegisterPublicPolicy {
                owner: owner_keypair.public_key(),
                permissions: BTreeMap::default(),
            };

            // Instantiate the same Register on two replicas
            let mut replicas = gen_pub_reg_replicas(
                Some(owner_keypair.clone()),
                register_name,
                register_tag,
                Some(policy),
                2);
            let (_, mut replica1) = replicas.remove(0);
            let (_, mut replica2) = replicas.remove(0);

            let dataset_length = dataset.len() as u64;

            let mut ops = vec![];
            for (data, delivery_chance) in dataset {
                    let op = sign_register_op(replica1.create_unsigned_append_op(data, BTreeSet::new())?, &owner_keypair)?;
                    replica1.apply_op(op.clone())?;

                    ops.push((op, delivery_chance));
            }

            for (op, delivery_chance) in ops.clone() {
                if delivery_chance < u8::MAX / 3 {
                    replica2.apply_op(op)?;
                }
            }

            // here we statistically should have dropped some messages
            if dataset_length > 50 {
                assert_ne!(replica2.len(None), replica1.len(None));
            }

            // reapply all ops
            for (op, _) in ops {
                replica2.apply_op(op)?;
            }

            // now we converge
            verify_data_convergence(vec![replica1, replica2], dataset_length)?;
        }

        #[test]
        fn proptest_converge_with_shuffled_ops_from_many_while_dropping_some_at_random(
            dataset in generate_dataset_and_probability(1000),
            res in generate_replicas(100),
        ) {
            let (mut replicas, owner_keypair) = res?;
            let dataset_length = dataset.len() as u64;

            // generate an ops set using random replica for each data
            let mut ops = vec![];
            for (data, delivery_chance) in dataset {

                // a random index within the replicas range
                let index: usize = OsRng.gen_range( 0, replicas.len());
                let replica = &mut replicas[index];

                let op = sign_register_op(replica.create_unsigned_append_op(data, BTreeSet::new())?, &owner_keypair)?;
                replica.apply_op(op.clone())?;
                ops.push((op, delivery_chance));
            }

            let opslen = ops.len() as u64;
            prop_assert_eq!(dataset_length, opslen);

            // now we randomly shuffle ops and apply at each replica
            for replica in &mut replicas {
                let mut ops = ops.clone();
                ops.shuffle(&mut OsRng);

                for (op, delivery_chance) in ops.clone() {
                    if delivery_chance > u8::MAX / 3 {
                        replica.apply_op(op)?;
                    }
                }

                // reapply all ops, simulating lazy messaging filling in the gaps
                for (op, _) in ops {
                    replica.apply_op(op)?;
                }
            }

            verify_data_convergence(replicas, dataset_length)?;
        }

        #[test]
        fn proptest_converge_with_shuffled_ops_including_bad_ops_which_error_and_are_not_applied(
            dataset in generate_dataset(10),
            bogus_dataset in generate_dataset(10), // should be same number as dataset
            gen_replicas_result in generate_replicas(10),

        ) {
            let (mut replicas, owner_keypair) = gen_replicas_result?;
            let dataset_length = dataset.len();
            let bogus_dataset_length = bogus_dataset.len();
            let number_replicas = replicas.len();

            // generate the real ops set using random replica for each data
            let mut ops = vec![];
            for data in dataset {
                if let Some(replica) = replicas.choose_mut(&mut OsRng)
                {
                    let op = sign_register_op(replica.create_unsigned_append_op(data, BTreeSet::new())?, &owner_keypair)?;

                    replica.apply_op(op.clone())?;
                    ops.push(op);
                }
            }

            // set up a replica that has nothing to do with the rest, random xor... different owner...
            let xorname = XorName::random();
            let tag = 45_000u64;
            let random_owner_keypair = Keypair::new_ed25519(&mut OsRng);
            let mut bogus_replica = Register::new_public(random_owner_keypair.public_key(), xorname, tag, None);

            // add bogus ops from bogus replica + bogus data
            for data in bogus_dataset {
                let bogus_op = sign_register_op(bogus_replica.create_unsigned_append_op(data, BTreeSet::new())?, &random_owner_keypair)?;
                bogus_replica.apply_op(bogus_op.clone())?;
                ops.push(bogus_op);
            }

            let opslen = ops.len();
            prop_assert_eq!(dataset_length + bogus_dataset_length, opslen);

            let mut err_count = vec![];
            // now we randomly shuffle ops and apply at each replica
            for replica in &mut replicas {
                let mut ops = ops.clone();
                ops.shuffle(&mut OsRng);

                for op in ops {
                    match replica.apply_op(op) {
                        Ok(_) => {},
                        // record all errors to check this matches bogus data
                        Err(error) => {err_count.push(error)},
                    }
                }
            }

            // check we get an error per bogus datum per replica
            assert_eq!(err_count.len(), bogus_dataset_length * number_replicas);

            verify_data_convergence(replicas, dataset_length as u64)?;
        }
    }
}
