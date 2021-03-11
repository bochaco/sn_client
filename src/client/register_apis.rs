// Copyright 2021 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under The General Public License (GPL), version 3.
// Unless required by applicable law or agreed to in writing, the SAFE Network Software distributed
// under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied. Please review the Licences for the specific language governing
// permissions and limitations relating to use of the SAFE Network Software.

use crate::{connection_manager::ConnectionManager, errors::Error, Client};
use log::{debug, trace};
use sn_data_types::{
    PublicKey, Register, RegisterAddress, RegisterEntries, RegisterEntry, RegisterIndex,
    RegisterNodeId, RegisterPermissions, RegisterPrivatePermissions, RegisterPrivatePolicy,
    RegisterPublicPermissions, RegisterPublicPolicy, RegisterUser,
};
use sn_messaging::client::{
    Cmd, DataCmd, DataQuery, Query, QueryResponse, RegisterRead, RegisterWrite,
};
use std::collections::{BTreeMap, BTreeSet};
use xor_name::XorName;

fn wrap_seq_read(read: RegisterRead) -> Query {
    Query::Data(DataQuery::Register(read))
}

impl Client {
    //----------------------
    // Write Operations
    //---------------------

    /// Create Private Register Data on to the Network
    ///
    /// Creates a private sequence on the network which can be appended to.
    /// Private data can be removed from the network at a later date.
    ///
    /// A tag must be supplied.
    /// A xorname must be supplied, this can be random or deterministic as per your apps needs.
    ///
    /// # Examples
    ///
    /// Store data
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let _address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn store_private_sequence(
        &self,
        sequence: Option<RegisterEntries>,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<PublicKey, RegisterPrivatePermissions>,
    ) -> Result<RegisterAddress, Error> {
        trace!("Store Private Register Data {:?}", name);
        let pk = self.public_key().await;
        let policy = RegisterPrivatePolicy { owner, permissions };
        let mut data = Register::new_private(pk, name, tag, Some(policy));
        let address = *data.address();

        if let Some(entries) = sequence {
            for entry in entries {
                // FIXME: parents should possibly be linking to previous entry
                let mut op = data.create_unsigned_append_op(entry, BTreeSet::new())?;
                let bytes = bincode::serialize(&op.crdt_op)?;
                let signature = self.keypair.sign(&bytes);
                op.signature = Some(signature);
                data.apply_op(op.clone())?;
            }
        }

        self.pay_and_write_sequence_to_network(data.clone()).await?;

        Ok(address)
    }

    /// Create Public Register Data into the Network
    ///
    /// Creates a public sequence on the network which can be appended to.
    /// Public data can _not_ be removed from the network at a later date.
    ///
    /// A tag must be supplied.
    /// A xorname must be supplied, this can be random or deterministic as per your apps needs.
    ///
    /// # Examples
    ///
    /// Store data
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, RegisterUser, Token, RegisterPublicPermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<RegisterUser, RegisterPublicPermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    RegisterUser::Key(owner),
    ///    RegisterPublicPermissions::new(true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let _address = client.store_public_sequence(None, name, tag, owner, perms).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn store_public_sequence(
        &self,
        sequence: Option<RegisterEntries>,
        name: XorName,
        tag: u64,
        owner: PublicKey,
        permissions: BTreeMap<RegisterUser, RegisterPublicPermissions>,
    ) -> Result<RegisterAddress, Error> {
        trace!("Store Public Register Data {:?}", name);
        let pk = self.public_key().await;
        let policy = RegisterPublicPolicy { owner, permissions };
        let mut data = Register::new_public(pk, name, tag, Some(policy));
        let address = *data.address();

        if let Some(entries) = sequence {
            for entry in entries {
                // FIXME: parents should probably link to previous inserted entry
                let mut op = data.create_unsigned_append_op(entry, BTreeSet::new())?;
                let bytes = bincode::serialize(&op.crdt_op)?;
                let signature = self.keypair.sign(&bytes);
                op.signature = Some(signature);
                data.apply_op(op.clone())?;
            }
        }

        self.pay_and_write_sequence_to_network(data.clone()).await?;

        Ok(address)
    }

    /// Delete sequence
    ///
    /// You're only able to delete a PrivateRegister. Public data can no be removed from the network.
    ///
    /// # Examples
    ///
    /// Delete data
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// client.delete_sequence(address).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn delete_sequence(&self, address: RegisterAddress) -> Result<(), Error> {
        let cmd = DataCmd::Register(RegisterWrite::Delete(address));
        // Payment for PUT
        let payment_proof = self.create_write_payment_proof(&cmd).await?;

        // The _actual_ message
        let msg_contents = Cmd::Data {
            cmd,
            payment: payment_proof.clone(),
        };
        let message = self.create_cmd_message(msg_contents)?;
        let endpoint = self.session.endpoint()?.clone();
        let elders = self.session.elders.iter().cloned().collect();

        let _ = ConnectionManager::send_cmd(&message, endpoint, elders).await?;

        self.apply_write_payment_to_local_actor(payment_proof).await
    }

    /// Append to Register
    ///
    /// Public or private isn't important for append. You can append to either (though the data you append will be Public or Private).
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// client.append_to_sequence(address, b"New Entry Value".to_vec()).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn append_to_sequence(
        &self,
        address: RegisterAddress,
        entry: RegisterEntry,
        parents: BTreeSet<RegisterNodeId>,
    ) -> Result<(), Error> {
        // First we fetch it so we can get the causality info,
        // either from local CRDT replica or from the network if not found
        let mut sequence = self.get_sequence(address).await?;

        // We can now append the entry to the Register
        let mut op = sequence.create_unsigned_append_op(entry, parents)?;
        let bytes = bincode::serialize(&op.crdt_op)?;
        let signature = self.keypair.sign(&bytes);
        op.signature = Some(signature);
        sequence.apply_op(op.clone())?;

        // Finally we can send the mutation to the network's replicas
        let cmd = DataCmd::Register(RegisterWrite::Edit(op));

        self.pay_and_send_data_command(cmd).await
    }

    /// Store a new public sequenced data object
    /// Wraps msg_contents for payment validation and mutation
    pub(crate) async fn pay_and_write_sequence_to_network(
        &self,
        data: Register,
    ) -> Result<(), Error> {
        debug!("Attempting to pay and write data to network");
        let cmd = DataCmd::Register(RegisterWrite::New(data));

        self.pay_and_send_data_command(cmd).await
    }

    //----------------------
    // Get Register
    //---------------------

    /// Get Register Data from the Network
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let _data = client.get_sequence(address).await?;
    ///
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence(&self, address: RegisterAddress) -> Result<Register, Error> {
        trace!("Get Register Data at {:?}", address.name());
        // Let's fetch the Register from the network
        let sequence = match self
            .send_query(wrap_seq_read(RegisterRead::Get(address)))
            .await?
        {
            QueryResponse::GetRegister(res) => res.map_err(Error::from),
            _ => Err(Error::ReceivedUnexpectedEvent),
        }?;

        Ok(sequence)
    }

    /// Get the last data entry from a Register Data.
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    /// client.append_to_sequence(address, b"New Entry Value".to_vec()).await?;
    /// client.append_to_sequence(address, b"Another New Entry Value".to_vec()).await?;
    ///
    /// // Now we can retrieve the alst entry in the sequence:
    /// let (_position, last_entry) = client.get_sequence_last_entry(address).await?;
    ///
    /// assert_eq!(last_entry, b"Another New Entry Value".to_vec());
    ///
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_last_entry(
        &self,
        address: RegisterAddress,
    ) -> Result<(u64, RegisterEntry), Error> {
        trace!(
            "Get latest entry from Register Data at {:?}",
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        // TODO: do we need to query with some specific PK?
        match sequence.last_entry(None)? {
            Some(entry) => Ok((sequence.len(None)? - 1, entry.to_vec())),
            None => Err(Error::from(sn_data_types::Error::NoSuchEntry)),
        }
    }

    /// Get Register Data from the Network at a specific version
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    /// client.append_to_sequence(address, b"New Entry Value".to_vec()).await?;
    /// client.append_to_sequence(address, b"Another New Entry Value".to_vec()).await?;
    ///
    /// // Now we can retrieve the alst entry in the sequence:
    /// let entry_v1 = client.get_sequence_entry(address, 1).await?;
    ///
    /// assert_eq!(entry_v1, b"Another New Entry Value".to_vec());
    /// # Ok(()) } ); }
    /// ```
    pub async fn get_sequence_entry(
        &self,
        address: RegisterAddress,
        index_from_start: u64,
    ) -> Result<RegisterEntry, Error> {
        trace!(
            "Get entry at index {:?} from Register Data {:?}",
            index_from_start,
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        let index = RegisterIndex::FromStart(index_from_start);
        match sequence.get(index, None)? {
            Some(entry) => Ok(entry.to_vec()),
            None => Err(Error::from(sn_data_types::Error::NoSuchEntry)),
        }
    }

    /// Get a set of Entries for the requested range from a Register.
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions, RegisterIndex};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    /// client.append_to_sequence(address, b"New Entry Value".to_vec()).await?;
    /// client.append_to_sequence(address, b"Another New Entry Value".to_vec()).await?;
    /// client.append_to_sequence(address, b"Third Entry Value".to_vec()).await?;
    ///
    /// // Now we can retrieve the alst entry in the sequence:
    /// let entries = client.get_sequence_range(address, (RegisterIndex::FromStart(1), RegisterIndex::FromEnd(0) )).await?;
    ///
    /// assert_eq!(entries[0], b"Another New Entry Value".to_vec());
    /// assert_eq!(entries[1], b"Third Entry Value".to_vec());
    ///
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_range(
        &self,
        address: RegisterAddress,
        range: (RegisterIndex, RegisterIndex),
    ) -> Result<RegisterEntries, Error> {
        trace!(
            "Get range of entries from Register Data at {:?}",
            address.name()
        );

        let sequence = self.get_sequence(address).await?;
        // TODO: do we need to query with some specific PK?
        sequence
            .in_range(range.0, range.1, None)?
            .ok_or_else(|| Error::from(sn_data_types::Error::NoSuchEntry))
    }

    //----------------------
    // Ownership
    //---------------------

    /// Get the owner of a Register.
    ///
    /// # Examples
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let seq_owner = client.get_sequence_owner(address).await?;
    /// assert_eq!(seq_owner, owner);
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_owner(&self, address: RegisterAddress) -> Result<PublicKey, Error> {
        trace!("Get owner of the Register Data at {:?}", address.name());

        // TODO: perhaps we want to grab it directly from the network and update local replica
        let sequence = self.get_sequence(address).await?;

        let owner = if sequence.is_public() {
            sequence.public_policy()?.owner
        } else {
            // TODO: do we need to query with some specific PK?
            sequence.private_policy(None)?.owner
        };

        Ok(owner)
    }

    //----------------------
    // Permissions
    //---------------------

    /// Get the set of Permissions of a Public Register.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, Token, RegisterUser,RegisterPublicPermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<RegisterUser, RegisterPublicPermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    RegisterUser::Key(owner),
    ///    RegisterPublicPermissions::new(true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_public_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let _permissions = client.get_sequence_public_permissions_for_user(address, owner).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_public_permissions_for_user(
        &self,
        address: RegisterAddress,
        user: PublicKey,
    ) -> Result<RegisterPublicPermissions, Error> {
        trace!(
            "Get permissions from Public Register Data at {:?}",
            address.name()
        );

        // TODO: perhaps we want to grab it directly from
        // the network and update local replica
        let sequence = self.get_sequence(address).await?;
        // TODO: do we need to query with some specific PK?
        let perms = match sequence
            .permissions(RegisterUser::Key(user), None)
            .map_err(Error::from)?
        {
            RegisterPermissions::Public(perms) => perms,
            _ => return Err(Error::NotPublicPermissions),
        };

        Ok(perms)
    }

    /// Get the set of Permissions of a Private Register.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let _permissions = client.get_sequence_private_permissions_for_user(address, owner).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_private_permissions_for_user(
        &self,
        address: RegisterAddress,
        user: PublicKey,
    ) -> Result<RegisterPrivatePermissions, Error> {
        trace!(
            "Get permissions from Private Register Data at {:?}",
            address.name()
        );
        let sequence = self.get_sequence(address).await?;

        // TODO: do we need to query with some specific PK?
        let perms = match sequence
            .permissions(RegisterUser::Key(user), None)
            .map_err(Error::from)?
        {
            RegisterPermissions::Private(perms) => perms,
            _ => return Err(Error::NotPrivatePermissions),
        };

        Ok(perms)
    }

    /// Get the set of Permissions for a specific user in a Register.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # extern crate tokio; use anyhow::Result; use std::str::FromStr;
    /// # use sn_client::utils::test_utils::read_network_conn_info;
    /// use sn_client::Client;
    /// use sn_data_types::{Keypair, PublicKey, Token, RegisterPrivatePermissions};
    /// use std::collections::BTreeMap;
    /// use xor_name::XorName;
    /// use rand::rngs::OsRng;
    /// # #[tokio::main] async fn main() { let _: Result<()> = futures::executor::block_on( async {
    /// // Let's use an existing client, with a pre-existing balance to be used for write payments.
    /// let id = Keypair::new_ed25519(&mut OsRng);

    /// # let bootstrap_contacts = Some(read_network_conn_info()?);
    /// let mut client = Client::new(Some(id), None, bootstrap_contacts).await?;
    /// # let initial_balance = Token::from_str("100")?; client.trigger_simulated_farming_payout(initial_balance).await?;
    /// let name = XorName::random();
    /// let tag = 10;
    /// let owner = client.public_key().await;
    /// let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
    ///
    /// // Set the access permissions
    /// let _ = perms.insert(
    ///    owner,
    ///    RegisterPrivatePermissions::new(true, true),
    /// );
    ///
    /// // The returned address can then be used to `append` data to.
    /// let address = client.store_private_sequence(None, name, tag, owner, perms).await?;
    ///
    /// let _permissions = client.get_sequence_public_permissions_for_user(address, owner).await?;
    /// # let balance_after_write = client.get_local_balance().await; assert_ne!(initial_balance, balance_after_write); Ok(()) } ); }
    /// ```
    pub async fn get_sequence_permissions(
        &self,
        address: RegisterAddress,
        user: RegisterUser,
    ) -> Result<RegisterPermissions, Error> {
        trace!(
            "Get permissions for user {:?} from Register Data at {:?}",
            user,
            address.name()
        );

        // TODO: perhaps we want to grab it directly from
        // the network and update local replica
        let sequence = self.get_sequence(address).await?;
        // TODO: do we need to query with some specific PK?
        let perms = sequence.permissions(user, None).map_err(Error::from)?;

        Ok(perms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::test_utils::{create_test_client, gen_ed_keypair};
    use anyhow::{anyhow, bail, Result};
    use sn_data_types::{Error as DtError, RegisterAction, RegisterPrivatePermissions, Token};
    use sn_messaging::client::Error as ErrorMessage;
    use std::{collections::BTreeSet, str::FromStr};
    use tokio::time::{delay_for, Duration};
    use xor_name::XorName;

    #[tokio::test]
    pub async fn sequence_deletions_should_cost_put_price() -> Result<()> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = create_test_client().await?;
        let owner = client.public_key().await;
        let perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
        let sequence_address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let mut balance_before_delete = client.get_balance().await?;

        while balance_before_delete == Token::from_str("0")?
            || balance_before_delete == Token::from_str("10")?
        {
            delay_for(Duration::from_millis(200)).await;
            balance_before_delete = client.get_balance().await?;
        }

        client.delete_sequence(sequence_address).await?;
        let mut new_balance = client.get_balance().await?;

        // now let's ensure we've paid _something_
        while new_balance == balance_before_delete {
            delay_for(Duration::from_millis(200)).await;
            new_balance = client.get_balance().await?;
        }

        Ok(())
    }

    /// Register data tests ///

    #[tokio::test]
    pub async fn sequence_basics() -> Result<()> {
        let client = create_test_client().await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Register
        let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
        let _ = perms.insert(owner, RegisterPrivatePermissions::new(true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let mut seq_res = client.get_sequence(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence(address).await;
        }

        let sequence = seq_res?;

        assert!(sequence.is_private());
        assert_eq!(*sequence.name(), name);
        assert_eq!(sequence.tag(), tag);
        assert_eq!(sequence.len(None)?, 0);

        // store a Public Register
        let mut perms = BTreeMap::<RegisterUser, RegisterPublicPermissions>::new();
        let _ = perms.insert(RegisterUser::Anyone, RegisterPublicPermissions::new(true));
        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;

        let mut seq_res = client.get_sequence(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence(address).await;
        }

        let sequence = seq_res?;

        assert!(sequence.is_public());
        assert_eq!(*sequence.name(), name);
        assert_eq!(sequence.tag(), tag);
        assert_eq!(sequence.len(None)?, 0);

        Ok(())
    }

    #[tokio::test]
    pub async fn sequence_private_permissions() -> Result<()> {
        let client = create_test_client().await?;
        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
        let _ = perms.insert(owner, RegisterPrivatePermissions::new(true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let mut seq_res = client.get_sequence(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence(address).await;
        }

        let data = seq_res?;

        assert_eq!(data.len(None)?, 0);

        let mut seq_res = client
            .get_sequence_private_permissions_for_user(address, owner)
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_private_permissions_for_user(address, owner)
                .await;
        }

        let user_perms = seq_res?;

        assert!(user_perms.is_allowed(RegisterAction::Read));
        assert!(user_perms.is_allowed(RegisterAction::Append));

        let mut seq_res = client
            .get_sequence_permissions(address, RegisterUser::Key(owner))
            .await;
        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_permissions(address, RegisterUser::Key(owner))
                .await;
        }

        match seq_res? {
            RegisterPermissions::Private(user_perms) => {
                assert!(user_perms.is_allowed(RegisterAction::Read));
                assert!(user_perms.is_allowed(RegisterAction::Append));
            }
            RegisterPermissions::Public(_) => return Err(Error::IncorrectPermissions.into()),
        }

        let other_user = gen_ed_keypair().public_key();

        match client
            .get_sequence_private_permissions_for_user(address, other_user)
            .await
        {
            Err(Error::NetworkDataError(DtError::NoSuchEntry)) => {}
            other => bail!(
                "Unexpected result when querying private permissions: {:?}",
                other
            ),
        }

        match client
            .get_sequence_permissions(address, RegisterUser::Key(other_user))
            .await
        {
            Err(Error::NetworkDataError(DtError::NoSuchEntry)) => Ok(()),
            other => Err(anyhow!(
                "Unexpected result when querying permissions: {:?}",
                other
            )),
        }
    }

    #[tokio::test]
    pub async fn sequence_public_permissions() -> Result<()> {
        let client = create_test_client().await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;
        let mut perms = BTreeMap::<RegisterUser, RegisterPublicPermissions>::new();
        let _ = perms.insert(
            RegisterUser::Key(owner),
            RegisterPublicPermissions::new(None),
        );
        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;

        let mut seq_res = client
            .get_sequence_public_permissions_for_user(address, owner)
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_public_permissions_for_user(address, owner)
                .await;
        }

        let user_perms = seq_res?;

        assert_eq!(Some(true), user_perms.is_allowed(RegisterAction::Read));
        assert_eq!(None, user_perms.is_allowed(RegisterAction::Append));

        let mut seq_res = client
            .get_sequence_permissions(address, RegisterUser::Key(owner))
            .await;
        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_permissions(address, RegisterUser::Key(owner))
                .await;
        }

        match seq_res? {
            RegisterPermissions::Public(user_perms) => {
                assert_eq!(Some(true), user_perms.is_allowed(RegisterAction::Read));
                assert_eq!(None, user_perms.is_allowed(RegisterAction::Append));
            }
            RegisterPermissions::Private(_) => {
                return Err(anyhow!("Unexpectedly obtained incorrect user permissions",));
            }
        }

        let other_user = gen_ed_keypair().public_key();

        match client
            .get_sequence_public_permissions_for_user(address, other_user)
            .await
        {
            Err(Error::NetworkDataError(DtError::NoSuchEntry)) => {}
            other => bail!(
                "Unexpected result when querying private permissions: {:?}",
                other
            ),
        }

        match client
            .get_sequence_permissions(address, RegisterUser::Key(other_user))
            .await
        {
            Err(Error::NetworkDataError(DtError::NoSuchEntry)) => Ok(()),
            other => Err(anyhow!(
                "Unexpected result when querying permissions: {:?}",
                other
            )),
        }
    }

    #[tokio::test]
    pub async fn append_to_sequence() -> Result<()> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = create_test_client().await?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<RegisterUser, RegisterPublicPermissions>::new();
        let _ = perms.insert(
            RegisterUser::Key(owner),
            RegisterPublicPermissions::new(true),
        );

        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;

        // append to the data the data
        let mut seq_res = client
            .append_to_sequence(address, b"VALUE1".to_vec(), BTreeSet::new())
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .append_to_sequence(address, b"VALUE1".to_vec(), BTreeSet::new())
                .await;
        }

        // now check last entry
        let mut seq_res = client.get_sequence_last_entry(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence_last_entry(address).await;
        }

        let (index, data) = seq_res?;

        assert_eq!(0, index);
        assert_eq!(std::str::from_utf8(&data)?, "VALUE1");

        // append to the data the data
        let mut seq_res = client
            .append_to_sequence(address, b"VALUE2".to_vec(), BTreeSet::new())
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .append_to_sequence(address, b"VALUE2".to_vec(), BTreeSet::new())
                .await;
        }

        // and then lets check last entry
        let mut seq_res = client.get_sequence_last_entry(address).await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client.get_sequence_last_entry(address).await;
        }

        let (mut index, mut data) = seq_res?;
        // we might still be getting old data here
        while index == 0 {
            delay_for(Duration::from_millis(200)).await;
            let (i, d) = client.get_sequence_last_entry(address).await?;
            index = i;
            data = d;
        }

        assert_eq!(1, index);
        assert_eq!(std::str::from_utf8(&data)?, "VALUE2");

        let mut seq_res = client
            .get_sequence_range(
                address,
                (RegisterIndex::FromStart(0), RegisterIndex::FromEnd(0)),
            )
            .await;

        while seq_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            seq_res = client
                .get_sequence_range(
                    address,
                    (RegisterIndex::FromStart(0), RegisterIndex::FromEnd(0)),
                )
                .await;
        }

        let data = seq_res?;

        assert_eq!(std::str::from_utf8(&data[0])?, "VALUE1");
        assert_eq!(std::str::from_utf8(&data[1])?, "VALUE2");

        // get_sequence_entry

        let data0 = client.get_sequence_entry(address, 0).await?;
        assert_eq!(std::str::from_utf8(&data0)?, "VALUE1");

        let data1 = client.get_sequence_entry(address, 1).await?;
        assert_eq!(std::str::from_utf8(&data1)?, "VALUE2");

        // Requesting a version that's too high throws an error
        let res = client.get_sequence_entry(address, 2).await;
        match res {
            Err(_) => Ok(()),
            Ok(_data) => Err(anyhow!(
                "Unexpectedly retrieved a sequence entry at index that's too high!",
            )),
        }
    }

    #[tokio::test]
    pub async fn sequence_owner() -> Result<()> {
        let name = XorName(rand::random());
        let tag = 10;
        let client = create_test_client().await?;

        let owner = client.public_key().await;
        let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
        let _ = perms.insert(owner, RegisterPrivatePermissions::new(true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        // Assert that the data is stored.
        let mut owner_res = client.get_sequence_owner(address).await;

        while owner_res.is_err() {
            delay_for(Duration::from_millis(200)).await;
            owner_res = client.get_sequence_owner(address).await;
        }

        let current_owner = owner_res?;

        assert_eq!(owner, current_owner);

        Ok(())
    }

    #[tokio::test]
    pub async fn sequence_can_delete_private() -> Result<()> {
        let client = create_test_client().await?;
        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Private Register
        let mut perms = BTreeMap::<PublicKey, RegisterPrivatePermissions>::new();
        let _ = perms.insert(owner, RegisterPrivatePermissions::new(true, true));
        let address = client
            .store_private_sequence(None, name, tag, owner, perms)
            .await?;

        let mut sequence = client.get_sequence(address).await;

        while sequence.is_err() {
            delay_for(Duration::from_millis(200)).await;
            sequence = client.get_sequence(address).await;
        }

        assert!(sequence?.is_private());

        client.delete_sequence(address).await?;

        let mut res = client.get_sequence(address).await;

        while res.is_ok() {
            delay_for(Duration::from_millis(200)).await;
            res = client.get_sequence(address).await;
        }

        match res {
            Err(Error::ErrorMessage(ErrorMessage::NoSuchData)) => Ok(()),
            Err(err) => Err(anyhow!(
                "Unexpected error returned when deleting a nonexisting Private Register: {}",
                err
            )),
            Ok(_data) => Err(anyhow!(
                "Unexpectedly retrieved a deleted Private Register!",
            )),
        }
    }

    #[tokio::test]
    pub async fn sequence_cannot_delete_public() -> Result<()> {
        let client = create_test_client().await?;

        let name = XorName(rand::random());
        let tag = 15000;
        let owner = client.public_key().await;

        // store a Public Register
        let mut perms = BTreeMap::<RegisterUser, RegisterPublicPermissions>::new();
        let _ = perms.insert(RegisterUser::Anyone, RegisterPublicPermissions::new(true));
        let address = client
            .store_public_sequence(None, name, tag, owner, perms)
            .await?;

        let mut sequence = client.get_sequence(address).await;

        while sequence.is_err() {
            sequence = client.get_sequence(address).await;
        }

        assert!(sequence?.is_public());

        client.delete_sequence(address).await?;

        // Check that our data still exists.
        match client.get_sequence(address).await {
            Err(Error::ErrorMessage(ErrorMessage::InvalidOperation)) => Ok(()),
            Err(err) => Err(anyhow!(
                "Unexpected error returned when attempting to get a Public Register: {}",
                err
            )),
            Ok(_data) => Ok(()),
        }
    }
}
