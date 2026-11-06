use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use custom_ring_interface::{
    storage_instruction::{tag, EnrollRequest},
    RingMode, STORAGE_PROGRAM_ID,
};
use solana_account::Account;
use solana_message::Hash;
use solana_transaction::versioned::VersionedTransaction;
use spr_client::{AsyncProverClient, AsyncSprClient, ClientError};
use spr_interface::ZERO_NULLIFIER_PUBKEY;
use spr_keypair::{ShieldedAddress, ShieldedKeypair, ViewingKey};
use zolana_ring_client::ViewingRotation;
use zolana_ring_keys::RingAddress;

use super::*;
use crate::tests::support::{keypair, ring, Chain, RingSettings};
use crate::SaltedOwnerCheck;

/// The chain with each landed rotation written to its authorization.
struct Ledger {
    chain: Arc<Mutex<Chain>>,
    sent: Arc<Mutex<usize>>,
}

impl Ledger {
    fn chain(&self) -> Chain {
        self.chain.lock().unwrap().clone()
    }
}

#[async_trait]
impl AsyncRpc for Ledger {
    async fn get_account(&self, address: Address) -> Result<Option<Account>, ClientError> {
        self.chain().get_account(address).await
    }

    async fn get_latest_blockhash(&self) -> Result<(Hash, u64), ClientError> {
        Ok((Hash::default(), 0))
    }

    async fn process_transaction(
        &self,
        transaction: VersionedTransaction,
    ) -> Result<Signature, ClientError> {
        let keys = transaction.message.static_account_keys();
        let [instruction] = transaction.message.instructions() else {
            panic!("one instruction");
        };
        assert_eq!(
            keys[usize::from(instruction.program_id_index)],
            STORAGE_PROGRAM_ID
        );
        let (&enroll, request) = instruction.data.split_first().unwrap();
        assert_eq!(enroll, tag::ENROLL);
        let request = EnrollRequest::parse(request).unwrap();
        assert!(request.proof.is_none());
        let authorization = keys[usize::from(instruction.accounts[3])];
        let mut account = self.chain().get_account(authorization).await?.unwrap();
        TrackingAuthorization::from_data_mut(&mut account.data)
            .unwrap()
            .viewing_u = request.ix.viewing_u;
        let mut chain = self.chain.lock().unwrap();
        *chain = chain.clone().with(authorization, account);
        *self.sent.lock().unwrap() += 1;
        Ok(transaction.signatures[0])
    }
}

fn rotation<'a>(
    identity: &'a ShieldedKeypair,
    keys: &'a RotatingRingKeys,
    history: &'a ViewingHistory,
) -> RotateViewingKey<'a> {
    RotateViewingKey {
        ring: ring(),
        owner: identity,
        payer: identity,
        keys,
        history,
    }
}

#[tokio::test]
async fn a_rotated_key_resolves_for_a_sender_and_a_repeat_sends_nothing() {
    let identity = keypair(3);
    let address = identity.shielded_address().unwrap();
    let chain = Chain::ring(RingSettings::new(RingMode::Confidential)).with_tracking(&[address]);
    let sent = Arc::new(Mutex::new(0));
    let ledger = Ledger {
        chain: Arc::new(Mutex::new(chain.clone())),
        sent: Arc::clone(&sent),
    };
    let client = RingClient::new(
        AsyncSprClient::new(ledger, chain, AsyncProverClient::local()),
        AsyncProverClient::local(),
    );
    let start = ViewingRotation {
        keys: RotatingRingKeys::new(&identity).unwrap(),
        history: ViewingHistory::new(identity.viewing_pubkey(), 0),
    };
    let ahead = start.keys.clone().rotate(ViewingKey::new()).unwrap();
    assert!(matches!(
        rotation(&identity, &ahead, &start.history)
            .send(&client)
            .await,
        Err(RingError::ViewingHistoryNotCurrent)
    ));

    let rotated = start.rotate(ViewingKey::new(), 1).unwrap();
    let new = rotated.keys.address().unwrap().viewing_pubkey;
    let landed = rotation(&identity, &rotated.keys, &rotated.history)
        .send(&client)
        .await
        .unwrap();
    assert!(landed.signature.is_some());
    assert_eq!(landed.viewing_pubkey, new);
    let held = RingAddress {
        recipient: ShieldedAddress {
            nullifier_pubkey: ZERO_NULLIFIER_PUBKEY,
            ..address
        },
        ring_program_id: ring().program_id(),
        list_salt: [0; 32],
    };
    let resolved = SaltedOwnerCheck {
        ring: ring(),
        address: &held,
    }
    .run(client.zolana())
    .await
    .unwrap();
    assert_eq!(resolved.viewing_pubkey, new);

    let repeated = rotation(&identity, &rotated.keys, &rotated.history)
        .send(&client)
        .await
        .unwrap();
    assert_eq!(repeated.signature, None);
    assert_eq!(*sent.lock().unwrap(), 1);
}
