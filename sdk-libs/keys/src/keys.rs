use custom_ring_interface::stream::{
    confidential_slot_tag, DeliveredSlot, SlotSecret, StreamError,
};
use spr_keypair::{
    shielded::{ShieldedAddress, ShieldedKeypair},
    viewing_key::{Salt, ViewTag},
    NullifierKey, ViewingKey, X25519Pubkey,
};
use spr_transaction::{
    DecryptRequest, DeriveRequest, LocalShieldedKeys, ShieldedKeys, TransactionError,
    TransactionKeyRequest,
};
use zeroize::Zeroizing;

use crate::RingKeyError;

/// The public context of one delivered ring output slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingDeliveryRequest {
    pub viewing_pubkey: X25519Pubkey,
    pub tx_viewing_pk: X25519Pubkey,
    pub salt: Salt,
    pub output_index: u32,
    pub first_nullifier: [u8; 32],
}

/// The derivation a published tag follows, one reader answers every kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RingTagKind {
    /// A confidential output, tagged by the recipient key.
    Confidential,
    /// An anonymous payment, tagged by its slot secret.
    Recipient,
    SenderBundle,
}

impl RingTagKind {
    fn tag(
        self,
        viewing_pubkey: &X25519Pubkey,
        secret: &SlotSecret,
    ) -> Result<ViewTag, StreamError> {
        Ok(match self {
            Self::Confidential => confidential_slot_tag(viewing_pubkey.u()),
            Self::Recipient => secret.anonymous_slot_tag()?,
            Self::SenderBundle => secret.sender_tag()?,
        })
    }
}

/// One published tag, `output_index` is `m` on a sender bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingTagProbe {
    pub kind: RingTagKind,
    pub output_index: u32,
    pub tag: ViewTag,
}

/// The published tags of one transaction under one viewing key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingTagFrame {
    pub viewing_pubkey: X25519Pubkey,
    pub tx_viewing_pk: X25519Pubkey,
    pub salt: Salt,
    pub first_nullifier: [u8; 32],
    pub probes: Vec<RingTagProbe>,
}

/// One own-key spec view tag of an anonymous ring under a wallet viewing key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ViewTagStream {
    Sender { tx_count: u64 },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewTagRequest {
    pub viewing_pubkey: X25519Pubkey,
    pub stream: ViewTagStream,
}

/// The ring derivations of a key holder, no viewing key or agreement output leaves it.
pub trait RingKeys {
    /// One CRDS slot secret per request, one agreement per run of one key and transaction.
    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, RingKeyError>;

    /// Per frame one answer per probe, the slot secret when the probe's tag matches.
    fn ring_tag_matches(
        &self,
        frames: &[RingTagFrame],
    ) -> Result<Vec<Vec<Option<SlotSecret>>>, RingKeyError>;

    /// One tag per request.
    fn view_tags(&self, requests: &[ViewTagRequest]) -> Result<Vec<ViewTag>, RingKeyError>;
}

/// One identity under its current and every retired viewing key, a note sealed to any of them opens here.
#[must_use]
#[derive(Clone)]
pub struct RotatingRingKeys {
    local: LocalShieldedKeys,
    /// The current key first.
    viewing: Vec<ViewingKey>,
    /// The identity key, `list_tag` is final so a rotation keeps the salt.
    list_root: ViewingKey,
    address: ShieldedAddress,
    nullifier: NullifierKey,
}

impl RotatingRingKeys {
    pub fn new(identity: &ShieldedKeypair) -> Result<Self, RingKeyError> {
        Self::holding(
            identity.shielded_address()?,
            vec![identity.viewing_key.clone()],
            identity.viewing_key.clone(),
            identity.nullifier_key.clone(),
        )
    }

    /// The wallet's stored keys, a note sealed to any of them opens here.
    pub fn with_retired(self, retired: Vec<ViewingKey>) -> Result<Self, RingKeyError> {
        let mut viewing = self.viewing;
        viewing.extend(retired);
        Self::holding(self.address, viewing, self.list_root, self.nullifier)
    }

    /// `next` becomes current and the earlier keys stay held.
    pub fn rotate(self, next: ViewingKey) -> Result<Self, RingKeyError> {
        let address = ShieldedAddress {
            viewing_pubkey: next.pubkey(),
            ..self.address
        };
        let mut viewing = vec![next];
        viewing.extend(self.viewing);
        Self::holding(address, viewing, self.list_root, self.nullifier)
    }

    fn holding(
        address: ShieldedAddress,
        viewing: Vec<ViewingKey>,
        list_root: ViewingKey,
        nullifier: NullifierKey,
    ) -> Result<Self, RingKeyError> {
        let local = LocalShieldedKeys::new(address, viewing.clone(), nullifier.clone())
            .map_err(|_| RingKeyError::UnknownViewingKey)?;
        Ok(Self {
            local,
            viewing,
            list_root,
            address,
            nullifier,
        })
    }

    /// A rotation keeps it, a wallet's stored state stays keyed by it.
    pub fn identity_viewing_pubkey(&self) -> X25519Pubkey {
        self.list_root.pubkey()
    }

    pub(crate) const fn list_root(&self) -> &ViewingKey {
        &self.list_root
    }
}

impl ShieldedKeys for RotatingRingKeys {
    fn address(&self) -> Result<ShieldedAddress, TransactionError> {
        Ok(self.address)
    }

    fn viewing_public_keys(&self) -> Vec<X25519Pubkey> {
        self.local.viewing_public_keys()
    }

    fn decrypt(&self, requests: &[DecryptRequest<'_>]) -> Result<Vec<Vec<u8>>, TransactionError> {
        self.local.decrypt(requests)
    }

    fn derive(&self, requests: &[DeriveRequest]) -> Result<Vec<[u8; 32]>, TransactionError> {
        self.local.derive(requests)
    }

    fn transaction_keys(
        &self,
        requests: &[TransactionKeyRequest],
    ) -> Result<Vec<ViewingKey>, TransactionError> {
        self.local.transaction_keys(requests)
    }
}

/// Finds the secret a request names, every derivation below stays inside the holder.
pub(crate) trait HeldKeys {
    fn held(&self, pubkey: &X25519Pubkey) -> Result<&ViewingKey, RingKeyError>;
}

impl HeldKeys for ShieldedKeypair {
    fn held(&self, pubkey: &X25519Pubkey) -> Result<&ViewingKey, RingKeyError> {
        match self.viewing_key.pubkey() == *pubkey {
            true => Ok(&self.viewing_key),
            false => Err(RingKeyError::UnknownViewingKey),
        }
    }
}

impl HeldKeys for RotatingRingKeys {
    fn held(&self, pubkey: &X25519Pubkey) -> Result<&ViewingKey, RingKeyError> {
        self.viewing
            .iter()
            .find(|key| key.pubkey() == *pubkey)
            .ok_or(RingKeyError::UnknownViewingKey)
    }
}

impl RingKeys for ShieldedKeypair {
    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, RingKeyError> {
        delivery_secrets(self, requests)
    }

    fn ring_tag_matches(
        &self,
        frames: &[RingTagFrame],
    ) -> Result<Vec<Vec<Option<SlotSecret>>>, RingKeyError> {
        tag_matches(self, frames)
    }

    fn view_tags(&self, requests: &[ViewTagRequest]) -> Result<Vec<ViewTag>, RingKeyError> {
        view_tags(self, requests)
    }
}

impl RingKeys for RotatingRingKeys {
    fn ring_delivery_secrets(
        &self,
        requests: &[RingDeliveryRequest],
    ) -> Result<Vec<[u8; 32]>, RingKeyError> {
        delivery_secrets(self, requests)
    }

    fn ring_tag_matches(
        &self,
        frames: &[RingTagFrame],
    ) -> Result<Vec<Vec<Option<SlotSecret>>>, RingKeyError> {
        tag_matches(self, frames)
    }

    fn view_tags(&self, requests: &[ViewTagRequest]) -> Result<Vec<ViewTag>, RingKeyError> {
        view_tags(self, requests)
    }
}

fn delivery_secrets<H: HeldKeys>(
    holder: &H,
    requests: &[RingDeliveryRequest],
) -> Result<Vec<[u8; 32]>, RingKeyError> {
    let mut agreements = Agreements::new(holder);
    requests
        .iter()
        .map(|request| {
            let agreement = agreements.of(&request.viewing_pubkey, &request.tx_viewing_pk)?;
            Ok(*slot_secret(
                agreement,
                &request.tx_viewing_pk,
                &request.viewing_pubkey,
                &request.salt,
                request.output_index,
                &request.first_nullifier,
            )?
            .as_bytes())
        })
        .collect()
}

fn tag_matches<H: HeldKeys>(
    holder: &H,
    frames: &[RingTagFrame],
) -> Result<Vec<Vec<Option<SlotSecret>>>, RingKeyError> {
    let mut agreements = Agreements::new(holder);
    frames
        .iter()
        .map(|frame| {
            let agreement = agreements.of(&frame.viewing_pubkey, &frame.tx_viewing_pk)?;
            frame
                .probes
                .iter()
                .map(|probe| {
                    let secret = slot_secret(
                        agreement,
                        &frame.tx_viewing_pk,
                        &frame.viewing_pubkey,
                        &frame.salt,
                        probe.output_index,
                        &frame.first_nullifier,
                    )?;
                    let tag = probe.kind.tag(&frame.viewing_pubkey, &secret)?;
                    Ok((tag == probe.tag).then_some(secret))
                })
                .collect()
        })
        .collect()
}

fn view_tags<H: HeldKeys>(
    holder: &H,
    requests: &[ViewTagRequest],
) -> Result<Vec<ViewTag>, RingKeyError> {
    requests
        .iter()
        .map(|request| {
            let key = holder.held(&request.viewing_pubkey)?;
            Ok(match request.stream {
                ViewTagStream::Sender { tx_count } => key.get_sender_view_tag(tx_count)?,
            })
        })
        .collect()
}

/// Holds the latest agreement, a run of one key and transaction computes it once.
struct Agreements<'a, H> {
    holder: &'a H,
    latest: Option<(X25519Pubkey, X25519Pubkey, Zeroizing<[u8; 32]>)>,
    #[cfg(test)]
    computed: usize,
}

impl<'a, H: HeldKeys> Agreements<'a, H> {
    fn new(holder: &'a H) -> Self {
        Self {
            holder,
            latest: None,
            #[cfg(test)]
            computed: 0,
        }
    }

    fn of(
        &mut self,
        viewing_pubkey: &X25519Pubkey,
        tx_viewing_pk: &X25519Pubkey,
    ) -> Result<&[u8; 32], RingKeyError> {
        let current = matches!(
            &self.latest,
            Some((key, tx, _)) if key == viewing_pubkey && tx == tx_viewing_pk
        );
        if !current {
            let agreement = self.holder.held(viewing_pubkey)?.ecdh(tx_viewing_pk)?;
            self.latest = Some((*viewing_pubkey, *tx_viewing_pk, Zeroizing::new(agreement)));
            #[cfg(test)]
            {
                self.computed += 1;
            }
        }
        match &self.latest {
            Some((_, _, agreement)) => Ok(agreement),
            None => Err(RingKeyError::UnknownViewingKey),
        }
    }
}

fn slot_secret(
    agreement: &[u8; 32],
    tx_viewing_pk: &X25519Pubkey,
    viewing_pubkey: &X25519Pubkey,
    salt: &Salt,
    output_index: u32,
    first_nullifier: &[u8; 32],
) -> Result<SlotSecret, RingKeyError> {
    Ok(DeliveredSlot {
        agreement,
        tx_viewing_pk: tx_viewing_pk.as_bytes(),
        recipient_viewing_pk: viewing_pubkey.as_bytes(),
        salt,
        output_index,
        first_nullifier,
    }
    .secret()?)
}

#[cfg(test)]
mod tests {
    use custom_ring_interface::stream::SlotSecret;
    use spr_keypair::SigningKey;

    use super::*;

    fn keypair() -> ShieldedKeypair {
        ShieldedKeypair::from_keypair(SigningKey::from_ed25519_bytes(&[3; 32])).unwrap()
    }

    fn frame(
        tx: &ViewingKey,
        viewing_pubkey: X25519Pubkey,
        probes: Vec<RingTagProbe>,
    ) -> RingTagFrame {
        RingTagFrame {
            viewing_pubkey,
            tx_viewing_pk: tx.pubkey(),
            salt: [5; 16],
            first_nullifier: [0; 32],
            probes,
        }
    }

    fn sealed(tx: &ViewingKey, viewing_pubkey: &X25519Pubkey, output_index: u32) -> SlotSecret {
        slot_secret(
            &tx.ecdh(viewing_pubkey).unwrap(),
            &tx.pubkey(),
            viewing_pubkey,
            &[5; 16],
            output_index,
            &[0; 32],
        )
        .unwrap()
    }

    #[test]
    fn a_probe_answers_only_under_its_own_domain_and_index() {
        let holder = keypair();
        let viewing_pubkey = holder.viewing_key.pubkey();
        let tx = ViewingKey::new();
        let body = sealed(&tx, &viewing_pubkey, 1);
        let bundle = sealed(&tx, &viewing_pubkey, 2);
        let probe = |kind, output_index, tag| RingTagProbe {
            kind,
            output_index,
            tag,
        };
        let answers = holder
            .ring_tag_matches(&[frame(
                &tx,
                viewing_pubkey,
                vec![
                    probe(
                        RingTagKind::Recipient,
                        1,
                        body.anonymous_slot_tag().unwrap(),
                    ),
                    probe(RingTagKind::SenderBundle, 2, bundle.sender_tag().unwrap()),
                    probe(
                        RingTagKind::Confidential,
                        1,
                        confidential_slot_tag(viewing_pubkey.u()),
                    ),
                    probe(
                        RingTagKind::Recipient,
                        0,
                        body.anonymous_slot_tag().unwrap(),
                    ),
                    probe(
                        RingTagKind::SenderBundle,
                        2,
                        bundle.recipient_tag().unwrap(),
                    ),
                    probe(
                        RingTagKind::Confidential,
                        1,
                        body.anonymous_slot_tag().unwrap(),
                    ),
                ],
            )])
            .unwrap();
        let hits: Vec<_> = answers[0]
            .iter()
            .map(|answer| answer.as_ref().map(SlotSecret::as_bytes))
            .collect();
        assert_eq!(
            hits,
            [
                Some(body.as_bytes()),
                Some(bundle.as_bytes()),
                Some(body.as_bytes()),
                None,
                None,
                None
            ]
        );
    }

    #[test]
    fn a_probe_under_a_key_the_holder_lacks_is_refused() {
        let holder = keypair();
        let tx = ViewingKey::new();
        let other = ViewingKey::new().pubkey();
        assert_eq!(
            holder
                .ring_tag_matches(&[frame(&tx, other, Vec::new())])
                .err(),
            Some(RingKeyError::UnknownViewingKey)
        );
    }

    #[test]
    fn one_agreement_serves_every_slot_of_one_transaction_and_key() {
        let holder = keypair();
        let viewing_pubkey = holder.viewing_key.pubkey();
        let (first, second) = (ViewingKey::new().pubkey(), ViewingKey::new().pubkey());
        let mut agreements = Agreements::new(&holder);
        for tx in [first, first, first, second, second] {
            agreements.of(&viewing_pubkey, &tx).unwrap();
        }
        assert_eq!(agreements.computed, 2);
    }

    #[test]
    fn a_rotated_holder_answers_under_each_key_and_refuses_another() {
        let identity = keypair();
        let old = identity.viewing_key.pubkey();
        let rotated = RotatingRingKeys::new(&identity)
            .unwrap()
            .rotate(ViewingKey::new())
            .unwrap();
        let current = rotated.address().unwrap().viewing_pubkey;
        assert_ne!(current, old);
        assert_eq!(rotated.viewing_public_keys(), [current, old]);
        let tx = ViewingKey::new();
        for key in [old, current] {
            let tag = sealed(&tx, &key, 0).anonymous_slot_tag().unwrap();
            let answers = rotated
                .ring_tag_matches(&[frame(
                    &tx,
                    key,
                    vec![RingTagProbe {
                        kind: RingTagKind::Recipient,
                        output_index: 0,
                        tag,
                    }],
                )])
                .unwrap();
            assert!(answers[0][0].is_some());
        }
        let stranger = frame(&tx, ViewingKey::new().pubkey(), Vec::new());
        assert_eq!(
            rotated.ring_tag_matches(&[stranger]).err(),
            Some(RingKeyError::UnknownViewingKey)
        );
    }
}
