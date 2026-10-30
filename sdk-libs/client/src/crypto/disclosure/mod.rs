//! The auditor envelope, CROD pad and disclosures, mirrored by Go `custom_rings/circuits/base`.

use custom_ring_interface::{
    domain, pack_disclosure, unpack_disclosure, AnonymousAuditKey, AnonymousInputFields,
    AnonymousLayout, DeliveredLayout, DisclosureLayout, InputPrefix, ANONYMOUS_ENTRY_CLASS,
    ANONYMOUS_SLOT_BYTES, AUDIT_CIPHERTEXT_LEN, DELIVERED_SLOT_BYTES,
    DISCLOSURE_INPUT_AMOUNT_BYTES, DISCLOSURE_SENDER_KEY_BYTES,
};
use spr_hasher::{
    primitives::{is_canonical_bn254_scalar_be, pack_be, right_align},
    Hasher, Poseidon,
};
use spr_keypair::{ViewingKey, X25519Keypair, X25519Pubkey};
use spr_transaction::field::{field_add, field_sub};
use zeroize::Zeroizing;

use crate::{
    encryption::{open_stream, seal_stream, StreamSchedule},
    AuditError, REDACTED,
};

const KEY_BYTES: usize = 32;
const AMOUNT_BYTES: usize = 8;
const KEY_AND_AMOUNT_BYTES: usize = KEY_BYTES + AMOUNT_BYTES;
const ZERO: [u8; 32] = [0; 32];

const _: () = assert!(DELIVERED_SLOT_BYTES == KEY_AND_AMOUNT_BYTES);
const _: () = assert!(ANONYMOUS_SLOT_BYTES == 2 * KEY_BYTES + AMOUNT_BYTES);
const _: () = assert!(DISCLOSURE_INPUT_AMOUNT_BYTES == AMOUNT_BYTES);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEnvelope {
    pub eph_u: [u8; 32],
    pub sealed: [u8; AUDIT_CIPHERTEXT_LEN],
}

/// The audit proof witnesses `ephemeral_sk`.
pub struct SealedAuditEnvelope {
    pub envelope: AuditEnvelope,
    pub ephemeral_sk: Zeroizing<[u8; 32]>,
}

impl AuditEnvelope {
    /// A fresh ephemeral key per call, a reused one repeats the keystream under the auditor key.
    pub fn seal(
        tx_viewing_key: &ViewingKey,
        auditor_pk: &X25519Pubkey,
    ) -> Result<SealedAuditEnvelope, AuditError> {
        let ephemeral = X25519Keypair::new();
        let mut sealed = tx_viewing_key.secret_bytes();
        seal_stream(&ephemeral, auditor_pk, StreamSchedule::Audit, &mut *sealed)?;
        Ok(SealedAuditEnvelope {
            envelope: Self {
                eph_u: ephemeral.pubkey().u(),
                sealed: *sealed,
            },
            ephemeral_sk: ephemeral.secret_bytes(),
        })
    }

    /// The circuit seals the clamped encoding, an unclamped alias of the same key is refused.
    pub fn open(&self, auditor: &X25519Keypair) -> Result<ViewingKey, AuditError> {
        let mut secret = Zeroizing::new(self.sealed);
        open_stream(
            auditor,
            &X25519Pubkey::from_u(self.eph_u)?,
            StreamSchedule::Audit,
            &mut *secret,
        )?;
        ViewingKey::from_canonical_bytes(&secret).map_err(|_| AuditError::NonCanonicalViewingKey)
    }
}

/// `pad_j = Poseidon(seed, j)`, a known pad reveals no other.
pub struct DisclosurePad {
    seed: Zeroizing<[u8; 32]>,
}

impl DisclosurePad {
    /// `seed = Poseidon(CROD, pack_be(tx_sk), salt)`.
    pub fn new(tx_viewing_key: &ViewingKey, salt: &[u8; 16]) -> Result<Self, AuditError> {
        Self::keyed(
            &domain::field(domain::DISCLOSURE_PAD),
            &tx_viewing_key.secret_bytes(),
            salt,
        )
    }

    pub(crate) fn keyed(
        domain: &[u8; 32],
        key: &[u8; 32],
        salt: &[u8; 16],
    ) -> Result<Self, AuditError> {
        let [key0, key1] = pack_be(key);
        Ok(Self {
            seed: Zeroizing::new(Poseidon::hashv(&[
                domain,
                &key0,
                &key1,
                &right_align(salt),
            ])?),
        })
    }

    /// `C_j = P_j + pad_j mod q`.
    pub fn encrypt(&self, plaintext: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, AuditError> {
        self.apply(plaintext, field_add)
    }

    pub fn decrypt(&self, published: &[[u8; 32]]) -> Result<Vec<[u8; 32]>, AuditError> {
        self.apply(published, field_sub)
    }

    fn apply(
        &self,
        fields: &[[u8; 32]],
        combine: fn(&[u8; 32], &[u8; 32]) -> [u8; 32],
    ) -> Result<Vec<[u8; 32]>, AuditError> {
        (0u64..)
            .zip(fields)
            .map(|(index, field)| {
                let pad = Poseidon::hashv(&[&*self.seed, &right_align(&index.to_be_bytes())])?;
                Ok(combine(&canonical(*field)?, &pad))
            })
            .collect()
    }
}

/// The body opens the rest of a ring output, an exit's owner is its owner tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeliveredOutputOpening {
    Ring {
        owner_key: [u8; 32],
        nullifier_pk: Option<[u8; 32]>,
    },
    Exit {
        nullifier_pk: Option<[u8; 32]>,
        asset: [u8; 32],
        amount: u64,
    },
    Dummy,
}

/// The disclosure opens every live slot's asset and amount, the published body is unproven.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnonymousOutputOpening {
    Ring {
        owner_key: [u8; 32],
        nullifier_pk: [u8; 32],
        asset: [u8; 32],
        amount: u64,
    },
    Exit {
        nullifier_pk: [u8; 32],
        asset: [u8; 32],
        amount: u64,
    },
    Dummy,
    /// Decoded from bytes that fit no opening of the slot's kind, encoding refuses it.
    Unreadable,
}

/// A spent UTXO of the hidden sender, its data hashes zero.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub struct AnonymousInputOpening {
    pub asset: [u8; 32],
    pub amount: u64,
    pub blinding: [u8; 32],
}

impl core::fmt::Debug for AnonymousInputOpening {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            asset,
            amount,
            blinding: _,
        } = self;
        f.debug_struct("AnonymousInputOpening")
            .field("asset", asset)
            .field("amount", amount)
            .field("blinding", &REDACTED)
            .finish()
    }
}

/// A `None` input is a dummy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnonymousInputs {
    /// Every spent UTXO a ring note, spent UTXO 0 named by its hash and every later one by its prefix.
    Commitments {
        first: [u8; 32],
        prefixes: Vec<Option<InputPrefix>>,
    },
    /// The entry key opens every spent UTXO, all under the sender's key and one nullifier key.
    Openings {
        sender_key: [u8; 32],
        sender_nullifier_pk: [u8; 32],
        inputs: Vec<Option<AnonymousInputOpening>>,
    },
}

impl AnonymousInputs {
    /// Spent UTXO 0 must be real.
    pub fn commitments(hashes: &[Option<[u8; 32]>]) -> Result<Self, AuditError> {
        let [Some(first), rest @ ..] = hashes else {
            return Err(AuditError::DisclosureLayout);
        };
        let prefixes = rest
            .iter()
            .map(|hash| {
                hash.map(|hash| InputPrefix::of(&hash).ok_or(AuditError::DisclosureField))
                    .transpose()
            })
            .collect::<Result<_, _>>()?;
        Ok(Self::Commitments {
            first: *first,
            prefixes,
        })
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct AnonymousDisclosure {
    pub layout: AnonymousLayout,
    pub seed_out: Option<[u8; 32]>,
    pub outputs: Vec<AnonymousOutputOpening>,
    pub inputs: AnonymousInputs,
}

/// `seed_out` is present exactly when an output exits.
#[derive(Clone, PartialEq, Eq)]
pub enum AuditDisclosure {
    Delivered {
        layout: DeliveredLayout,
        seed_out: Option<[u8; 32]>,
        outputs: Vec<DeliveredOutputOpening>,
    },
    Anonymous(AnonymousDisclosure),
}

impl core::fmt::Debug for AnonymousDisclosure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self {
            layout,
            seed_out,
            outputs,
            inputs,
        } = self;
        f.debug_struct("AnonymousDisclosure")
            .field("layout", layout)
            .field("seed_out", &seed_out.map(|_| REDACTED))
            .field("outputs", outputs)
            .field("inputs", inputs)
            .finish()
    }
}

impl core::fmt::Debug for AuditDisclosure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Delivered {
                layout,
                seed_out,
                outputs,
            } => f
                .debug_struct("Delivered")
                .field("layout", layout)
                .field("seed_out", &seed_out.map(|_| REDACTED))
                .field("outputs", outputs)
                .finish(),
            Self::Anonymous(disclosure) => f.debug_tuple("Anonymous").field(disclosure).finish(),
        }
    }
}

/// A ring slot and an exit share a byte width, the exit bitmap tells them apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublishedOutputs<'a> {
    pub layout: DisclosureLayout,
    /// One per published slot.
    pub exits: &'a [bool],
}

impl AuditDisclosure {
    pub fn layout(&self) -> DisclosureLayout {
        match self {
            Self::Delivered { layout, .. } => DisclosureLayout::Delivered(*layout),
            Self::Anonymous(disclosure) => DisclosureLayout::Anonymous(disclosure.layout),
        }
    }

    /// The plaintext `P` the pad masks.
    pub fn fields(&self) -> Result<Vec<[u8; 32]>, AuditError> {
        let mut fields = vec![ZERO; self.layout().field_count()];
        match self {
            Self::Delivered {
                layout,
                seed_out,
                outputs,
            } => {
                let at = layout.fields();
                check_len(outputs.len(), layout.outputs)?;
                place_seed_out(&mut fields, at.seed_out, *seed_out)?;
                match &at.nullifier_pks {
                    Some(range) => fields[range.clone()].copy_from_slice(
                        &outputs
                            .iter()
                            .map(DeliveredOutputOpening::published_nullifier_pk)
                            .collect::<Result<Vec<_>, _>>()?,
                    ),
                    None if outputs.iter().any(|output| output.nullifier_pk().is_some()) => {
                        return Err(AuditError::DisclosureLayout)
                    }
                    None => {}
                }
                let mut slots = Vec::with_capacity(at.slot_bytes * outputs.len());
                for output in outputs {
                    slots.extend(output.slot_bytes(at.slot_bytes)?);
                }
                fields[at.slots].copy_from_slice(&pack_disclosure(&slots));
            }
            Self::Anonymous(disclosure) => disclosure.place(&mut fields)?,
        }
        fields.into_iter().map(canonical).collect()
    }

    /// Refuses a field at or above the modulus and any nonzero padding.
    pub fn decode(
        published: PublishedOutputs<'_>,
        fields: &[[u8; 32]],
    ) -> Result<Self, AuditError> {
        let PublishedOutputs { layout, exits } = published;
        if fields.len() != layout.field_count() {
            return Err(AuditError::DisclosureLayout);
        }
        fields
            .iter()
            .try_for_each(|field| canonical(*field).map(drop))?;
        Ok(match layout {
            DisclosureLayout::Delivered(layout) => {
                check_len(exits.len(), layout.outputs)?;
                let at = layout.fields();
                if !layout.exits && exits.contains(&true) {
                    return Err(AuditError::DisclosureLayout);
                }
                let nullifier_pks = at.nullifier_pks.clone().map(|range| &fields[range]);
                let slots =
                    packed_bytes(&fields[at.slots.clone()], at.slot_bytes * layout.outputs)?;
                let outputs = slots
                    .chunks(at.slot_bytes)
                    .zip(exits)
                    .enumerate()
                    .map(|(index, (slot, exit))| {
                        DeliveredOutputOpening::read(
                            nullifier_pks.map(|pks| pks[index]),
                            slot,
                            *exit,
                        )
                    })
                    .collect::<Result<_, _>>()?;
                Self::Delivered {
                    layout,
                    seed_out: at.seed_out.map(|index| fields[index]),
                    outputs,
                }
            }
            DisclosureLayout::Anonymous(layout) => {
                check_len(exits.len(), layout.outputs)?;
                Self::Anonymous(AnonymousDisclosure::read(layout, exits, fields)?)
            }
        })
    }
}

impl DeliveredOutputOpening {
    fn nullifier_pk(&self) -> Option<[u8; 32]> {
        match self {
            Self::Ring { nullifier_pk, .. } | Self::Exit { nullifier_pk, .. } => *nullifier_pk,
            Self::Dummy => None,
        }
    }

    fn published_nullifier_pk(&self) -> Result<[u8; 32], AuditError> {
        match self {
            Self::Dummy => Ok(ZERO),
            _ => self.nullifier_pk().ok_or(AuditError::DisclosureLayout),
        }
    }

    fn slot_bytes(&self, width: usize) -> Result<Vec<u8>, AuditError> {
        let full = match self {
            Self::Ring { owner_key, .. } => key_and_amount(owner_key, 0),
            Self::Exit { .. } if width != DELIVERED_SLOT_BYTES => {
                return Err(AuditError::DisclosureLayout)
            }
            Self::Exit { asset, amount, .. } => key_and_amount(&canonical(*asset)?, *amount),
            Self::Dummy => [0; DELIVERED_SLOT_BYTES],
        };
        Ok(full[..width].to_vec())
    }

    fn read(nullifier_pk: Option<[u8; 32]>, slot: &[u8], exit: bool) -> Result<Self, AuditError> {
        let head: [u8; KEY_BYTES] = slot
            .get(..KEY_BYTES)
            .and_then(|head| head.try_into().ok())
            .ok_or(AuditError::DisclosureLayout)?;
        let tail = &slot[KEY_BYTES..];
        if exit {
            let amount: [u8; AMOUNT_BYTES] =
                tail.try_into().map_err(|_| AuditError::DisclosureLayout)?;
            return Ok(Self::Exit {
                nullifier_pk,
                asset: canonical(head)?,
                amount: u64::from_be_bytes(amount),
            });
        }
        // A disclosed zero key marks a dummy, under key escrow its zero slot does.
        let dummy = match nullifier_pk {
            Some(nullifier_pk) => nullifier_pk == ZERO,
            None => head == ZERO,
        };
        if dummy {
            return zero(slot).map(|()| Self::Dummy);
        }
        zero(tail)?;
        Ok(Self::Ring {
            owner_key: head,
            nullifier_pk,
        })
    }
}

impl AnonymousOutputOpening {
    fn nullifier_pk(&self) -> [u8; 32] {
        match self {
            Self::Ring { nullifier_pk, .. } | Self::Exit { nullifier_pk, .. } => *nullifier_pk,
            Self::Dummy | Self::Unreadable => ZERO,
        }
    }

    /// `mask(ring, owner_key) ‖ asset ‖ u64be(amount)`, a dummy all zero.
    fn slot_bytes(&self) -> Result<[u8; ANONYMOUS_SLOT_BYTES], AuditError> {
        let mut slot = [0; ANONYMOUS_SLOT_BYTES];
        let (owner, rest) = slot.split_at_mut(KEY_BYTES);
        let (asset_bytes, amount_bytes) = rest.split_at_mut(KEY_BYTES);
        let (asset, amount) = match self {
            Self::Ring {
                owner_key,
                asset,
                amount,
                ..
            } => {
                owner.copy_from_slice(owner_key);
                (asset, amount)
            }
            Self::Exit { asset, amount, .. } => (asset, amount),
            Self::Dummy => return Ok(slot),
            Self::Unreadable => return Err(AuditError::DisclosureLayout),
        };
        asset_bytes.copy_from_slice(&canonical(*asset)?);
        amount_bytes.copy_from_slice(&amount.to_be_bytes());
        Ok(slot)
    }

    fn read(nullifier_pk: [u8; 32], slot: &[u8; ANONYMOUS_SLOT_BYTES], exit: bool) -> Self {
        let owner_key: [u8; KEY_BYTES] = core::array::from_fn(|i| slot[i]);
        let asset: [u8; KEY_BYTES] = core::array::from_fn(|i| slot[KEY_BYTES + i]);
        let amount = u64::from_be_bytes(core::array::from_fn(|i| slot[2 * KEY_BYTES + i]));
        let opening = match exit {
            true => zero(&owner_key).and_then(|()| {
                Ok(Self::Exit {
                    nullifier_pk,
                    asset: canonical(asset)?,
                    amount,
                })
            }),
            false if nullifier_pk == ZERO => zero(slot).map(|()| Self::Dummy),
            false => canonical(asset).map(|asset| Self::Ring {
                owner_key,
                nullifier_pk,
                asset,
                amount,
            }),
        };
        opening.unwrap_or(Self::Unreadable)
    }
}

impl AnonymousDisclosure {
    fn place(&self, fields: &mut [[u8; 32]]) -> Result<(), AuditError> {
        let layout = self.layout;
        let at = layout.fields();
        check_len(self.outputs.len(), layout.outputs)?;
        place_seed_out(fields, at.seed_out, self.seed_out)?;
        fields[at.nullifier_pks.clone()].copy_from_slice(
            &self
                .outputs
                .iter()
                .map(AnonymousOutputOpening::nullifier_pk)
                .collect::<Vec<_>>(),
        );
        let mut block = Vec::with_capacity(at.slot_bytes);
        match (&self.inputs, &at.inputs, layout.key) {
            (
                AnonymousInputs::Commitments { first, prefixes },
                AnonymousInputFields::Commitments {
                    first: first_at,
                    prefix_pairs,
                },
                AnonymousAuditKey::Commitment { class },
            ) if prefixes.len() + 1 == layout.inputs && layout.inputs <= class => {
                fields[*first_at] = *first;
                for (field, pair) in fields[prefix_pairs.clone()]
                    .iter_mut()
                    .zip(prefixes.chunks(2))
                {
                    *field = InputPrefix::pair(pair[0], pair.get(1).copied().flatten());
                }
            }
            (
                AnonymousInputs::Openings {
                    sender_key,
                    sender_nullifier_pk,
                    inputs: openings,
                },
                AnonymousInputFields::Openings {
                    sender_nullifier_pk: sender_at,
                    amounts,
                    openings: openings_at,
                },
                AnonymousAuditKey::Entry,
            ) if openings.len() == layout.inputs && layout.inputs <= ANONYMOUS_ENTRY_CLASS => {
                block.extend_from_slice(sender_key);
                let openings: Vec<_> = openings
                    .iter()
                    .map(|opening| opening.unwrap_or_default())
                    .collect();
                for (pair, opening) in fields[openings_at.clone()].chunks_mut(2).zip(&openings) {
                    pair.copy_from_slice(&[opening.asset, opening.blinding]);
                }
                let mut packed = vec![0; DISCLOSURE_INPUT_AMOUNT_BYTES * ANONYMOUS_ENTRY_CLASS];
                for (slot, opening) in packed
                    .as_chunks_mut::<DISCLOSURE_INPUT_AMOUNT_BYTES>()
                    .0
                    .iter_mut()
                    .zip(&openings)
                {
                    *slot = opening.amount.to_be_bytes();
                }
                fields[amounts.clone()].copy_from_slice(&pack_disclosure(&packed));
                fields[*sender_at] = *sender_nullifier_pk;
            }
            _ => return Err(AuditError::DisclosureLayout),
        }
        for output in &self.outputs {
            block.extend(output.slot_bytes()?);
        }
        fields[at.slots.clone()].copy_from_slice(&pack_disclosure(&block));
        Ok(())
    }

    fn read(
        layout: AnonymousLayout,
        exits: &[bool],
        fields: &[[u8; 32]],
    ) -> Result<Self, AuditError> {
        let at = layout.fields();
        let block = packed_bytes(&fields[at.slots.clone()], at.slot_bytes)?;
        let slots = match at.inputs {
            AnonymousInputFields::Openings { .. } => block
                .get(DISCLOSURE_SENDER_KEY_BYTES..)
                .ok_or(AuditError::DisclosureLayout)?,
            AnonymousInputFields::Commitments { .. } => &block[..],
        };
        let outputs = fields[at.nullifier_pks.clone()]
            .iter()
            .zip(slots.as_chunks::<ANONYMOUS_SLOT_BYTES>().0)
            .zip(exits)
            .map(|((nullifier_pk, slot), exit)| {
                AnonymousOutputOpening::read(*nullifier_pk, slot, *exit)
            })
            .collect();
        let inputs = match &at.inputs {
            AnonymousInputFields::Commitments {
                first,
                prefix_pairs,
            } => Self::read_commitments(layout, fields[*first], &fields[prefix_pairs.clone()])?,
            AnonymousInputFields::Openings {
                sender_nullifier_pk,
                amounts,
                openings,
            } => {
                let amounts = packed_bytes(
                    &fields[amounts.clone()],
                    DISCLOSURE_INPUT_AMOUNT_BYTES * ANONYMOUS_ENTRY_CLASS,
                )?;
                let (spent, unpublished) = amounts
                    .split_at_checked(DISCLOSURE_INPUT_AMOUNT_BYTES * layout.inputs)
                    .ok_or(AuditError::DisclosureLayout)?;
                zero(unpublished)?;
                let sender_key = block
                    .first_chunk::<DISCLOSURE_SENDER_KEY_BYTES>()
                    .ok_or(AuditError::DisclosureLayout)?;
                AnonymousInputs::Openings {
                    sender_key: *sender_key,
                    sender_nullifier_pk: fields[*sender_nullifier_pk],
                    inputs: spent
                        .as_chunks::<DISCLOSURE_INPUT_AMOUNT_BYTES>()
                        .0
                        .iter()
                        .zip(fields[openings.clone()].chunks(2))
                        .map(|(amount, pair)| {
                            let opening = AnonymousInputOpening {
                                asset: pair[0],
                                amount: u64::from_be_bytes(*amount),
                                blinding: pair[1],
                            };
                            (opening != AnonymousInputOpening::default()).then_some(opening)
                        })
                        .collect(),
                }
            }
        };
        Ok(Self {
            layout,
            seed_out: at.seed_out.map(|index| fields[index]),
            outputs,
            inputs,
        })
    }

    /// Spent UTXO 0 is real, an even published count closes the last pair with a zero half.
    fn read_commitments(
        layout: AnonymousLayout,
        first: [u8; 32],
        pairs: &[[u8; 32]],
    ) -> Result<AnonymousInputs, AuditError> {
        if first == ZERO {
            return Err(AuditError::DisclosureLayout);
        }
        let mut prefixes = Vec::with_capacity(2 * pairs.len());
        for pair in pairs {
            prefixes.extend(InputPrefix::split(pair).ok_or(AuditError::DisclosureField)?);
        }
        if prefixes.len() >= layout.inputs && prefixes.pop().flatten().is_some() {
            return Err(AuditError::DisclosurePadding);
        }
        Ok(AnonymousInputs::Commitments { first, prefixes })
    }
}

fn packed_bytes(fields: &[[u8; 32]], len: usize) -> Result<Zeroizing<Vec<u8>>, AuditError> {
    unpack_disclosure(fields, len)
        .map(Zeroizing::new)
        .ok_or(AuditError::DisclosurePadding)
}

fn check_len(found: usize, expected: usize) -> Result<(), AuditError> {
    match found == expected {
        true => Ok(()),
        false => Err(AuditError::DisclosureLayout),
    }
}

fn place_seed_out(
    fields: &mut [[u8; 32]],
    at: Option<usize>,
    seed_out: Option<[u8; 32]>,
) -> Result<(), AuditError> {
    match (at, seed_out) {
        (Some(index), Some(seed_out)) => {
            fields[index] = seed_out;
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(AuditError::DisclosureLayout),
    }
}

fn key_and_amount(key: &[u8; 32], amount: u64) -> [u8; KEY_AND_AMOUNT_BYTES] {
    let mut bytes = [0; KEY_AND_AMOUNT_BYTES];
    let (head, tail) = bytes.split_at_mut(KEY_BYTES);
    head.copy_from_slice(key);
    tail.copy_from_slice(&amount.to_be_bytes());
    bytes
}

fn zero(bytes: &[u8]) -> Result<(), AuditError> {
    match bytes.iter().all(|byte| *byte == 0) {
        true => Ok(()),
        false => Err(AuditError::DisclosurePadding),
    }
}

pub(crate) fn canonical(field: [u8; 32]) -> Result<[u8; 32], AuditError> {
    match is_canonical_bn254_scalar_be(&field) {
        true => Ok(field),
        false => Err(AuditError::DisclosureField),
    }
}

#[cfg(test)]
mod tests;
