//! Scheme 1 recipient and scheme 2 sender bundle plaintexts, the verified fields first.

use solana_address::Address;
use spr_keypair::{constants::PUBLIC_KEY_LEN, x25519::X25519_PUBKEY_LEN, PublicKey, X25519Pubkey};
use spr_transaction::{
    utxo::derive_transact_output_blinding, AssetRegistry, Data, Mint, TransactionError, Utxo,
};
use wincode::{containers, len::FixIntLen, SchemaRead, SchemaWrite};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferRecipientPlaintext {
    pub verified: VerifiedRecipientPlaintext,
    pub unverified: UnverifiedRecipientPlaintext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecipientPlaintext {
    pub owner_pubkey: PublicKey,
    pub mint: Address,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedRecipientPlaintext {
    /// Unauthenticated, the recipient pairs with whichever key the sender writes.
    pub sender_pubkey: X25519Pubkey,
    pub blinding: [u8; 32],
    pub data: Data,
}

/// Published as a message, its change outputs carry no ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnonymousTransferSenderPlaintext {
    pub verified: VerifiedSenderPlaintext,
    pub unverified: UnverifiedSenderPlaintext,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedSenderPlaintext {
    pub owner_pubkey: PublicKey,
    pub spl_mint: Address,
    pub spl_amount: u64,
    pub sol_amount: u64,
    /// One per recipient output, in output order.
    pub recipient_viewing_pks: Vec<X25519Pubkey>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnverifiedSenderPlaintext {
    pub blinding_seed: [u8; 32],
    pub spl_data: Data,
    pub sol_data: Data,
}

impl AnonymousTransferRecipientPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let Self {
            verified,
            unverified,
        } = self;
        unverified.data.validate()?;
        Ok(wincode::serialize(&RecipientWire {
            owner_pubkey: *verified.owner_pubkey.as_bytes(),
            mint: verified.mint,
            amount: verified.amount,
            sender_pubkey: *unverified.sender_pubkey.as_bytes(),
            blinding: unverified.blinding,
            data: unverified.data.clone(),
        })?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let wire: RecipientWire = wincode::deserialize_exact(bytes)?;
        wire.data.validate()?;
        Ok(Self {
            verified: VerifiedRecipientPlaintext {
                owner_pubkey: PublicKey::from_bytes(wire.owner_pubkey)?,
                mint: wire.mint,
                amount: wire.amount,
            },
            unverified: UnverifiedRecipientPlaintext {
                sender_pubkey: X25519Pubkey::from_bytes(wire.sender_pubkey)?,
                blinding: wire.blinding,
                data: wire.data,
            },
        })
    }

    /// A memo is the only record a recipient output carries.
    pub fn into_utxo(self, assets: &AssetRegistry) -> Result<Utxo, TransactionError> {
        let Self {
            verified,
            unverified,
        } = self;
        if unverified.data.ring_data().is_some() || unverified.data.utxo_data().is_some() {
            return Err(TransactionError::UnsupportedOutputData);
        }
        Ok(Utxo {
            owner: verified.owner_pubkey,
            asset: assets.mint(&verified.mint)?,
            amount: verified.amount,
            blinding: unverified.blinding,
            ring_program_id: None,
            data: unverified.data,
        })
    }
}

impl AnonymousTransferSenderPlaintext {
    pub fn serialize(&self) -> Result<Vec<u8>, TransactionError> {
        let Self {
            verified,
            unverified,
        } = self;
        unverified.spl_data.validate()?;
        unverified.sol_data.validate()?;
        Ok(wincode::serialize(&SenderWire {
            owner_pubkey: *verified.owner_pubkey.as_bytes(),
            spl_mint: verified.spl_mint,
            spl_amount: verified.spl_amount,
            sol_amount: verified.sol_amount,
            recipient_viewing_pks: verified
                .recipient_viewing_pks
                .iter()
                .map(|key| *key.as_bytes())
                .collect(),
            blinding_seed: unverified.blinding_seed,
            spl_data: unverified.spl_data.clone(),
            sol_data: unverified.sol_data.clone(),
        })?)
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, TransactionError> {
        let wire: SenderWire = wincode::deserialize_exact(bytes)?;
        wire.spl_data.validate()?;
        wire.sol_data.validate()?;
        Ok(Self {
            verified: VerifiedSenderPlaintext {
                owner_pubkey: PublicKey::from_bytes(wire.owner_pubkey)?,
                spl_mint: wire.spl_mint,
                spl_amount: wire.spl_amount,
                sol_amount: wire.sol_amount,
                recipient_viewing_pks: wire
                    .recipient_viewing_pks
                    .into_iter()
                    .map(X25519Pubkey::from_bytes)
                    .collect::<Result<_, _>>()?,
            },
            unverified: UnverifiedSenderPlaintext {
                blinding_seed: wire.blinding_seed,
                spl_data: wire.spl_data,
                sol_data: wire.sol_data,
            },
        })
    }

    /// A zero amount marks a change output absent, the SOL change at slot 1 only after an SPL change.
    pub fn into_utxos(
        self,
        first_nullifier: &[u8; 32],
        assets: &AssetRegistry,
    ) -> Result<Vec<Utxo>, TransactionError> {
        let Self {
            verified,
            unverified,
        } = self;
        if (verified.spl_amount == 0 && !unverified.spl_data.is_empty())
            || (verified.sol_amount == 0 && !unverified.sol_data.is_empty())
        {
            return Err(TransactionError::DataWithoutOutput);
        }
        let spl = (verified.spl_amount > 0)
            .then(|| assets.mint(&verified.spl_mint))
            .transpose()?
            .map(|mint| (mint, verified.spl_amount, unverified.spl_data));
        let sol = (verified.sol_amount > 0).then_some((
            Mint::SOL,
            verified.sol_amount,
            unverified.sol_data,
        ));
        let mut utxos = Vec::new();
        for (slot, (asset, amount, data)) in (0u32..).zip(spl.into_iter().chain(sol)) {
            if data.ring_data().is_some() {
                return Err(TransactionError::MissingRingProgramId);
            }
            utxos.push(Utxo {
                owner: verified.owner_pubkey,
                asset,
                amount,
                blinding: derive_transact_output_blinding(
                    first_nullifier,
                    &unverified.blinding_seed,
                    slot,
                )?,
                ring_program_id: None,
                data,
            });
        }
        Ok(utxos)
    }
}

#[derive(SchemaWrite, SchemaRead)]
struct RecipientWire {
    owner_pubkey: [u8; PUBLIC_KEY_LEN],
    mint: Address,
    amount: u64,
    sender_pubkey: [u8; X25519_PUBKEY_LEN],
    blinding: [u8; 32],
    data: Data,
}

#[derive(SchemaWrite, SchemaRead)]
struct SenderWire {
    owner_pubkey: [u8; PUBLIC_KEY_LEN],
    spl_mint: Address,
    spl_amount: u64,
    sol_amount: u64,
    #[wincode(with = "containers::Vec<[u8; X25519_PUBKEY_LEN], FixIntLen<u8>>")]
    recipient_viewing_pks: Vec<[u8; X25519_PUBKEY_LEN]>,
    blinding_seed: [u8; 32],
    spl_data: Data,
    sol_data: Data,
}
