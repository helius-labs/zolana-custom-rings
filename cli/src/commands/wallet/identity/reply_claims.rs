use anyhow::{ensure, Context as _, Result};
use custom_ring_interface::RingMode;
use spr_keypair::{ShieldedKeypair, X25519Pubkey};

use crate::{file, ui::line, wallet::WalletScan, Context, ReplyClaimsArgs};

pub fn run(ctx: &Context, args: ReplyClaimsArgs) -> Result<()> {
    let config = ctx.ring_config()?;
    ensure!(
        config.mode == RingMode::Anonymous,
        "a reply travels on an anonymous ring, ring {} is not one",
        ctx.ring.program_id()
    );
    let keypair = match &args.keypair {
        Some(path) => file::read_keypair(&ctx.path(path))?,
        None => ctx.sender()?,
    };
    let member = ShieldedKeypair::from_keypair(&keypair)?;
    let store = ctx.anonymous_wallet_store(member.viewing_pubkey());
    let keys = ctx.ring_keys(&member)?;
    let assets = crate::assets::ring_assets(ctx.rpc())?;
    WalletScan {
        keys: &keys,
        assets: &assets,
        config: &config,
    }
    .fetch(ctx)?;
    if let Some(claimed) = &args.confirm {
        let bytes: [u8; 33] = hex::decode(claimed)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .context("--confirm takes a viewing key as 33 hex bytes")?;
        let sender = X25519Pubkey::from_bytes(bytes)?;
        store.update(|wallet| Ok(wallet.confirm_claim(sender)?))?;
        line("confirmed by you", claimed);
    }
    for claim in store.load()?.pending_claims() {
        line(
            "unverified claim",
            format_args!(
                "note {} says it came from viewing key {}",
                hex::encode(claim.utxo_hash),
                hex::encode(claim.claimed_viewing_key.as_bytes())
            ),
        );
    }
    Ok(())
}
