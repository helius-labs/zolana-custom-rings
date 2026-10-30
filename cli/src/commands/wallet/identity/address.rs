//! `address`, the `zolana:` payment request an anonymous ring pays a member through.

use anyhow::{ensure, Result};
use custom_ring_interface::RingMode;
use spr_keypair::ShieldedKeypair;
use zolana_ring_keys::{RingAddress, RingPaymentRequest};

use crate::{file, AddressArgs, Context};

pub fn run(ctx: &Context, args: AddressArgs) -> Result<()> {
    let config = ctx.ring_config()?;
    ensure!(
        config.mode == RingMode::Anonymous,
        "a `zolana:` request pays an anonymous ring, ring {} is not one",
        ctx.ring.program_id()
    );
    let keypair = match &args.keypair {
        Some(path) => file::read_keypair(&ctx.path(path))?,
        None => ctx.sender()?,
    };
    let member = ShieldedKeypair::from_keypair(&keypair)?;
    let address = RingAddress {
        recipient: member.shielded_address()?,
        ring_program_id: ctx.ring.program_id(),
    };
    // Stored before it prints, a sync reads every request tag a payer may hold.
    let request_view_tag = ctx.anonymous_wallet_store(&member).update(|history| {
        let minted = history.request_tag(&member)?;
        *history = minted.history;
        Ok(minted.tag)
    })?;
    println!("{}", args.request(address, request_view_tag));
    Ok(())
}

impl AddressArgs {
    fn request(self, address: RingAddress, request_view_tag: [u8; 32]) -> RingPaymentRequest {
        RingPaymentRequest {
            amount: self.amount,
            mint: self.mint.map(|mint| mint.0),
            label: self.label,
            ..RingPaymentRequest::new(address, request_view_tag)
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use serde::Deserialize;
    use spr_keypair::ShieldedAddress;

    use super::*;
    use crate::{Cli, Command};

    const VECTORS: &str = include_str!("../../../../../test-vectors/wallet/ring_address.json");

    #[derive(Deserialize)]
    struct Vectors {
        valid: Vec<Case>,
    }

    #[derive(Deserialize)]
    struct Case {
        name: String,
        uri: String,
        recipient: String,
        ring_program_id: String,
        request_view_tag: String,
        amount: Option<String>,
        mint: Option<String>,
        label: Option<String>,
    }

    fn parse(flags: &[&str]) -> AddressArgs {
        let argv = ["zolana-ring", "address"].iter().chain(flags).copied();
        match Cli::try_parse_from(argv).unwrap().command {
            Command::Address(args) => args,
            _ => panic!("address"),
        }
    }

    #[test]
    fn the_printed_request_matches_the_keypair_vectors() {
        for case in serde_json::from_str::<Vectors>(VECTORS).unwrap().valid {
            let recipient = hex::decode(&case.recipient).unwrap().try_into().unwrap();
            let mut flags = Vec::new();
            for (flag, value) in [
                ("--amount", &case.amount),
                ("--mint", &case.mint),
                ("--label", &case.label),
            ] {
                if let Some(value) = value {
                    flags.extend([flag, value.as_str()]);
                }
            }
            let address = RingAddress {
                recipient: ShieldedAddress::from_bytes(&recipient).unwrap(),
                ring_program_id: case.ring_program_id.parse().unwrap(),
            };
            let tag = hex::decode(&case.request_view_tag)
                .unwrap()
                .try_into()
                .unwrap();
            assert_eq!(
                parse(&flags).request(address, tag).to_string(),
                case.uri,
                "{}",
                case.name
            );
        }
    }
}
