use std::{
    collections::HashSet,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use hyper::{HeaderMap, Request};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::error::API_KEY_PARAMETER;

const API_KEY_HEADER: &str = "x-api-key";
const FORWARDED_FOR_HEADER: &str = "x-forwarded-for";

/// Set by the accept loop on every request of the connection.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerAddress(pub(crate) SocketAddr);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ClientIdentity {
    /// One per IPv4 address or IPv6 /64.
    Address(IpAddr),
    ApiKey(ApiKeyDigest),
}

/// SHA-256 of an API key, the service never holds the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApiKeyDigest([u8; 32]);

#[derive(Debug, Error)]
#[error("api key digest is not 64 lowercase hex characters")]
pub struct ApiKeyDigestError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnknownApiKey;

#[must_use]
#[derive(Clone, Debug, Default)]
pub struct ClientIdentityPolicy {
    trusted_proxies: HashSet<IpAddr>,
    api_keys: HashSet<ApiKeyDigest>,
}

impl FromStr for ApiKeyDigest {
    type Err = ApiKeyDigestError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return Err(ApiKeyDigestError);
        }
        let mut digest = [0u8; 32];
        hex::decode_to_slice(text, &mut digest).map_err(|_| ApiKeyDigestError)?;
        Ok(Self(digest))
    }
}

impl ApiKeyDigest {
    fn of(key: &[u8]) -> Self {
        Self(Sha256::digest(key).into())
    }
}

impl ClientIdentityPolicy {
    /// Only these peers may name the client in `x-forwarded-for`.
    pub fn with_trusted_proxies(mut self, proxies: impl IntoIterator<Item = IpAddr>) -> Self {
        self.trusted_proxies = proxies.into_iter().map(|ip| ip.to_canonical()).collect();
        self
    }

    /// Once set, a request naming any other key is refused.
    pub fn with_api_keys(mut self, digests: impl IntoIterator<Item = ApiKeyDigest>) -> Self {
        self.api_keys = digests.into_iter().collect();
        self
    }

    pub(crate) fn identify<B>(
        &self,
        peer: IpAddr,
        request: &Request<B>,
    ) -> Result<ClientIdentity, UnknownApiKey> {
        if let Some(key) = api_key(request).filter(|_| !self.api_keys.is_empty()) {
            let digest = ApiKeyDigest::of(key);
            if !self.api_keys.contains(&digest) {
                return Err(UnknownApiKey);
            }
            return Ok(ClientIdentity::ApiKey(digest));
        }
        let client = if self.trusts(peer) {
            self.forwarded_client(request.headers()).unwrap_or(peer)
        } else {
            peer
        };
        Ok(ClientIdentity::Address(client_address(client)))
    }

    fn trusts(&self, ip: IpAddr) -> bool {
        self.trusted_proxies.contains(&ip.to_canonical())
    }

    /// The nearest hop no trusted proxy holds, every hop past it is the client's own claim.
    fn forwarded_client(&self, headers: &HeaderMap) -> Option<IpAddr> {
        for value in headers.get_all(FORWARDED_FOR_HEADER).iter().rev() {
            for hop in value.to_str().ok()?.rsplit(',') {
                let hop = hop.trim().parse::<IpAddr>().ok()?;
                if !self.trusts(hop) {
                    return Some(hop);
                }
            }
        }
        None
    }
}

/// The header, else the `api-key` query value as sent.
fn api_key<B>(request: &Request<B>) -> Option<&[u8]> {
    request
        .headers()
        .get(API_KEY_HEADER)
        .map(|key| key.as_bytes())
        .or_else(|| {
            request
                .uri()
                .query()?
                .split('&')
                .find_map(|pair| pair.strip_prefix(API_KEY_PARAMETER))
                .map(str::as_bytes)
        })
}

/// One host holds a whole IPv6 /64.
fn client_address(ip: IpAddr) -> IpAddr {
    match ip.to_canonical() {
        IpAddr::V6(v6) => IpAddr::V6(Ipv6Addr::from(u128::from(v6) & !u128::from(u64::MAX))),
        v4 => v4,
    }
}
