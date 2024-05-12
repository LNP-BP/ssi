// Self-sovereign identity
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::cmp::Ordering;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, SecretKey, XOnlyPublicKey, SECP256K1};

use crate::{Algo, Chain, InvalidPubkey, InvalidSig, SsiPub, SsiSig};

#[derive(Clone, Eq, PartialEq)]
pub struct Bip340Secret(pub(crate) SecretKey);

impl Ord for Bip340Secret {
    fn cmp(&self, other: &Self) -> Ordering { self.0.secret_bytes().cmp(&other.0.secret_bytes()) }
}

impl PartialOrd for Bip340Secret {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Hash for Bip340Secret {
    fn hash<H: Hasher>(&self, state: &mut H) { self.0.secret_bytes().hash(state) }
}

impl DisplayBaid64 for Bip340Secret {
    const HRI: &'static str = "bip340-priv";
    const CHUNKING: bool = false;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = true;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 32] { <[u8; 32]>::from(self.clone()) }
}

impl FromBaid64Str for Bip340Secret {}

impl From<Bip340Secret> for [u8; 32] {
    fn from(ssi: Bip340Secret) -> Self { ssi.0.secret_bytes() }
}

impl From<[u8; 32]> for Bip340Secret {
    fn from(value: [u8; 32]) -> Self {
        Self(SecretKey::from_slice(&value).expect("invalid secret key"))
    }
}

impl Display for Bip340Secret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl FromStr for Bip340Secret {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}

impl Bip340Secret {
    pub fn new(chain: Chain) -> Self {
        use rand::thread_rng;
        loop {
            let sk = SecretKey::new(&mut thread_rng());
            let (pk, _) = sk.x_only_public_key(SECP256K1);
            let data = pk.serialize();
            if data[30] == u8::from(Algo::Bip340) && data[31] == u8::from(chain) {
                return Self(sk);
            }
        }
    }

    pub fn to_public(&self) -> SsiPub {
        let (pk, _) = self.0.x_only_public_key(SECP256K1);
        let data = pk.serialize();
        SsiPub::from(data)
    }

    pub fn sign(&self, msg: [u8; 32]) -> SsiSig {
        let msg = Message::from_digest(msg);
        let keypair = Keypair::from_secret_key(SECP256K1, &self.0);
        let sig = SECP256K1.sign_schnorr(&msg, &keypair);
        SsiSig::from(sig.serialize())
    }
}

impl SsiPub {
    pub fn verify_bip360(self, msg: [u8; 32], sig: SsiSig) -> Result<(), InvalidSig> {
        let sig = Signature::from_slice(sig.as_slice()).map_err(|_| InvalidSig::InvalidData)?;
        let msg = Message::from_digest(msg);
        let pk = XOnlyPublicKey::try_from(self)?;
        sig.verify(&msg, &pk).map_err(|_| InvalidSig::InvalidSig)
    }
}

impl TryFrom<SsiPub> for XOnlyPublicKey {
    type Error = InvalidPubkey;

    fn try_from(ssi: SsiPub) -> Result<Self, Self::Error> {
        Self::from_slice(&<[u8; 32]>::from(ssi)).map_err(|_| InvalidPubkey)
    }
}

impl SsiPub {
    pub fn from_bip340(key: XOnlyPublicKey) -> Self {
        let bytes = key.serialize();
        Self::from(bytes)
    }
}
