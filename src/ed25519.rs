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
use std::hash::{Hash, Hasher};
use std::ops::Deref;

use ec25519::{KeyPair, Noise, PublicKey, SecretKey, Seed, Signature};

use crate::{Algo, Chain, InvalidPubkey, InvalidSig, SsiPub, SsiSig};

#[derive(Clone, Eq, PartialEq, From)]
pub struct Ed25519Secret(pub(crate) SecretKey);

impl Ord for Ed25519Secret {
    fn cmp(&self, other: &Self) -> Ordering { self.0.as_slice().cmp(other.0.as_slice()) }
}

impl PartialOrd for Ed25519Secret {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Hash for Ed25519Secret {
    fn hash<H: Hasher>(&self, state: &mut H) { self.0.as_slice().hash(state) }
}

impl From<Ed25519Secret> for [u8; 64] {
    fn from(ssi: Ed25519Secret) -> Self { *ssi.0.deref() }
}

impl From<[u8; 64]> for Ed25519Secret {
    fn from(value: [u8; 64]) -> Self {
        Self(SecretKey::from_slice(&value).expect("invalid secret key"))
    }
}

impl Ed25519Secret {
    pub fn new(chain: Chain) -> Self {
        loop {
            let pair = KeyPair::from_seed(Seed::generate());
            let pk = pair.pk;

            let sig = pair.sk.sign("test", Some(Noise::generate()));
            pk.verify("test", &sig).expect("unable to create key");

            if pk[30] == u8::from(Algo::Ed25519) && pk[31] == u8::from(chain) {
                return Self(pair.sk);
            }
        }
    }

    pub fn to_public(&self) -> SsiPub {
        let pk = self.0.public_key();
        SsiPub::from(*pk)
    }

    pub fn sign(&self, msg: [u8; 32]) -> SsiSig {
        let sig = self.0.sign(msg, None);
        SsiSig::from(*sig)
    }
}

impl SsiPub {
    pub fn verify_ed25519(self, msg: [u8; 32], sig: SsiSig) -> Result<(), InvalidSig> {
        let sig = Signature::from_slice(sig.as_slice()).map_err(|_| InvalidSig::InvalidData)?;
        let pk = PublicKey::try_from(self)?;
        pk.verify(msg, &sig).map_err(|err| {
            eprintln!("{err}");
            InvalidSig::InvalidSig
        })
    }
}

impl TryFrom<SsiPub> for PublicKey {
    type Error = InvalidPubkey;

    fn try_from(ssi: SsiPub) -> Result<Self, Self::Error> {
        Self::from_slice(&<[u8; 32]>::from(ssi)).map_err(|_| InvalidPubkey)
    }
}

impl SsiPub {
    pub fn from_ed25519(key: PublicKey) -> Self { Self::from(*key) }
}
