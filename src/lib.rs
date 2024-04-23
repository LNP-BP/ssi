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

#[macro_use]
extern crate amplify;

use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use amplify::{Bytes, Display};
use baid58::{Baid58ParseError, Chunking, FromBaid58, ToBaid58, CHUNKING_32};

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, Default)]
#[non_exhaustive]
pub enum Algo {
    #[default]
    #[display("bip340")]
    Bip340,
    // Ed25519,
    #[display("other({0})")]
    Other(u8),
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("unknown algorithm '{0}'")]
pub struct UnknownAlgo(String);

impl FromStr for Algo {
    type Err = UnknownAlgo;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bip340" | "Bip340" | "BIP340" => Ok(Algo::Bip340),
            s => Err(UnknownAlgo(s.to_owned())),
        }
    }
}

impl From<Algo> for u8 {
    fn from(algo: Algo) -> Self {
        match algo {
            Algo::Bip340 => 0,
            Algo::Other(v) => v,
        }
    }
}

impl From<u8> for Algo {
    fn from(value: u8) -> Self {
        match value {
            0 => Algo::Bip340,
            n => Algo::Other(n),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Default, Display)]
#[display(lowercase)]
#[non_exhaustive]
pub enum Chain {
    #[default]
    Bitcoin,
    Liquid,
    #[display("other({0})")]
    Other(u8),
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("unknown chain '{0}'")]
pub struct UnknownChain(String);

impl FromStr for Chain {
    type Err = UnknownChain;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "bitcoin" => Ok(Chain::Bitcoin),
            "liquid" => Ok(Chain::Liquid),
            s => Err(UnknownChain(s.to_owned())),
        }
    }
}

impl From<Chain> for u8 {
    fn from(chain: Chain) -> Self {
        match chain {
            Chain::Bitcoin => 0,
            Chain::Liquid => 1,
            Chain::Other(v) => v,
        }
    }
}

impl From<u8> for Chain {
    fn from(value: u8) -> Self {
        match value {
            0 => Chain::Bitcoin,
            1 => Chain::Liquid,
            n => Chain::Other(n),
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct Ssi {
    chain: Chain,
    algo: Algo,
    key: Bytes<30>,
}

impl ToBaid58<32> for Ssi {
    const HRI: &'static str = "ssi";
    const CHUNKING: Option<Chunking> = CHUNKING_32;

    fn to_baid58_payload(&self) -> [u8; 32] { <[u8; 32]>::from(*self) }
    fn to_baid58_string(&self) -> String { self.to_string() }
}

impl From<Ssi> for [u8; 32] {
    fn from(ssi: Ssi) -> Self {
        let mut buf = [0u8; 32];
        buf[0..30].copy_from_slice(ssi.key.as_slice());
        buf[30] = ssi.algo.into();
        buf[31] = ssi.chain.into();
        buf
    }
}

impl From<[u8; 32]> for Ssi {
    fn from(value: [u8; 32]) -> Self {
        let key = Bytes::from_slice_unsafe(&value[0..30]);
        let algo = Algo::from(value[30]);
        let chain = Chain::from(value[31]);
        Self { algo, key, chain }
    }
}

impl FromBaid58<32> for Ssi {}

impl Display for Ssi {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { write!(f, "{::<.2}", self.to_baid58()) }
}
impl FromStr for Ssi {
    type Err = Baid58ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_baid58_maybe_chunked_str(s, ':', '#')
    }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("invalid public key")]
pub struct InvalidPublicKey;

impl TryFrom<Ssi> for secp256k1::XOnlyPublicKey {
    type Error = InvalidPublicKey;

    fn try_from(ssi: Ssi) -> Result<Self, Self::Error> {
        Self::from_slice(&<[u8; 32]>::from(ssi)).map_err(|_| InvalidPublicKey)
    }
}

impl Ssi {
    pub fn new(chain: Chain) -> Self {
        use rand::thread_rng;
        use secp256k1::SECP256K1;
        loop {
            let sk = secp256k1::SecretKey::new(&mut thread_rng());
            let (pk, _) = sk.x_only_public_key(&SECP256K1);
            let data = pk.serialize();
            if data[30] == u8::from(Algo::Bip340) && data[31] == u8::from(chain) {
                let mut key = [0u8; 30];
                key.copy_from_slice(&data[0..30]);
                return Self {
                    chain,
                    algo: Algo::Bip340,
                    key: key.into(),
                };
            }
        }
    }

    pub fn vanity(prefix: &str, chain: Chain, threads: u8) -> Self {
        let (tx, rx) = crossbeam_channel::bounded(1);
        for _ in 0..threads {
            let tx = tx.clone();
            let prefix = prefix.to_owned();
            std::thread::spawn(move || {
                loop {
                    let new = Self::new(chain);
                    let start = format!("ssi:{prefix}");
                    if new.to_string().starts_with(&start) {
                        tx.send(new).expect("unable to send key");
                    }
                }
            });
        }
        rx.recv().expect("threading failed")
    }

    pub fn from_bip340(key: secp256k1::XOnlyPublicKey) -> Self {
        let bytes = key.serialize();
        Self::from(bytes)
    }
}
