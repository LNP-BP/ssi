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

use std::fmt::{self, Display, Formatter};
use std::hash::Hash;
use std::str::FromStr;

use amplify::{Bytes, Display};

use crate::baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};

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
pub struct SsiPub {
    pub(crate) chain: Chain,
    pub(crate) algo: Algo,
    pub(crate) key: Bytes<30>,
}

impl DisplayBaid64 for SsiPub {
    const HRI: &'static str = "ssi";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 32] { <[u8; 32]>::from(*self) }
}

impl FromBaid64Str for SsiPub {}

impl From<SsiPub> for [u8; 32] {
    fn from(ssi: SsiPub) -> Self { ssi.to_byte_array() }
}

impl From<[u8; 32]> for SsiPub {
    fn from(value: [u8; 32]) -> Self {
        let key = Bytes::from_slice_unsafe(&value[0..30]);
        let algo = Algo::from(value[30]);
        let chain = Chain::from(value[31]);
        Self { algo, key, chain }
    }
}

impl SsiPub {
    pub fn to_byte_array(&self) -> [u8; 32] {
        let mut buf = [0u8; 32];
        buf[0..30].copy_from_slice(self.key.as_slice());
        buf[30] = self.algo.into();
        buf[31] = self.chain.into();
        buf
    }
}

impl Display for SsiPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl FromStr for SsiPub {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
pub struct SsiSig(pub(crate) [u8; 64]);

impl DisplayBaid64<64> for SsiSig {
    const HRI: &'static str = "ssi:sig";
    const CHUNKING: bool = false;
    const PREFIX: bool = false;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 64] { self.0 }
}

impl FromBaid64Str<64> for SsiSig {}

impl FromStr for SsiSig {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}

impl Display for SsiSig {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("invalid public key")]
pub struct InvalidPubkey;

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum InvalidSig {
    /// invalid signature data.
    InvalidData,

    /// invalid identity public key.
    InvalidSsi,

    /// signature doesn't match the given identity and a message.
    InvalidSig,
}
