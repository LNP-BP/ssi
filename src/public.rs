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
use std::io;
use std::str::FromStr;

use amplify::{hex, Bytes, Bytes32, Bytes64, Display};
use baid64::{Baid64ParseError, DisplayBaid64, FromBaid64Str};
use sha2::{Digest, Sha256};
use strict_encoding::{
    DecodeError, ReadTuple, StrictDecode, StrictEncode, StrictProduct, StrictTuple, StrictType,
    TypeName, TypedRead, TypedWrite, WriteTuple,
};

use crate::LIB_NAME_SSI;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, Display, Default)]
#[non_exhaustive]
pub enum Algo {
    #[default]
    #[display("ed25519")]
    Ed25519,
    #[display("bip340")]
    Bip340,
    #[display("other({0})")]
    Other(u8),
}

impl StrictType for Algo {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_SSI;
    fn strict_name() -> Option<TypeName> { Some(tn!("Algo")) }
}
impl StrictProduct for Algo {}
impl StrictTuple for Algo {
    const FIELD_COUNT: u8 = 1;
}
impl StrictEncode for Algo {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_tuple::<Self>(|w| Ok(w.write_field(&self.to_u8())?.complete()))
    }
}
impl StrictDecode for Algo {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let val = r.read_field::<u8>()?;
            Ok(Self::from(val))
        })
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display("unknown algorithm '{0}'")]
pub struct UnknownAlgo(String);

impl FromStr for Algo {
    type Err = UnknownAlgo;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ed25519" | "Ed25519" | "ED25519" => Ok(Algo::Ed25519),
            "bip340" | "Bip340" | "BIP340" => Ok(Algo::Bip340),
            s => Err(UnknownAlgo(s.to_owned())),
        }
    }
}

impl From<Algo> for u8 {
    fn from(algo: Algo) -> Self { algo.to_u8() }
}

impl From<u8> for Algo {
    fn from(value: u8) -> Self {
        match value {
            0x13 => Algo::Ed25519,
            0 => Algo::Bip340,
            n => Algo::Other(n),
        }
    }
}

impl Algo {
    pub fn to_u8(&self) -> u8 {
        match self {
            Algo::Ed25519 => 0x13,
            Algo::Bip340 => 0,
            Algo::Other(v) => *v,
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

impl StrictType for Chain {
    const STRICT_LIB_NAME: &'static str = LIB_NAME_SSI;
    fn strict_name() -> Option<TypeName> { Some(tn!("Chain")) }
}
impl StrictProduct for Chain {}
impl StrictTuple for Chain {
    const FIELD_COUNT: u8 = 1;
}
impl StrictEncode for Chain {
    fn strict_encode<W: TypedWrite>(&self, writer: W) -> io::Result<W> {
        writer.write_tuple::<Self>(|w| Ok(w.write_field(&self.to_u8())?.complete()))
    }
}
impl StrictDecode for Chain {
    fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
        reader.read_tuple(|r| {
            let val = r.read_field::<u8>()?;
            Ok(Self::from(val))
        })
    }
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
    fn from(chain: Chain) -> Self { chain.to_u8() }
}

impl From<u8> for Chain {
    fn from(value: u8) -> Self {
        match value {
            0xB7 => Chain::Bitcoin,
            0x10 => Chain::Liquid,
            n => Chain::Other(n),
        }
    }
}

impl Chain {
    pub fn to_u8(&self) -> u8 {
        match self {
            Chain::Bitcoin => 0xB7,
            Chain::Liquid => 0x10,
            Chain::Other(v) => *v,
        }
    }
}

#[derive(Getters, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSI)]
pub struct SsiPub {
    chain: Chain,
    algo: Algo,
    key: Bytes32,
}

impl DisplayBaid64<34> for SsiPub {
    const HRI: &'static str = "ssi";
    const CHUNKING: bool = true;
    const PREFIX: bool = true;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 34] { <[u8; 34]>::from(*self) }
}

impl FromBaid64Str<34> for SsiPub {}

impl From<SsiPub> for [u8; 34] {
    fn from(ssi: SsiPub) -> Self {
        let mut bytes = [0u8; 34];
        bytes[0] = ssi.algo.to_u8();
        bytes[1] = ssi.chain.to_u8();
        bytes[2..].copy_from_slice(&ssi.to_byte_array());
        bytes
    }
}

impl From<[u8; 34]> for SsiPub {
    fn from(value: [u8; 34]) -> Self {
        let algo = Algo::from(value[0]);
        let chain = Chain::from(value[1]);
        let key = Bytes::from_slice_unsafe(&value[2..]);
        Self { algo, key, chain }
    }
}

impl SsiPub {
    pub fn with(chain: Chain, algo: Algo, key: impl Into<[u8; 32]>) -> Self {
        Self {
            chain,
            algo,
            key: Bytes32::from(key.into()),
        }
    }

    pub fn verify_text(self, text: &str, sig: SsiSig) -> Result<(), InvalidSig> {
        let msg = Sha256::digest(text);
        let digest = Sha256::digest(msg);
        self.verify(digest.into(), sig)
    }

    pub fn verify(self, msg: [u8; 32], sig: SsiSig) -> Result<(), InvalidSig> {
        match self.algo {
            Algo::Ed25519 => self.verify_ed25519(msg, sig),
            Algo::Bip340 => self.verify_bip360(msg, sig),
            Algo::Other(other) => Err(InvalidSig::UnsupportedAlgo(other)),
        }
    }

    pub fn fingerprint(self) -> Fingerprint {
        Fingerprint([self.key[0], self.key[1], self.key[2], self.key[3], self.key[4], self.key[5]])
    }
}

impl Display for SsiPub {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if !f.alternate() {
            self.fmt_baid64(f)
        } else {
            write!(f, "{}", self.fingerprint())
        }
    }
}

impl FromStr for SsiPub {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSI)]
pub struct SsiSig(#[from([u8; 64])] Bytes64);

impl SsiSig {
    pub fn as_slice(&self) -> &[u8] { self.0.as_slice() }
}

impl DisplayBaid64<64> for SsiSig {
    const HRI: &'static str = "";
    const CHUNKING: bool = false;
    const PREFIX: bool = false;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 64] { self.0.to_byte_array() }
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

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum InvalidSig {
    /// invalid signature data.
    InvalidData,

    /// invalid identity public key.
    #[from(InvalidPubkey)]
    InvalidPubkey,

    /// signature doesn't match the given identity and a message.
    InvalidSig,

    /// can't verify signature - unsupported signature method {0}.
    UnsupportedAlgo(u8),
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default, Debug, Display, From)]
#[display(inner)]
pub enum SsiQuery {
    #[default]
    #[display("default key")]
    Default,
    #[from]
    Pub(SsiPub),
    #[from]
    Fp(Fingerprint),
    #[from]
    Id(String),
}

impl FromStr for SsiQuery {
    type Err = Baid64ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() == 8 {
            Fingerprint::from_str(s).map(Self::Fp)
        } else if s.starts_with("ssi:") || (s.contains('-') && (s.len() == 48 || s.len() == 52)) {
            SsiPub::from_str(s).map(Self::Pub)
        } else {
            Ok(SsiQuery::Id(s.to_owned()))
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSI)]
pub struct Fingerprint([u8; 6]);

impl DisplayBaid64<6> for Fingerprint {
    const HRI: &'static str = "";
    const CHUNKING: bool = false;
    const PREFIX: bool = false;
    const EMBED_CHECKSUM: bool = false;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 6] { self.0 }
}

impl FromBaid64Str<6> for Fingerprint {}

impl Display for Fingerprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl FromStr for Fingerprint {
    type Err = Baid64ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSI)]
pub struct SsiCert {
    pub fp: Fingerprint,
    pub pk: Option<SsiPub>,
    pub msg: Bytes32,
    pub sig: SsiSig,
}

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum VerifyError {
    #[display("the certificate has no identity, verification impossible.")]
    NoIdentity,
    #[from]
    InvalidSig(InvalidSig),
    #[display("the provided text doesn't match the signed message")]
    MessageMismatch,
}

impl SsiCert {
    pub fn verify(&self) -> Result<(), VerifyError> {
        let Some(pk) = self.pk else {
            return Err(VerifyError::NoIdentity);
        };
        Ok(pk.verify(self.msg.to_byte_array(), self.sig)?)
    }

    pub fn verify_text(&self, text: &str) -> Result<(), VerifyError> {
        let Some(pk) = self.pk else {
            return Err(VerifyError::NoIdentity);
        };
        let msg = Sha256::digest(text);
        let digest = Sha256::digest(msg);
        let msg = <[u8; 32]>::from(digest);
        if self.msg.to_byte_array() != msg {
            return Err(VerifyError::MessageMismatch);
        }
        Ok(pk.verify(digest.into(), self.sig)?)
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum CertParseError {
    /// SSI URI lacks signature or message information.
    DataMissed,
    /// invalid certificate identity fingerprint - {0}.
    InvalidFingerprint(Baid64ParseError),
    /// invalid certificate identity key - {0}.
    InvalidPub(Baid64ParseError),
    /// invalid message digest - {0}.
    #[from]
    InvalidMessage(hex::Error),
    #[from]
    /// invalid signature data - {0}
    InvalidSig(Baid64ParseError),
}

impl FromStr for SsiCert {
    type Err = CertParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (fp, rest) = s
            .trim_start_matches("ssi:")
            .split_once('?')
            .ok_or(CertParseError::DataMissed)?;
        let (msg, rest) = rest
            .trim_start_matches("msg=")
            .split_once('&')
            .ok_or(CertParseError::DataMissed)?;
        let sig = rest.trim_start_matches("sig=");
        let (fp, pk) = match fp.len() {
            8 => (Fingerprint::from_str(fp).map_err(CertParseError::InvalidFingerprint)?, None),
            _ => {
                let pk = SsiPub::from_str(fp).map_err(CertParseError::InvalidPub)?;
                (pk.fingerprint(), Some(pk))
            }
        };
        let msg = Bytes32::from_str(msg)?;
        let sig = SsiSig::from_str(sig)?;
        Ok(SsiCert { fp, pk, msg, sig })
    }
}

impl Display for SsiCert {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            if let Some(pk) = self.pk {
                return write!(f, "{pk}?msg={msg}&sig={sig}", msg = self.msg, sig = self.sig);
            }
        }
        write!(f, "ssi:{fp}?msg={msg}&sig={sig}", fp = self.fp, msg = self.msg, sig = self.sig)
    }
}
