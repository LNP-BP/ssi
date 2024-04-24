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

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};
use std::str::{FromStr, Utf8Error};

use chrono::{DateTime, Utc};
use fluent_uri::Uri;
use percent_encoding::{percent_decode_str, utf8_percent_encode, CONTROLS};
use sha2::{Digest, Sha256};

use crate::baid64::Baid64ParseError;
use crate::{InvalidSig, SsiPub, SsiSecret, SsiSig};

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum UidParseError {
    #[from]
    /// non-UTF-8 UID. {0}
    Utf8(Utf8Error),
    /// UID '{0}' without identity part
    NoId(String),
    /// UID '{0}' without identity schema
    NoSchema(String),
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("{name} <{schema}:{id}>")]
pub struct Uid {
    pub name: String,
    pub schema: String,
    pub id: String,
}

impl Uid {
    pub fn from_url_str(s: &str) -> Result<Self, UidParseError> {
        let s = percent_decode_str(s).decode_utf8()?;
        Self::parse_str(&s)
    }

    fn parse_str(s: &str) -> Result<Self, UidParseError> {
        let (name, rest) = s
            .rsplit_once(' ')
            .ok_or_else(|| UidParseError::NoId(s.to_string()))?;
        let (schema, id) = rest
            .split_once(':')
            .ok_or_else(|| UidParseError::NoSchema(rest.to_owned()))?;
        Ok(Self {
            name: name.to_owned(),
            schema: schema.to_owned(),
            id: id.to_owned(),
        })
    }
}

impl FromStr for Uid {
    type Err = UidParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::parse_str(&s.replace(['<', '>'], "")) }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct Ssi {
    pub pk: SsiPub,
    pub uids: BTreeSet<Uid>,
    pub expiry: Option<DateTime<Utc>>,
    pub sig: SsiSig,
}

impl Ssi {
    pub fn new(uids: BTreeSet<Uid>, expiry: Option<DateTime<Utc>>, secret: &SsiSecret) -> Self {
        let mut me = Self {
            pk: secret.to_public(),
            uids,
            expiry,
            sig: SsiSig([0u8; 64]),
        };
        me.sig = secret.sign(me.to_message());
        me
    }

    fn to_message(&self) -> [u8; 32] {
        let s = self.to_string();
        let (mut s, _) = s.rsplit_once("sig=").expect("no signature");
        s = s.trim_end_matches(&['&', '?']);
        let msg = Sha256::digest(s);
        Sha256::digest(msg).into()
    }

    pub fn check_integrity(&self) -> Result<(), InvalidSig> {
        self.sig.verify(self.pk, self.to_message())
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SsiParseError {
    #[from]
    #[display(inner)]
    InvalidUri(fluent_uri::ParseError),
    /// SSI must be a valid URI containing schema part.
    NoUriScheme,
    /// SSI must start with 'ssi:' prefix (URI scheme).
    InvalidScheme(String),
    /// the SSI must be signed
    Unsigned,
    /// SSI contains invalid attribute '{0}'.
    InvalidQueryParam(String),
    /// SSI contains unknown attribute '{0}'.
    UnknownParam(String),
    /// SSI contains multiple expiration dates.
    RepeatedExpiry,
    /// SSI contains multiple signatures.
    RepeatedSig,

    #[from]
    /// SSI contains {0}
    InvalidUid(UidParseError),

    #[from]
    /// SSI contains signature not matching the provided data. {0}
    WrongSig(InvalidSig),

    #[from]
    /// SSI contains non-parsable expiration date. {0}
    WrongExpiry(chrono::ParseError),

    /// SSI contains non-parsable public key. {0}
    InvalidPub(Baid64ParseError),
    /// SSI contains non-parsable signature. {0}
    InvalidSig(Baid64ParseError),
}

impl FromStr for Ssi {
    type Err = SsiParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = Uri::parse(s)?;

        let scheme = uri.scheme().ok_or(SsiParseError::NoUriScheme)?;
        if scheme.as_str() != "ssi" {
            return Err(SsiParseError::InvalidScheme(scheme.to_string()));
        }

        let pk = uri.path().as_str();
        let ssi = SsiPub::from_str(pk).map_err(SsiParseError::InvalidPub)?;

        let query = uri.query().ok_or(SsiParseError::Unsigned)?.as_str();

        let mut expiry = None;
        let mut sig = None;
        let mut uids = bset![];
        for p in query.split('&') {
            let (k, v) = p
                .split_once('=')
                .ok_or_else(|| SsiParseError::InvalidQueryParam(p.to_owned()))?;
            match k {
                "expiry" if expiry.is_none() => {
                    expiry = Some(DateTime::parse_from_str(v, "%Y-%m-%d")?.to_utc())
                }
                "expiry" => return Err(SsiParseError::RepeatedExpiry),
                "uid" => {
                    uids.insert(Uid::from_url_str(v)?);
                }
                "sig" if sig.is_none() => {
                    sig = Some(SsiSig::from_str(v).map_err(SsiParseError::InvalidSig)?)
                }
                "sig" => return Err(SsiParseError::RepeatedSig),
                other => return Err(SsiParseError::UnknownParam(other.to_owned())),
            }
        }

        let Some(sig) = sig else {
            return Err(SsiParseError::Unsigned);
        };
        let ssi = Self {
            pk: ssi,
            uids,
            expiry,
            sig,
        };
        ssi.check_integrity()?;

        Ok(ssi)
    }
}

impl Display for Ssi {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}?", self.pk)?;

        for uid in &self.uids {
            write!(
                f,
                "uid={}+{}:{}&",
                utf8_percent_encode(&uid.name, CONTROLS),
                utf8_percent_encode(&uid.schema, CONTROLS),
                utf8_percent_encode(&uid.id, CONTROLS)
            )?;
        }

        if let Some(expiry) = self.expiry {
            write!(f, "expiry={}&", expiry.format("%Y-%m-%d"))?;
        }

        write!(f, "sig={}", self.sig)?;

        Ok(())
    }
}
