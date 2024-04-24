// Base64-encoded identifiers
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2024 by
//     Dr Maxim Orlovsky <orlovsky@cyphernet.io>
//
// Copyright (C) 2024 Cyphernet. All rights reserved.
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

use base64::Engine;
use sha2::Digest;

pub const HRI_MAX_LEN: usize = 16;

pub const BAID64_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$";

fn check<const LEN: usize>(hri: &'static str, payload: [u8; LEN]) -> [u8; 4] {
    let key = sha2::Sha256::digest(hri.as_bytes());
    let mut sha = sha2::Sha256::new_with_prefix(key);
    sha.update(&payload);
    let sha = sha.finalize();
    [sha[0], sha[1], sha[1], sha[2]]
}

pub trait DisplayBaid64<const LEN: usize = 32> {
    const HRI: &'static str;
    const CHUNKING: bool;
    const PREFIX: bool;
    const EMBED_CHECKSUM: bool;
    const MNEMONIC: bool;

    fn to_baid64_payload(&self) -> [u8; LEN];
    fn to_baid64_string(&self) -> String { self.display_baid64().to_string() }
    fn to_baid64_mnemonic(&self) -> String { self.display_baid64().mnemonic }
    fn display_baid64(&self) -> Baid64Display<LEN> {
        Baid64Display::with(
            Self::HRI,
            self.to_baid64_payload(),
            Self::CHUNKING,
            Self::PREFIX,
            Self::MNEMONIC,
            Self::EMBED_CHECKSUM,
        )
    }
    fn fmt_baid64(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(&self.display_baid64(), f)
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum Baid64ParseError {
    /// invalid human-readable prefix in {0} ({1} is expected).
    InvalidHri(String, &'static str),

    /// invalid length of identifier {0}.
    InvalidLen(String),

    /// invalid checksum value in {0} - expected {1:#x} while found
    /// {2:#x}.
    InvalidChecksum(String, u32, u32),

    /// invalid length of mnemonic in {0}.
    InvalidMnemonicLen(String),

    #[from]
    #[display(inner)]
    InvalidMnemonic(mnemonic::Error),

    #[from]
    #[display(inner)]
    Base64(base64::DecodeError),
}

pub trait FromBaid64Str<const LEN: usize = 32>: DisplayBaid64<LEN> + From<[u8; LEN]> {
    fn from_baid64_str(mut s: &str) -> Result<Self, Baid64ParseError> {
        let orig = s;

        use base64::alphabet::Alphabet;
        use base64::engine::general_purpose::NO_PAD;
        use base64::engine::GeneralPurpose;

        let mut checksum = None;

        if let Some((hri, rest)) = s.rsplit_once(':') {
            if hri != Self::HRI {
                return Err(Baid64ParseError::InvalidHri(orig.to_owned(), Self::HRI));
            }
            s = rest;
        }

        if let Some((rest, sfx)) = s.split_once('#') {
            let mut mnemo = Vec::<u8>::with_capacity(4);
            mnemonic::decode(sfx, &mut mnemo)?;
            if mnemo.len() != 4 {
                return Err(Baid64ParseError::InvalidMnemonicLen(orig.to_string()));
            }
            checksum = Some([mnemo[0], mnemo[1], mnemo[2], mnemo[3]]);
            s = rest;
        }

        let s = if s.contains('-') {
            s.replace('-', "")
        } else {
            s.to_owned()
        };

        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, NO_PAD);
        let data = engine.decode(s)?;

        if data.len() != LEN && data.len() != LEN + 4 {
            return Err(Baid64ParseError::InvalidLen(orig.to_owned()));
        }
        let mut payload = [0u8; LEN];
        payload.copy_from_slice(&data[..LEN]);
        if data.len() == LEN + 4 {
            checksum = Some([data[LEN], data[LEN + 1], data[LEN + 2], data[LEN + 3]]);
        }

        let ck = check(Self::HRI, payload);
        if matches!(checksum, Some(c) if c != ck) {
            return Err(Baid64ParseError::InvalidChecksum(
                orig.to_owned(),
                u32::from_le_bytes(ck),
                u32::from_le_bytes(checksum.unwrap()),
            ));
        }

        Ok(Self::from(payload))
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Baid64Display<const LEN: usize = 32> {
    hri: &'static str,
    chunking: bool,
    mnemonic: String,
    prefix: bool,
    suffix: bool,
    embed_checksum: bool,
    checksum: [u8; 4],
    payload: [u8; LEN],
}

impl<const LEN: usize> Baid64Display<LEN> {
    pub fn with(
        hri: &'static str,
        payload: [u8; LEN],
        chunking: bool,
        prefix: bool,
        suffix: bool,
        embed_checksum: bool,
    ) -> Self {
        debug_assert!(hri.len() <= HRI_MAX_LEN, "HRI is too long");
        debug_assert!(LEN > HRI_MAX_LEN, "Baid64 id must be at least 9 bytes");

        let checksum = check(hri, payload);
        let mnemonic = mnemonic::to_string(checksum);

        Self {
            hri,
            chunking,
            mnemonic,
            prefix,
            suffix,
            embed_checksum,
            checksum,
            payload,
        }
    }

    pub fn new(hri: &'static str, payload: [u8; LEN]) -> Self {
        Self::with(hri, payload, false, false, false, false)
    }
    pub const fn use_hri(mut self) -> Self {
        self.prefix = true;
        self
    }
    pub const fn use_chunking(mut self) -> Self {
        self.chunking = true;
        self
    }
    pub const fn use_mnemonic(mut self) -> Self {
        self.suffix = true;
        self
    }
    pub const fn embed_checksum(mut self) -> Self {
        self.embed_checksum = true;
        self
    }

    pub const fn human_identifier(&self) -> &'static str { self.hri }

    pub fn mnemonic(&self) -> &str { self.mnemonic.as_str() }
    pub const fn checksum(&self) -> [u8; 4] { self.checksum }
}

impl<const LEN: usize> Display for Baid64Display<LEN> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use base64::alphabet::Alphabet;
        use base64::engine::general_purpose::NO_PAD;
        use base64::engine::GeneralPurpose;

        if (self.prefix && !f.sign_minus()) || (!self.prefix && f.sign_minus()) {
            write!(f, "{}:", self.hri)?;
        }

        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, NO_PAD);

        let mut payload = self.payload.to_vec();
        if self.embed_checksum {
            payload.extend(self.checksum);
        }
        let s = engine.encode(payload);

        if self.chunking {
            let bytes = s.as_bytes();
            f.write_str(&String::from_utf8_lossy(&bytes[..6]))?;
            for chunk in bytes[6..].chunks(8) {
                write!(f, "-{}", &String::from_utf8_lossy(chunk))?;
            }
        } else {
            f.write_str(&s)?;
        }

        if (self.suffix && !f.alternate()) || (!self.suffix && f.alternate()) {
            write!(f, "#{}", self.mnemonic)?;
        }

        Ok(())
    }
}
