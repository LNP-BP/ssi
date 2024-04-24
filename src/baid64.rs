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
const LEN: usize = 32;

pub const BAID64_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789@$";

pub trait ToBaid64 {
    const HRI: &'static str;
    const CHUNKING: bool;
    const PREFIX: bool;
    const MNEMONIC: bool;

    fn to_baid64_payload(&self) -> [u8; 32];
    fn to_baid64(&self) -> Baid64 {
        Baid64::with(
            Self::HRI,
            self.to_baid64_payload(),
            Self::CHUNKING,
            Self::PREFIX,
            Self::MNEMONIC,
        )
    }
    fn to_baid64_string(&self) -> String { self.to_baid64().to_string() }
    fn fmt_baid64(&self, f: &mut Formatter) -> fmt::Result { Display::fmt(&self.to_baid64(), f) }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub struct Baid64 {
    hri: &'static str,
    chunking: bool,
    mnemonic: String,
    prefix: bool,
    suffix: bool,
    checksum: u32,
    payload: [u8; LEN],
}

impl Baid64 {
    pub fn with(
        hri: &'static str,
        payload: [u8; LEN],
        chunking: bool,
        prefix: bool,
        suffix: bool,
    ) -> Self {
        debug_assert!(hri.len() <= HRI_MAX_LEN, "HRI is too long");
        debug_assert!(LEN > HRI_MAX_LEN, "Baid64 id must be at least 9 bytes");

        let key = sha2::Sha256::digest(hri.as_bytes());
        let mut sha = sha2::Sha256::new_with_prefix(key);
        sha.update(&payload);
        let sha = sha.finalize();
        let checksum = u32::from_le_bytes([sha[0], sha[1], sha[1], sha[2]]);
        let mnemonic = mnemonic::to_string(checksum.to_le_bytes());

        Self {
            hri,
            chunking,
            mnemonic,
            prefix,
            suffix,
            checksum,
            payload,
        }
    }

    pub fn plain(hri: &'static str, payload: [u8; LEN]) -> Self {
        Self::with(hri, payload, false, false, false)
    }
    pub fn chunked(hri: &'static str, payload: [u8; LEN]) -> Self {
        Self::with(hri, payload, true, false, false)
    }
    pub fn full(hri: &'static str, payload: [u8; LEN]) -> Self {
        Self::with(hri, payload, true, true, true)
    }

    pub const fn human_identifier(&self) -> &'static str { self.hri }

    pub fn mnemonic(&self) -> &str { &self.mnemonic }
    pub const fn checksum(&self) -> u32 { self.checksum }
}

impl Display for Baid64 {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        use base64::alphabet::Alphabet;
        use base64::engine::general_purpose::NO_PAD;
        use base64::engine::GeneralPurpose;

        if (self.prefix && !f.sign_minus()) || (!self.prefix && f.sign_minus()) {
            write!(f, "{}:", self.hri)?;
        }

        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, NO_PAD);
        let s = engine.encode(self.payload);

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
