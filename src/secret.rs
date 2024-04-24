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

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes256, Block};
use sha2::{Digest, Sha256};

use crate::baid64::{Baid64ParseError, FromBaid64Str, ToBaid64};
use crate::{Chain, SsiPub};

#[derive(Clone, Eq, PartialEq)]
pub struct SsiSecret(pub(crate) secp256k1::SecretKey);

impl Ord for SsiSecret {
    fn cmp(&self, other: &Self) -> Ordering { self.secret_bytes().cmp(&other.secret_bytes()) }
}

impl PartialOrd for SsiSecret {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Hash for SsiSecret {
    fn hash<H: Hasher>(&self, state: &mut H) { self.secret_bytes().hash(state) }
}

impl ToBaid64 for SsiSecret {
    const HRI: &'static str = "ssi:priv";
    const CHUNKING: bool = false;
    const PREFIX: bool = true;
    const MNEMONIC: bool = false;

    fn to_baid64_payload(&self) -> [u8; 32] { <[u8; 32]>::from(self.clone()) }
}

impl FromBaid64Str for SsiSecret {}

impl From<SsiSecret> for [u8; 32] {
    fn from(ssi: SsiSecret) -> Self { ssi.0.secret_bytes() }
}

impl From<[u8; 32]> for SsiSecret {
    fn from(value: [u8; 32]) -> Self {
        Self(secp256k1::SecretKey::from_slice(&value).expect("invalid secret key"))
    }
}

impl Display for SsiSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { self.fmt_baid64(f) }
}

impl FromStr for SsiSecret {
    type Err = Baid64ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_baid64_str(s) }
}

impl SsiSecret {
    pub fn vanity(prefix: &str, chain: Chain, threads: u8) -> Self {
        let (tx, rx) = crossbeam_channel::bounded(1);
        for _ in 0..threads {
            let tx = tx.clone();
            let prefix = prefix.to_owned();
            std::thread::spawn(move || {
                loop {
                    let sk = Self::new(chain);
                    let pk = sk.to_public();
                    let start = format!("ssi:{prefix}");
                    if pk.to_string().starts_with(&start) {
                        tx.send(sk).expect("unable to send key");
                    }
                }
            });
        }
        rx.recv().expect("threading failed")
    }

    pub fn encrypt(&mut self, passwd: impl AsRef<str>) {
        let key = Sha256::digest(passwd.as_ref().as_bytes());
        let key = GenericArray::from_slice(key.as_slice());
        let cipher = Aes256::new(key);

        let mut source = self.0.secret_bytes().to_vec();
        for chunk in source.chunks_mut(16) {
            let block = Block::from_mut_slice(chunk);
            cipher.encrypt_block(block);
        }
        self.0 = secp256k1::SecretKey::from_slice(&source).expect("same size")
    }

    pub fn decrypt(&mut self, passwd: impl AsRef<str>) {
        let key = Sha256::digest(passwd.as_ref().as_bytes());
        let key = GenericArray::from_slice(key.as_slice());
        let cipher = Aes256::new(key);

        let mut source = self.0.secret_bytes().to_vec();
        for chunk in source.chunks_mut(16) {
            let block = Block::from_mut_slice(chunk);
            cipher.decrypt_block(block);
        }
        self.0 = secp256k1::SecretKey::from_slice(&source).expect("same size")
    }

    pub fn secret_bytes(&self) -> [u8; 32] { self.0.secret_bytes() }
}

impl From<SsiSecret> for SsiPub {
    fn from(sk: SsiSecret) -> Self { sk.to_public() }
}
