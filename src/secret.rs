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

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes256, Block};
use amplify::Bytes32;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::baid64::Baid64ParseError;
use crate::{Algo, Bip340Secret, Chain, Ed25519Secret, Fingerprint, Ssi, SsiCert, SsiPub, SsiSig};

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SsiSecret {
    Bip340(Fingerprint, Bip340Secret),
    Ed25519(Fingerprint, Ed25519Secret),
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SecretParseError {
    /// incomplete private key data.
    Incomplete,
    /// invalid fingerprint data in private key - {0}.
    InvalidFingerprint(Baid64ParseError),
    #[from]
    /// invalid secret key data - {0}
    InvalidSecret(Baid64ParseError),
}

impl FromStr for SsiSecret {
    type Err = SecretParseError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        s = s.trim_start_matches("ssi:");
        let (fp, sk) = s.split_once('/').ok_or(SecretParseError::Incomplete)?;
        let fp = Fingerprint::from_str(fp).map_err(SecretParseError::InvalidFingerprint)?;
        if sk.starts_with("bip340-priv") {
            Ok(Self::Bip340(fp, Bip340Secret::from_str(sk)?))
        } else {
            Ok(Self::Ed25519(fp, Ed25519Secret::from_str(sk)?))
        }
    }
}

impl Display for SsiSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SsiSecret::Bip340(fp, sk) => write!(f, "{fp}/{sk}"),
            SsiSecret::Ed25519(fp, sk) => write!(f, "{fp}/{sk}"),
        }
    }
}

impl SsiSecret {
    pub fn new(algo: Algo, chain: Chain) -> Self {
        match algo {
            Algo::Ed25519 => Self::new_ed25519(chain),
            Algo::Bip340 => Self::new_bip340(chain),
            Algo::Other(other) => panic!("unsupported algorithm {}", other),
        }
    }

    pub fn new_ed25519(chain: Chain) -> Self {
        let sk = Ed25519Secret::new(chain);
        let fp = sk.to_public().fingerprint();
        Self::Ed25519(fp, sk)
    }

    pub fn new_bip340(chain: Chain) -> Self {
        let sk = Bip340Secret::new(chain);
        let fp = sk.to_public().fingerprint();
        Self::Bip340(fp, sk)
    }

    pub fn vanity(prefix: &str, algo: Algo, chain: Chain, threads: u8) -> Self {
        let (tx, rx) = crossbeam_channel::bounded(1);
        for _ in 0..threads {
            let tx = tx.clone();
            let prefix = prefix.to_owned();
            std::thread::spawn(move || {
                loop {
                    let sk = Self::new(algo, chain);
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

    pub fn algorithm(&self) -> Algo {
        match self {
            SsiSecret::Bip340(_, _) => Algo::Bip340,
            SsiSecret::Ed25519(_, _) => Algo::Ed25519,
        }
    }

    pub fn fingerprint(&self) -> Fingerprint {
        match self {
            SsiSecret::Bip340(fp, _) | SsiSecret::Ed25519(fp, _) => *fp,
        }
    }

    pub fn to_public(&self) -> SsiPub {
        match self {
            SsiSecret::Bip340(_, sk) => sk.to_public(),
            SsiSecret::Ed25519(_, sk) => sk.to_public(),
        }
    }

    pub fn sign(&self, msg: [u8; 32]) -> SsiSig {
        match self {
            SsiSecret::Bip340(_, sk) => sk.sign(msg),
            SsiSecret::Ed25519(_, sk) => sk.sign(msg),
        }
    }

    pub fn encrypt(&mut self, passwd: impl AsRef<str>) {
        let key = Sha256::digest(passwd.as_ref().as_bytes());
        let key = GenericArray::from_slice(key.as_slice());
        let cipher = Aes256::new(key);

        let mut source = self.to_vec();
        for chunk in source.chunks_mut(16) {
            let block = Block::from_mut_slice(chunk);
            cipher.encrypt_block(block);
        }
        self.replace(&source);
    }

    pub fn decrypt(&mut self, passwd: impl AsRef<str>) {
        let key = Sha256::digest(passwd.as_ref().as_bytes());
        let key = GenericArray::from_slice(key.as_slice());
        let cipher = Aes256::new(key);

        let mut source = self.to_vec();
        for chunk in source.chunks_mut(16) {
            let block = Block::from_mut_slice(chunk);
            cipher.decrypt_block(block);
        }
        self.replace(&source);
    }

    pub fn to_vec(&self) -> Vec<u8> {
        match self {
            SsiSecret::Bip340(_, sk) => sk.0.secret_bytes().to_vec(),
            SsiSecret::Ed25519(_, sk) => sk.0.to_vec(),
        }
    }

    fn replace(&mut self, secret: &[u8]) {
        match self {
            SsiSecret::Bip340(_, sk) => {
                sk.0 = secp256k1::SecretKey::from_slice(&secret).expect("same size")
            }
            SsiSecret::Ed25519(_, sk) => {
                sk.0 = ec25519::SecretKey::from_slice(&secret).expect("same size")
            }
        }
    }
}

impl From<SsiSecret> for SsiPub {
    fn from(sk: SsiSecret) -> Self { sk.to_public() }
}

#[derive(Clone, Eq, PartialEq, Display)]
#[display("{pk}")]
pub struct SsiPair {
    pub pk: SsiPub,
    pub sk: SsiSecret,
    pub expiry: Option<DateTime<Utc>>,
}

impl SsiPair {
    pub fn new(ssi: Ssi, sk: SsiSecret) -> Self {
        SsiPair {
            pk: ssi.pk,
            sk,
            expiry: ssi.expiry,
        }
    }

    pub fn sign(&self, msg: impl AsRef<[u8]>) -> SsiCert {
        let msg = Sha256::digest(msg);
        let digest = Sha256::digest(msg);
        let sig = self.sk.sign(digest.into());
        SsiCert {
            fp: self.pk.fingerprint(),
            msg: Bytes32::from_byte_array(digest),
            sig,
        }
    }
}
