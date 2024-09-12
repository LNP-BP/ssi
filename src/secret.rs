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

use aes_gcm::aead::Nonce;
use aes_gcm::Aes256Gcm;
use amplify::hex::{FromHex, ToHex};
use amplify::{hex, Bytes32};
use baid64::{Baid64ParseError, BAID64_ALPHABET};
use base64::alphabet::Alphabet;
use base64::engine::general_purpose::NO_PAD;
use base64::engine::GeneralPurpose;
use base64::Engine;
use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};

use crate::{
    decrypt, encrypt, Algo, Bip340Secret, Chain, Ed25519Secret, Fingerprint, Ssi, SsiCert, SsiPub,
    SsiSig,
};

#[derive(Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum RevealError {
    #[from(ec25519::Error)]
    #[from(secp256k1::Error)]
    /// invalid password.
    InvalidPassword,

    /// unsupported algorithm #{0}.
    Unsupported(u8),

    /// unable to decrypt data.
    #[from(aes_gcm::Error)]
    Decrypt,
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct EncryptedSecret {
    pub fp: Fingerprint,
    pub nonce: Nonce<Aes256Gcm>,
    pub algo: Algo,
    pub chain: Chain,
    pub key: Vec<u8>,
}

impl EncryptedSecret {
    pub fn reveal(&self, passwd: impl AsRef<str>) -> Result<SsiSecret, RevealError> {
        let sk = decrypt(&self.key, self.nonce, passwd.as_ref())?;
        match self.algo {
            Algo::Ed25519 => {
                Ok(Ed25519Secret::with(self.chain, ec25519::SecretKey::from_slice(&sk)?).into())
            }
            Algo::Bip340 => Ok(secp256k1::SecretKey::from_slice(&sk)?.into()),
            Algo::Other(algo) => Err(RevealError::Unsupported(algo)),
        }
    }
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SecretParseError {
    /// incomplete private key data.
    Incomplete,

    /// private key data misses key and signature scheme information.
    NoAlgo,

    /// private key signature scheme {0} is not supported yet.
    UnsupportedAlgo(String),

    #[from]
    /// private key has invalid nonce value - {0}
    InvalidNonce(hex::Error),

    /// invalid fingerprint data in private key - {0}
    InvalidFingerprint(Baid64ParseError),

    #[from]
    /// invalid secret key data - {0}
    Decode(base64::DecodeError),
}

impl FromStr for EncryptedSecret {
    type Err = SecretParseError;

    fn from_str(mut s: &str) -> Result<Self, Self::Err> {
        s = s.trim_start_matches("ssi://");
        let (prefix, sk) = s.split_once('/').ok_or(SecretParseError::Incomplete)?;
        let (fp, nonce) = prefix.split_once(':').ok_or(SecretParseError::Incomplete)?;
        let fp = Fingerprint::from_str(fp).map_err(SecretParseError::InvalidFingerprint)?;

        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, NO_PAD);

        let (schema, key) = sk.split_once(':').ok_or(SecretParseError::NoAlgo)?;
        let nonce = <[u8; 12]>::from_hex(nonce)?.into();
        let algo = match schema {
            "bip340-priv" => Algo::Bip340,
            "ed25519-priv" => Algo::Ed25519,
            other => return Err(SecretParseError::UnsupportedAlgo(other.to_owned())),
        };

        let key = engine.decode(key)?;

        Ok(Self {
            fp,
            nonce,
            algo,
            key,
        })
    }
}

impl Display for EncryptedSecret {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let alphabet = Alphabet::new(BAID64_ALPHABET).expect("invalid Baid64 alphabet");
        let engine = GeneralPurpose::new(&alphabet, NO_PAD);
        write!(
            f,
            "ssi://{}:{}/{}-priv:{}",
            self.fp,
            self.nonce.to_hex(),
            self.algo,
            engine.encode(&self.key)
        )
    }
}

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, From)]
pub enum SsiSecret {
    #[from]
    Bip340(Bip340Secret),
    #[from]
    Ed25519(Ed25519Secret),
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
        Self::Ed25519(sk)
    }

    pub fn new_bip340(chain: Chain) -> Self {
        let sk = Bip340Secret::new(chain);
        Self::Bip340(sk)
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
            SsiSecret::Bip340(_) => Algo::Bip340,
            SsiSecret::Ed25519(_) => Algo::Ed25519,
        }
    }

    pub fn to_public(&self) -> SsiPub {
        match self {
            SsiSecret::Bip340(sk) => sk.to_public(),
            SsiSecret::Ed25519(sk) => sk.to_public(),
        }
    }

    pub fn sign(&self, msg: [u8; 32]) -> SsiSig {
        match self {
            SsiSecret::Bip340(sk) => sk.sign(msg),
            SsiSecret::Ed25519(sk) => sk.sign(msg),
        }
    }

    pub fn conceal(&self, passwd: impl AsRef<str>) -> EncryptedSecret {
        let (nonce, key) = encrypt(self.secret_bytes().to_vec(), passwd.as_ref());
        EncryptedSecret {
            fp: self.to_public().fingerprint(),
            nonce,
            algo: self.algorithm(),
            key,
        }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        match self {
            SsiSecret::Bip340(sk) => sk.key.secret_bytes(),
            SsiSecret::Ed25519(sk) => sk.key.seed().scalar(),
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

impl From<SsiSecret> for SsiPair {
    fn from(sk: SsiSecret) -> Self {
        SsiPair {
            pk: sk.to_public(),
            sk,
            expiry: None,
        }
    }
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
            pk: Some(self.pk),
            msg: Bytes32::from_byte_array(digest),
            sig,
        }
    }
}
