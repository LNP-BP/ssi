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

use std::str::FromStr;

use aes_gcm::aead::{Aead, Nonce, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, KeyInit};
use amplify::confinement::{Confined, SmallOrdMap, U64 as U64MAX};
use amplify::Bytes32;
use armor::{ArmorHeader, ArmorParseError, AsciiArmor};
use ec25519::{edwards25519, KeyPair, Seed};
use rand::random;
use sha2::{Digest, Sha256};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::{Algo, InvalidPubkey, SsiPair, SsiPub, LIB_NAME_SSI};

#[derive(Copy, Clone, Debug, Display, Error)]
pub enum EncryptionError {
    #[display("the number of receivers exceeds 2^16.")]
    TooManyReceivers,
    #[display("invalid public key {0}.")]
    InvalidPubkey(SsiPub),
}

#[derive(Copy, Clone, Debug, Display, Error, From)]
pub enum DecryptionError {
    #[display("the message can't be decrypted using key {0}.")]
    KeyMismatch(SsiPub),
    #[display("invalid public key {0}.")]
    InvalidPubkey(SsiPub),
    #[from(aes_gcm::Error)]
    #[display("unable to decrypt data.")]
    Decrypt,
}

#[derive(Clone, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSI)]
pub struct SymmetricKey(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl AsRef<[u8]> for SymmetricKey {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl SymmetricKey {
    pub fn new() -> Self {
        loop {
            let key = random::<[u8; 32]>();
            if edwards25519::GeP3::from_bytes_vartime(&key).is_some() {
                return Self(Bytes32::from_byte_array(key));
            }
        }
    }
}

#[derive(Clone, Debug, Display)]
#[display(AsciiArmor::to_ascii_armored_string)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSI)]
pub struct Encrypted {
    pub keys: SmallOrdMap<SsiPub, (Bytes32, Bytes32)>,
    pub nonce: [u8; 12],
    pub data: Confined<Vec<u8>, 0, U64MAX>,
}

impl StrictSerialize for Encrypted {}
impl StrictDeserialize for Encrypted {}

impl AsciiArmor for Encrypted {
    type Err = ArmorParseError;
    const PLATE_TITLE: &'static str = "SSI MESSAGE";

    fn ascii_armored_headers(&self) -> Vec<ArmorHeader> {
        vec![ArmorHeader::with("Receivers", self.keys.keys().map(|pk| pk.to_string()))]
    }

    fn to_ascii_armored_data(&self) -> Vec<u8> {
        self.to_strict_serialized::<U64MAX>()
            .expect("64 bits will never error")
            .into_inner()
    }

    fn with_headers_data(_headers: Vec<ArmorHeader>, data: Vec<u8>) -> Result<Self, Self::Err> {
        // TODO: Check receivers list
        Ok(Self::from_strict_serialized::<U64MAX>(Confined::from_collection_unsafe(data))
            .expect("64 bits will never fail"))
    }
}

impl FromStr for Encrypted {
    type Err = ArmorParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_ascii_armored_str(s) }
}

impl Encrypted {
    pub fn encrypt(
        source: Vec<u8>,
        receivers: impl IntoIterator<Item = SsiPub>,
    ) -> Result<Self, EncryptionError> {
        let key = SymmetricKey::new();
        let mut keys = bmap![];
        for pk in receivers {
            let (msg, c1) = pk
                .encrypt_key(&key)
                .map_err(|_| EncryptionError::InvalidPubkey(pk))?;
            keys.insert(pk, (msg, Bytes32::from_slice_unsafe(c1.as_slice())));
        }
        let (nonce, msg) = encrypt(source, key);
        Ok(Self {
            keys: Confined::try_from(keys).map_err(|_| EncryptionError::TooManyReceivers)?,
            nonce: nonce.into(),
            data: Confined::from_collection_unsafe(msg),
        })
    }

    pub fn decrypt(&self, pair: impl Into<SsiPair>) -> Result<Vec<u8>, DecryptionError> {
        let pair = pair.into();
        let (msg, c1) = self
            .keys
            .iter()
            .find(|(pk, _)| *pk == &pair.pk)
            .map(|(_, secret)| secret)
            .ok_or(DecryptionError::KeyMismatch(pair.pk))?;
        let c1 = ec25519::PublicKey::new(c1.to_byte_array());
        let key = pair
            .decrypt_key(*msg, c1)
            .map_err(|_| DecryptionError::InvalidPubkey(pair.pk))?;
        Ok(decrypt(self.data.as_slice(), self.nonce.into(), key)?)
    }
}

impl SsiPub {
    pub fn encrypt_key(
        &self,
        key: &SymmetricKey,
    ) -> Result<(Bytes32, ec25519::PublicKey), InvalidPubkey> {
        match self.algo() {
            Algo::Ed25519 => self.encrypt_key_ed25519(key),
            Algo::Bip340 | Algo::Other(_) => Err(InvalidPubkey),
        }
    }

    pub fn encrypt_key_ed25519(
        &self,
        message: &SymmetricKey,
    ) -> Result<(Bytes32, ec25519::PublicKey), InvalidPubkey> {
        let pair = KeyPair::from_seed(Seed::generate());
        let y = pair.sk;
        let c1 = pair.pk;

        let h =
            edwards25519::GeP3::from_bytes_vartime(&self.to_byte_array()).ok_or(InvalidPubkey)?;
        let s = edwards25519::ge_scalarmult(&y.seed().scalar(), &h);

        let m = edwards25519::GeP3::from_bytes_vartime(&message.0.to_byte_array())
            .ok_or(InvalidPubkey)?;
        let c2 = m + s;

        Ok((c2.to_bytes().into(), c1))
    }
}

impl SsiPair {
    pub fn decrypt_key(
        &self,
        encrypted_message: Bytes32,
        c1: ec25519::PublicKey,
    ) -> Result<SymmetricKey, InvalidPubkey> {
        match self.pk.algo() {
            Algo::Ed25519 => self.decrypt_key_ed25519(encrypted_message, c1),
            Algo::Bip340 | Algo::Other(_) => Err(InvalidPubkey),
        }
    }

    pub fn decrypt_key_ed25519(
        &self,
        encrypted_message: Bytes32,
        c1: ec25519::PublicKey,
    ) -> Result<SymmetricKey, InvalidPubkey> {
        let c1 = edwards25519::GeP3::from_bytes_vartime(&c1).ok_or(InvalidPubkey)?;
        let s = edwards25519::ge_scalarmult(&self.sk.secret_bytes(), &c1);
        let c2 = edwards25519::GeP3::from_bytes_vartime(&encrypted_message.to_byte_array())
            .ok_or(InvalidPubkey)?;
        let key = c2 - s;
        Ok(SymmetricKey::from(key.to_bytes()))
    }
}

pub fn encrypt(source: Vec<u8>, key: impl AsRef<[u8]>) -> (Nonce<Aes256Gcm>, Vec<u8>) {
    let key = Sha256::digest(key.as_ref());
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key.as_slice());

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let cipher = Aes256Gcm::new(key);

    let ciphered_data = cipher
        .encrypt(&nonce, source.as_ref())
        .expect("failed to encrypt");

    (nonce, ciphered_data)
}

pub fn decrypt(
    encrypted: &[u8],
    nonce: Nonce<Aes256Gcm>,
    key: impl AsRef<[u8]>,
) -> Result<Vec<u8>, aes_gcm::Error> {
    let key = Sha256::digest(key.as_ref());
    let key = aes_gcm::Key::<Aes256Gcm>::from_slice(key.as_slice());
    Aes256Gcm::new(key).decrypt(&nonce, encrypted)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Chain, SsiSecret};

    #[test]
    fn aes_roundcrypt() {
        let key = "Some key";
        let source = b"Message to encrypt";

        let (nonce, encrypted) = encrypt(source.to_vec(), key);
        let decrypted = decrypt(&encrypted, nonce, key).unwrap();
        assert_eq!(decrypted, source);
    }

    #[test]
    fn ed25519_keycrypt() {
        let sk = SsiSecret::new(Algo::Ed25519, Chain::Bitcoin);
        let pair = SsiPair::from(sk);
        let key = SymmetricKey::new();
        let (encrypted, c1) = pair.pk.encrypt_key(&key).unwrap();
        let decrypted = pair.decrypt_key(encrypted, c1).unwrap();
        assert_eq!(key.0, decrypted.0);
    }

    #[test]
    fn ed25519_roundcrypt() {
        let key = SsiSecret::new(Algo::Ed25519, Chain::Bitcoin);
        let source = b"Message to encrypt";

        let encrypted = Encrypted::encrypt(source.to_vec(), [key.to_public()]).unwrap();
        let decrypted = encrypted.decrypt(key).unwrap();
        assert_eq!(decrypted, source);
    }
}
