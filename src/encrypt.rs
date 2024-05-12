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

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes256, Block};
use amplify::confinement::{Confined, SmallOrdMap, U64 as U64MAX};
use amplify::Bytes32;
use armor::{ArmorHeader, ArmorParseError, AsciiArmor};
use ec25519::{edwards25519, Error};
use rand::random;
use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha256};
use strict_encoding::{StrictDeserialize, StrictSerialize};

use crate::{Algo, InvalidPubkey, SsiPub, LIB_NAME_SSI};

#[derive(Copy, Clone, Debug, Display, Error)]
pub enum EncryptionError {
    #[display("the number of receivers exceeds 2^16")]
    TooManyReceivers,
    #[display("invalid public key {0}")]
    InvalidPubkey(SsiPub),
}

#[derive(Clone, Debug, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSI)]
pub struct SymmetricKey(Bytes32);

impl AsRef<[u8]> for SymmetricKey {
    fn as_ref(&self) -> &[u8] { self.0.as_ref() }
}

impl SymmetricKey {
    pub fn new() -> Self {
        let key = random::<[u8; 32]>();
        Self(Bytes32::from_byte_array(key))
    }
}

#[derive(Clone, Debug, Display)]
#[display(AsciiArmor::to_ascii_armored_string)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSI)]
pub struct Encrypted {
    pub keys: SmallOrdMap<SsiPub, Bytes32>,
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
            .expect("64 bits will not error")
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
            keys.insert(
                pk,
                pk.encrypt(&key)
                    .map_err(|_| EncryptionError::InvalidPubkey(pk))?,
            );
        }
        let msg = encrypt(source, key);
        Ok(Self {
            keys: Confined::try_from(keys).map_err(|_| EncryptionError::TooManyReceivers)?,
            data: Confined::from_collection_unsafe(msg),
        })
    }
}

impl SsiPub {
    pub fn encrypt(&self, key: &SymmetricKey) -> Result<Bytes32, InvalidPubkey> {
        match self.algo() {
            Algo::Ed25519 => self.encrypt_ed25519(key),
            Algo::Bip340 | Algo::Other(_) => Err(InvalidPubkey),
        }
    }

    pub fn encrypt_ed25519(&self, key: &SymmetricKey) -> Result<Bytes32, InvalidPubkey> {
        let pk = ec25519::PublicKey::try_from(*self)?;
        let ge = edwards25519::GeP3::from_bytes_vartime(&pk).ok_or(InvalidPubkey)?;

        Ok(edwards25519::ge_scalarmult(key.as_ref(), &ge)
            .to_bytes()
            .into())
    }
}

pub fn encrypt(mut source: Vec<u8>, passwd: impl AsRef<[u8]>) -> Vec<u8> {
    let key = Sha256::digest(passwd.as_ref());
    let key = GenericArray::from_slice(key.as_slice());
    let cipher = Aes256::new(key);

    for chunk in source.chunks_mut(16) {
        let block = Block::from_mut_slice(chunk);
        cipher.encrypt_block(block);
    }
    source
}

pub fn decrypt(mut source: Vec<u8>, passwd: impl AsRef<[u8]>) -> Vec<u8> {
    let key = Sha256::digest(passwd.as_ref());
    let key = GenericArray::from_slice(key.as_slice());
    let cipher = Aes256::new(key);

    for chunk in source.chunks_mut(16) {
        let block = Block::from_mut_slice(chunk);
        cipher.decrypt_block(block);
    }
    source
}
