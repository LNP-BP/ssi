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
use std::hash::{Hash, Hasher};
use std::io;

use amplify::confinement::ConfinedVec;
use amplify::{ByteArray, FromSliceError};
use ec25519::{KeyPair, PublicKey, SecretKey, Seed, Signature};
use strict_encoding::{StrictDeserialize, StrictEncode, StrictSerialize};

use crate::{Algo, Chain, InvalidPubkey, InvalidSig, SsiPub, SsiSig, LIB_NAME_SSI};

#[derive(Clone, Eq, PartialEq, From)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_SSI)]
pub struct Ed25519Secret {
    pub chain: Chain,
    pub algo: Algo,
    pub(crate) key: SecretKey,
}

impl StrictSerialize for Ed25519Secret {}
impl StrictDeserialize for Ed25519Secret {}

impl Ord for Ed25519Secret {
    fn cmp(&self, other: &Self) -> Ordering { self.serialize().cmp(other.serialize()) }
}

impl PartialOrd for Ed25519Secret {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> { Some(self.cmp(other)) }
}

impl Hash for Ed25519Secret {
    fn hash<H: Hasher>(&self, state: &mut H) { self.serialize().hash(state) }
}

impl ByteArray<34> for Ed25519Secret {
    fn from_byte_array(val: impl Into<[u8; 34]>) -> Self {
        Self::from_strict_serialized::<34>(ConfinedVec::from_slice_checked(&val.into())).unwrap()
    }

    fn from_slice(slice: impl AsRef<[u8]>) -> Result<Self, FromSliceError> {
        let len = slice.as_ref().len();
        if len != 34 {
            return Err(FromSliceError {
                expected: 34,
                actual: len,
            });
        }
        Ok(Self::from_strict_serialized::<34>(ConfinedVec::from_slice_checked(&slice.as_ref()))
            .unwrap())
    }

    fn from_slice_unsafe(slice: impl AsRef<[u8]>) -> Self {
        Self::from_strict_serialized::<34>(ConfinedVec::from_slice_checked(&slice.as_ref()))
            .unwrap()
    }

    fn to_byte_array(&self) -> [u8; 34] {
        let mut array = [0u8; 34];
        array.copy_from_slice(&self.to_strict_serialized::<34>().unwrap());
        array
    }
}

impl Ed25519Secret {
    pub fn new(chain: Chain) -> Self {
        let pair = KeyPair::from_seed(Seed::generate());

        Self {
            chain,
            algo: Algo::Ed25519,
            key: pair.sk,
        }
    }

    pub fn to_public(&self) -> SsiPub {
        let pk = self.key.public_key();
        SsiPub::with(self.chain, self.algo, *pk)
    }

    pub fn sign(&self, msg: [u8; 32]) -> SsiSig {
        let sig = self.key.sign(msg, None);
        SsiSig::from(*sig)
    }
}

impl SsiPub {
    pub fn verify_ed25519(self, msg: [u8; 32], sig: SsiSig) -> Result<(), InvalidSig> {
        let sig = Signature::from_slice(sig.as_slice()).map_err(|_| InvalidSig::InvalidData)?;
        let pk = PublicKey::try_from(self)?;
        pk.verify(msg, &sig).map_err(|err| {
            eprintln!("{err}");
            InvalidSig::InvalidSig
        })
    }
}

impl TryFrom<SsiPub> for PublicKey {
    type Error = InvalidPubkey;

    fn try_from(ssi: SsiPub) -> Result<Self, Self::Error> {
        Self::from_slice(&<[u8; 32]>::from(ssi)).map_err(|_| InvalidPubkey)
    }
}

impl SsiPub {
    pub fn from_ed25519(key: PublicKey) -> Self { Self::from(*key) }
}
