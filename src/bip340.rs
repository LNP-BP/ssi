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

use secp256k1::schnorr::Signature;
use secp256k1::{Keypair, Message, XOnlyPublicKey, SECP256K1};

use crate::{Algo, Chain, InvalidPubkey, InvalidSig, SsiPub, SsiSecret, SsiSig};

impl TryFrom<SsiPub> for XOnlyPublicKey {
    type Error = InvalidPubkey;

    fn try_from(ssi: SsiPub) -> Result<Self, Self::Error> {
        Self::from_slice(&<[u8; 32]>::from(ssi)).map_err(|_| InvalidPubkey)
    }
}

impl SsiPub {
    pub fn from_bip340(key: XOnlyPublicKey) -> Self {
        let bytes = key.serialize();
        Self::from(bytes)
    }
}

impl SsiSecret {
    pub fn new(chain: Chain) -> Self {
        use rand::thread_rng;
        loop {
            let sk = secp256k1::SecretKey::new(&mut thread_rng());
            let (pk, _) = sk.x_only_public_key(SECP256K1);
            let data = pk.serialize();
            if data[30] == u8::from(Algo::Bip340) && data[31] == u8::from(chain) {
                let mut key = [0u8; 30];
                key.copy_from_slice(&data[0..30]);
                return Self(sk);
            }
        }
    }

    pub fn to_public(&self) -> SsiPub {
        let (pk, _) = self.0.x_only_public_key(SECP256K1);
        let data = pk.serialize();
        SsiPub::from(data)
    }

    pub fn sign(&self, msg: [u8; 32]) -> SsiSig {
        let msg = Message::from_digest(msg);
        let keypair = Keypair::from_secret_key(SECP256K1, &self.0);
        let sig = SECP256K1.sign_schnorr(&msg, &keypair);
        SsiSig(sig.serialize())
    }
}

impl SsiSig {
    pub fn verify(&self, ssi: SsiPub, msg: [u8; 32]) -> Result<(), InvalidSig> {
        let sig = Signature::from_slice(&self.0).map_err(|_| InvalidSig::InvalidData)?;
        let msg = Message::from_digest(msg);
        let pk =
            XOnlyPublicKey::from_slice(&ssi.to_byte_array()).map_err(|_| InvalidSig::InvalidSsi)?;
        sig.verify(&msg, &pk).map_err(|_| InvalidSig::InvalidSig)
    }
}
