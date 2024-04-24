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

#[macro_use]
extern crate amplify;

pub mod baid64;

mod identity;
mod secret;
mod public;
mod bip340;

mod runtime;

pub use identity::{Ssi, SsiParseError, Uid};
pub use public::{
    Algo, Chain, InvalidPubkey, InvalidSig, SsiPub, SsiSig, UnknownAlgo, UnknownChain,
};
pub use runtime::{Error, SsiRuntime, SSI_DIR};
pub use secret::SsiSecret;
