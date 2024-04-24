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
extern crate clap;

use std::str::FromStr;

use chrono::DateTime;
use clap::Parser;
use ssi::{Algo, Chain, Ssi, SsiRuntime, SsiSecret, Uid};

#[derive(Parser, Clone, Debug)]
pub struct Args {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    /// Generate a new identity - a pair of public and private keys.
    New {
        #[clap(short, long, default_value = "bip340")]
        algo: Algo,

        #[clap(short, long, default_value = "bitcoin")]
        chain: Chain,

        /// Vanity prefix
        #[clap(long)]
        prefix: Option<String>,

        /// Number of threads to run vanity generation
        #[clap(short, long, requires = "prefix", default_value = "8")]
        threads: u8,

        #[clap(long, required = true)]
        uid: Vec<String>,

        #[clap(long, required_unless_present = "expiry")]
        no_expiry: bool,

        #[clap(conflicts_with = "no_expiry", required_unless_present = "no_expiry")]
        expiry: Option<String>,
    },
}

fn main() {
    let args = Args::parse();

    match args.command {
        Command::New {
            algo: _,
            chain,
            prefix,
            threads,
            no_expiry: _,
            expiry,
            uid,
        } => {
            let expiry = expiry.map(|expiry| {
                DateTime::parse_from_str(&expiry, "%Y-%m-%d")
                    .expect("invalid expiry date")
                    .to_utc()
            });
            let uids = uid
                .iter()
                .map(String::as_str)
                .map(Uid::from_str)
                .collect::<Result<_, _>>()
                .expect("invalid UID");

            let mut runtime = SsiRuntime::load().expect("unable to load data");

            let passwd = rpassword::prompt_password("Password for private key encryption: ")
                .expect("unable to read password");

            eprintln!("Generating new identity....");
            let mut secret = match prefix {
                Some(prefix) => SsiSecret::vanity(&prefix, chain, threads),
                None => SsiSecret::new(chain),
            };

            let ssi = Ssi::new(uids, expiry, &secret);
            println!("{ssi}");

            if !passwd.is_empty() {
                secret.encrypt(passwd);
            }

            runtime.secrets.insert(secret);
            runtime.identities.insert(ssi);

            runtime.store().expect("unable to save data");
        }
    }
}
