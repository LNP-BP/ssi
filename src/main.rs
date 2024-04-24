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

use std::fs;
use std::path::PathBuf;

use clap::Parser;
use ssi::{Algo, Chain, SsiSecret};

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

        #[clap(short, long, default_value = "id")]
        name: String,
    },
}

fn main() {
    let args = Args::parse();

    let data_dir = PathBuf::from(shellexpand::tilde("~/.ssi").to_string());
    fs::create_dir_all(&data_dir).expect("unable to initialize data directory");

    match args.command {
        Command::New {
            algo: _,
            chain,
            prefix,
            threads,
            name,
        } => {
            let passwd = rpassword::prompt_password("Password for private key encryption: ")
                .expect("unable to read password");

            eprintln!("Generating new identity....");
            let mut secret = match prefix {
                Some(prefix) => SsiSecret::vanity(&prefix, chain, threads),
                None => SsiSecret::new(chain),
            };
            let ssi = secret.to_public();
            println!("{ssi}");

            if !passwd.is_empty() {
                secret.encrypt(passwd);
            }

            let mut path = data_dir.clone();
            path.push(name);
            fs::write(&path, format!("{secret}")).expect("unable to save secret key");
            path.set_extension("pub");
            fs::write(&path, format!("{ssi}")).expect("unable to save public key");
        }
    }
}
