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

use clap::Parser;
use ssi::{Algo, Chain, Ssi};

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
        } => {
            eprintln!("Generating new identity....");
            let ssi = match prefix {
                Some(prefix) => Ssi::vanity(&prefix, chain, threads),
                None => Ssi::new(chain),
            };
            println!("{ssi}");
        }
    }
}
