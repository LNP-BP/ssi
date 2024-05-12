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
#[macro_use]
extern crate clap;

use std::fs;
use std::io::{stdin, Read};
use std::path::PathBuf;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use clap::Parser;
use rand::random;
use ssi::{
    encrypt, Algo, Chain, Encrypted, InvalidSig, Ssi, SsiCert, SsiQuery, SsiRuntime, SsiSecret, Uid,
};

#[derive(Parser, Clone, Debug)]
pub struct Args {
    /// Command to execute
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Command {
    /// Generate a new identity - a pair of public and private keys
    New {
        /// Signature algorithm to use
        #[clap(short, long, default_value = "ed25519")]
        algo: Algo,

        /// Which blockchain should be used for key revocation
        #[clap(short, long, default_value = "bitcoin")]
        chain: Chain,

        /// Vanity prefix: "mine" an identity starting with certain string
        #[clap(long)]
        prefix: Option<String>,

        /// Number of threads to run vanity generation
        #[clap(short, long, requires = "prefix", default_value = "8")]
        threads: u8,

        /// User identity information in form of "Name Surname ...
        /// <schema:address>"
        #[clap(long, required = true)]
        uid: Vec<String>,

        /// Create identity with no specific expiration date
        #[clap(long, required_unless_present = "expiry")]
        no_expiry: bool,

        /// Set expiration date for the identity (in YYYY-MM-DD format)
        #[clap(conflicts_with = "no_expiry", required_unless_present = "no_expiry")]
        expiry: Option<String>,
    },

    /// List known identitites
    List {
        /// List only signing identities
        #[clap(short, long)]
        signing: bool,
    },

    /// Sign a file or a message
    Sign {
        /// Generate signature including the full identity
        #[clap(long)]
        full: bool,

        /// Text message to sign
        #[clap(short, long, conflicts_with = "file")]
        text: Option<String>,

        /// File to create a detached signature for
        #[clap(short, long)]
        file: Option<PathBuf>,

        /// Identity to use for the signature
        ssi: SsiQuery,
    },

    /// Verify signature certificate
    Verify {
        /// Signature certificate to verify
        signature: SsiCert,
    },

    Encrypt {
        /// Identities which must be able to decrypt
        #[clap(short, long, required = true)]
        receiver: Vec<SsiQuery>,

        /// Text message to encrypt
        #[clap(short, long, conflicts_with = "file")]
        text: Option<String>,

        /// File to encrypt
        #[clap(short, long)]
        file: Option<PathBuf>,
    },
    //    Recover,
}

fn main() {
    let args = Args::parse();

    let mut runtime = SsiRuntime::load().expect("unable to load data");

    match args.command {
        Command::List { signing } => {
            let now = Utc::now();
            for ssi in &runtime.identities {
                if signing && !runtime.is_signing(ssi.pk.fingerprint()) {
                    continue;
                }
                print!("{}\t", ssi.pk);
                match ssi.expiry {
                    None => print!("no expiry"),
                    Some(e) => print!("{}", e.format("%Y-%m-%d")),
                }
                print!("\t");
                match ssi.check_integrity() {
                    Ok(_) if ssi.expiry >= Some(now) => println!("expired"),
                    Ok(_) => println!("valid"),
                    Err(InvalidSig::InvalidPubkey) => println!("invalid pubkey"),
                    Err(InvalidSig::InvalidSig) => println!("invalid"),
                    Err(InvalidSig::InvalidData) => println!("broken"),
                    Err(InvalidSig::UnsupportedAlgo(_)) => println!("unsupported"),
                }
                for uid in &ssi.uids {
                    println!("\t{uid}");
                }
            }
            println!();
        }

        Command::New {
            algo,
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

            let passwd = rpassword::prompt_password("Password for private key encryption: ")
                .expect("unable to read password");

            eprintln!("Generating new {algo} identity....");
            let mut secret = match prefix {
                Some(prefix) => SsiSecret::vanity(&prefix, algo, chain, threads),
                None => SsiSecret::new(algo, chain),
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

        Command::Sign {
            full,
            text,
            file,
            ssi,
        } => {
            eprintln!("Signing with {ssi} ...");

            let passwd = rpassword::prompt_password("Password for private key encryption: ")
                .expect("unable to read password");
            let msg = get_message(text, file);
            let signer = runtime
                .find_signer(ssi, &passwd)
                .expect("unknown signing identity");
            eprintln!("Using key {signer}");
            let cert = signer.sign(msg);
            if full {
                println!("{cert:#}");
            } else {
                println!("{cert}");
            }
        }

        Command::Verify { signature } => {
            eprint!("Verifying signature for message digest {} ... ", signature.msg);
            let pk = runtime
                .find_identity(signature.fp)
                .map(|ssi| ssi.pk)
                .or(signature.pk)
                .expect("unknown signing identity");
            match pk.verify(signature.msg.to_byte_array(), signature.sig) {
                Ok(_) => eprintln!("valid"),
                Err(err) => eprintln!("invalid: {err}"),
            }
            println!();
        } /*  */
        //Command::Recover => {
        //use std::collections::HashSet;
        //let passwd = rpassword::prompt_password("Password for private key encryption: ")
        //.expect("unable to read password");
        //let mut identities = HashSet::new();
        //for mut ssi in runtime.identities.iter().cloned() {
        //let secret = runtime.find_signer(ssi.pk.fingerprint(), &passwd).unwrap();
        //ssi.sig = secret.sk.sign(ssi.to_message());
        //identities.push(ssi);
        //}
        //runtime.identities = identities;
        //runtime.store().unwrap()
        //}
        Command::Encrypt {
            receiver,
            text,
            file,
        } => {
            let msg = get_message(text, file);
            let receivers = receiver.into_iter().map(|query| {
                runtime
                    .find_identity(query.clone())
                    .unwrap_or_else(|| panic!("unknown identity {query}"))
                    .pk
            });
            let encrypted = Encrypted::encrypt(msg, receivers).expect("unable to encrypt");
            println!("{encrypted}");
        }
    }
}

fn get_message(text: Option<String>, file: Option<PathBuf>) -> Vec<u8> {
    match (text, file) {
        (Some(t), None) => t.into_bytes(),
        (None, Some(f)) => fs::read(f).expect("unable to read the file"),
        (None, None) => {
            let mut s = String::new();
            stdin()
                .read_to_string(&mut s)
                .expect("unable to read standard input");
            s.into_bytes()
        }
        _ => unreachable!(),
    }
}
