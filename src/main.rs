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

use std::collections::BTreeSet;
use std::io::{stdin, Read};
use std::path::PathBuf;
use std::str::FromStr;
use std::{fs, io};

use armor::{ArmorParseError, AsciiArmor};
use chrono::{DateTime, Utc};
use clap::Parser;
use ssi::{
    Algo, Chain, DecryptionError, Encrypted, EncryptionError, InvalidSig, LoadError, SignerError,
    Ssi, SsiCert, SsiQuery, SsiRuntime, SsiSecret, Uid, UidParseError,
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

    /// Recover identity signatures for identities with private keys
    Recover,

    /// Encrypt a message for receiver(s)
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

    /// Decrypt a message using one of your private keys
    Decrypt {
        /// Private key to use for decryption
        #[clap(short, long)]
        key: Option<SsiQuery>,

        /// Text message to decrypt
        #[clap(short, long, conflicts_with = "file")]
        text: Option<String>,

        /// File to decrypt
        #[clap(short, long)]
        file: Option<PathBuf>,
    },
}

#[derive(Debug, Display, Error, From)]
#[display(doc_comments)]
enum CliError {
    #[from]
    /// unable to load identities - {0}
    Load(LoadError),

    /// unable to store identities - {0}
    Store(io::Error),

    /// unable to load signer - {0}
    #[from]
    Signer(SignerError),

    /// error reading password - {0}
    Password(io::Error),

    /// invalid expiry date.
    InvalidExpiry,

    #[from]
    #[display(inner)]
    InvalidUid(UidParseError),

    /// the provided message is not ASCII armored.
    NoArmor,

    /// unable to parse armored message - {0}
    #[from]
    InvalidArmor(ArmorParseError),

    /// unable to read message - {0}
    ReadMessage(io::Error),

    #[from]
    #[display(inner)]
    Encrypt(EncryptionError),

    #[from]
    #[display(inner)]
    Decrypt(DecryptionError),
}

fn main() {
    let args = Args::parse();
    if let Err(err) = exec(args.command) {
        eprintln!("Error: {err}");
    }
}

fn exec(command: Command) -> Result<(), CliError> {
    let mut runtime = SsiRuntime::load()?;

    match command {
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
            let expiry = expiry
                .map(|expiry| {
                    DateTime::parse_from_str(&expiry, "%Y-%m-%d")
                        .as_ref()
                        .map(DateTime::to_utc)
                        .map_err(|_| CliError::InvalidExpiry)
                })
                .transpose()?;
            let uids = uid
                .iter()
                .map(String::as_str)
                .map(Uid::from_str)
                .collect::<Result<_, _>>()?;

            let passwd = rpassword::prompt_password("Password for private key encryption: ")
                .map_err(CliError::Password)?;

            eprintln!("Generating new {algo} identity....");
            let secret = match prefix {
                Some(prefix) => SsiSecret::vanity(&prefix, algo, chain, threads),
                None => SsiSecret::new(algo, chain),
            };

            let ssi = Ssi::new(uids, expiry, &secret);
            println!("{ssi}");

            runtime.secrets.insert(secret.conceal(passwd));
            runtime.identities.insert(ssi);

            runtime.store().map_err(CliError::Store)?;
        }

        Command::Sign {
            full,
            text,
            file,
            ssi,
        } => {
            eprintln!("Signing with {ssi} ...");

            let passwd = rpassword::prompt_password("Password for the private key: ")
                .map_err(CliError::Password)?;
            let signer = runtime.find_signer(ssi, &passwd)?;
            eprintln!("Using key {signer}");
            let msg = get_message(text, file)?;
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
                .ok_or(SignerError::UnknownIdentity)?;
            match pk.verify(signature.msg.to_byte_array(), signature.sig) {
                Ok(_) => eprintln!("valid"),
                Err(err) => eprintln!("invalid: {err}"),
            }
            println!();
        }
        Command::Recover => {
            let passwd = rpassword::prompt_password("Password for private key encryption: ")
                .map_err(CliError::Password)?;
            let mut identities = BTreeSet::new();
            for mut ssi in runtime.identities.iter().cloned() {
                let Ok(secret) = runtime.find_signer(ssi.pk.fingerprint(), &passwd) else {
                    identities.insert(ssi);
                    continue;
                };
                ssi.sig = Some(secret.sk.sign(ssi.to_message()));
                identities.insert(ssi);
            }
            runtime.identities = identities;
            runtime.store().unwrap()
        }
        Command::Encrypt {
            receiver,
            text,
            file,
        } => {
            let msg = get_message(text, file)?;
            let receivers = receiver
                .into_iter()
                .map(|query| {
                    runtime
                        .find_identity(query.clone())
                        .map(|i| i.pk)
                        .ok_or(SignerError::UnknownIdentity)
                })
                .collect::<Result<Vec<_>, _>>()?;
            let encrypted = Encrypted::encrypt(msg, receivers)?;
            println!("{encrypted}");
        }
        Command::Decrypt { key, text, file } => {
            let key = key.unwrap_or_default();
            eprintln!("Decrypting with {key} ...");

            let passwd = rpassword::prompt_password("Password for the private key: ")
                .map_err(CliError::Password)?;
            let pair = runtime.find_signer(key, &passwd)?;
            eprintln!("Using key {pair}");

            let s = String::from_utf8(get_message(text, file)?).map_err(|_| CliError::NoArmor)?;
            let encrypted = Encrypted::from_ascii_armored_str(&s)?;
            let msg = encrypted.decrypt(pair)?;
            println!("{}", String::from_utf8_lossy(&msg));
        }
    }
    Ok(())
}

fn get_message(text: Option<String>, file: Option<PathBuf>) -> Result<Vec<u8>, CliError> {
    match (text, file) {
        (Some(t), None) => Ok(t.into_bytes()),
        (None, Some(f)) => fs::read(f).map_err(CliError::ReadMessage),
        (None, None) => {
            eprintln!("Type or paste your message and press Ctrl+D on the last empty line:");
            let mut s = String::new();
            stdin()
                .read_to_string(&mut s)
                .map_err(CliError::ReadMessage)?;
            Ok(s.into_bytes())
        }
        _ => unreachable!(),
    }
}
