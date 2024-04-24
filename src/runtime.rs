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

pub const SSI_DIR: &str = "~/.ssi";

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use baid64::Baid64ParseError;

use crate::{Fingerprint, SecretParseError, Ssi, SsiPair, SsiParseError, SsiQuery, SsiSecret};

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from]
    Io(io::Error),

    #[from]
    Baid64(Baid64ParseError),

    #[from]
    Secret(SecretParseError),

    #[from]
    Ssi(SsiParseError),
}

pub struct SsiRuntime {
    pub secrets: BTreeSet<SsiSecret>,
    pub identities: HashSet<Ssi>,
}

impl SsiRuntime {
    pub fn load() -> Result<Self, Error> {
        let data_dir = PathBuf::from(shellexpand::tilde(SSI_DIR).to_string());
        fs::create_dir_all(&data_dir)?;

        let mut path = data_dir.clone();
        path.push("secrets");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        let reader = io::BufReader::new(file);
        let mut secrets = bset![];
        for line in reader.lines() {
            let line = line?;
            secrets.insert(line.parse()?);
        }

        let mut path = data_dir.clone();
        path.push("identities");
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_mode(0o600);
        let reader = io::BufReader::new(file);
        let mut identities = set![];
        for line in reader.lines() {
            let line = line?;
            identities.insert(line.parse()?);
        }

        Ok(Self {
            secrets,
            identities,
        })
    }

    pub fn store(&self) -> io::Result<()> {
        let data_dir = PathBuf::from(shellexpand::tilde(SSI_DIR).to_string());
        fs::create_dir_all(&data_dir)?;

        let mut path = data_dir.clone();
        path.push("secrets");
        let mut file = fs::File::create(path)?;
        for secret in &self.secrets {
            writeln!(file, "{secret}")?;
        }

        let mut path = data_dir.clone();
        path.push("identities");
        let mut file = fs::File::create(path)?;
        for ssi in &self.identities {
            writeln!(file, "{ssi}")?;
        }

        Ok(())
    }

    pub fn find_identity(&self, query: impl Into<SsiQuery>) -> Option<&Ssi> {
        let query = query.into();
        self.identities.iter().find(|ssi| match query {
            SsiQuery::Pub(pk) => ssi.pk == pk,
            SsiQuery::Fp(fp) => ssi.pk.fingerprint() == fp,
            SsiQuery::Id(ref id) => ssi.uids.iter().any(|uid| {
                &uid.id == id ||
                    &uid.to_string() == id ||
                    &uid.name == id ||
                    &format!("{}:{}", uid.schema, uid.id) == id
            }),
        })
    }

    pub fn find_signer(&self, query: impl Into<SsiQuery>, passwd: &str) -> Option<SsiPair> {
        let ssi = self.find_identity(query.into()).cloned()?;
        let sk = self.secrets.iter().find_map(|s| {
            let mut s = (*s).clone();
            if !passwd.is_empty() {
                s.decrypt(passwd);
            }
            if s.to_public() == ssi.pk {
                Some(s)
            } else {
                None
            }
        })?;
        Some(SsiPair::new(ssi, sk))
    }

    pub fn is_signing(&self, fp: Fingerprint) -> bool {
        self.secrets.iter().any(|s| s.fingerprint() == fp)
    }
}
