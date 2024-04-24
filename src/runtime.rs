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

pub const SSI_DIR: &'static str = "~/.ssi";

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::PathBuf;

use crate::baid64::Baid64ParseError;
use crate::{Ssi, SsiParseError, SsiSecret};

#[derive(Debug, Display, Error, From)]
#[display(inner)]
pub enum Error {
    #[from]
    Io(io::Error),

    #[from]
    Baid64(Baid64ParseError),

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
            .open(path)?;
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
            .open(path)?;
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

    pub fn identities(&self) -> impl Iterator<Item = &Ssi> { self.identities.iter() }
}
