# Self-sovereign identity

![Build](https://github.com/LNP-BP/ssi/workflows/Build/badge.svg)
![Tests](https://github.com/LNP-BP/ssi/workflows/Tests/badge.svg)
![Lints](https://github.com/LNP-BP/ssi/workflows/Lints/badge.svg)

[![crates.io](https://img.shields.io/crates/v/s2id)](https://crates.io/crates/s2id)
[![Docs](https://docs.rs/s2id/badge.svg)](https://docs.rs/s2id)
[![Apache-2 licensed](https://img.shields.io/crates/l/s2id)](./LICENSE)

## Installation

```console
$ cargo install s2id --all-features
```

## Use

```console
$ ssi help
$ ssi new --no-expiry --uid "My Name <mailto:my@email.com>"
$ ssi list
$ SIG=`ssi sign my@email.com -t "Test message"`
$ ssi verify $SIG
```
