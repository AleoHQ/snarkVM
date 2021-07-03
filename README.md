<p align="center">
    <img alt="snarkVM" width="1412" src="https://cdn.aleo.org/snarkvm/banner.png">
</p>

<p align="center">
    <a href="https://circleci.com/gh/AleoHQ/snarkVM"><img src="https://circleci.com/gh/AleoHQ/snarkVM.svg?style=svg&circle-token=6e9ad6d39d95350544f352d34e0e5c62ef54db26"></a>
    <a href="https://codecov.io/gh/AleoHQ/snarkVM"><img src="https://codecov.io/gh/AleoHQ/snarkVM/branch/master/graph/badge.svg?token=cck8tS9HpO"/></a>
    <a href="https://discord.gg/5v2ynrw2ds"><img src="https://img.shields.io/discord/700454073459015690?logo=discord"/></a>
</p>

## Table of Contents

* [1. Overview](#1-overview)
* [2. Build Guide](#2-build-guide)
* [3. Usage Guide](#3-usage-guide)
* [4. License](#4-license)

## 1. Overview

|       Package      |                                    Crate.io                                   |        `std`       |       `wasm`       |    `no_std`    |
|:------------------:|-------------------------------------------------------------------------------|:------------------:|:------------------:|:--------------:|
| snarkvm            |![crates.io](https://img.shields.io/crates/v/snarkvm.svg?color=neon)           | :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-algorithms |![crates.io](https://img.shields.io/crates/v/snarkvm-algorithms.svg?color=neon)| :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-curves     | ![crates.io](https://img.shields.io/crates/v/snarkvm-curves.svg?color=neon)   | :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-derives    | ![crates.io](https://img.shields.io/crates/v/snarkvm-derives.svg?color=neon)  | :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-dpc        | ![crates.io](https://img.shields.io/crates/v/snarkvm-dpc.svg?color=neon)      | :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-fields     | ![crates.io](https://img.shields.io/crates/v/snarkvm-fields.svg?color=neon)   | :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-gadgets    | ![crates.io](https://img.shields.io/crates/v/snarkvm-gadgets.svg?color=neon)  | :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-marlin     | ![crates.io](https://img.shields.io/crates/v/snarkvm-marlin.svg?color=neon)   | :white_check_mark: |   :construction:   | :construction: |
| snarkvm-parameters |![crates.io](https://img.shields.io/crates/v/snarkvm-parameters.svg?color=neon)| :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-polycommit |![crates.io](https://img.shields.io/crates/v/snarkvm-polycommit.svg?color=neon)| :white_check_mark: |   :construction:   | :construction: |
| snarkvm-posw       | ![crates.io](https://img.shields.io/crates/v/snarkvm-posw.svg?color=neon)     | :white_check_mark: |   :construction:   | :construction: |
| snarkvm-profiler   | ![crates.io](https://img.shields.io/crates/v/snarkvm-profiler.svg?color=neon) | :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-r1cs       | ![crates.io](https://img.shields.io/crates/v/snarkvm-r1cs.svg?color=neon)     | :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-utilities  | ![crates.io](https://img.shields.io/crates/v/snarkvm-utilities.svg?color=neon)| :white_check_mark: | :white_check_mark: | :construction: |
| snarkvm-wasm       | ![crates.io](https://img.shields.io/crates/v/snarkvm-wasm.svg?color=neon)     | :white_check_mark: | :white_check_mark: | :construction: |

For more information, visit [Welcome to Aleo](https://github.com/AleoHQ/welcome) to get started.

## 2. Build Guide

### 2.1 Install Rust

We recommend installing Rust using [rustup](https://www.rustup.rs/). You can install `rustup` as follows:

- macOS or Linux:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- Windows:  
  
  Download the [Windows 64-bit executable](https://win.rustup.rs/x86_64) or
  [Windows 32-bit executable](https://win.rustup.rs/i686) and follow the on-screen instructions.

### 2.2a Build from Crates.io

We recommend installing `snarkvm` this way. In your terminal, run:

```bash
cargo install snarkvm
```

Now to use `snarkvm`, in your terminal, run:
```bash
snarkvm
```
 
### 2.2b Build from Source Code

Alternatively, you can install `snarkvm` by building from the source code as follows:

```bash
# Download the source code
git clone https://github.com/AleoHQ/snarkvm && cd snarkvm

# Install snarkVM
$ cargo install --path .
```

Now to use `snarkvm`, in your terminal, run:
```bash
snarkvm
```

## 3. Usage Guide

## 4. License

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](./LICENSE.md)
