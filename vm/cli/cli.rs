// Copyright (C) 2019-2023 Aleo Systems Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::cli::commands::{Build, Clean, New, Run, Update};

use anstyle::{AnsiColor, Color, Style};
use anyhow::Result;
use clap::{builder::Styles, Parser};

const HEADER_COLOR: Option<Color> = Some(Color::Ansi(AnsiColor::Yellow));
const LITERAL_COLOR: Option<Color> = Some(Color::Ansi(AnsiColor::Green));
const STYLES: Styles = Styles::plain()
    .header(Style::new().bold().fg_color(HEADER_COLOR))
    .usage(Style::new().bold().fg_color(HEADER_COLOR))
    .literal(Style::new().bold().fg_color(LITERAL_COLOR));

#[derive(Debug, Parser)]
#[clap(name = "snarkVM", author = "The Aleo Team <hello@aleo.org>", styles = STYLES)]
pub struct CLI {
    /// Specify the verbosity [options: 0, 1, 2, 3]
    #[clap(default_value = "2", short, long)]
    pub verbosity: u8,
    /// Specify a subcommand.
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Debug, Parser)]
pub enum Command {
    #[clap(name = "build")]
    Build(Build),
    #[clap(name = "clean")]
    Clean(Clean),
    #[clap(name = "new")]
    New(New),
    #[clap(name = "run")]
    Run(Run),
    #[clap(name = "update")]
    Update(Update),
}

impl Command {
    /// Parse the command.
    pub fn parse(self) -> Result<String> {
        match self {
            Self::Build(command) => command.parse(),
            Self::Clean(command) => command.parse(),
            Self::New(command) => command.parse(),
            Self::Run(command) => command.parse(),
            Self::Update(command) => command.parse(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A test case recommended by clap (https://docs.rs/clap/latest/clap/_derive/_tutorial/index.html#testing).
    #[test]
    fn verify_cli() {
        use clap::CommandFactory;
        CLI::command().debug_assert()
    }

    #[test]
    fn clap_snarkvm_run() {
        use crate::prelude::{Identifier, Value};

        let arg_vec = vec!["snarkvm", "run", "hello", "1u32", "2u32", "--endpoint", "ENDPOINT", "--offline"];
        let cli = CLI::parse_from(&arg_vec);

        if let Command::Run(run) = cli.command {
            assert_eq!(run.function(), Identifier::try_from(arg_vec[2]).unwrap());
            assert_eq!(run.inputs(), vec![Value::try_from(arg_vec[3]).unwrap(), Value::try_from(arg_vec[4]).unwrap()]);
            assert_eq!(run.endpoint(), Some("ENDPOINT"));
            assert!(run.offline());
        } else {
            panic!("Unexpected result of clap parsing!");
        }
    }
}
