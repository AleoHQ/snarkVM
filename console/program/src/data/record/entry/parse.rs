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

use super::*;

impl<N: Network> Parser for Entry<N, Plaintext<N>> {
    /// Parses a string into the entry.
    #[inline]
    fn parse(string: &str) -> ParserResult<Self> {
        /// A helper enum encoding the visibility.
        #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
        enum Mode {
            Constant,
            Public,
            Private,
        }

        /// Parses an entry as a literal: `literal.visibility`.
        fn parse_literal<N: Network>(string: &str) -> ParserResult<(Plaintext<N>, Mode)> {
            alt((
                map(pair(Literal::parse, tag(".constant")), |(literal, _)| (Plaintext::from(literal), Mode::Constant)),
                map(pair(Literal::parse, tag(".public")), |(literal, _)| (Plaintext::from(literal), Mode::Public)),
                map(pair(Literal::parse, tag(".private")), |(literal, _)| (Plaintext::from(literal), Mode::Private)),
            ))(string)
        }

        /// Parses a sanitized pair: `identifier: entry`.
        fn parse_pair<N: Network>(string: &str) -> ParserResult<(Identifier<N>, Plaintext<N>, Mode)> {
            // Parse the whitespace and comments from the string.
            let (string, _) = Sanitizer::parse(string)?;
            // Parse the identifier from the string.
            let (string, identifier) = Identifier::parse(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the ":" from the string.
            let (string, _) = tag(":")(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the plaintext and visibility from the string.
            let (string, (plaintext, mode)) = alt((
                // Parse a literal.
                parse_literal,
                // Parse a struct.
                parse_struct,
                // Parse an array.
                parse_array,
            ))(string)?;
            // Return the identifier, plaintext, and visibility.
            Ok((string, (identifier, plaintext, mode)))
        }

        /// Parses an entry as a struct: `{ identifier_0: plaintext_0.visibility, ..., identifier_n: plaintext_n.visibility }`.
        /// Observe the `visibility` is the same for all members of the plaintext value.
        fn parse_struct<N: Network>(string: &str) -> ParserResult<(Plaintext<N>, Mode)> {
            // Parse the whitespace and comments from the string.
            let (string, _) = Sanitizer::parse(string)?;
            // Parse the "{" from the string.
            let (string, _) = tag("{")(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the members.
            let (string, (members, mode)) = map_res(separated_list1(tag(","), parse_pair), |members: Vec<_>| {
                // Ensure the members has no duplicate names.
                if has_duplicates(members.iter().map(|(name, ..)| name)) {
                    return Err(error("Duplicate member in struct"));
                }
                // Ensure the members all have the same visibility.
                let mode = members.iter().map(|(_, _, mode)| mode).dedup().collect::<Vec<_>>();
                let mode = match mode.len() == 1 {
                    true => *mode[0],
                    false => return Err(error("Members of struct in entry have different visibilities")),
                };
                // Ensure the number of structs is within the maximum limit.
                match members.len() <= N::MAX_STRUCT_ENTRIES {
                    // Return the members and the visibility.
                    true => Ok((members.into_iter().map(|(i, p, _)| (i, p)).collect::<Vec<_>>(), mode)),
                    false => Err(error(format!("Found a plaintext that exceeds size ({})", members.len()))),
                }
            })(string)?;
            // Parse the whitespace and comments from the string.
            let (string, _) = Sanitizer::parse(string)?;
            // Parse the '}' from the string.
            let (string, _) = tag("}")(string)?;
            // Output the plaintext and visibility.
            Ok((string, (Plaintext::Struct(IndexMap::from_iter(members.into_iter()), Default::default()), mode)))
        }

        /// Parses an entry as an array: `[plaintext_0.visibility, ..., plaintext_n.visibility]`.
        /// Observe the `visibility` is the same for all members of the plaintext value.
        fn parse_array<N: Network>(string: &str) -> ParserResult<(Plaintext<N>, Mode)> {
            // Parse the whitespace and comments from the string.
            let (string, _) = Sanitizer::parse(string)?;
            // Parse the "[" from the string.
            let (string, _) = tag("[")(string)?;
            // Parse the whitespace from the string.
            let (string, _) = Sanitizer::parse_whitespaces(string)?;
            // Parse the members.
            let (string, (members, mode)) = map_res(separated_list1(tag(","), parse_pair), |members: Vec<_>| {
                // Ensure the members all have the same visibility.
                let mode = members.iter().map(|(_, _, mode)| mode).dedup().collect::<Vec<_>>();
                let mode = match mode.len() == 1 {
                    true => *mode[0],
                    false => return Err(error("Members of array in entry have different visibilities")),
                };
                // Ensure the number of structs is within the maximum limit.
                // TODO (d0cd): Revisit these limits
                match members.len() <= u32::MAX as usize {
                    // Return the members and the visibility.
                    true => Ok((members.into_iter().map(|(_, p, _)| p).collect::<Vec<_>>(), mode)),
                    false => Err(error(format!("Found a plaintext that exceeds size ({})", members.len()))),
                }
            })(string)?;
            // Parse the whitespace and comments from the string.
            let (string, _) = Sanitizer::parse(string)?;
            // Parse the ']' from the string.
            let (string, _) = tag("]")(string)?;
            // Output the plaintext and visibility.
            Ok((string, (Plaintext::Array(members.into_iter().collect::<Vec<_>>(), Default::default()), mode)))
        }

        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse to determine the entry (order matters).
        let (string, (plaintext, mode)) = alt((
            // Parse a literal.
            parse_literal,
            // Parse a struct.
            parse_struct,
            // Parse an array.
            parse_array,
        ))(string)?;

        // Return the entry.
        match mode {
            Mode::Constant => Ok((string, Entry::Constant(plaintext))),
            Mode::Public => Ok((string, Entry::Public(plaintext))),
            Mode::Private => Ok((string, Entry::Private(plaintext))),
        }
    }
}

impl<N: Network> FromStr for Entry<N, Plaintext<N>> {
    type Err = Error;

    /// Returns the entry from a string literal.
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                // Ensure the remainder is empty.
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                // Return the object.
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network> Debug for Entry<N, Plaintext<N>> {
    /// Prints the entry as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network> Display for Entry<N, Plaintext<N>> {
    /// Prints the entry as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        self.fmt_internal(f, 0)
    }
}

impl<N: Network> Entry<N, Plaintext<N>> {
    /// Prints the entry with the given indentation depth.
    pub(in crate::data::record) fn fmt_internal(&self, f: &mut Formatter, depth: usize) -> fmt::Result {
        /// The number of spaces to indent.
        const INDENT: usize = 2;

        let (plaintext, visibility) = match self {
            Self::Constant(constant) => (constant, "constant"),
            Self::Public(public) => (public, "public"),
            Self::Private(private) => (private, "private"),
        };

        match plaintext {
            // Prints the literal, i.e. 10field.public
            Plaintext::Literal(literal, ..) => {
                write!(f, "{:indent$}{literal}.{visibility}", "", indent = depth * INDENT)
            }
            // Prints the struct, i.e. { first: 10i64.private, second: 198u64.private }
            Plaintext::Struct(struct_, ..) => {
                // Print the opening brace.
                write!(f, "{{")?;
                // Print the members.
                struct_.iter().enumerate().try_for_each(|(i, (name, plaintext))| {
                    match plaintext {
                        #[rustfmt::skip]
                        Plaintext::Literal(literal, ..) => match i == struct_.len() - 1 {
                            true => {
                                // Print the last member without a comma.
                                write!(f, "\n{:indent$}{name}: {literal}.{visibility}", "", indent = (depth + 1) * INDENT)?;
                                // Print the closing brace.
                                write!(f, "\n{:indent$}}}", "", indent = depth * INDENT)
                            }
                            // Print the member with a comma.
                            false => write!(f, "\n{:indent$}{name}: {literal}.{visibility},", "", indent = (depth + 1) * INDENT),
                        },
                        Plaintext::Struct(..) | Plaintext::Array(..) => {
                            // Print the member name.
                            write!(f, "\n{:indent$}{name}: ", "", indent = (depth + 1) * INDENT)?;
                            // Print the member.
                            match self {
                                Self::Constant(..) => Self::Constant(plaintext.clone()).fmt_internal(f, depth + 1)?,
                                Self::Public(..) => Self::Public(plaintext.clone()).fmt_internal(f, depth + 1)?,
                                Self::Private(..) => Self::Private(plaintext.clone()).fmt_internal(f, depth + 1)?,
                            }
                            // Print the closing brace.
                            match i == struct_.len() - 1 {
                                // Print the last member without a comma.
                                true => write!(f, "\n{:indent$}}}", "", indent = depth * INDENT),
                                // Print the member with a comma.
                                false => write!(f, "\n{:indent$}}},", "", indent = depth * INDENT),
                            }
                        }
                    }
                })
            }
            // Prints the array, i.e. [ 10i64.public, 198u64.public ]
            Plaintext::Array(array, _) => {
                write!(f, "{indent}[ ", indent = depth * INDENT)?;
                array.iter().enumerate().try_for_each(|(i, plaintext)| {
                    // Print the member.
                    match self {
                        Self::Constant(..) => Self::Constant(plaintext.clone()).fmt_internal(f, 0)?,
                        Self::Public(..) => Self::Public(plaintext.clone()).fmt_internal(f, 0)?,
                        Self::Private(..) => Self::Private(plaintext.clone()).fmt_internal(f, 0)?,
                    }
                    // If this is not the last member, print a comma.
                    if i != array.len() - 1 {
                        write!(f, ",")?;
                    }
                    Ok(())
                })?;
                write!(f, "]")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkvm_console_network::Testnet3;

    type CurrentNetwork = Testnet3;

    #[test]
    fn test_parse() -> Result<()> {
        // Sanity check.
        let expected = r"{
  foo: 5u8.private
}";
        let (remainder, candidate) = Entry::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse("{ foo: 5u8.private }")?;
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        let expected = r"{
  foo: 5u8.public,
  bar: {
    baz: 10field.public,
    qux: {
      quux: {
        corge: {
          grault: {
            garply: {
              waldo: {
                fred: {
                  plugh: {
                    xyzzy: {
                      thud: true.public
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}";
        let (remainder, candidate) = Entry::<CurrentNetwork, Plaintext<CurrentNetwork>>::parse(
            "{ foo: 5u8.public, bar: { baz: 10field.public, qux: {quux:{corge :{grault:  {garply:{waldo:{fred:{plugh:{xyzzy: { thud: true.public}} }}}  }}}}}}",
        )?;
        println!("\nExpected: {expected}\n\nFound: {candidate}\n");
        assert_eq!(expected, candidate.to_string());
        assert_eq!("", remainder);

        Ok(())
    }
}
