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

/// An argument passed into a future.
#[derive(Clone)]
pub enum Argument<N: Network> {
    /// A plaintext value.
    Plaintext(Plaintext<N>),
    /// A future.
    Future(Future<N>),
}

impl<N: Network> Serialize for Argument<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => match self {
                Self::Plaintext(value) => serializer.collect_str(value),
                Self::Future(value) => value.serialize(serializer),
            },
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Argument<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                let value = serde_json::Value::deserialize(deserializer)?;

                if let Some(plaintext) = value.as_str() {
                    let plaintext = Plaintext::from_str(plaintext).map_err(de::Error::custom)?;
                    Ok(Argument::Plaintext(plaintext))
                } else {
                    let future = Future::deserialize(value).map_err(de::Error::custom)?;
                    Ok(Argument::Future(future))
                }
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "argument"),
        }
    }
}

impl<N: Network> Equal<Self> for Argument<N> {
    type Output = Boolean<N>;

    /// Returns `true` if `self` and `other` are equal.
    fn is_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Plaintext(plaintext_a), Self::Plaintext(plaintext_b)) => plaintext_a.is_equal(plaintext_b),
            (Self::Future(future_a), Self::Future(future_b)) => future_a.is_equal(future_b),
            (Self::Plaintext(..), _) | (Self::Future(..), _) => Boolean::new(false),
        }
    }

    /// Returns `true` if `self` and `other` are *not* equal.
    fn is_not_equal(&self, other: &Self) -> Self::Output {
        match (self, other) {
            (Self::Plaintext(plaintext_a), Self::Plaintext(plaintext_b)) => plaintext_a.is_not_equal(plaintext_b),
            (Self::Future(future_a), Self::Future(future_b)) => future_a.is_not_equal(future_b),
            (Self::Plaintext(..), _) | (Self::Future(..), _) => Boolean::new(true),
        }
    }
}

impl<N: Network> FromBytes for Argument<N> {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self>
    where
        Self: Sized,
    {
        // Read the index.
        let index = u8::read_le(&mut reader)?;
        // Read the argument.
        let argument = match index {
            0 => Self::Plaintext(Plaintext::read_le(&mut reader)?),
            1 => Self::Future(Future::read_le(&mut reader)?),
            2.. => return Err(error(format!("Failed to decode future argument {index}"))),
        };
        Ok(argument)
    }
}

impl<N: Network> ToBytes for Argument<N> {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        match self {
            Self::Plaintext(plaintext) => {
                0u8.write_le(&mut writer)?;
                plaintext.write_le(&mut writer)
            }
            Self::Future(future) => {
                1u8.write_le(&mut writer)?;
                future.write_le(&mut writer)
            }
        }
    }
}

impl<N: Network> ToBits for Argument<N> {
    /// Returns the argument as a list of **little-endian** bits.
    #[inline]
    fn write_bits_le(&self, vec: &mut Vec<bool>) {
        match self {
            Self::Plaintext(plaintext) => {
                vec.push(false);
                plaintext.write_bits_le(vec);
            }
            Self::Future(future) => {
                vec.push(true);
                future.write_bits_le(vec);
            }
        }
    }

    /// Returns the argument as a list of **big-endian** bits.
    #[inline]
    fn write_bits_be(&self, vec: &mut Vec<bool>) {
        match self {
            Self::Plaintext(plaintext) => {
                vec.push(false);
                plaintext.write_bits_be(vec);
            }
            Self::Future(future) => {
                vec.push(true);
                future.write_bits_be(vec);
            }
        }
    }
}
