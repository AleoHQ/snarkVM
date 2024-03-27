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

impl<N: Network> Serialize for Future<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match serializer.is_human_readable() {
            true => {
                let mut state = serializer.serialize_struct("Future", 3)?;
                state.serialize_field("program_id", &self.program_id)?;
                state.serialize_field("function_name", &self.function_name)?;
                state.serialize_field("arguments", &self.arguments)?;
                state.end()
            }
            false => ToBytesSerializer::serialize_with_size_encoding(self, serializer),
        }
    }
}

impl<'de, N: Network> Deserialize<'de> for Future<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        match deserializer.is_human_readable() {
            true => {
                let mut value = serde_json::Value::deserialize(deserializer)?;
                let program_id: ProgramID<N> = DeserializeExt::take_from_value::<D>(&mut value, "program_id")?;
                let function_name: Identifier<N> = DeserializeExt::take_from_value::<D>(&mut value, "function_name")?;
                let arguments: Vec<Argument<N>> = DeserializeExt::take_from_value::<D>(&mut value, "arguments")?;

                Ok(Future { program_id, function_name, arguments })
            }
            false => FromBytesDeserializer::<Self>::deserialize_with_size_encoding(deserializer, "future"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Literal;
    use once_cell::sync::OnceCell;
    use snarkvm_console_network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_future_serde_json() -> Result<()> {
        // Check a sample nested instance of Future
        let future = Future {
            program_id: ProgramID::from_str("test.aleo").unwrap(),
            function_name: Identifier::from_str("test_function").unwrap(),
            arguments: vec![
                Argument::Plaintext(Plaintext::Literal(Literal::U64(U64::<CurrentNetwork>::new(10)), OnceCell::new())),
                Argument::Future(Future {
                    program_id: ProgramID::from_str("credits.aleo").unwrap(),
                    function_name: Identifier::from_str("transfer_public").unwrap(),
                    arguments: vec![],
                }),
            ],
        };

        let serialized = serde_json::to_string(&future).unwrap();
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert_eq!(future, deserialized);
        Ok(())
    }

    #[test]
    fn test_future_bincode() -> Result<()> {
        let future = Future {
            program_id: ProgramID::from_str("test.aleo").unwrap(),
            function_name: Identifier::from_str("test_function").unwrap(),
            arguments: vec![
                Argument::Plaintext(Plaintext::Literal(Literal::U64(U64::<CurrentNetwork>::new(10)), OnceCell::new())),
                Argument::Future(Future {
                    program_id: ProgramID::from_str("credits.aleo").unwrap(),
                    function_name: Identifier::from_str("transfer_public").unwrap(),
                    arguments: vec![],
                }),
            ],
        };

        let serialized = bincode::serialize(&future).unwrap();
        let deserialized = bincode::deserialize(&serialized).unwrap();
        assert_eq!(future, deserialized);
        Ok(())
    }
}
