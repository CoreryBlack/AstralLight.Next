//! memory-v1 标识的字节与规范 UUID 字符串编解码。
//!
//! 此类型只表达 16 字节值，不生成标识，也不证明对象存在、身份有效或具有权限。

use std::{fmt, str::FromStr};

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// memory-v1 的 16 字节标识；字节按 UUID 文本从左到右的顺序保存。
///
/// 全部字节值均可表示，包括全零；业务有效性由未来的身份生命周期合同决定。
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct MemoryId([u8; 16]);

impl MemoryId {
    /// 从 UUID 网络字节序的 16 个原始字节构造标识。memory—v1
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// 借用未重排的原始字节。memory—v1
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// 返回未重排的原始字节。memory—v1
    pub const fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// 输入不符合小写、带连字符的规范 UUID 字符串格式。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseMemoryIdError;

impl fmt::Display for ParseMemoryIdError {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("expected a lowercase hyphenated UUID")
    }
}

impl std::error::Error for ParseMemoryIdError {}

impl FromStr for MemoryId {
    type Err = ParseMemoryIdError;

    // memory—v1
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let bytes = value.as_bytes();
        if bytes.len() != 36
            || !bytes.iter().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    *byte == b'-'
                } else {
                    byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)
                }
            })
        {
            return Err(ParseMemoryIdError);
        }

        Uuid::parse_str(value)
            .map(|uuid| Self(*uuid.as_bytes()))
            .map_err(|_| ParseMemoryIdError)
    }
}

impl fmt::Display for MemoryId {
    // memory—v1
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Uuid::from_bytes(self.0).hyphenated().fmt(f)
    }
}

impl Serialize for MemoryId {
    // memory—v1
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for MemoryId {
    // memory—v1
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    // memory—v1
    fn preserves_uuid_network_byte_order_and_exact_wire_format() {
        let bytes = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let id = MemoryId::from_bytes(bytes);
        let text = "00112233-4455-6677-8899-aabbccddeeff";
        assert_eq!(id.as_bytes(), &bytes);
        assert_eq!(id.into_bytes(), bytes);
        assert_eq!(id.to_string(), text);
        assert_eq!(text.parse::<MemoryId>(), Ok(id));
        assert_eq!(serde_json::to_string(&id).unwrap(), format!("\"{text}\""));
        assert_eq!(
            serde_json::from_str::<MemoryId>(&format!("\"{text}\"")).unwrap(),
            id
        );
    }

    #[test]
    // memory—v1
    fn preserves_zero_and_arbitrary_uuid_bits() {
        for bytes in [[0; 16], [0xff; 16], [0x80; 16], [0x01; 16]] {
            let id = MemoryId::from_bytes(bytes);
            assert_eq!(
                id.to_string().parse::<MemoryId>().unwrap().into_bytes(),
                bytes
            );
            let json = serde_json::to_string(&id).unwrap();
            assert_eq!(serde_json::from_str::<MemoryId>(&json).unwrap(), id);
        }
        assert_eq!(
            MemoryId::from_bytes([0; 16]).to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    // memory—v1
    fn rejects_noncanonical_and_malformed_strings() {
        for text in [
            "",
            "00112233445566778899aabbccddeeff",
            "00112233-4455-6677-8899-AABBCCDDEEFF",
            "00112233-4455-6677-8899-aabbccddeefg",
            "00112233_4455-6677-8899-aabbccddeeff",
            "00112233-4455-6677-8899-aabbccddeef",
            "00112233-4455-6677-8899-aabbccddeeff0",
            " 00112233-4455-6677-8899-aabbccddeeff",
            "{00112233-4455-6677-8899-aabbccddeeff}",
            "urn:uuid:00112233-4455-6677-8899-aabbccddeeff",
            "00112233-4455-6677-8899-aabbccddeeé",
        ] {
            assert!(text.parse::<MemoryId>().is_err(), "accepted {text:?}");
            let json = serde_json::to_string(text).unwrap();
            assert!(
                serde_json::from_str::<MemoryId>(&json).is_err(),
                "accepted {text:?}"
            );
        }
        for json in ["null", "123", "[]", "{}"] {
            assert!(
                serde_json::from_str::<MemoryId>(json).is_err(),
                "accepted {json}"
            );
        }
    }
}
