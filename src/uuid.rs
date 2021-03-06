use crate::security::{UnspecifiedError, SYSTEM_RNG};

/// A universal identifier.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Uuid(u128);

impl Uuid {
    /// Generate a new, random Uuid
    pub fn random() -> Result<Self, UnspecifiedError> {
        use ring::rand::SecureRandom as _;
        let mut buf = [0u8; std::mem::size_of::<u128>()];
        SYSTEM_RNG.fill(&mut buf)?;
        Ok(Uuid(u128::from_le_bytes(buf)))
    }

    pub fn to_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Uuid(u128::from_le_bytes(bytes))
    }
}

impl std::str::FromStr for Uuid {
    type Err = <u128 as std::str::FromStr>::Err;

    fn from_str(s: &str) -> Result<Uuid, Self::Err> {
        Ok(Uuid(u128::from_str_radix(s, 16)?))
    }
}

impl std::fmt::Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}

impl From<Uuid> for String {
    fn from(uuid: Uuid) -> String {
        format!("{}", uuid)
    }
}

impl std::convert::TryFrom<String> for Uuid {
    type Error = <Uuid as std::str::FromStr>::Err;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}
