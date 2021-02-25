use crate::security::{UnspecifiedError, SYSTEM_RNG};

use rusqlite::{
    self,
    types::{FromSql, FromSqlResult, ToSql, ToSqlOutput, ValueRef},
};

/// A universal identifer
#[derive(Debug, Copy, Clone)]
pub struct Uuid(u128);

impl Uuid {
    /// Generate a new, random Uuid
    pub fn random() -> Result<Self, UnspecifiedError> {
        use ring::rand::SecureRandom as _;
        let mut buf = [0u8; std::mem::size_of::<u128>()];
        SYSTEM_RNG.fill(&mut buf)?;
        Ok(Uuid(u128::from_le_bytes(buf)))
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

impl FromSql for Uuid {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        Ok(String::column_result(value)?.parse().unwrap())
    }
}

impl ToSql for Uuid {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        Ok(format!("{}", self).into())
    }
}