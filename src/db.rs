use anyhow::Context as _;
use rusqlite::{params, Connection, NO_PARAMS};

use std::path::Path;

use crate::security::{generate_db_salt, DataGuard, Nonce};

/// A record that has an ID
#[derive(Debug)]
pub struct Ided<T> {
    pub id: i64,
    pub data: T,
}

/// A record containing journal entry metadata
#[derive(Debug)]
pub struct Metadata {
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub author: String,
}

impl Metadata {
    /// Create new metadata for journal entry by the specified user.
    pub fn new(username: &str) -> Self {
        let now = chrono::Utc::now();
        Metadata {
            created: now,
            modified: now,
            author: username.to_string(),
        }
    }
}

/// A store of journal entries
#[derive(Debug)]
pub struct Store {
    /// The database connection
    conn: Connection,
}

impl Store {
    /// Open the journals stored at the specified path.
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Store> {
        let path = path.as_ref();
        let conn =
            Connection::open(path).context(format!("Could open database at {}", path.display()))?;

        // Initialize the database
        conn.execute_batch(
            r#"
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS security (
	id INTEGER PRIMARY KEY ASC,
	salt BLOB NOT NULL,
	key BLOB
);

CREATE TABLE IF NOT EXISTS entries (
	id INTEGER PRIMARY KEY ASC,
	created TEXT NOT NULL,
	modified TEXT NOT NULL,
	author TEXT NOT NULL,
	nonce BLOB NOT NULL,
	data BLOB NOT NULL
);"#,
        )
        .context("Could not initialize database")?;

        // Make sure the database has a unique salt value
        let security_data_exists =
            conn.query_row("SELECT COUNT(*) FROM security", NO_PARAMS, |row| {
                row.get::<usize, i64>(0)
            })? > 0;
        if !security_data_exists {
            conn.execute(
                "INSERT INTO security (salt) VALUES (?)",
                params![&generate_db_salt().unwrap()[..],],
            )?;
        }
        Ok(Store { conn })
    }

    /// Get the database's unique salt (for use in encryption).
    pub fn get_salt(&self) -> rusqlite::Result<Vec<u8>> {
        self.conn
            .query_row("SELECT salt FROM security", NO_PARAMS, |row| {
                row.get::<usize, Vec<u8>>(0)
            })
    }

    /// Get the database's encryption key. This key is used to encrypt/decrypt
    /// all data in the database. However, it is encrypted using the user's
    /// name and password.
    pub fn get_key(&mut self) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row("SELECT key FROM security", NO_PARAMS, |row| {
                row.get::<usize, Option<Vec<u8>>>(0)
            })
    }

    /// Update the database's encryption key. It must already be encrypted with
    /// the user's name and password. Note that the key itself should _never_
    /// change as then there will be no way to decrypt existing entries in the
    /// database. It can be reencrypted with a new username and password, however.
    pub fn update_key(&mut self, encrypted_key: &[u8]) -> rusqlite::Result<()> {
        let id: i64 = self
            .conn
            .query_row("SELECT id FROM security", NO_PARAMS, |row| row.get(0))?;
        self.conn
            .execute(
                "UPDATE security SET key = ? WHERE id = ?",
                params![encrypted_key, id],
            )
            .map(|_| ())
    }

    /// Use the specified guard to encrypt/decrypt the database.
    pub fn guard<'a>(
        &'a mut self,
        guard: &'a mut DataGuard,
        username: &'a str,
    ) -> GuardedStore<'a> {
        GuardedStore {
            store: self,
            username,
            guard,
        }
    }
}

/// A database of journal entries protected by the encryption facilities of a
/// DataGuard. This is the only way to read/write entries from/to the database.
pub struct GuardedStore<'a> {
    /// The underlying store.
    pub store: &'a mut Store,
    /// The user's name.
    pub username: &'a str,
    /// The guard used for encryption/decryption.
    guard: &'a mut DataGuard,
}

impl<'a> GuardedStore<'a> {
    /// Insert a new entry into the database with the associated metadata.
    /// Returns an ID for the new entry.
    pub fn insert(&mut self, meta: &Metadata, entry: String) -> anyhow::Result<i64> {
        let entry = entry.into_bytes();
        let (nonce, entry) = self.guard.seal_in_place(entry)?;
        self.store.conn.execute(
            "INSERT INTO entries (created, modified, author, nonce, data) VALUES (?, ?, ?, ?, ?)",
            params![
                meta.created.to_rfc3339(),
                meta.modified.to_rfc3339(),
                meta.author,
                &nonce.to_le_bytes()[..],
                entry
            ],
        )
        .context("Could not insert entry")?;
        Ok(self.store.conn.last_insert_rowid())
    }

    /// Update an existing entry.
    pub fn update(
        &mut self,
        id: i64,
        modified: chrono::DateTime<chrono::Utc>,
        entry: String,
    ) -> anyhow::Result<()> {
        let entry = entry.into_bytes();
        let (nonce, entry) = self.guard.seal_in_place(entry)?;
        self.store
            .conn
            .execute(
                "UPDATE entries SET modified = ?, nonce = ?, data = ? WHERE id = ?",
                params![modified.to_rfc3339(), &nonce.to_le_bytes()[..], entry, id],
            )
            .context("Could not update entry")?;
        Ok(())
    }

    /// Get the ids of all the journal entries
    pub fn get_ids(&self) -> rusqlite::Result<Vec<i64>> {
        let mut stmt = self.store.conn.prepare("SELECT id FROM entries")?;
        let rows = stmt.query_map(NO_PARAMS, |row| row.get(0))?;
        let mut ids = Vec::new();
        for id in rows {
            ids.push(id?);
        }
        Ok(ids)
    }

    /// Get Metadata about the specified entries
    pub fn get_metadata(&self, ids: &[i64]) -> rusqlite::Result<Vec<Ided<Metadata>>> {
        use itertools::Itertools as _; // for join on iterators
        let mut stmt = self.store.conn.prepare(
            format!(
                "SELECT id, created, modified, author FROM entries WHERE id IN ({})",
                ids.iter().join(", ")
            )
            .as_str(),
        )?;
        let rows = stmt.query_map(NO_PARAMS, |row| {
            Ok(Ided {
                id: row.get(0)?,
                data: Metadata {
                    created: {
                        let date_string: String = row.get(1)?;
                        chrono::DateTime::parse_from_rfc3339(date_string.as_str())
                            .unwrap()
                            .with_timezone(&chrono::Utc)
                    },
                    modified: {
                        let date_string: String = row.get(2)?;
                        chrono::DateTime::parse_from_rfc3339(date_string.as_str())
                            .unwrap()
                            .with_timezone(&chrono::Utc)
                    },
                    author: row.get(3)?,
                },
            })
        })?;
        let mut data = Vec::new();
        for row in rows {
            data.push(row?);
        }
        Ok(data)
    }

    /// Get the journal entries for the specified ids
    pub fn get_entries(&mut self, ids: &[i64]) -> rusqlite::Result<Vec<Ided<String>>> {
        use itertools::Itertools as _; // for join on iterators
        let mut stmt = self.store.conn.prepare(
            format!(
                "SELECT id, nonce, data FROM entries WHERE id IN ({})",
                ids.iter().join(", ")
            )
            .as_str(),
        )?;
        let guard = &mut self.guard;
        let rows = stmt.query_map(NO_PARAMS, |row| {
            use std::convert::TryInto as _;
            let nonce_bytes: Vec<u8> = row.get(1)?;
            let nonce = Nonce::from_le_bytes(nonce_bytes.try_into().unwrap());
            let data: Vec<u8> = row.get(2)?;
            let data = guard.open_in_place(nonce, data).unwrap();
            Ok(Ided {
                id: row.get(0)?,
                data: String::from_utf8(data).unwrap(),
            })
        })?;
        let mut data = Vec::new();
        for row in rows {
            data.push(row?);
        }
        Ok(data)
    }
}
