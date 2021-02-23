use anyhow::Context as _;
use rusqlite::{params, Connection, NO_PARAMS};

use std::path::Path;

use crate::security::{generate_salt_db_part, DataGuard, Nonce};

/// A record that has an ID
#[derive(Debug)]
pub struct Ided<T> {
    pub id: i64,
    pub data: T,
}

#[derive(Debug)]
pub struct Metadata {
    pub created: chrono::DateTime<chrono::Utc>,
    pub modified: chrono::DateTime<chrono::Utc>,
    pub author: String,
}

impl Metadata {
    pub fn new(username: &str) -> Self {
        let now = chrono::Utc::now();
        Metadata {
            created: now,
            modified: now,
            author: username.to_string(),
        }
    }
}

#[derive(Debug)]
pub struct Store {
    conn: Connection,
}

impl Store {
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
	pass_marker BLOB
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

        let mut store = Store { conn };
        store.init_security_if_missing()?;
        Ok(store)
    }

    fn init_security_if_missing(&mut self) -> rusqlite::Result<()> {
        let security_data_exists =
            self.conn
                .query_row("SELECT COUNT(*) FROM security", NO_PARAMS, |row| {
                    row.get::<usize, i64>(0)
                })?
                > 0;
        if !security_data_exists {
            self.conn.execute(
                "INSERT INTO security (salt) VALUES (?)",
                params![&generate_salt_db_part().unwrap()[..],],
            )?;
        }
        Ok(())
    }

    pub fn get_salt(&self) -> rusqlite::Result<Vec<u8>> {
        self.conn
            .query_row("SELECT salt FROM security", NO_PARAMS, |row| {
                row.get::<usize, Vec<u8>>(0)
            })
    }

    pub fn get_key(&mut self) -> rusqlite::Result<Option<Vec<u8>>> {
        self.conn
            .query_row("SELECT pass_marker FROM security", NO_PARAMS, |row| {
                row.get::<usize, Option<Vec<u8>>>(0)
            })
    }

    pub fn update_key(&mut self, marker: &[u8]) -> rusqlite::Result<()> {
        let id: i64 = self
            .conn
            .query_row("SELECT id FROM security", NO_PARAMS, |row| row.get(0))?;
        self.conn
            .execute(
                "UPDATE security SET pass_marker = ? WHERE id = ?",
                params![marker, id],
            )
            .map(|_| ())
    }

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

pub struct GuardedStore<'a> {
    pub store: &'a mut Store,
    pub username: &'a str,
    guard: &'a mut DataGuard,
}

impl<'a> GuardedStore<'a> {
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

    pub fn update(&mut self, meta: &Ided<Metadata>, entry: String) -> anyhow::Result<()> {
        let entry = entry.into_bytes();
        let (nonce, entry) = self.guard.seal_in_place(entry)?;
        self.store
            .conn
            .execute(
                "UPDATE entries SET modified = ?, nonce = ?, data = ? WHERE id = ?",
                params![
                    meta.data.modified.to_rfc3339(),
                    &nonce.to_le_bytes()[..],
                    entry,
                    meta.id
                ],
            )
            .context("Could not update entry")?;
        Ok(())
    }

    pub fn get_ids(&self) -> rusqlite::Result<Vec<i64>> {
        let mut stmt = self.store.conn.prepare("SELECT id FROM entries")?;
        let rows = stmt.query_map(NO_PARAMS, |row| row.get(0))?;
        let mut ids = Vec::new();
        for id in rows {
            ids.push(id?);
        }
        Ok(ids)
    }

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
