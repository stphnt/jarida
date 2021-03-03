use anyhow::Context as _;

use fs_err as fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use crate::security::{generate_db_salt, DataGuard, Open, Seal};
use crate::uuid::Uuid;

/// A record that has an ID
#[derive(Debug)]
pub struct Ided<T> {
    pub uuid: Uuid,
    pub data: T,
}

/// A record containing journal entry metadata
#[derive(Debug, serde::Serialize, serde::Deserialize)]
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

/// A record containing the journal entry's metadata and content
pub struct MetadataAndContent {
    pub metadata: Metadata,
    pub content: String,
}

/// A store of journal entries
#[derive(Debug)]
pub struct Store {
    /// The root directory of the data storage
    root: PathBuf,
}

impl Store {
    const ENTRIES_DIR_NAME: &'static str = "entries";
    const SECURITY_DIR_NAME: &'static str = "security";
    const SALT_FILE_NAME: &'static str = "salt";
    const KEY_FILE_NAME: &'static str = "key";
    const INDEX_FILE_NAME: &'static str = "index";

    /// Get the file path for the specified entry
    fn get_entry_path(&self, id: Uuid) -> PathBuf {
        let mut path = self.root.join(Self::ENTRIES_DIR_NAME);
        path.push(format!("{}", id));
        path
    }

    /// Get the file path for the database salt.
    fn get_salt_path(&self) -> PathBuf {
        let mut path = self.root.join(Self::SECURITY_DIR_NAME);
        path.push(Self::SALT_FILE_NAME);
        path
    }

    /// Get the file path for the database key.
    fn get_key_path(&self) -> PathBuf {
        let mut path = self.root.join(Self::SECURITY_DIR_NAME);
        path.push(Self::KEY_FILE_NAME);
        path
    }

    /// Get the file path for the index file, which contains the list of entry
    /// Uuids in ascending order.
    fn get_index_path(&self) -> PathBuf {
        self.root.join(Self::INDEX_FILE_NAME)
    }

    /// Open the journal stored at the specified path.
    pub fn open<P: AsRef<Path>>(path: P) -> anyhow::Result<Store> {
        let path = path.as_ref();
        let store = Store {
            root: path.to_path_buf(),
        };

        fn ignore_already_existing(error: std::io::Error) -> std::io::Result<()> {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Ok(())
            } else {
                Err(error)
            }
        }
        let security_path = path.join(Self::SECURITY_DIR_NAME);
        let entries_path = path.join(Self::ENTRIES_DIR_NAME);
        fs::create_dir_all(path).or_else(ignore_already_existing)?;
        fs::create_dir(security_path).or_else(ignore_already_existing)?;
        fs::create_dir(entries_path).or_else(ignore_already_existing)?;

        // Make sure the is a unique salt value
        let salt_path = store.get_salt_path();
        if !salt_path.exists() {
            let mut f = fs::File::create(salt_path)?;
            f.write_all(&generate_db_salt().unwrap())?;
        }
        // Make sure the key file exists, even if it is empty.
        let key_path = store.get_key_path();
        if !key_path.exists() {
            fs::File::create(key_path)?;
        }
        // Make sure the index files exists, even if it is empty.
        let index_path = store.get_index_path();
        if !index_path.exists() {
            fs::File::create(index_path)?;
        }
        Ok(store)
    }

    /// Get the database's unique salt (for use in encryption).
    pub fn get_salt(&self) -> anyhow::Result<Vec<u8>> {
        let mut buf = Vec::new();
        fs::File::open(self.get_salt_path())
            .context("Could not open salt file")?
            .read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Get the database's encryption key. This key is used to encrypt/decrypt
    /// all data in the database. However, it is encrypted using the user's
    /// name and password.
    pub fn get_key(&mut self) -> anyhow::Result<Option<Vec<u8>>> {
        let path = self.get_key_path();
        if path.exists() {
            let mut buf = Vec::new();
            let size = fs::File::open(path)
                .context("Could not open key file")?
                .read_to_end(&mut buf)?;
            Ok(if size > 0 { Some(buf) } else { None })
        } else {
            Ok(None)
        }
    }

    /// Update the database's encryption key. It must already be encrypted with
    /// the user's name and password. Note that the key itself should _never_
    /// change as then there will be no way to decrypt existing entries in the
    /// database. It can be reencrypted with a new username and password, however.
    pub fn update_key(&mut self, encrypted_key: &[u8]) -> anyhow::Result<()> {
        let mut f = fs::File::create(self.get_key_path()).context("Could not open key file")?;
        f.write_all(encrypted_key)?;
        Ok(())
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
    /// Get the filepath for a journal entry's metadata
    fn get_entry_metadata_path(&self, uuid: Uuid) -> PathBuf {
        let mut path = self.store.get_entry_path(uuid);
        path.push("meta");
        path
    }

    /// Get the filepath for a journal entry's content
    fn get_entry_content_path(&self, uuid: Uuid) -> PathBuf {
        let mut path = self.store.get_entry_path(uuid);
        path.push("content");
        path
    }

    /// Set/update the content of a journal entry. If the journal entry already
    /// exists it's content will be overwritten. The content is encrypted prior
    /// to writing.
    fn write_content(&mut self, uuid: Uuid, content: String) -> anyhow::Result<()> {
        let mut f = fs::File::create(self.get_entry_content_path(uuid))
            .context(format!("Could not create content file for {}", uuid))?;
        f.write_all(&content.seal(self.guard)?)?;
        Ok(())
    }

    /// Get the decrypted contents of a journal entry.
    fn read_content(&mut self, uuid: Uuid) -> anyhow::Result<String> {
        let path = self.get_entry_content_path(uuid);
        if path.exists() {
            let mut f =
                fs::File::open(&path).context(format!("Could not open {}", path.display()))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            Ok(Open::open(buf, self.guard)?)
        } else {
            Err(anyhow::anyhow!("Invalid id {}", uuid))
        }
    }

    /// Set/update the metadata for a journal entry. If the metadata already
    /// exists it will be overwritten. The metadata is encrypted prior to
    /// writing.
    fn write_metadata(&mut self, uuid: Uuid, metadata: &Metadata) -> anyhow::Result<()> {
        let mut f = fs::File::create(self.get_entry_metadata_path(uuid))
            .context(format!("Could not create metadata file for {}", uuid))?;
        f.write_all(&toml::to_string(metadata)?.seal(self.guard)?)?;
        Ok(())
    }

    /// Get the decrypted metadata for a journal entry.
    fn read_metadata(&mut self, uuid: Uuid) -> anyhow::Result<Metadata> {
        let path = self.get_entry_metadata_path(uuid);
        if path.exists() {
            let mut f =
                fs::File::open(&path).context(format!("Could not open {}", path.display()))?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            let buf: Vec<_> = Open::open(buf, self.guard)?;
            let meta: Metadata = toml::from_slice(&buf)?;
            Ok(meta)
        } else {
            Err(anyhow::anyhow!("Invalid id {}", uuid))
        }
    }

    /// Insert a new entry into the database with the associated metadata.
    /// Returns an ID for the new entry.
    pub fn insert(&mut self, meta: &Metadata, entry: String) -> anyhow::Result<Uuid> {
        let uuid = Uuid::random().unwrap();
        fs::create_dir_all(self.store.get_entry_path(uuid))?;
        self.write_content(uuid, entry)?;
        self.write_metadata(uuid, meta)?;

        // Add the new UUID to the index file
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(self.store.get_index_path())
            .context("Could not open index file")?;
        f.write_all(format!("{}\n", uuid).as_bytes())?;
        Ok(uuid)
    }

    /// Update an existing entry.
    pub fn update(
        &mut self,
        uuid: Uuid,
        modified: chrono::DateTime<chrono::Utc>,
        entry: String,
    ) -> anyhow::Result<()> {
        let mut result = self.get_metadata(&[uuid]).into_iter().next().unwrap()?;
        result.data.modified = modified;
        let mut meta = self.read_metadata(uuid)?;
        meta.modified = modified;
        self.write_metadata(uuid, &meta)?;
        self.write_content(uuid, entry)
    }

    /// Get the uuids of all the journal entries
    pub fn get_uuids(&self) -> anyhow::Result<Vec<Uuid>> {
        use std::io::{BufRead as _, BufReader};
        let f = fs::File::open(self.store.get_index_path()).context("Could not open index file")?;
        let reader = BufReader::new(f);

        let mut uuids = Vec::new();
        for line in reader.lines() {
            let line = line?;
            uuids.push(
                line.parse::<Uuid>()
                    .context(format!("Could not parse uuid {}", line))?,
            );
        }
        Ok(uuids)
    }

    /// Get Metadata about the specified entries
    pub fn get_metadata(&mut self, uuids: &[Uuid]) -> Vec<anyhow::Result<Ided<Metadata>>> {
        uuids
            .iter()
            .cloned()
            .map(|uuid| {
                Ok(Ided {
                    uuid,
                    data: self.read_metadata(uuid)?,
                })
            })
            .collect()
    }

    /// Get the content of the journal entries with the specified uuids
    pub fn get_content(&mut self, uuids: &[Uuid]) -> Vec<anyhow::Result<Ided<String>>> {
        uuids
            .iter()
            .cloned()
            .map(|uuid| {
                Ok(Ided {
                    uuid,
                    data: self.read_content(uuid)?,
                })
            })
            .collect()
    }

    /// Get the metadata and content of the journal entries with the specified uuids
    pub fn get_metadata_and_content(
        &mut self,
        uuids: &[Uuid],
    ) -> Vec<anyhow::Result<Ided<MetadataAndContent>>> {
        uuids
            .iter()
            .cloned()
            .map(|uuid| {
                Ok(Ided {
                    uuid,
                    data: MetadataAndContent {
                        metadata: self.read_metadata(uuid)?,
                        content: self.read_content(uuid)?,
                    },
                })
            })
            .collect()
    }
}
