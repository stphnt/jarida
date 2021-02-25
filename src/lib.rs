use anyhow::Context as _;

mod cli;
mod config;
mod db;
mod security;
mod uuid;

pub use cli::*;
pub use config::Config;
pub use db::*;
pub use security::{CredentialGuard, DataGuard};
pub use uuid::Uuid;

/// The formatting string for all date-time
const DATETIME_FORMAT: &str = "%a %v %R";

/// Retry the specified function up to the specified number of times times until is succeeds.
fn retry<T, S: FnMut() -> anyhow::Result<T>>(max: usize, mut func: S) -> anyhow::Result<T> {
    let mut result = func();
    for i in 0..max {
        if result.is_ok() {
            break;
        } else {
            if i == max - 1 {
                return result;
            }
            println!("Oops! Try again.");
            result = func();
        }
    }
    result
}

/// Prompt the user for a password once
fn prompt_password() -> anyhow::Result<String> {
    rpassword::prompt_password_stdout("Password: ").context("Error getting a password")
}

/// Prompt the user for a password and prompt again to confirm it. If the
/// passwords do not match, prompt up to 3 more times before failing.
fn prompt_and_confirm_password() -> anyhow::Result<String> {
    let err = "Error getting a password";
    let p1 = rpassword::prompt_password_stdout("Password: ").context(err)?;
    let p2 = rpassword::prompt_password_stdout("Confirm: ").context(err)?;
    if p1 == p2 {
        Ok(p1)
    } else {
        anyhow::bail!("Passwords do not match");
    }
}

// Prompt the use for their name once.
fn prompt_username() -> anyhow::Result<String> {
    use std::io::BufRead as _;
    use std::io::Write as _;

    print!("Username: ");
    std::io::stdout().flush()?;
    let stdin = std::io::stdin();
    let username = stdin
        .lock()
        .lines()
        .next()
        .expect("Cannot read from stdin")?;
    Ok(username)
}

// Open the specified file with the editor defined in config
pub fn open_file_in_editor<P: AsRef<std::path::Path>>(cfg: &Config, path: P) -> anyhow::Result<()> {
    let path = path.as_ref();
    log::trace!("Opening {} in {}", path.display(), cfg.editor.display());

    let status = std::process::Command::new(cfg.editor.as_os_str())
        .arg(path)
        .status()
        .context(format!(
            "Failed to execute {} {}",
            cfg.editor.display(),
            path.display()
        ))?;
    if !status.success() {
        Err(anyhow::anyhow!(
            "{} exited with code {}",
            cfg.editor.display(),
            status
                .code()
                .map(|i| format!("{}", i))
                .unwrap_or_else(|| "NONE".to_string())
        )
        .context(format!("Failed to open/edit {}", path.display())))
    } else {
        Ok(())
    }
}

// Create a new entry.
pub fn new_entry(cfg: &Config, db: &mut GuardedStore) -> anyhow::Result<()> {
    use std::io::Read;

    let metadata = Metadata::new(db.username);
    let mut entry = String::new();
    {
        let temp = tempfile::NamedTempFile::new_in(
            cfg.temp_dir
                .as_ref()
                .cloned()
                .unwrap_or_else(std::env::temp_dir),
        )?;
        open_file_in_editor(&cfg, temp.path())?;
        std::fs::File::open(temp.path())
            .context(format!(
                "Could not open temp file: {}",
                temp.path().display()
            ))?
            .read_to_string(&mut entry)
            .context(format!(
                "Failed to read from temp file: {}",
                temp.path().display()
            ))?;
    }

    if entry.is_empty() || entry.chars().all(|c| c.is_whitespace()) {
        anyhow::bail!("Entry was empty/blank. No journal entry saved.");
    } else {
        db.insert(&metadata, entry)
            .context("Could not save journal entry")?;
    }
    Ok(())
}

/// Edit the content of the specified entry.
pub fn edit_entry(cfg: &Config, mut db: &mut GuardedStore, id: Uuid) -> anyhow::Result<()> {
    use std::io::{Read, Write};

    let mut entry = get_entry(&mut db, id)?;
    let modified = chrono::Utc::now();
    {
        let temp = tempfile::NamedTempFile::new_in(
            cfg.temp_dir
                .as_ref()
                .cloned()
                .unwrap_or_else(std::env::temp_dir),
        )?;
        temp.as_file().write_all(entry.data.as_bytes())?;
        temp.as_file().sync_data()?;

        open_file_in_editor(&cfg, temp.path())?;

        entry.data.clear();
        std::fs::File::open(temp.path())
            .context(format!(
                "Could not open temp file: {}",
                temp.path().display()
            ))?
            .read_to_string(&mut entry.data)
            .context(format!(
                "Failed to read from temp file: {}",
                temp.path().display()
            ))?;
    }

    db.update(entry.uuid, modified, entry.data)
        .context("Could not save journal entry")?;
    Ok(())
}

/// Print the metadata and content of every entry in the database.
pub fn print_all_entries(db: &mut GuardedStore) -> anyhow::Result<()> {
    let ids = db.get_uuids().context("Could not read metadata ids")?;
    let metadata = db.get_metadata(&*ids).context("Could not read metadata")?;
    let entries = db.get_entries(&*ids).context("Could not read entries")?;
    assert_eq!(metadata.len(), entries.len());
    for (meta, entry) in metadata.iter().zip(entries) {
        print_meta_and_entry(meta, &entry.data);
        println!();
    }
    Ok(())
}

/// Print the metadata and contents of the specified entry.
pub fn print_entry(mut db: &mut GuardedStore, id: Uuid) -> anyhow::Result<()> {
    let (metadata, entry) = get_meta_and_entry(&mut db, id)?;
    print_meta_and_entry(&metadata, &entry.data);
    Ok(())
}

/// List identifying metadata for every entry in the database.
pub fn print_entry_list(db: &GuardedStore) -> anyhow::Result<()> {
    let ids = db.get_uuids().context("Could not read metadata ids")?;
    let metadata = db.get_metadata(&*ids).context("Could not read metadata")?;
    for meta in metadata {
        println!(
            "[{}] {}",
            meta.uuid,
            meta.data
                .created
                .with_timezone(&chrono::Local)
                .format(DATETIME_FORMAT)
        );
    }
    Ok(())
}

/// Get the content and metadata of the specified entry.
fn get_meta_and_entry(
    db: &mut GuardedStore,
    uuid: Uuid,
) -> anyhow::Result<(Ided<Metadata>, Ided<String>)> {
    let metadata = db
        .get_metadata(&[uuid])
        .context(format!("Could not find metadata for id {}", uuid))?;
    let metadata = match metadata.len() {
        1 => metadata.into_iter().next().unwrap(),
        0 => anyhow::bail!("No records for {}", uuid),
        _ => anyhow::bail!("Multiple records found for {}", uuid),
    };
    let entry = db
        .get_entries(&[uuid])
        .context(format!("Could not read entry for {}", uuid))?;
    let entry = match entry.len() {
        1 => entry.into_iter().next().unwrap(),
        0 => anyhow::bail!("No records for {}", uuid),
        _ => anyhow::bail!("Multiple records found for {}", uuid),
    };
    Ok((metadata, entry))
}

/// Get the content of the specified entry in the database.
fn get_entry(db: &mut GuardedStore, uuid: Uuid) -> anyhow::Result<Ided<String>> {
    let entry = db
        .get_entries(&[uuid])
        .context(format!("Could not read entry for {}", uuid))?;
    let entry = match entry.len() {
        1 => entry.into_iter().next().unwrap(),
        0 => anyhow::bail!("No records for {}", uuid),
        _ => anyhow::bail!("Multiple records found for {}", uuid),
    };
    Ok(entry)
}

/// Print the specified entry metadata and content.
fn print_meta_and_entry(meta: &Ided<Metadata>, entry: &str) {
    let modified = meta.data.created != meta.data.modified;
    println!(
        // The Uuid is 32 hexadecimal characters so 80 - 3 - 2 - 32 = 43
        r#"{:=<3} {} {:=<43}
Author:   {}
Written:  {}"#,
        "",
        meta.uuid,
        "",
        meta.data.author,
        meta.data
            .created
            .with_timezone(&chrono::Local)
            .format(DATETIME_FORMAT),
    );
    if modified {
        println!(
            "Modified: {}",
            meta.data
                .modified
                .with_timezone(&chrono::Local)
                .format(DATETIME_FORMAT)
        );
    }
    println!("{:=<80}", "");
    println!("{}", entry);
}

/// Prompt the user for their credentials, as needed, in order to work with an
/// encrypted database.
///
/// Returns the user's name and the DataGuard for used for decrypting the
/// database.
pub fn get_and_validate_credentials(
    cfg: &Config,
    db: &mut Store,
) -> anyhow::Result<(String, DataGuard)> {
    use std::convert::TryInto as _;

    // Get encryption data from the database.
    let salt = db.get_salt()?;
    let mut encrypted_key = db.get_key()?.unwrap_or_else(Vec::new);

    // Get and confirm the user's name and password

    let mut username = cfg
        .user
        .as_ref()
        .map(|user| user.clone())
        .ok_or(())
        .or_else(|_| prompt_username())?;
    let mut password = cfg.password.as_ref().map(|pass| pass.clone());

    if encrypted_key.is_empty() {
        // The database has no key, which means the user has never put anything
        // in the database.
        if let Some(password) = &password {
            // The user has specified a password in config, confirm it before
            // blindly using it to encrypt the key for the database.
            println!("Please confirm your password");
            retry(3, || {
                let password2 = prompt_password()?;
                if *password == password2 {
                    Ok(())
                } else {
                    Err(anyhow::anyhow!("Passwords do not match"))
                }
            })?;
        } else {
            // The user has specified no password, ask for it
            password = Some(retry(3, prompt_and_confirm_password)?);
        }
    }

    // We still may not have the password if it was not in config and the
    // database has already been keyed (so we didn't ask for the password above).
    // In that case we should also prompt the user for the password here.
    let mut password = password.ok_or(()).or_else(|_| prompt_password())?;
    let mut cred_guard = CredentialGuard::new(
        salt.try_into().expect("Salt is the wrong size"),
        &username,
        &password,
    );

    if encrypted_key.is_empty() {
        // We have the user's credentials so we can generate an encrypted key
        // for the database.
        encrypted_key = cred_guard
            .generate_encrypted_key()
            .map_err(|_| anyhow::anyhow!("Could not generate database key"))?;
        db.update_key(&encrypted_key)?;
    }

    // Validate the credentials. Give the user 3 tries.
    let mut data_guard = None;
    for i in 0..3 {
        match cred_guard.try_decrypt_key(encrypted_key.clone()) {
            Ok(guard) => {
                data_guard = Some(guard);
                break;
            }
            Err(g) => {
                cred_guard = g;
                if i != 2 {
                    println!("Invalid credentials. Try again.");
                    username = prompt_username()?;
                    password = prompt_password()?;
                    cred_guard.update_credentials(&username, &password);
                }
            }
        }
    }
    Ok((username, data_guard.context("Invalid credentials")?))
}
