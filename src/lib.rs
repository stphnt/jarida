use anyhow::Context as _;

mod cli;
mod config;
mod db;
mod security;

pub use cli::*;
pub use config::Config;
pub use db::*;
pub use security::{CredentialGuard, DataGuard};

/// The formatting string for all date-time
const DATETIME_FORMAT: &str = "%a %v %R";

pub fn prompt_password() -> anyhow::Result<String> {
    rpassword::prompt_password_stdout("Password: ").context("Error getting a password")
}

pub fn prompt_and_confirm_password() -> anyhow::Result<String> {
    let err = "Error getting a password";
    let mut p1 = rpassword::prompt_password_stdout("Password: ").context(err)?;
    let mut p2 = rpassword::prompt_password_stdout("Confirm: ").context(err)?;
    for i in 0..4 {
        if p1 == p2 {
            break;
        } else {
            if i == 3 {
                anyhow::bail!("Passwords do not match");
            }
            println!("Passwords do not match. Try again.");
            p1 = rpassword::prompt_password_stdout("Password: ").context(err)?;
            p2 = rpassword::prompt_password_stdout("Confirm: ").context(err)?;
        }
    }
    Ok(p1)
}

pub fn prompt_username() -> anyhow::Result<String> {
    {
        use std::io::Write as _;
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();
        write!(stdout, "Username: ")?;
        stdout.flush()?;
    }
    use std::io::BufRead as _;
    let stdin = std::io::stdin();
    let username = stdin
        .lock()
        .lines()
        .next()
        .expect("Cannot read from stdin")?;
    Ok(username)
}

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

pub fn edit_entry(cfg: &Config, mut db: &mut GuardedStore, id: i64) -> anyhow::Result<()> {
    use std::io::{Read, Write};

    let (mut meta, mut entry) = get_meta_and_entry(&mut db, id)?;
    meta.data.modified = chrono::Utc::now();
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

    db.update(&meta, entry.data)
        .context("Could not save journal entry")?;
    Ok(())
}

pub fn print_all_entries(db: &mut GuardedStore) -> anyhow::Result<()> {
    let ids = db.get_ids().context("Could not read metadata ids")?;
    let metadata = db.get_metadata(&*ids).context("Could not read metadata")?;
    let entries = db.get_entries(&*ids).context("Could not read entries")?;
    assert_eq!(metadata.len(), entries.len());
    for (meta, entry) in metadata.iter().zip(entries) {
        print_meta_and_entry(meta, &entry.data);
        println!();
    }
    Ok(())
}

pub fn print_entry(mut db: &mut GuardedStore, id: i64) -> anyhow::Result<()> {
    let (metadata, entry) = get_meta_and_entry(&mut db, id)?;
    print_meta_and_entry(&metadata, &entry.data);
    Ok(())
}

pub fn print_entry_list(db: &GuardedStore) -> anyhow::Result<()> {
    let ids = db.get_ids().context("Could not read metadata ids")?;
    let metadata = db.get_metadata(&*ids).context("Could not read metadata")?;
    for meta in metadata {
        println!(
            "[{:0>4}] {}",
            meta.id,
            meta.data
                .created
                .with_timezone(&chrono::Local)
                .format(DATETIME_FORMAT)
        );
    }
    Ok(())
}

fn get_meta_and_entry(
    db: &mut GuardedStore,
    id: i64,
) -> anyhow::Result<(Ided<Metadata>, Ided<String>)> {
    let metadata = db
        .get_metadata(&[id])
        .context(format!("Could not find metadata for id {}", id))?;
    let metadata = match metadata.len() {
        1 => metadata.into_iter().next().unwrap(),
        0 => anyhow::bail!("No records for {}", id),
        _ => anyhow::bail!("Multiple records found for {}", id),
    };
    let entry = db
        .get_entries(&[metadata.id])
        .context(format!("Could not read entry for {}", id))?;
    let entry = match entry.len() {
        1 => entry.into_iter().next().unwrap(),
        0 => anyhow::bail!("No records for {}", id),
        _ => anyhow::bail!("Multiple records found for {}", id),
    };
    Ok((metadata, entry))
}

fn print_meta_and_entry(meta: &Ided<Metadata>, entry: &str) {
    let modified = meta.data.created != meta.data.modified;
    println!(
        r#"{:=<3} {:0>4} {:=<71}
{}
Written:  {}"#,
        "",
        meta.id,
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
