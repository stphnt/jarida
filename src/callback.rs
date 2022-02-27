use super::{
    common::{open_file_in_editor, Format, DATETIME_FORMAT},
    config::Config,
    db::{GuardedStore, Ided, Metadata, MetadataAndContent},
    uuid::Uuid,
};
use anyhow::Context as _;

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
        open_file_in_editor(cfg, temp.path())?;
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
    }
    db.insert(&metadata, entry)
        .context("Could not save journal entry")?;
    Ok(())
}

/// Edit the content of the specified entry.
pub fn edit_entry(cfg: &Config, db: &mut GuardedStore, id: Uuid) -> anyhow::Result<()> {
    use std::io::{Read, Write};

    let entry = db.get_content(&[id]).into_iter().next().unwrap();
    let mut data = entry.data?;
    let modified = time::OffsetDateTime::now_utc();
    {
        let temp = tempfile::NamedTempFile::new_in(
            cfg.temp_dir
                .as_ref()
                .cloned()
                .unwrap_or_else(std::env::temp_dir),
        )?;
        temp.as_file().write_all(data.as_bytes())?;
        temp.as_file().sync_data()?;

        open_file_in_editor(cfg, temp.path())?;

        data.clear();
        std::fs::File::open(temp.path())
            .context(format!(
                "Could not open temp file: {}",
                temp.path().display()
            ))?
            .read_to_string(&mut data)
            .context(format!(
                "Failed to read from temp file: {}",
                temp.path().display()
            ))?;
    }

    db.update(entry.uuid, modified, data)
        .context("Could not save journal entry")?;
    Ok(())
}

/// Print the metadata and content of every entry in the database.
pub fn print_all_entries(db: &mut GuardedStore, format: Format) -> anyhow::Result<()> {
    let ids = db.get_uuids().context("Could not read entry ids")?;
    let (ok, err): (Vec<_>, Vec<_>) = db
        .get_metadata_and_content(&ids[..])
        .into_iter()
        .partition(|item| item.data.is_ok());
    match format {
        Format::Default => {
            for entry in ok {
                let data = entry.data.unwrap();
                print_metadata_and_content(entry.uuid, &data);
                println!();
            }
        }
        Format::Toml => {
            let mut map = std::collections::HashMap::new();
            for entry in ok {
                map.insert(entry.uuid, entry.data.unwrap());
            }
            println!("{}", toml::to_string_pretty(&map)?);
        }
    }
    if let Some(Ided { uuid, data: Err(e) }) = err.into_iter().next() {
        Err(e).context(format!(
            "Could not read metadata and/or content for at least one id: {}",
            uuid
        ))
    } else {
        Ok(())
    }
}

/// Print the metadata and contents of the specified entry.
pub fn print_entry(db: &mut GuardedStore, id: Uuid, format: Format) -> anyhow::Result<()> {
    let entry = db
        .get_metadata_and_content(&[id])
        .into_iter()
        .next()
        .unwrap();
    let data = entry.data?;
    match format {
        Format::Default => print_metadata_and_content(entry.uuid, &data),
        Format::Toml => {
            let mut map = std::collections::HashMap::new();
            map.insert(entry.uuid, data);
            println!("{}", toml::to_string_pretty(&map)?);
        }
    };
    Ok(())
}

/// List identifying metadata for every entry in the database.
pub fn print_entry_list(db: &mut GuardedStore) -> anyhow::Result<()> {
    let ids = db.get_uuids().context("Could not read entry ids")?;
    let (ok, err): (Vec<_>, Vec<_>) = db
        .get_metadata(&*ids)
        .into_iter()
        .partition(|item| item.data.is_ok());
    for ided_meta in ok {
        let meta = &ided_meta.data.unwrap();
        println!(
            "[{}] {}",
            ided_meta.uuid,
            meta.created
                .to_offset(time::UtcOffset::current_local_offset().unwrap())
                .format(DATETIME_FORMAT)
                .unwrap()
        );
    }
    if let Some(Ided { uuid, data: Err(e) }) = err.into_iter().next() {
        Err(e).context(format!(
            "Could not read metadata for at least one id: {}",
            uuid
        ))
    } else {
        Ok(())
    }
}

/// Print the specified entry metadata and content.
fn print_metadata_and_content(uuid: Uuid, entry: &MetadataAndContent) {
    let modified = entry.metadata.created != entry.metadata.modified;
    println!(
        // The Uuid is 32 hexadecimal characters so 80 - 3 - 2 - 32 = 43
        r#"{:=<3} {} {:=<43}
Author:   {}
Written:  {}"#,
        "",
        uuid,
        "",
        entry.metadata.author,
        entry
            .metadata
            .created
            .to_offset(time::UtcOffset::current_local_offset().unwrap())
            .format(DATETIME_FORMAT)
            .unwrap(),
    );
    if modified {
        println!(
            "Modified: {}",
            entry
                .metadata
                .modified
                .to_offset(time::UtcOffset::current_local_offset().unwrap())
                .format(DATETIME_FORMAT)
                .unwrap()
        );
    }
    println!("{:=<80}", "");
    println!("{}", entry.content);
}

/// Try to initialize the specified directory. If `dir` is None, the user's home
/// directory is assumed. If config directory already exists, an error is
/// returned.
pub fn init(dir: Option<std::path::PathBuf>) -> anyhow::Result<()> {
    use std::io::Write as _;

    let mut path = dir
        .ok_or_else(|| anyhow::anyhow!("")) // This error is never used, but must match that of get_user_config_dir_path.
        .map(|mut path| {
            path.push(Config::DIR_NAME);
            path
        })
        .or_else(|_| Config::get_user_config_dir_path())?;
    if path.exists() {
        anyhow::bail!("{} is already initialized", path.display());
    }
    std::fs::create_dir(&path)?;
    path.push(Config::FILE_NAME);
    std::fs::File::create(path)?.write_all(Config::template().as_bytes())?;
    Ok(())
}
