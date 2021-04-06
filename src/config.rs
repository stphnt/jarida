use std::path::PathBuf;
use std::{
    fs::{self, File},
    io::Read,
};

use anyhow::Context as _;

#[derive(Debug, serde::Deserialize)]
pub struct Config {
    /// The temporary work directory
    pub temp_dir: Option<PathBuf>,
    /// The directory to save all journal data in
    pub journal_dir: Option<PathBuf>,
    /// The path to the user's editor of choice
    pub editor: PathBuf,
    /// The name of the user
    pub user: Option<String>,
    /// Password
    pub password: Option<String>,
}

impl std::str::FromStr for Config {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Config, Self::Err> {
        let cfg = toml::from_str::<Config>(s).context("Invalid/malformed config")?;
        if let Some(ref temp_dir) = cfg.temp_dir {
            if !temp_dir.is_absolute() {
                return Err(anyhow::anyhow!("temp_dir must be an absolute path"));
            }
        } else if let Some(ref journal_dir) = cfg.journal_dir {
            if !journal_dir.is_absolute() {
                return Err(anyhow::anyhow!("journal_dir must be an absolute path"));
            }
        }
        Ok(cfg)
    }
}

impl Config {
    /// The name of the configuration directory.
    pub const DIR_NAME: &'static str = ".jarida";
    /// The name of the configuration file.
    pub const FILE_NAME: &'static str = "config.toml";

    /// Find the configuration file and parse it.
    ///
    /// Returns an error if the file cannot be found or is invalid/malformed.
    pub fn find() -> anyhow::Result<Config> {
        let path = Config::find_config_file_path()?;
        let mut file =
            File::open(&path).context(format!("Could open config {}", path.display()))?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;
        contents
            .parse()
            .context(format!("Could not parse {}", path.display()))
    }

    /// Try to find the config file, first in a parent directory, then in the
    /// user's home directory. The file may not exist.
    ///
    /// An error is returned if the configuration directory cannot be found.
    pub fn find_config_file_path() -> anyhow::Result<PathBuf> {
        let mut path = Config::find_config_dir_path()?;
        path.push(Config::FILE_NAME);
        Ok(path)
    }

    /// Try to find the config directory, first in a parent directory, then in
    /// the user's home directory. If the directory cannot be found an error is
    /// returned/
    pub fn find_config_dir_path() -> anyhow::Result<PathBuf> {
        Config::find_parent_config_dir_path().or_else(|_| Config::find_user_config_dir_path())
    }

    /// Try to find a config directory in one of the parent directories.
    ///
    /// If the file does not exist an error is returned.
    fn find_parent_config_dir_path() -> anyhow::Result<PathBuf> {
        // Walk up the directory tree until we find a .jarida directory
        let mut dir = std::env::current_dir()?;
        loop {
            for entry in fs::read_dir(&dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() && entry.file_name() == Config::DIR_NAME {
                    // Found it.
                    return Ok(entry.path());
                }
            }
            if !dir.pop() {
                break;
            }
        }
        Err(anyhow::anyhow!(
            "Could not find config file in a parent directory"
        ))
    }

    /// Try to find a config directory in the user's home directory.
    ///
    /// If the file does not exist an error is returned.
    fn find_user_config_dir_path() -> anyhow::Result<PathBuf> {
        let path = Config::get_user_config_dir_path()?;
        if path.exists() {
            Ok(path)
        } else {
            Err(anyhow::anyhow!(
                "Could not find config file in user's home directory"
            ))
        }
    }

    /// Get the expected path to the config direcotry in the user's home directory.
    ///
    /// The file may not exist. If the user's home directory could not be found
    /// an error is returned.
    pub fn get_user_config_dir_path() -> anyhow::Result<PathBuf> {
        dirs_next::home_dir()
            .map(|mut path| {
                path.push(Config::DIR_NAME);
                path
            })
            .ok_or_else(|| anyhow::anyhow!("Could not find user's home directory"))
    }

    /// Get the path to the directory containing journal data.
    pub fn data_store_path(&self) -> PathBuf {
        self.journal_dir
            .clone()
            .unwrap_or_else(|| Config::find_config_dir_path().unwrap())
    }

    /// Get the contents of a template config.toml file.
    pub fn template() -> &'static str {
        r#"
# The path to your editor of choice. It will be used to write/edit journal
# entries. Jarida considers the journal entry complete when the editor exits, so
# if the editor exits early or sends its work to another process, an incomplete
# entry will be saved.
editor = ""

# Your name. This value is permanently associated with each journal entry and
# together with the password are used to encrypt all journal data. There is no
# way to recover the password if it is lost. If omitted you will be prompted
# for it every time you run the program.
#user = "Your Name"

# The password that, in combination with the user name, is used to encrypt all
# journal data. There is no way to recover this password if it is lost. If
# omitted you will be prompted for it every time you run the program.
#password = "your-password-here"

# An optional temporary working directory. All working data will be stored here.
# If not specified, the OS's temporary directory will be used instead.
#temp-dir = "<your-path-here>"

# An optional directory to save all journal data in. If not specified, journal
# data is stored in the same directory as the config file.
#journal-dir = "<your-path-here>"
"#
    }
}
