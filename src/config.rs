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
    const DIR_NAME: &'static str = ".jnl";

    /// Find the config data
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

    pub fn find_config_file_path() -> anyhow::Result<PathBuf> {
        let mut path = Config::find_config_dir_path()?;
        path.push("config.toml");
        Ok(path)
    }

    pub fn find_config_dir_path() -> anyhow::Result<PathBuf> {
        Config::find_parent_config_dir_path().or_else(|_| Config::find_user_config_dir_path())
    }

    fn find_parent_config_dir_path() -> anyhow::Result<PathBuf> {
        // Walk up the directory tree until we find a .jnl directory
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

    fn find_user_config_dir_path() -> anyhow::Result<PathBuf> {
        let path = dirs_next::home_dir()
            .map(|mut path| {
                path.push(Config::DIR_NAME);
                path
            })
            .ok_or_else(|| anyhow::anyhow!("Could not find user's home directory"))?;
        if !path.exists() {
            Err(anyhow::anyhow!(
                "Could not find config file in user's home directory"
            ))
        } else {
            Ok(path)
        }
    }

    pub fn ensure_password(&mut self) -> anyhow::Result<()> {
        if self.password.is_none() {
            log::trace!("No password in config, Prompting user for password");
            self.password = Some(
                rpassword::prompt_password_stdout("Password: ")
                    .context("Could not read password".to_string())?,
            );
        }
        Ok(())
    }

    pub fn data_store_path(&self) -> PathBuf {
        self.journal_dir
            .clone()
            .unwrap_or_else(|| Config::find_config_dir_path().unwrap())
    }
}
