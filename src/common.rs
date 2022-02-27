use anyhow::Context as _;

use super::{
    config::Config,
    db::Store,
    security::{CredentialGuard, DataGuard},
};

/// The formats for printing out entries
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum Format {
    Default,
    Toml,
}

/// The formatting string for all date-time (Sun  8-Jul-2001 00:34)
pub const DATETIME_FORMAT: &[::time::format_description::FormatItem<'_>] = time::macros::format_description!(
    "[weekday repr:short] [day padding:space]-[month repr:short]-[year] [hour repr:24]:[minute]"
);

/// Retry the specified function up to the specified number of times times until is succeeds.
fn retry<T, S: FnMut() -> anyhow::Result<T>>(max: usize, mut func: S) -> anyhow::Result<T> {
    let mut result = func();
    for i in 0..max {
        if result.is_ok() {
            break;
        }

        if i == max - 1 {
            return result;
        }
        println!("Oops! Try again.");
        result = func();
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
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{} exited with code {}",
            cfg.editor.display(),
            status
                .code()
                .map(|i| format!("{}", i))
                .unwrap_or_else(|| "NONE".to_string())
        )
        .context(format!("Failed to open/edit {}", path.display())))
    }
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
    let mut encrypted_key = db.get_key()?.unwrap_or_default();

    // Get and confirm the user's name and password

    let mut username = cfg.user.clone().ok_or(()).or_else(|_| prompt_username())?;
    let mut password = cfg.password.clone();

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
