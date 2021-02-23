use anyhow::Context as _;
use std::convert::TryInto;
use structopt::StructOpt as _;

use journal::{prompt_password, prompt_username, Args, Config, CredentialGuard, Store};

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let cfg = Config::find()?;

    let mut username = cfg
        .user
        .as_ref()
        .map(|user| user.clone())
        .ok_or(())
        .or_else(|_| prompt_username())?;
    let mut password = cfg
        .password
        .as_ref()
        .map(|pass| pass.clone())
        .ok_or(())
        .or_else(|_| prompt_password())?;

    let mut db = Store::open(cfg.data_store_path())?;
    let salt = db.get_salt()?;
    let mut encrypted_key = db.get_key()?.unwrap_or_else(Vec::new);
    let mut cred_guard = CredentialGuard::new(
        salt.try_into()
            .map_err(|_| anyhow::anyhow!("Salt is the wrong size"))?,
        &username,
        &password,
    );
    if encrypted_key.is_empty() {
        // The user has never put anything in the database.
        // Confirm their password and then store a key so we can validate it
        // in the future.
        let mut password2 = String::new();
        println!("Please confirm your password");
        for i in 0..4 {
            if password2 != *password {
                if i == 3 {
                    anyhow::bail!("Passwords do not match. Exiting.");
                }
                password2 = prompt_password()?;
            } else {
                break;
            }
        }
        encrypted_key = cred_guard
            .generate_encrypted_key()
            .map_err(|_| anyhow::anyhow!("Could not generate database key"))?;
        db.update_key(&encrypted_key)?;
    }

    // Validate the credentials. Give the user 3 tries.
    let mut data_guard = None;
    for _ in 0..3 {
        match cred_guard.try_decrypt_key(encrypted_key.clone()) {
            Ok(guard) => {
                data_guard = Some(guard);
                break;
            }
            Err(g) => {
                println!("Invalid credentials. Try again.");
                cred_guard = g;
                username = prompt_username()?;
                password = prompt_password()?;
                cred_guard.update_credentials(&username, &password);
            }
        }
    }
    let mut data_guard = data_guard.context("Invalid credentials")?;
    let mut db = db.guard(&mut data_guard, &username);

    Args::from_args().run(&cfg, &mut db)
}
