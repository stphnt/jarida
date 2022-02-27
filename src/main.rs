#![forbid(unused_must_use)]
use clap::Parser as _;

mod callback;
mod cli;
mod common;
mod config;
mod db;
mod security;
mod uuid;

use cli::Args;
use common::get_and_validate_credentials;
use config::Config;
use db::Store;

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let command = Args::parse();
    let cfg = Config::find()?;
    let mut db = Store::open(cfg.data_store_path())?;
    let (username, mut data_guard) = get_and_validate_credentials(&cfg, &mut db)?;
    let mut db = db.guard(&mut data_guard, &username);
    command.run(&cfg, &mut db)
}
