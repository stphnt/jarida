use structopt::StructOpt as _;

use journal::{get_and_validate_credentials, Args, Config, Store};

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();

    let command = Args::from_args();
    let cfg = Config::find()?;
    let mut db = Store::open(cfg.data_store_path())?;
    let (username, mut data_guard) = get_and_validate_credentials(&cfg, &mut db)?;
    let mut db = db.guard(&mut data_guard, &username);
    command.run(&cfg, &mut db)
}
