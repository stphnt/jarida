use super::{
    edit_entry, init, new_entry, print_all_entries, print_entry, print_entry_list, Config, Format,
    GuardedStore, Uuid,
};
use std::path::PathBuf;

#[derive(Debug, clap::Parser)]
#[clap(version, about, long_about = None)]
pub struct Args {
    #[clap(subcommand)]
    action: Action,
}

#[derive(Debug, clap::Subcommand)]
pub enum Action {
    /// Create a new journal entry
    New,
    /// List all existing journal entries
    List,
    /// Show one or all journal entries
    Show {
        /// The ID of the entry to show
        id: Option<Uuid>,
        /// Whether to print the entry in TOML format instead of the default
        #[clap(long, short)]
        toml: bool,
    },
    /// Edit an existing journal entry
    Edit {
        /// The ID of the entry to edit
        id: Uuid,
    },
    /// Index all journal entries
    ///
    /// This should only be needed for maintenance reasons.
    Index,
    /// Initialize the system
    Init {
        /// The directory to use for program data. If omitted, a directory will be created in the user's home directory.
        dir: Option<PathBuf>,
    },
}

impl Args {
    pub fn run(&self, cfg: &Config, db: &mut GuardedStore) -> anyhow::Result<()> {
        match &self.action {
            Action::New => new_entry(cfg, db),
            Action::List => print_entry_list(db),
            Action::Show { id, toml } => {
                if let Some(id) = id {
                    print_entry(db, *id, if *toml { Format::Toml } else { Format::Default })
                } else {
                    print_all_entries(db, if *toml { Format::Toml } else { Format::Default })
                }
            }
            Action::Edit { id } => edit_entry(cfg, db, *id),
            Action::Index => db.index(),
            Action::Init { dir } => init(dir.clone()),
        }
    }
}
