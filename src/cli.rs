use super::{
    edit_entry, init, new_entry, print_all_entries, print_entry, print_entry_list, Config, Format,
    GuardedStore, Uuid,
};
use std::path::PathBuf;

#[derive(Debug, structopt::StructOpt)]
#[structopt(name = "journal", rename_all = "kebab-case")]
pub enum Args {
    /// Create a new journal entry
    New,
    /// List all existing journal entries
    List,
    /// Show one or all journal entries
    Show {
        /// The ID of the entry to show
        id: Option<Uuid>,
        /// Whether to print the entry in TOML format instead of the default
        #[structopt(long, short)]
        toml: bool,
    },
    /// Edit an existing journal entry
    Edit {
        /// The ID of the entry to edit
        id: Uuid,
    },
    /// Index all journal entries
    ///
    /// This should only be needed for maintainence reasons.
    Index,
    /// Initialize the system
    Init {
        /// The directory to use for program data. If omitted, a directory will be created in the user's home directory.
        dir: Option<PathBuf>,
    },
}

impl Args {
    pub fn run(&self, cfg: &Config, db: &mut GuardedStore) -> anyhow::Result<()> {
        match self {
            Args::New => new_entry(cfg, db),
            Args::List => print_entry_list(db),
            Args::Show { id, toml } => {
                if let Some(id) = id {
                    print_entry(db, *id, if *toml { Format::Toml } else { Format::Default })
                } else {
                    print_all_entries(db, if *toml { Format::Toml } else { Format::Default })
                }
            }
            Args::Edit { id } => edit_entry(cfg, db, *id),
            Args::Index => db.index(),
            Args::Init { dir } => init(dir.clone()),
        }
    }
}
