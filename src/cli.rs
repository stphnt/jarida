use super::{
    edit_entry, new_entry, print_all_entries, print_entry, print_entry_list, Config, Format,
    GuardedStore, Uuid,
};

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
}

impl Args {
    pub fn run(&self, cfg: &Config, mut db: &mut GuardedStore) -> anyhow::Result<()> {
        match self {
            Args::New => new_entry(&cfg, &mut db),
            Args::List => print_entry_list(&mut db),
            Args::Show { id, toml } => {
                if let Some(id) = id {
                    print_entry(
                        &mut db,
                        *id,
                        if *toml { Format::Toml } else { Format::Default },
                    )
                } else {
                    print_all_entries(&mut db, if *toml { Format::Toml } else { Format::Default })
                }
            }
            Args::Edit { id } => edit_entry(&cfg, &mut db, *id),
            Args::Index => db.index(),
        }
    }
}
