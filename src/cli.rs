use super::{
    edit_entry, new_entry, print_all_entries, print_entry, print_entry_list, Config, GuardedStore,
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
        id: Option<i64>,
    },
    /// Edit an existing journal entry
    Edit {
        /// The ID of the entry to edit
        id: i64,
    },
}

impl Args {
    pub fn run(&self, cfg: &Config, mut db: &mut GuardedStore) -> anyhow::Result<()> {
        match self {
            Args::New => new_entry(&cfg, &mut db),
            Args::List => print_entry_list(&db),
            Args::Show { id } => {
                if let Some(id) = id {
                    print_entry(&mut db, *id)
                } else {
                    print_all_entries(&mut db)
                }
            }
            Args::Edit { id } => edit_entry(&cfg, &mut db, *id),
        }
    }
}
