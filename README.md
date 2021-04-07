## Jarida

A minimalist, encrypted journaling tool. "Jarida" is Swahili for "journal."

## Security

Data is encrypted using [ring](https://crates.io/crates/ring)'s AES 256 GCM implementation with a key derived from a username and password pair.

## Installation

`jarida` is written in Rust so you'll need the Rust compiler. You can get it [here](https://www.rust-lang.org/learn/get-started).

1. Run `cargo install --path . --git <url-to-this-repo>` to install `jarida` on your system
1. Run `jarida init` to setup some configuration data in your home directory.
1. Open the newly created `$HOME/.jarida/config.toml` file and update it as necessary. At the minimum you will need to specify the text editor you would like to use.

## Quick start

* `jarida new` - create a new journal entry
* `jarida list` - print a list of existing journal entries
* `jarida show` - view one or more journal entries

See `jarida --help` or `jarida <subcommand> --help` for more details.

`jarida` looks for a `.jarida` folder containing configuration information first in parent folders and then in the user's home directory.
This allows multiple journals to be set up and used independently on the same system, similar to how you can use multiple repositories independently with `git`.
