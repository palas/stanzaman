use std::process::exit;

use thiserror::Error;

use clap::{Arg, Command};

#[derive(Debug, Error)]
enum InvocationError {
    #[error("A subcommand is required, use --help for more information")]
    NoSubcommand,
    #[error("Invalid subcommand: {0}")]
    InvalidSubcommand(String),
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        exit(1);
    } else {
        exit(0);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let m = Command::new("Stanzaman")
        .author("Pablo Lamela <pablo.lamela@iohk.io>")
        .version("1.0.0")
        .about(
            "This tool that aims to simplify the repository source code stanzas \
             when developing a feature across several repositories that depend \
             on each other.",
        )
        .subcommand(
            Command::new("init")
                .about("Initialize the stanzaman database file")
                .long_about(
                    "Initialize the stanzaman database file at the current working directory, \
                             the file will be called `stanzaman.toml`",
                ),
        )
        .subcommand(
            Command::new("add-repo")
                .about("Add a new repository to the database")
                .arg(
                    Arg::new("new-alias")
                        .help("The alias for the repository")
                        .required(true),
                )
                .arg(
                    Arg::new("path")
                        .help("The relative path to the repository")
                        .required(true),
                ),
        )
        .subcommand(
            Command::new("add-stanza")
                .about("Add a new stanza to the database")
                .arg(
                    Arg::new("repo-alias")
                        .help("The alias of the repository where the stanza will be added")
                        .required(true),
                )
                .arg(
                    Arg::new("dep-alias")
                        .help("The alias of the dependency to be added")
                        .required(true),
                )
                .long_about(
                    "Add a new stanza to the database, the repository where the stanza \
                     will be added is identified by its alias, and the dependency to \
                     be added is also identified by its alias.",
                ),
        )
        .subcommand(
            Command::new("update")
                .about("Update the stanzaman database")
                .long_about(
                    "Update the stanzaman database file with the latest information from the \
                     repositories. This command should be run every time you add and push a \
                     commit to ensure all stanzas are up to date.",
                ),
        )
        .after_help(
            "First use `init` to create the database file for stanzaman, then use \
             `add-repo` to make aliases for each local respository, then use \
             `add-stanza` to add stanzas using those aliases. Finally, you can \
             use `update` everytime you add and push a commit to make sure all \
             the stanzas are up to date.",
        )
        .get_matches();
    match m.subcommand() {
        Some(("init", _data)) => {
            // Handle the init subcommand
            init_stanzaman()
        }
        Some(("add-repo", data)) => {
            // Handle the add-repo subcommand
            let new_alias = data
                .get_one::<String>("new-alias")
                .ok_or("new-alias not specified")?;
            let path = data.get_one::<String>("path").ok_or("path not specified")?;
            add_repo_to_stanzaman(new_alias, path)
        }
        Some(("add-stanza", data)) => {
            // Handle the add-stanza subcommand
            let repo_alias = data
                .get_one::<String>("repo-alias")
                .ok_or("repo-alias not specified")?;
            let dep_alias = data
                .get_one::<String>("dep-alias")
                .ok_or("dep-alias not specified")?;
            add_dependency_for_repo(repo_alias, dep_alias)
        }
        Some(("update", _data)) => {
            // Handle the update subcommand
            update_stanzaman()
        }
        Some((subcommand, _)) => {
            // This should be unreachable due to clap's validation
            Err(Box::new(InvocationError::InvalidSubcommand(
                subcommand.to_string(),
            )))
        }
        None => Err(Box::new(InvocationError::NoSubcommand)),
    }
}

// Initialize the stanzaman database
fn init_stanzaman() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing stanzaman database...");
    Ok(())
}

// Add a repository to the stanzaman database
fn add_repo_to_stanzaman(new_alias: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Adding repository {} at {}", new_alias, path);
    Ok(())
}

// Add a dependency for a repository in the stanzaman database
fn add_dependency_for_repo(
    repo_alias: &str,
    dep_alias: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Adding stanza to {} with dependency {}",
        repo_alias, dep_alias
    );
    Ok(())
}

// Update the stanzaman database
fn update_stanzaman() -> Result<(), Box<dyn std::error::Error>> {
    println!("Updating stanzaman database...");
    Ok(())
}
