use std::{collections::HashMap, fs::canonicalize, path::Path, process::exit};

use thiserror::Error;

use clap::{Arg, Command};

use toml::Table;

#[derive(Debug, Error)]
enum InvocationError {
    #[error("A subcommand is required, use --help for more information")]
    NoSubcommand,
    #[error("Invalid subcommand: {0}")]
    InvalidSubcommand(String),
}

#[derive(Debug, Error)]
enum TomlError {
    #[error("File already exists: {0}")]
    FileExistsError(String),
    #[error("Error writing TOML file: {0}")]
    ErrorWritingTomlFile(String),
    #[error("Error reading TOML file: {0}")]
    ErrorReadingTomlFile(String),
    #[error("Error parsing TOML: {0}")]
    ErrorParsingTomlFile(String),
    #[error("Error reading config from TOML: {0}")]
    ErrorReadingConfigFile(String),
}

#[derive(Debug, Error)]
enum CommandError {
    #[error("Could not canonicalize path: {0}")]
    CouldNotCanonicalizePath(String),
    #[error("Could not find repository origin: {0}")]
    CouldNotFindRepoOrigin(String),
    #[error("Repo \"{0}\" already registered")]
    RepoAlreadyRegistered(String),
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

#[derive(PartialEq, Debug)]
struct Config {
    repos: HashMap<String, Repo>,
}

#[derive(PartialEq, Debug)]
struct Repo {
    alias: String,
    path: String,
    origin: String,
    dependencies: HashMap<String, Dep>,
}

#[derive(PartialEq, Debug)]
struct Dep {
    commit: String,
    hash: String,
}

fn generate_toml_table(config: &Config) -> Table {
    let mut repositories = Table::new();
    for repo in config.repos.values() {
        repositories.insert(
            repo.alias.clone(),
            toml::Value::Table({
                let mut repo_table = Table::new();
                repo_table.insert("path".into(), toml::Value::String(repo.path.clone()));
                repo_table.insert("origin".into(), toml::Value::String(repo.origin.clone()));
                let mut dep_table = Table::new();
                for (dep_alias, dep) in &repo.dependencies {
                    dep_table.insert(
                        dep_alias.clone(),
                        toml::Value::Table({
                            let mut dep_table = Table::new();
                            dep_table
                                .insert("commit".into(), toml::Value::String(dep.commit.clone()));
                            dep_table.insert("hash".into(), toml::Value::String(dep.hash.clone()));
                            dep_table
                        }),
                    );
                }
                repo_table.insert("dependencies".into(), toml::Value::Table(dep_table.clone()));
                repo_table
            }),
        );
    }
    repositories
}

fn table_to_config(table: &Table) -> Result<Config, Box<dyn std::error::Error>> {
    let mut repos = HashMap::new();
    for (repo_alias, repo_value) in table {
        let repo_path = repo_value
            .get("path")
            .ok_or(format!("Repo \"{}\" does not have a \"path\"", repo_alias))?
            .as_str()
            .ok_or(format!("Path for repo \"{}\" is not a string", repo_alias))?;
        let repo_origin = repo_value
            .get("origin")
            .ok_or(format!(
                "Repo \"{}\" does not have an \"origin\"",
                repo_alias
            ))?
            .as_str()
            .ok_or(format!(
                "Origin for repo \"{}\" is not a string",
                repo_alias
            ))?;
        let mut repo_dependencies = HashMap::new();
        if let Some(toml::Value::Table(dep_table)) = repo_value.get("dependencies") {
            for (dep_alias, dep_value) in dep_table {
                let commit = dep_value
                    .get("commit")
                    .and_then(|v| v.as_str())
                    .ok_or(format!(
                        "Commit for dependency \"{}\" in repo \"{}\" is not a string",
                        dep_alias, repo_alias
                    ))?;
                let hash = dep_value
                    .get("hash")
                    .and_then(|v| v.as_str())
                    .ok_or(format!(
                        "Hash for dependency \"{}\" in repo \"{}\" is not a string",
                        dep_alias, repo_alias
                    ))?;
                repo_dependencies.insert(
                    dep_alias.clone(),
                    Dep {
                        commit: commit.to_string(),
                        hash: hash.to_string(),
                    },
                );
            }
        }
        repos.insert(
            repo_alias.clone(),
            Repo {
                alias: repo_alias.clone(),
                path: repo_path.to_string(),
                origin: repo_origin.to_string(),
                dependencies: repo_dependencies,
            },
        );
    }
    Ok(Config { repos })
}

// Write the config to the TOML file
fn write_config(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::write(
        "stanzaman.toml",
        toml::to_string(&generate_toml_table(config))
            .map_err(|e| Box::new(TomlError::ErrorWritingTomlFile(e.to_string())))?,
    )?;
    Ok(())
}

// Read the config from the TOML file
fn read_config() -> Result<Config, Box<dyn std::error::Error>> {
    let config_str = std::fs::read_to_string("stanzaman.toml")
        .map_err(|e| Box::new(TomlError::ErrorReadingTomlFile(e.to_string())))?;
    let config_table = toml::from_str::<Table>(&config_str)
        .map_err(|e| Box::new(TomlError::ErrorParsingTomlFile(e.to_string())))?;
    let config = table_to_config(&config_table)
        .map_err(|e| Box::new(TomlError::ErrorReadingConfigFile(e.to_string())))?;
    Ok(config)
}

fn find_repo_origin(canonical_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    // Run "git remote get-url origin" on folder to get origin
    let output = std::process::Command::new("git")
        .arg("remote")
        .arg("get-url")
        .arg("origin")
        .current_dir(canonical_path)
        .output()
        .map_err(|e| Box::new(CommandError::CouldNotFindRepoOrigin(e.to_string())))?;
    if output.status.success() {
        let origin = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Ok(origin)
    } else {
        Err(Box::new(CommandError::CouldNotFindRepoOrigin(
            String::from_utf8_lossy(&output.stderr).to_string(),
        )))
    }
}

// Initialize the stanzaman database
fn init_stanzaman() -> Result<(), Box<dyn std::error::Error>> {
    println!("Initializing stanzaman database...");
    let config = Config {
        repos: HashMap::new(),
    };

    // Ensure file doesn't exist
    if Path::new("stanzaman.toml").exists() {
        Err(Box::new(TomlError::FileExistsError(
            "stanzaman.toml".to_string(),
        )))
    } else {
        write_config(&config)?;
        Ok(())
    }
}

// Add a repository to the stanzaman database
fn add_repo_to_stanzaman(new_alias: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Adding repository \"{}\" at \"{}\"", new_alias, path);
    let mut config = read_config()?;
    let canonical_path_buf = canonicalize(path)
        .map_err(|e| Box::new(CommandError::CouldNotCanonicalizePath(e.to_string())))?;
    let canonical_path = canonical_path_buf.as_path();
    let canonical_path_str = canonical_path
        .to_str()
        .ok_or(format!("Failed to convert canonical path to string"))?;

    // Find out origin for the repository
    if config.repos.contains_key(new_alias) {
        Err(Box::new(CommandError::RepoAlreadyRegistered(
            new_alias.to_string(),
        )))
    } else {
        let origin = find_repo_origin(canonical_path)?;
        config.repos.insert(
            new_alias.to_string(),
            Repo {
                alias: new_alias.to_string(),
                path: canonical_path_str.to_string(),
                origin: origin,
                dependencies: HashMap::new(),
            },
        );
        write_config(&config)?;
        Ok(())
    }
}

// Add a dependency for a repository in the stanzaman database
fn add_dependency_for_repo(
    repo_alias: &str,
    dep_alias: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!(
        "Adding stanza to \"{}\" with dependency \"{}\"",
        repo_alias, dep_alias
    );
    Ok(())
}

// Update the stanzaman database
fn update_stanzaman() -> Result<(), Box<dyn std::error::Error>> {
    println!("Updating stanzaman database...");
    Ok(())
}

// Unit test for serialisation
#[test]
fn test_generate_toml_table() {
    let test_config = Config {
        repos: HashMap::from([
            (
                "repo1".to_string(),
                Repo {
                    alias: "repo1".to_string(),
                    path: "/path/to/repo1".to_string(),
                    origin: "https://github.com/example/repo1".to_string(),
                    dependencies: HashMap::from([
                        (
                            "dep1".to_string(),
                            Dep {
                                commit: "abc123".to_string(),
                                hash: "def456".to_string(),
                            },
                        ),
                        (
                            "dep2".to_string(),
                            Dep {
                                commit: "def456".to_string(),
                                hash: "abc123".to_string(),
                            },
                        ),
                    ]),
                },
            ),
            (
                "repo2".to_string(),
                Repo {
                    alias: "repo2".to_string(),
                    path: "/path/to/repo2".to_string(),
                    origin: "https://github.com/example/repo2".to_string(),
                    dependencies: HashMap::from([
                        (
                            "dep1".to_string(),
                            Dep {
                                commit: "abc123".to_string(),
                                hash: "def456".to_string(),
                            },
                        ),
                        (
                            "dep2".to_string(),
                            Dep {
                                commit: "def456".to_string(),
                                hash: "abc123".to_string(),
                            },
                        ),
                    ]),
                },
            ),
        ]),
    };
    let result_str = toml::to_string(&generate_toml_table(&test_config))
        .map_err(|e| Box::new(TomlError::ErrorWritingTomlFile(e.to_string())))
        .unwrap();
    let round_trip_table = toml::from_str::<Table>(&result_str).unwrap();
    assert_eq!(generate_toml_table(&test_config), round_trip_table);
}
