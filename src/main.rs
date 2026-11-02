mod config;
mod firewall;
mod ops;
mod rules;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use config::DEFAULT_CONFIG_PATH;
use firewall::SystemFirewall;
use ops::{FamilyStatus, FenceError, Report};
use rules::Family;

#[derive(Debug, Parser)]
#[command(
    name = "docker-fence",
    version,
    about = "Block Docker containers from opening new connections to listed networks"
)]
struct Cli {
    /// Path to the configuration file
    #[arg(long, global = true, value_name = "PATH", default_value = DEFAULT_CONFIG_PATH)]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install the firewall rules for the configured networks
    Apply,
    /// Remove the firewall rules (ignores the configuration file)
    Remove,
    /// Check that the installed rules match the configuration
    Status,
}

fn log(msg: impl std::fmt::Display) {
    eprintln!("docker-fence: {msg}");
}

fn print_notices(report: &Report) {
    for n in &report.notices {
        log(n);
    }
}

fn fail(e: &FenceError) -> ExitCode {
    log(e);
    ExitCode::from(1)
}

fn load_config(path: &Path) -> Result<config::FenceConfig, ExitCode> {
    config::load(path).map_err(|e| {
        log(e);
        ExitCode::from(2)
    })
}

fn family_label(f: Family) -> &'static str {
    match f {
        Family::V4 => "ipv4",
        Family::V6 => "ipv6",
    }
}

fn run(cli: &Cli) -> ExitCode {
    let fw = SystemFirewall;
    match cli.command {
        Command::Apply => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return code,
            };
            match ops::apply(&fw, &cfg) {
                Ok(report) => {
                    print_notices(&report);
                    ExitCode::SUCCESS
                }
                Err(e) => fail(&e),
            }
        }
        Command::Remove => match ops::remove(&fw) {
            Ok(report) => {
                print_notices(&report);
                ExitCode::SUCCESS
            }
            Err(e) => fail(&e),
        },
        Command::Status => {
            let cfg = match load_config(&cli.config) {
                Ok(c) => c,
                Err(code) => return code,
            };
            match ops::status(&fw, &cfg) {
                Ok(report) => {
                    for (family, st) in &report.families {
                        let label = family_label(*family);
                        match st {
                            FamilyStatus::Ok => println!("{label}: ok"),
                            FamilyStatus::Skipped => {
                                println!("{label}: skipped (no DOCKER-USER chain)")
                            }
                            FamilyStatus::Missing => println!("{label}: missing"),
                            FamilyStatus::Mismatch(d) => println!("{label}: mismatch ({d})"),
                        }
                    }
                    if report.is_ok() {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::from(1)
                    }
                }
                Err(e) => fail(&e),
            }
        }
    }
}

fn main() -> ExitCode {
    run(&Cli::parse())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind;

    fn parse(v: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(v)
    }

    #[test]
    fn default_config_path() {
        let cli = parse(&["docker-fence", "apply"]).unwrap();
        assert!(matches!(cli.command, Command::Apply));
        assert_eq!(cli.config, PathBuf::from(config::DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn config_before_subcommand() {
        let cli = parse(&["docker-fence", "--config", "/tmp/x", "apply"]).unwrap();
        assert_eq!(cli.config, PathBuf::from("/tmp/x"));
    }

    #[test]
    fn config_after_subcommand() {
        let cli = parse(&["docker-fence", "status", "--config", "/tmp/y"]).unwrap();
        assert!(matches!(cli.command, Command::Status));
        assert_eq!(cli.config, PathBuf::from("/tmp/y"));
    }

    #[test]
    fn unknown_subcommand_is_error() {
        assert!(parse(&["docker-fence", "frobnicate"]).is_err());
    }

    #[test]
    fn missing_subcommand_is_error() {
        assert!(parse(&["docker-fence"]).is_err());
        assert!(parse(&["docker-fence", "--config", "/tmp/x"]).is_err());
    }

    #[test]
    fn config_without_value_is_error() {
        assert!(parse(&["docker-fence", "apply", "--config"]).is_err());
    }

    #[test]
    fn config_does_not_swallow_help_flag() {
        let err = parse(&["docker-fence", "--config", "--help", "apply"]).unwrap_err();
        assert_ne!(err.kind(), ErrorKind::DisplayHelp);
    }

    #[test]
    fn two_subcommands_is_error() {
        assert!(parse(&["docker-fence", "apply", "status"]).is_err());
    }

    #[test]
    fn version_flag() {
        let err = parse(&["docker-fence", "--version"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayVersion);
    }

    #[test]
    fn help_flag() {
        let err = parse(&["docker-fence", "--help"]).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::DisplayHelp);
    }
}
