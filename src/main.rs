mod config;
mod firewall;
mod ops;
mod rules;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use config::DEFAULT_CONFIG_PATH;
use firewall::SystemFirewall;
use ops::{FamilyStatus, FenceError, Report};
use rules::Family;

const USAGE: &str = "usage: docker-fence [--config PATH] <apply|remove|status>\n       docker-fence --help | --version";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Apply,
    Remove,
    Status,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Cli {
    pub command: Command,
    pub config: PathBuf,
}

/// Output for `--help` / `--version`, which print to stdout and exit 0.
fn early_output(args: &[String]) -> Option<String> {
    for arg in args {
        match arg.as_str() {
            "--help" | "-h" => return Some(USAGE.to_string()),
            "--version" | "-V" => {
                return Some(format!("docker-fence {}", env!("CARGO_PKG_VERSION")));
            }
            _ => {}
        }
    }
    None
}

/// Err carries a usage message.
pub fn parse_args(args: &[String]) -> Result<Cli, String> {
    let mut config = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut command = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--config" => match it.next() {
                Some(v) => config = PathBuf::from(v),
                None => return Err(format!("--config requires a path\n{USAGE}")),
            },
            "apply" | "remove" | "status" if command.is_some() => {
                return Err(format!("unexpected argument '{arg}'\n{USAGE}"));
            }
            "apply" => command = Some(Command::Apply),
            "remove" => command = Some(Command::Remove),
            "status" => command = Some(Command::Status),
            other if other.starts_with('-') => {
                return Err(format!("unknown option '{other}'\n{USAGE}"));
            }
            other => return Err(format!("unknown command '{other}'\n{USAGE}")),
        }
    }
    match command {
        Some(command) => Ok(Cli { command, config }),
        None => Err(format!("missing command\n{USAGE}")),
    }
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
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some(out) = early_output(&args) {
        println!("{out}");
        return ExitCode::SUCCESS;
    }
    match parse_args(&args) {
        Ok(cli) => run(&cli),
        Err(msg) => {
            log(msg);
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn default_config_path() {
        let cli = parse_args(&a(&["apply"])).unwrap();
        assert_eq!(cli.command, Command::Apply);
        assert_eq!(cli.config, PathBuf::from(config::DEFAULT_CONFIG_PATH));
    }

    #[test]
    fn config_option() {
        let cli = parse_args(&a(&["--config", "/tmp/x", "apply"])).unwrap();
        assert_eq!(cli.config, PathBuf::from("/tmp/x"));
        let cli = parse_args(&a(&["status", "--config", "/tmp/y"])).unwrap();
        assert_eq!(cli.command, Command::Status);
        assert_eq!(cli.config, PathBuf::from("/tmp/y"));
    }

    #[test]
    fn remove_command() {
        assert_eq!(
            parse_args(&a(&["remove"])).unwrap().command,
            Command::Remove
        );
    }

    #[test]
    fn unknown_command_errors() {
        assert!(
            parse_args(&a(&["frobnicate"]))
                .unwrap_err()
                .contains("frobnicate")
        );
    }

    #[test]
    fn missing_command_errors() {
        assert!(parse_args(&a(&[])).is_err());
        assert!(parse_args(&a(&["--config", "/tmp/x"])).is_err());
    }

    #[test]
    fn config_needs_value_and_extra_args_rejected() {
        assert!(parse_args(&a(&["apply", "--config"])).is_err());
        assert!(parse_args(&a(&["apply", "status"])).is_err());
        assert!(parse_args(&a(&["--bogus", "apply"])).is_err());
    }

    #[test]
    fn help_and_version() {
        assert_eq!(
            early_output(&a(&["--version"])),
            Some(format!("docker-fence {}", env!("CARGO_PKG_VERSION")))
        );
        assert_eq!(early_output(&a(&["--help"])), Some(USAGE.to_string()));
        assert_eq!(
            early_output(&a(&["apply", "--help"])),
            Some(USAGE.to_string())
        );
        assert_eq!(early_output(&a(&["apply"])), None);
    }
}
