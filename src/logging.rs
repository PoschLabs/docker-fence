//! Minimal stderr logger for the `log` crate.

use log::{LevelFilter, Log, Metadata, Record};

struct StderrLogger;

static LOGGER: StderrLogger = StderrLogger;

/// Install the stderr logger. Safe to call more than once.
pub fn init() {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(LevelFilter::Info);
    }
}

pub fn format_line(message: &str) -> String {
    format!("docker-fence: {message}")
}

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{}", format_line(&record.args().to_string()));
        }
    }

    fn flush(&self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_line_prefixes_message() {
        assert_eq!(format_line("hello"), "docker-fence: hello");
    }

    #[test]
    fn format_line_keeps_warning_text_unchanged() {
        let msg = "WARNING: ip6tables is not available; IPv6 networks are not fenced";
        assert_eq!(format_line(msg), format!("docker-fence: {msg}"));
    }
}
