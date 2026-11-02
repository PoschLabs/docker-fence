//! Minimal stderr logger for the `log` crate.

use log::{LevelFilter, Log, Metadata, Record};

/// A [`Log`] implementation that writes `Info` and more severe records to
/// stderr, each prefixed by [`format_line`].
struct StderrLogger;

/// The single logger instance registered with the `log` crate.
static LOGGER: StderrLogger = StderrLogger;

/// Installs the stderr logger and caps the level at `Info`.
///
/// Safe to call more than once: if a logger is already installed the call
/// does nothing.
pub fn init() {
    if log::set_logger(&LOGGER).is_ok() {
        log::set_max_level(LevelFilter::Info);
    }
}

/// Formats a log message as printed on stderr: `docker-fence: <message>`.
pub fn format_line(message: &str) -> String {
    format!("docker-fence: {message}")
}

impl Log for StderrLogger {
    /// Accepts records at `Info` level or more severe.
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::Level::Info
    }

    /// Prints the record to stderr if it is [`enabled`](Log::enabled).
    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            eprintln!("{}", format_line(&record.args().to_string()));
        }
    }

    /// No-op: `eprintln!` is unbuffered.
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
