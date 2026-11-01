use ipnet::IpNet;
use std::fmt;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG_PATH: &str = "/etc/docker-fence/docker-fence.conf";

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FenceConfig {
    pub v4: Vec<ipnet::Ipv4Net>,
    pub v6: Vec<ipnet::Ipv6Net>,
}

#[derive(Debug)]
pub struct ConfigError {
    pub path: PathBuf,
    pub line: Option<usize>,
    pub message: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.line {
            Some(n) => write!(f, "{}:{}: {}", self.path.display(), n, self.message),
            None => write!(f, "{}: {}", self.path.display(), self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

pub fn parse(text: &str, path: &Path) -> Result<FenceConfig, ConfigError> {
    let mut cfg = FenceConfig::default();
    for (idx, raw) in text.lines().enumerate() {
        let content = raw.split('#').next().unwrap_or("").trim();
        if content.is_empty() {
            continue;
        }
        let net: IpNet = content.parse().map_err(|_| ConfigError {
            path: path.to_path_buf(),
            line: Some(idx + 1),
            message: format!("invalid CIDR {content:?} (expected e.g. 192.0.2.0/24)"),
        })?;
        match net.trunc() {
            IpNet::V4(n) => {
                if !cfg.v4.contains(&n) {
                    cfg.v4.push(n);
                }
            }
            IpNet::V6(n) => {
                if !cfg.v6.contains(&n) {
                    cfg.v6.push(n);
                }
            }
        }
    }
    Ok(cfg)
}

pub fn load(path: &Path) -> Result<FenceConfig, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError {
        path: path.to_path_buf(),
        line: None,
        message: format!("cannot read config: {e}"),
    })?;
    parse(&text, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> &'static Path {
        Path::new("/etc/x.conf")
    }

    #[test]
    fn parses_mixed_families_comments_crlf_and_tabs() {
        let c = parse(
            "# mgmt\r\n192.0.2.0/24\t # inline\r\n\r\n2001:db8:10::/64  \n",
            p(),
        )
        .unwrap();
        assert_eq!(c.v4, vec!["192.0.2.0/24".parse().unwrap()]);
        assert_eq!(c.v6, vec!["2001:db8:10::/64".parse().unwrap()]);
    }

    #[test]
    fn normalises_host_bits() {
        let c = parse("192.0.2.5/24", p()).unwrap();
        assert_eq!(
            c.v4,
            vec!["192.0.2.0/24".parse::<ipnet::Ipv4Net>().unwrap()]
        );
    }

    #[test]
    fn rejects_bare_ip_with_line_number() {
        let e = parse("192.0.2.0/24\n192.0.2.5\n", p()).unwrap_err();
        assert_eq!(e.line, Some(2));
        assert!(e.to_string().starts_with("/etc/x.conf:2:"));
    }

    #[test]
    fn rejects_garbage() {
        for s in ["hello", "192.0.2.0/33", "192.0.2.0/24 extra"] {
            assert!(parse(s, p()).is_err(), "{s}");
        }
    }

    #[test]
    fn dedupes_exact_duplicates_keeping_order() {
        let c = parse(
            "192.0.2.0/25\n198.51.100.0/24\n192.0.2.0/25\n192.0.2.5/25\n",
            p(),
        )
        .unwrap();
        assert_eq!(
            c.v4,
            vec![
                "192.0.2.0/25".parse().unwrap(),
                "198.51.100.0/24".parse().unwrap()
            ]
        );
    }

    #[test]
    fn empty_and_comment_only_are_ok() {
        for s in ["", "\n\n", "# only\n  # comment\n"] {
            let c = parse(s, p()).unwrap();
            assert!(c.v4.is_empty() && c.v6.is_empty());
        }
    }

    #[test]
    fn load_missing_file_errors_without_line() {
        let e = load(Path::new("/nonexistent/docker-fence.conf")).unwrap_err();
        assert_eq!(e.line, None);
    }
}
