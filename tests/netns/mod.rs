//! Network-namespace harness for the docker-fence integration tests.
//!
//! Topology (every piece lives in a namespace created here; nothing touches
//! the namespace the test process runs in):
//!
//! ```text
//!   ct (container)                host (Docker host)                    pn (protected net)
//!   eth0 172.30.0.2/24  ---  veth-ct ] docker0 172.30.0.1/24
//!        fd30::2/64                  ]         fd30::1/64
//!                                    prot0 192.0.2.1/24        ---  eth0 192.0.2.2/24
//!                                          2001:db8:10::1/64             2001:db8:10::2/64
//!                                          198.51.100.1/24               198.51.100.2/24
//!                                          2001:db8:20::1/64             2001:db8:20::2/64
//! ```
//!
//! `host` forwards IPv4 and IPv6 and carries a Docker-like `DOCKER-USER`
//! chain (`-A DOCKER-USER -j RETURN`, jumped to from `FORWARD`) in both
//! `iptables` and `ip6tables`. 192.0.2.0/24 and 2001:db8:10::/64 are the
//! "protected" networks; 198.51.100.0/24 and 2001:db8:20::/64 sit on the
//! same link and serve as destinations outside the fenced CIDRs.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant};

pub const BIN: &str = env!("CARGO_BIN_EXE_docker-fence");

/// Protected destinations (inside the CIDRs of [`PROTECTED_CONFIG`]).
pub const PN_V4: &str = "192.0.2.2:9000";
pub const PN_V6: &str = "[2001:db8:10::2]:9000";
/// Destinations in `pn` outside the protected CIDRs.
pub const OTHER_V4: &str = "198.51.100.2:9000";
pub const OTHER_V6: &str = "[2001:db8:20::2]:9000";
/// Listener inside the container.
pub const CT_V4: &str = "172.30.0.2:9001";
pub const CT_V6: &str = "[fd30::2]:9001";

pub const PROTECTED_CONFIG: &str = "192.0.2.0/24\n2001:db8:10::/64\n";
pub const WIDE_CONFIG: &str = "192.0.2.0/24\n2001:db8:10::/64\n198.51.100.0/24\n2001:db8:20::/64\n";

/// The `DOCKER-USER` listing of the Docker emulation, for either family.
pub const DOCKER_USER_BASELINE: [&str; 2] = ["-N DOCKER-USER", "-A DOCKER-USER -j RETURN"];
pub const JUMP: &str = "-A DOCKER-USER -j DOCKER-FENCE";

const READY_TIMEOUT: Duration = Duration::from_secs(15);

/// Tests share fixed in-namespace addresses and process-unique namespace
/// names, so they must never overlap even if `--test-threads=1` is forgotten.
static SERIAL: Mutex<()> = Mutex::new(());
static SEQ: AtomicUsize = AtomicUsize::new(0);

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

pub fn stdout(out: &Output) -> String {
    lossy(&out.stdout)
}

pub fn stderr(out: &Output) -> String {
    lossy(&out.stderr)
}

/// Full description of a finished command, for panic messages.
pub fn describe<S: AsRef<str>>(argv: &[S], out: &Output) -> String {
    let cmd: Vec<&str> = argv.iter().map(AsRef::as_ref).collect();
    format!(
        "command: {}\nstatus: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        cmd.join(" "),
        out.status,
        stdout(out),
        stderr(out)
    )
}

/// Run a command to completion. Panics only if it cannot be spawned.
pub fn run<S: AsRef<str>>(argv: &[S]) -> Output {
    let (prog, args) = argv.split_first().expect("empty command line");
    Command::new(prog.as_ref())
        .args(args.iter().map(AsRef::as_ref))
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| {
            let cmd: Vec<&str> = argv.iter().map(AsRef::as_ref).collect();
            panic!("failed to spawn `{}`: {e}", cmd.join(" "))
        })
}

/// The one checked runner: panics with the full command, exit status,
/// stdout and stderr if the command does not exit 0.
pub fn run_ok<S: AsRef<str>>(argv: &[S]) -> Output {
    let out = run(argv);
    if !out.status.success() {
        panic!("command failed\n{}", describe(argv, &out));
    }
    out
}

/// Assert an exit code, showing the whole command result on mismatch.
pub fn assert_exit(out: &Output, code: i32, what: &str) {
    assert_eq!(
        out.status.code(),
        Some(code),
        "{what}: expected exit {code}\nstatus: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        out.status,
        stdout(out),
        stderr(out)
    );
}

fn in_ns<S: AsRef<str>>(ns: &str, argv: &[S]) -> Vec<String> {
    let mut v: Vec<String> = ["ip", "netns", "exec", ns]
        .iter()
        .map(|s| s.to_string())
        .collect();
    v.extend(argv.iter().map(|s| s.as_ref().to_string()));
    v
}

fn url(addr: &str) -> String {
    format!("http://{addr}/")
}

fn curl(ns: &str, addr: &str, max_time: u32) -> Vec<String> {
    let max_time = max_time.to_string();
    in_ns(
        ns,
        &[
            "curl",
            "--globoff",
            "--noproxy",
            "*",
            "--max-time",
            &max_time,
            "-s",
            "-o",
            "/dev/null",
            &url(addr),
        ],
    )
}

struct Listener {
    ns: String,
    addr: String,
    child: Child,
    log: PathBuf,
}

pub struct Harness {
    pub host: String,
    pub ct: String,
    pub pn: String,
    dir: PathBuf,
    config: PathBuf,
    namespaces: Vec<String>,
    listeners: Vec<Listener>,
    _serial: MutexGuard<'static, ()>,
}

impl Harness {
    /// Build the topology. The struct exists before any namespace is
    /// created, so a panic half-way through setup still cleans up in `Drop`.
    pub fn new() -> Harness {
        let serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let prefix = format!("fence-test-{}", std::process::id());
        let dir =
            std::env::temp_dir().join(format!("{prefix}-{}", SEQ.fetch_add(1, Ordering::SeqCst)));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("www"))
            .unwrap_or_else(|e| panic!("create {}: {e}", dir.display()));
        let mut h = Harness {
            host: format!("{prefix}-host"),
            ct: format!("{prefix}-ct"),
            pn: format!("{prefix}-pn"),
            config: dir.join("docker-fence.conf"),
            dir,
            namespaces: Vec::new(),
            listeners: Vec::new(),
            _serial: serial,
        };
        h.create_namespaces();
        h.wire_links();
        h.emulate_docker();
        h.start_listeners();
        h.wait_for_forwarding();
        h
    }

    fn create_namespaces(&mut self) {
        for ns in [self.host.clone(), self.ct.clone(), self.pn.clone()] {
            // Leftover from an earlier crashed run that had the same pid.
            let _ = run(&["ip", "netns", "del", &ns]);
            run_ok(&["ip", "netns", "add", &ns]);
            self.namespaces.push(ns.clone());
            // accept_dad is effectively max(all, dev): clear both before any
            // interface exists so new ones (and their link-local addresses)
            // never sit in DAD. Global addresses also get `nodad` below.
            for key in [
                "net.ipv6.conf.all.accept_dad=0",
                "net.ipv6.conf.default.accept_dad=0",
            ] {
                run_ok(&in_ns(&ns, &["sysctl", "-q", "-w", key]));
            }
            run_ok(&["ip", "-n", &ns, "link", "set", "lo", "up"]);
        }
    }

    fn wire_links(&self) {
        let (h, c, p) = (self.host.as_str(), self.ct.as_str(), self.pn.as_str());
        // No argument contains whitespace, so each line is split on it.
        let script = format!(
            "
            ip -n {h} link add docker0 type bridge
            ip -n {h} link add veth-ct type veth peer name eth0 netns {c}
            ip -n {h} link set veth-ct master docker0
            ip -n {h} link add prot0 type veth peer name eth0 netns {p}
            ip -n {h} link set docker0 up
            ip -n {h} link set veth-ct up
            ip -n {h} link set prot0 up
            ip -n {c} link set eth0 up
            ip -n {p} link set eth0 up
            ip -n {h} addr add 172.30.0.1/24 dev docker0
            ip -n {h} -6 addr add fd30::1/64 dev docker0 nodad
            ip -n {h} addr add 192.0.2.1/24 dev prot0
            ip -n {h} -6 addr add 2001:db8:10::1/64 dev prot0 nodad
            ip -n {h} addr add 198.51.100.1/24 dev prot0
            ip -n {h} -6 addr add 2001:db8:20::1/64 dev prot0 nodad
            ip -n {c} addr add 172.30.0.2/24 dev eth0
            ip -n {c} -6 addr add fd30::2/64 dev eth0 nodad
            ip -n {c} route add default via 172.30.0.1 dev eth0
            ip -n {c} -6 route add default via fd30::1 dev eth0
            ip -n {p} addr add 192.0.2.2/24 dev eth0
            ip -n {p} -6 addr add 2001:db8:10::2/64 dev eth0 nodad
            ip -n {p} addr add 198.51.100.2/24 dev eth0
            ip -n {p} -6 addr add 2001:db8:20::2/64 dev eth0 nodad
            ip -n {p} route add 172.30.0.0/24 via 192.0.2.1 dev eth0
            ip -n {p} -6 route add fd30::/64 via 2001:db8:10::1 dev eth0
            "
        );
        for line in script.lines().map(str::trim).filter(|l| !l.is_empty()) {
            run_ok(&line.split_whitespace().collect::<Vec<_>>());
        }
        for key in [
            "net.ipv4.ip_forward=1",
            "net.ipv6.conf.all.forwarding=1",
            // REJECT answers with ICMP errors; do not let per-peer rate
            // limiting turn quick refusals into silent drops.
            "net.ipv4.icmp_ratelimit=0",
            "net.ipv6.icmp.ratelimit=0",
        ] {
            run_ok(&in_ns(h, &["sysctl", "-q", "-w", key]));
        }
    }

    /// Docker's chain layout: FORWARD -> DOCKER-USER, which holds only a
    /// trailing RETURN (so appending after it would be ineffective).
    fn emulate_docker(&self) {
        for tool in ["iptables", "ip6tables"] {
            self.ipt(tool, &["-N", "DOCKER-USER"]);
            self.ipt(tool, &["-A", "DOCKER-USER", "-j", "RETURN"]);
            self.ipt(tool, &["-A", "FORWARD", "-j", "DOCKER-USER"]);
            assert_eq!(self.list(tool, "DOCKER-USER"), DOCKER_USER_BASELINE);
        }
    }

    fn start_listeners(&mut self) {
        let pn = self.pn.clone();
        let ct = self.ct.clone();
        for (ns, addr) in [
            (&pn, PN_V4),
            (&pn, PN_V6),
            (&pn, OTHER_V4),
            (&pn, OTHER_V6),
            (&ct, CT_V4),
            (&ct, CT_V6),
        ] {
            self.spawn_listener(ns, addr);
        }
        for i in 0..self.listeners.len() {
            self.wait_listener(i);
        }
    }

    /// `addr` is `HOST:PORT` with IPv6 hosts in brackets.
    fn spawn_listener(&mut self, ns: &str, addr: &str) {
        let (host, port) = addr.rsplit_once(':').expect("addr is HOST:PORT");
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let log = self
            .dir
            .join(format!("listener-{}.log", self.listeners.len()));
        let file = File::create(&log).unwrap_or_else(|e| panic!("create {}: {e}", log.display()));
        let www = self.dir.join("www");
        let argv = in_ns(
            ns,
            &[
                "python3",
                "-u",
                "-m",
                "http.server",
                "--bind",
                host,
                "--directory",
                www.to_str().expect("utf-8 temp dir"),
                port,
            ],
        );
        let child = Command::new(&argv[0])
            .args(&argv[1..])
            .stdin(Stdio::null())
            .stdout(file.try_clone().expect("clone log handle"))
            .stderr(file)
            .spawn()
            .unwrap_or_else(|e| panic!("failed to spawn `{}`: {e}", argv.join(" ")));
        self.listeners.push(Listener {
            ns: ns.to_string(),
            addr: addr.to_string(),
            child,
            log,
        });
    }

    /// Poll the listener from its own namespace until it answers.
    fn wait_listener(&mut self, i: usize) {
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            let l = &mut self.listeners[i];
            if let Ok(Some(status)) = l.child.try_wait() {
                panic!(
                    "listener {} in {} exited early ({status}); log:\n{}",
                    l.addr,
                    l.ns,
                    fs::read_to_string(&l.log).unwrap_or_default()
                );
            }
            let argv = curl(&l.ns, &l.addr, 1);
            let out = run(&argv);
            if out.status.success() {
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "listener {} in {} never became ready\n{}\nlistener log:\n{}",
                    l.addr,
                    l.ns,
                    describe(&argv, &out),
                    fs::read_to_string(&l.log).unwrap_or_default()
                );
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    /// With no fence installed, container -> protected must work for both
    /// families; otherwise every "is blocked" assertion would be vacuous.
    fn wait_for_forwarding(&self) {
        for addr in [PN_V4, PN_V6] {
            let deadline = Instant::now() + READY_TIMEOUT;
            loop {
                let argv = curl(&self.ct, addr, 2);
                let out = run(&argv);
                if out.status.success() {
                    break;
                }
                if Instant::now() > deadline {
                    panic!(
                        "harness broken: container cannot reach {addr} without any fence\n{}\n\
                         --- host routes ---\n{}\n--- host addresses ---\n{}",
                        describe(&argv, &out),
                        stdout(&run(&["ip", "-n", &self.host, "route"]))
                            + &stdout(&run(&["ip", "-n", &self.host, "-6", "route"])),
                        stdout(&run(&["ip", "-n", &self.host, "addr"]))
                    );
                }
                thread::sleep(Duration::from_millis(200));
            }
        }
    }

    /// A path in the harness directory that does not exist.
    pub fn missing_path(&self) -> PathBuf {
        self.dir.join("does-not-exist.conf")
    }

    pub fn write_config(&self, text: &str) {
        fs::write(&self.config, text)
            .unwrap_or_else(|e| panic!("write {}: {e}", self.config.display()));
    }

    /// Run the binary inside `host` with `--config <harness config>`.
    pub fn docker_fence(&self, args: &[&str]) -> Output {
        self.docker_fence_with_config(&self.config, args)
    }

    pub fn docker_fence_with_config(&self, config: &Path, args: &[&str]) -> Output {
        let config = config.to_str().expect("utf-8 config path");
        let mut argv = vec![BIN, "--config", config];
        argv.extend_from_slice(args);
        run(&in_ns(&self.host, &argv))
    }

    /// `docker-fence apply`, which must exit 0.
    pub fn apply_ok(&self) -> Output {
        let out = self.docker_fence(&["apply"]);
        assert_exit(&out, 0, "docker-fence apply");
        out
    }

    /// Run any command in `host`; the caller checks the result.
    pub fn fh(&self, argv: &[&str]) -> Output {
        run(&in_ns(&self.host, argv))
    }

    /// Run a command in `host` that must succeed.
    pub fn fh_ok(&self, argv: &[&str]) -> Output {
        run_ok(&in_ns(&self.host, argv))
    }

    /// `iptables`/`ip6tables` in `host` (with `-w`), must succeed.
    pub fn ipt(&self, tool: &str, args: &[&str]) -> Output {
        let mut argv = vec![tool, "-w"];
        argv.extend_from_slice(args);
        self.fh_ok(&argv)
    }

    /// `tool -S [chain]` lines in `host`; the chain must exist.
    pub fn list(&self, tool: &str, chain: &str) -> Vec<String> {
        let out = if chain.is_empty() {
            self.ipt(tool, &["-S"])
        } else {
            self.ipt(tool, &["-S", chain])
        };
        stdout(&out).lines().map(str::to_string).collect()
    }

    /// True if `chain` exists in `host` for `tool`. Any failure other than
    /// "No chain" panics.
    pub fn chain_exists(&self, tool: &str, chain: &str) -> bool {
        let argv = [tool, "-w", "-S", chain];
        let out = self.fh(&argv);
        if out.status.success() {
            return true;
        }
        assert!(
            stderr(&out).contains("No chain/target/match by that name"),
            "unexpected failure\n{}",
            describe(&in_ns(&self.host, &argv), &out)
        );
        false
    }

    /// Remove `DOCKER-USER` (and the FORWARD jump to it) for `tool`.
    pub fn delete_docker_user(&self, tool: &str) {
        self.ipt(tool, &["-D", "FORWARD", "-j", "DOCKER-USER"]);
        self.ipt(tool, &["-F", "DOCKER-USER"]);
        self.ipt(tool, &["-X", "DOCKER-USER"]);
        assert!(!self.chain_exists(tool, "DOCKER-USER"));
    }

    /// One HTTP probe from `ct` (`addr` is `HOST:PORT`, IPv6 in brackets).
    pub fn probe_from_container(&self, addr: &str) -> bool {
        self.probe_from_container_within(addr, 3)
    }

    pub fn probe_from_container_within(&self, addr: &str, max_time_secs: u32) -> bool {
        run(&curl(&self.ct, addr, max_time_secs)).status.success()
    }

    /// One HTTP probe from `pn`.
    pub fn probe_from_protected(&self, addr: &str) -> bool {
        run(&curl(&self.pn, addr, 3)).status.success()
    }
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Harness {
    /// Best effort and never panics (this also runs while unwinding).
    fn drop(&mut self) {
        for l in &mut self.listeners {
            let _ = l.child.kill();
            let _ = l.child.wait();
        }
        for ns in self.namespaces.iter().rev() {
            match Command::new("ip")
                .args(["netns", "del", ns])
                .stdin(Stdio::null())
                .output()
            {
                Ok(out) if out.status.success() => {}
                Ok(out) => eprintln!(
                    "warning: cleanup failed\n{}",
                    describe(&["ip", "netns", "del", ns], &out)
                ),
                Err(e) => eprintln!("warning: cannot run `ip netns del {ns}`: {e}"),
            }
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}
