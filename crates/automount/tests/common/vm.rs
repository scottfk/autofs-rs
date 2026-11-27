//! The root test tier: daemon cases on the test VM (`hydra-autofs-test`),
//! where a real kernel autofs is mounted. Each case runs twice, with the C
//! reference daemon and with the port, through `tests/vm/run-case.sh` (a
//! private mount namespace with overlays on `/etc` and `/usr` and recording
//! `mount`/`umount`), and everything observable is compared: the daemon's log
//! (`-f -d` to stderr), the recorded commands, the case's own notes and mount
//! snapshots, the exit status, and the mounts and files left at the end.
//!
//! The VM is reached with `ssh` (`$AUTOFS_VM_SSH`, by default the test VM's
//! key and port 2272 on localhost). The binaries go over once per test run.
//!
//! Normalized before comparing: thread ids, the kernel's wait queue tokens
//! (renumbered in order of appearance), requesting pids, and `/tmp/autoXXXXXX`
//! names.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use super::{normalize_tmp, reference_dir};

const VM_DIR: &str = "/root/autofs-rs-test";

fn ssh_args() -> Vec<String> {
    match std::env::var("AUTOFS_VM_SSH") {
        Ok(s) => s.split_whitespace().map(String::from).collect(),
        Err(_) => {
            let home = std::env::var("HOME").unwrap();
            vec![
                "-o".into(),
                "BatchMode=yes".into(),
                "-o".into(),
                "StrictHostKeyChecking=no".into(),
                "-o".into(),
                "UserKnownHostsFile=/dev/null".into(),
                "-o".into(),
                "LogLevel=ERROR".into(),
                "-i".into(),
                format!("{home}/.ssh/hydra-openrc-rs-test_ed25519"),
                "-p".into(),
                "2272".into(),
                "root@127.0.0.1".into(),
            ]
        }
    }
}

/// `ssh VM cmd`, with `input` on its stdin; its stdout.
fn ssh(cmd: &str, input: &[u8]) -> Vec<u8> {
    let mut child = Command::new("ssh")
        .args(ssh_args())
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("ssh");
    {
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "ssh {cmd}: {:?}", out.status);
    out.stdout
}

fn tar_of(dir: &std::path::Path, members: &[&str]) -> Vec<u8> {
    let out = Command::new("tar").arg("-C").arg(dir).arg("-chf").arg("-").args(members).output().unwrap();
    assert!(out.status.success(), "tar of {dir:?} {members:?}");
    out.stdout
}

/// Copy the reference build, the port and the case runner to the VM (once).
fn push() {
    static DONE: OnceLock<()> = OnceLock::new();
    DONE.get_or_init(|| {
        let refdir = reference_dir();
        let mut modules: Vec<String> = std::fs::read_dir(refdir.join("modules"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".so"))
            .map(|n| format!("modules/{n}"))
            .collect();
        modules.sort();
        let mut members: Vec<&str> = vec!["daemon/automount", "lib/libautofs.so"];
        members.extend(modules.iter().map(|s| s.as_str()));
        let c = tar_of(&refdir, &members);
        ssh(&format!("rm -rf {VM_DIR}/c && mkdir -p {VM_DIR}/c {VM_DIR}/r {VM_DIR}/cases && tar -C {VM_DIR}/c -xf -"), &c);
        let r = std::fs::read(env!("CARGO_BIN_EXE_automount")).unwrap();
        ssh(&format!("cat > {VM_DIR}/r/automount.new && chmod 755 {VM_DIR}/r/automount.new && mv {VM_DIR}/r/automount.new {VM_DIR}/r/automount"), &r);
        let script = std::fs::read(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vm/run-case.sh")).unwrap();
        ssh(&format!("cat > {VM_DIR}/run-case.sh && chmod 755 {VM_DIR}/run-case.sh"), &script);
    });
}

/// One daemon case.
#[derive(Debug, Clone)]
pub struct VmCase {
    pub name: String,
    pub args: Vec<String>,
    /// Files under `/etc` (path relative to it, contents, mode).
    pub etc: Vec<(String, Vec<u8>, u32)>,
    /// The shell fragment run while the daemon runs (see run-case.sh for its
    /// helpers: `ready`, `waitlog`, `snap`, `note`, `sig`, `quiet`, `stopd`).
    pub steps: String,
    /// A shell fragment run before the daemon starts.
    pub pre: String,
    /// Log lines containing any of these are left out (timing-dependent
    /// lines, such as the expire runs before a mount times out).
    pub drop_lines: Vec<String>,
    /// Compare the log as sorted lines: for cases where C's own order varies
    /// (threads racing, such as several mounts shutting down at once).
    pub unordered_log: bool,
}

impl VmCase {
    /// A case with `auto.master` (none for `-`) and the daemon run as
    /// `automount -f -d`.
    pub fn new(name: &str, master: &str) -> VmCase {
        let etc = if master == "-" {
            Vec::new()
        } else {
            vec![("autofs/auto.master".into(), master.as_bytes().to_vec(), 0o644)]
        };
        VmCase {
            name: name.into(),
            args: vec!["-f".into(), "-d".into()],
            etc,
            steps: String::new(),
            pre: String::new(),
            drop_lines: Vec::new(),
            unordered_log: false,
        }
    }

    pub fn pre(mut self, s: &str) -> VmCase {
        self.pre = s.into();
        self
    }

    pub fn drop_lines(mut self, pats: &[&str]) -> VmCase {
        self.drop_lines = pats.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn unordered_log(mut self) -> VmCase {
        self.unordered_log = true;
        self
    }

    pub fn args(mut self, args: &[&str]) -> VmCase {
        self.args = args.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn map(self, name: &str, contents: &str) -> VmCase {
        self.etc(&format!("autofs/{name}"), contents)
    }

    pub fn etc(mut self, path: &str, contents: &str) -> VmCase {
        self.etc.push((path.into(), contents.as_bytes().to_vec(), 0o644));
        self
    }

    pub fn etc_mode(mut self, path: &str, contents: &str, mode: u32) -> VmCase {
        self.etc.push((path.into(), contents.as_bytes().to_vec(), mode));
        self
    }

    pub fn conf(self, contents: &str) -> VmCase {
        self.etc("autofs/autofs.conf", contents)
    }

    pub fn steps(mut self, s: &str) -> VmCase {
        self.steps = s.into();
        self
    }
}

/// What a run left.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmOutcome {
    pub status: String,
    pub log: String,
    pub cmds: String,
    pub steps: String,
    pub mounts_after: String,
    pub tree_after: String,
}

fn local_dir(case: &VmCase, imp: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/vmtest").join(&case.name).join(imp)
}

/// Renumber the values after `word ` in order of first appearance.
fn renumber(s: &str, word: &str, tag: &str) -> String {
    let mut seen: Vec<String> = Vec::new();
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find(word) {
        out.push_str(&rest[..p + word.len()]);
        let tail = &rest[p + word.len()..];
        let n: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if n.is_empty() {
            rest = tail;
            continue;
        }
        let i = seen.iter().position(|x| *x == n).unwrap_or_else(|| {
            seen.push(n.clone());
            seen.len() - 1
        });
        out.push_str(&format!("{tag}{}", i + 1));
        rest = &tail[n.len()..];
    }
    out.push_str(rest);
    out
}

/// Thread ids: numbers of 12 digits or more.
fn mask_thread_ids(s: &str) -> String {
    let mut out = String::new();
    let mut digits = String::new();
    for ch in s.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        if digits.len() >= 12 {
            out.push_str("THID");
        } else {
            out.push_str(&digits);
        }
        digits.clear();
        out.push(ch);
    }
    if digits.len() >= 12 {
        out.push_str("THID");
    } else {
        out.push_str(&digits);
    }
    out
}

/// Mount request ids (`%02lx|` at the start of a line): they hash the token
/// and the requesting pid. Renumbered in order of appearance.
fn mask_request_ids(s: &str) -> String {
    let mut seen: Vec<String> = Vec::new();
    let mut out = String::new();
    for line in s.split_inclusive('\n') {
        if let Some(p) = line.find('|')
            && p >= 2
            && line[..p].chars().all(|c| c.is_ascii_hexdigit())
        {
            let id = line[..p].to_string();
            let i = seen.iter().position(|x| *x == id).unwrap_or_else(|| {
                seen.push(id.clone());
                seen.len() - 1
            });
            out.push_str(&format!("ID{}{}", i + 1, &line[p..]));
        } else {
            out.push_str(line);
        }
    }
    out
}

fn normalize(s: &str, names: &mut Vec<String>) -> String {
    let s = mask_request_ids(s);
    let s = s
        .replace(&format!("{VM_DIR}/c/daemon/automount"), "AUTOMOUNT")
        .replace(&format!("{VM_DIR}/r/automount"), "AUTOMOUNT");
    let s = mask_thread_ids(&s);
    let s = renumber(&s, "token ", "T");
    let s = renumber(&s, "token = ", "T");
    let s = renumber(&s, "request pid ", "P");
    let s = renumber(&s, " pid:", "Q");
    let s = renumber(&s, " tgid:", "Q");
    normalize_tmp(&s, names)
}

/// Run the case with one implementation.
pub fn run_vm(case: &VmCase, imp: &str) -> VmOutcome {
    push();
    let dir = local_dir(case, imp);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("case/etc")).unwrap();
    for (p, c, mode) in &case.etc {
        let f = dir.join("case/etc").join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, c).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(*mode)).unwrap();
    }
    std::fs::write(dir.join("case/args"), case.args.iter().map(|a| format!("{a}\n")).collect::<String>()).unwrap();
    std::fs::write(dir.join("case/steps"), &case.steps).unwrap();
    std::fs::write(dir.join("case/pre"), &case.pre).unwrap();
    let input = tar_of(&dir.join("case"), &["."]);
    // Both runs use the same directory, so paths in the outputs match.
    let rdir = format!("{VM_DIR}/cases/{}", case.name);
    let out = ssh(
        &format!(
            "rm -rf {rdir} && mkdir -p {rdir} && tar -m -C {rdir} -xf - && {VM_DIR}/run-case.sh {imp} {rdir} > {rdir}.runlog 2>&1; tar -C {rdir}/out -cf - ."
        ),
        &input,
    );
    std::fs::create_dir_all(dir.join("out")).unwrap();
    let mut t =
        Command::new("tar").arg("-C").arg(dir.join("out")).arg("-xf").arg("-").stdin(Stdio::piped()).spawn().unwrap();
    t.stdin.take().unwrap().write_all(&out).unwrap();
    assert!(t.wait().unwrap().success());
    let read =
        |f: &str| String::from_utf8_lossy(&std::fs::read(dir.join("out").join(f)).unwrap_or_default()).into_owned();
    assert!(dir.join("out/status").exists(), "{}/{imp}: the case didn't run (no out/status)", case.name);
    let mut names = Vec::new();
    let mut n = |s: String| normalize(&s, &mut names);
    VmOutcome {
        status: read("status").trim().to_string(),
        log: n(read("log"))
            .lines()
            .filter(|l| !case.drop_lines.iter().any(|p| l.contains(p.as_str())))
            .map(|l| format!("{l}\n"))
            .collect(),
        cmds: n(read("cmds")),
        steps: n(read("steps")),
        mounts_after: read("mounts-after"),
        // The command FIFO is removed by its thread as the daemon exits, a
        // race C usually loses.
        tree_after: read("tree-after")
            .lines()
            .filter(|l| *l != "/run/autofs.cmd.fifo")
            .map(|l| format!("{l}\n"))
            .collect(),
    }
}

/// Run the case with both implementations and compare; the C outcome.
pub fn check_vm(case: VmCase) -> VmOutcome {
    let mut c = run_vm(&case, "c");
    let mut r = run_vm(&case, "r");
    if case.unordered_log {
        let sorted = |s: &str, mask: bool| {
            let mut l: Vec<String> = s
                .lines()
                .map(|l| {
                    if !mask {
                        return l.to_string();
                    }
                    // Tokens are numbered in the order of a race.
                    let mut out = String::new();
                    let mut chars = l.chars().peekable();
                    while let Some(ch) = chars.next() {
                        out.push(ch);
                        if out.ends_with("token T") || out.ends_with("token = T") {
                            while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                                chars.next();
                            }
                        }
                    }
                    out
                })
                .collect();
            l.sort();
            l.join("\n")
        };
        // C writes a message and its newline separately, so two threads
        // logging at once can run messages together (and leave an empty
        // line): split lines where another line's start appears in them.
        let starts: Vec<String> = c
            .log
            .lines()
            .chain(r.log.lines())
            .filter(|l| l.len() >= 16)
            .map(|l| l.chars().take(16).collect())
            .collect();
        let split = |log: &str| -> String {
            let mut out = Vec::new();
            for line in log.lines() {
                let mut rest = line.to_string();
                'again: loop {
                    for st in &starts {
                        if let Some(p) = rest[1..].find(st.as_str()) {
                            let p = p + 1;
                            out.push(rest[..p].to_string());
                            rest = rest[p..].to_string();
                            continue 'again;
                        }
                    }
                    break;
                }
                if !rest.is_empty() {
                    out.push(rest);
                }
            }
            out.join("\n")
        };
        for o in [&mut c, &mut r] {
            o.log = sorted(&split(&o.log), true);
            o.cmds = sorted(&o.cmds, false);
        }
    }
    if std::env::var_os("AUTOFS_DIFF_SHOW").is_some() {
        eprintln!("=== {} ===\n{}\n--- steps\n{}--- cmds\n{}", case.name, c.log, c.steps, c.cmds);
    }
    if c != r {
        let mut msg = format!("case {} differs:\n", case.name);
        macro_rules! field {
            ($f:ident) => {
                if c.$f != r.$f {
                    msg.push_str(&format!("--- {}\n", stringify!($f)));
                    for d in diff_lines(&c.$f, &r.$f) {
                        msg.push_str(&d);
                        msg.push('\n');
                    }
                }
            };
        }
        field!(status);
        field!(log);
        field!(cmds);
        field!(steps);
        field!(mounts_after);
        field!(tree_after);
        panic!("{msg}");
    }
    c
}

/// A small line diff (`-` C, `+` Rust) for the failure message.
fn diff_lines(a: &str, b: &str) -> Vec<String> {
    let a: Vec<&str> = a.lines().collect();
    let b: Vec<&str> = b.lines().collect();
    let n = a.len().max(b.len());
    let mut out = Vec::new();
    for i in 0..n {
        let (x, y) = (a.get(i).copied(), b.get(i).copied());
        if x != y {
            out.push(format!("@{}\n- {}\n+ {}", i + 1, x.unwrap_or("<none>"), y.unwrap_or("<none>")));
            if out.len() > 8 {
                out.push("...".into());
                break;
            }
        }
    }
    out
}
