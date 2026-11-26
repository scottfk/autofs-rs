//! Differential test harness: run the C `automount` and the port in identical
//! sandboxes, with the same configuration and maps, and compare everything
//! observable.
//!
//! # The sandbox
//!
//! Each run gets a fresh directory `T` under `target/difftest/<case>/<impl>`,
//! bound onto `target/difftest/.root` inside the sandbox so both
//! implementations see the same paths (`@T@` in a case stands for it). The
//! sandbox has new user, mount, network, pid and UTS namespaces (host name
//! `autotest`). Ids are mapped with `newuidmap`/`newgidmap` from the invoking
//! user's subordinate ranges: id 0 is the invoking user, ids 1-65536 the first
//! subordinate ids, so there is a real root.
//!
//! Inside, a shell runs as pid 1. It mounts `/proc` and tmpfs on `/run` and
//! `/tmp`, brings up `lo`, and gives the program:
//!
//! - its own `/etc`: a tmpfs of links to the host's files, with the case's
//!   files (`autofs/auto.master`, `nsswitch.conf`, `mtab`...) in place of the
//!   links; `/etc/autofs` and `/etc/conf.d` start empty;
//! - recorders over `/usr/bin/mount`, `/usr/bin/umount` and `/usr/bin/mount.nfs`
//!   that log their arguments to `T/out/cmds` and run the real program;
//! - for the C side, the reference build's modules over `/usr/lib64/autofs`
//!   (with the symlinks `make install` adds) and its `libautofs.so` through
//!   `LD_LIBRARY_PATH`.
//!
//! Then it runs the program and records `/tmp` and `/run`. `/dev/log` is a
//! socket the harness reads.
//!
//! The C programs come from `$AUTOFS_REFERENCE` (a build tree), by default
//! `../autofs` (tools/build-reference.sh builds it there).

#![allow(dead_code)]

use std::ffi::{CString, c_char, c_int};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_dir() -> PathBuf {
    manifest_dir().join("../..").canonicalize().unwrap()
}

/// The C reference build tree.
pub fn reference_dir() -> PathBuf {
    std::env::var_os("AUTOFS_REFERENCE").map_or_else(|| workspace_dir().join("../autofs"), PathBuf::from)
}

/// A file of the reference build tree.
pub fn reference_file(rel: &str) -> PathBuf {
    let p = reference_dir().join(rel);
    assert!(p.exists(), "no C reference at {} (run tools/build-reference.sh)", p.display());
    p
}

pub fn rust_automount() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_automount"))
}

/// Where every run's `T` appears inside its sandbox.
pub fn fixed_root() -> PathBuf {
    let p = workspace_dir().join("target/difftest/.root");
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// The modules `make install` puts in `/usr/lib64/autofs`: (name, target)
/// where a target is a symlink.
const MODULES: &[(&str, Option<&str>)] = &[
    ("lookup_dir.so", None),
    ("lookup_file.so", None),
    ("lookup_files.so", Some("lookup_file.so")),
    ("lookup_hosts.so", None),
    ("lookup_multi.so", None),
    ("lookup_nis.so", Some("lookup_yp.so")),
    ("lookup_nisplus.so", None),
    ("lookup_program.so", None),
    ("lookup_userhome.so", None),
    ("lookup_yp.so", None),
    ("mount_afs.so", None),
    ("mount_autofs.so", None),
    ("mount_bind.so", None),
    ("mount_changer.so", None),
    ("mount_ext2.so", None),
    ("mount_ext3.so", Some("mount_ext2.so")),
    ("mount_ext4.so", Some("mount_ext2.so")),
    ("mount_generic.so", None),
    ("mount_nfs.so", None),
    ("mount_nfs4.so", Some("mount_nfs.so")),
    ("parse_amd.so", None),
    ("parse_sun.so", None),
];

/// One test case.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub args: Vec<String>,
    /// Files in the sandbox's `/etc`: (relative path, contents, mode).
    pub etc: Vec<(String, Vec<u8>, u32)>,
    /// Shell lines run before the program starts (as root, in the sandbox).
    pub setup: Vec<String>,
    /// The program's environment additions (`NAME=value`).
    pub env: Vec<String>,
    /// Files under `T` (relative path, contents), written before the run.
    pub files: Vec<(String, Vec<u8>)>,
    /// A command the program runs under (words, unquoted).
    pub wrap: String,
}

impl Case {
    /// A case running `automount ARGS` with an empty `/etc/autofs`.
    pub fn new(name: &str, args: &[&str]) -> Case {
        Case {
            name: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            etc: Vec::new(),
            setup: Vec::new(),
            env: Vec::new(),
            files: Vec::new(),
            wrap: String::new(),
        }
    }

    /// Run the program under `cmd`.
    pub fn wrap(mut self, cmd: &str) -> Case {
        self.wrap = format!("{cmd} ");
        self
    }

    /// Run the program as `nobody` (there is no `setpriv` on hydra).
    pub fn run_as_nobody(self) -> Case {
        self.wrap("python3 -c 'import os,sys; os.setgroups([]); os.setgid(65534); os.setuid(65534); os.execv(sys.argv[1], sys.argv[1:])'")
    }

    /// A `--dumpmaps` case.
    pub fn dump(name: &str) -> Case {
        Case::new(name, &["-m"])
    }

    pub fn setup(mut self, line: &str) -> Case {
        self.setup.push(line.to_string());
        self
    }

    /// A file in `/etc` (mode 0644).
    pub fn etc(self, path: &str, contents: &str) -> Case {
        self.etc_mode(path, contents.as_bytes(), 0o644)
    }

    pub fn etc_bytes(self, path: &str, contents: &[u8]) -> Case {
        self.etc_mode(path, contents, 0o644)
    }

    pub fn etc_mode(mut self, path: &str, contents: &[u8], mode: u32) -> Case {
        self.etc.push((path.to_string(), contents.to_vec(), mode));
        self
    }

    /// `/etc/autofs/NAME`.
    pub fn map(self, name: &str, contents: &str) -> Case {
        self.etc(&format!("autofs/{name}"), contents)
    }

    /// `/etc/autofs/auto.master`.
    pub fn master(self, contents: &str) -> Case {
        self.map("auto.master", contents)
    }

    /// `/etc/autofs/autofs.conf`.
    pub fn conf(self, contents: &str) -> Case {
        self.map("autofs.conf", contents)
    }

    pub fn env(mut self, kv: &str) -> Case {
        self.env.push(kv.to_string());
        self
    }

    pub fn args(mut self, args: &[&str]) -> Case {
        self.args = args.iter().map(|s| s.to_string()).collect();
        self
    }

    /// The same case under another name (each run needs its own directory).
    pub fn named(mut self, name: &str) -> Case {
        self.name = name.to_string();
        self
    }

    /// A file at `T/path` (`@T@/path` in the sandbox).
    pub fn file(mut self, path: &str, contents: &[u8]) -> Case {
        self.files.push((path.to_string(), contents.to_vec()));
        self
    }
}

/// Everything a run produced, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: String,
    pub stdout: String,
    pub stderr: String,
    pub syslog: Vec<String>,
    /// The `mount`, `umount` and `mount.nfs` command lines, in order.
    pub cmds: String,
    pub tmp: String,
    pub run: String,
    /// The tree under `/mnt` (mount points, browse directories).
    pub mnt: String,
}

/// One implementation's side of a case.
#[derive(Debug, Clone)]
pub struct Impl {
    pub label: &'static str,
    pub bin: PathBuf,
    pub env: Vec<String>,
    pub setup: Vec<String>,
}

fn cstr(s: impl AsRef<[u8]>) -> CString {
    CString::new(s.as_ref().to_vec()).unwrap()
}

fn path_c(p: &Path) -> CString {
    cstr(p.to_str().unwrap())
}

/// The invoking user's first subordinate id, from /etc/subuid or /etc/subgid.
fn subordinate(file: &str, name: &str, id: u32) -> u32 {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() == 3 && (f[0] == name || f[0] == id.to_string()) && f[2].parse::<u32>().unwrap_or(0) >= 65536 {
            return f[1].parse().unwrap();
        }
    }
    panic!("no subordinate range of 65536 ids for {name} in {file}: the sandbox needs one");
}

fn pipe() -> (c_int, c_int) {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for two ints.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    (fds[0], fds[1])
}

/// fork(); the child enters new user, mount, network, pid and UTS namespaces,
/// makes the binds, and forks pid 1 of the new pid namespace, which execs
/// `sh -c script`. The child exits with pid 1's status. Returns the child's pid.
///
/// Both the child and pid 1 have a parent-death signal of SIGKILL, so the
/// sandbox can't outlive the test.
fn spawn_in_sandbox(binds: &[(CString, CString)], script: &str, stdio: [c_int; 3]) -> u32 {
    // SAFETY: getuid/getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let name = std::env::var("USER").unwrap_or_default();
    let subuid = subordinate("/etc/subuid", &name, uid);
    let subgid = subordinate("/etc/subgid", &name, gid);

    let sh = cstr("/bin/sh");
    let argv_s = [cstr("sh"), cstr("-c"), cstr(script)];
    let mut argv: Vec<*const c_char> = argv_s.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let envp_s = [cstr("PATH=/usr/sbin:/usr/bin:/sbin:/bin"), cstr("LC_ALL=C")];
    let mut envp: Vec<*const c_char> = envp_s.iter().map(|a| a.as_ptr()).collect();
    envp.push(std::ptr::null());
    let (up_r, up_w) = pipe();
    let (go_r, go_w) = pipe();
    let root = cstr("/");
    let host = b"autotest";
    // SAFETY: getpid has no preconditions.
    let parent = unsafe { libc::getpid() };

    // SAFETY: between fork and exec the child only makes async-signal-safe
    // system calls on memory prepared above, then execs or _exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // SAFETY: as above.
        unsafe {
            libc::close(go_w);
            libc::close(up_r);
            let flags =
                libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWPID | libc::CLONE_NEWUTS;
            if libc::unshare(flags) != 0 {
                libc::_exit(120);
            }
            libc::write(up_w, b"u".as_ptr().cast(), 1);
            let mut b = [0u8; 1];
            if libc::read(go_r, b.as_mut_ptr().cast(), 1) != 1 {
                libc::_exit(121);
            }
            let none = std::ptr::null::<c_char>();
            if libc::mount(none, root.as_ptr(), none, libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) != 0 {
                libc::_exit(122);
            }
            for (src, dst) in binds {
                if libc::mount(src.as_ptr(), dst.as_ptr(), none, libc::MS_BIND | libc::MS_REC, std::ptr::null()) != 0 {
                    libc::_exit(123);
                }
            }
            if libc::setgid(0) != 0 || libc::setuid(0) != 0 {
                libc::_exit(124);
            }
            if libc::sethostname(host.as_ptr().cast(), host.len()) != 0 {
                libc::_exit(130);
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 || libc::getppid() != parent {
                libc::_exit(128);
            }
            let init = libc::fork();
            if init < 0 {
                libc::_exit(125);
            }
            if init == 0 {
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                    libc::_exit(129);
                }
                for (i, fd) in stdio.iter().enumerate() {
                    libc::dup2(*fd, i as c_int);
                }
                libc::execve(sh.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
            libc::close(up_w);
            let mut st: c_int = 0;
            libc::waitpid(init, &mut st, 0);
            libc::_exit(if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 126 });
        }
    }
    // SAFETY: closing our copies of the child's ends.
    unsafe {
        libc::close(go_r);
        libc::close(up_w);
    }
    let mut b = [0u8; 1];
    // SAFETY: reading one byte into b.
    let n = unsafe { libc::read(up_r, b.as_mut_ptr().cast(), 1) };
    assert_eq!(n, 1, "sandbox child failed before unshare");
    for (tool, host, sub) in [("newuidmap", uid, subuid), ("newgidmap", gid, subgid)] {
        let st = Command::new(tool)
            .arg(pid.to_string())
            .args(["0", &host.to_string(), "1", "1", &sub.to_string(), "65536"])
            .status()
            .unwrap_or_else(|e| panic!("{tool}: {e}"));
        assert!(st.success(), "{tool} failed");
    }
    // SAFETY: writing one byte from a static buffer, then closing.
    unsafe {
        libc::write(go_w, b"g".as_ptr().cast(), 1);
        libc::close(go_w);
        libc::close(up_r);
    }
    pid as u32
}

/// waitpid with a timeout; the status as text.
fn wait(pid: u32, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let mut st: c_int = 0;
        // SAFETY: st is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid as i32, &mut st, libc::WNOHANG) };
        if r == pid as i32 {
            return if libc::WIFEXITED(st) { format!("exit {}", libc::WEXITSTATUS(st)) } else { "killed".into() };
        }
        if Instant::now() > deadline {
            // SAFETY: killing and reaping our own child.
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
                libc::waitpid(pid as i32, &mut st, 0);
            }
            return "timeout".into();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Shell-quote a word.
fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The recorder that stands in for `/usr/bin/NAME`.
fn recorder(name: &str) -> String {
    format!(
        "#!/bin/sh\n\
         {{ printf '%s' {name}; for a in \"$@\"; do printf ' [%s]' \"$a\"; done; echo; }} >>\"$AUTOFS_TEST_ROOT/out/cmds\"\n\
         exec \"$AUTOFS_TEST_ROOT/real/{name}\" \"$@\"\n"
    )
}

/// The recorder for `p`, written once (to a temporary name, then renamed, so
/// no parallel test's fork() ever holds it open for writing) and shared.
fn recorder_file(p: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _l = LOCK.lock().unwrap();
    let dir = workspace_dir().join("target/difftest/.tools");
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join(format!("rec-{p}"));
    let text = recorder(p);
    if std::fs::read_to_string(&f).ok().as_deref() != Some(text.as_str()) {
        let tmp = dir.join(format!("rec-{p}.{}", std::process::id()));
        std::fs::write(&tmp, &text).unwrap();
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::rename(&tmp, &f).unwrap();
    }
    f
}

/// The pid-1 script.
fn script(case: &Case, imp: &Impl, r: &Path) -> String {
    let at_t = |a: &String| a.replace("@T@", r.to_str().unwrap());
    let r = r.display();
    let args: Vec<String> = case.args.iter().map(|a| q(&at_t(a))).collect();
    let env: Vec<String> = case.env.iter().chain(&imp.env).map(|a| q(&at_t(a))).collect();
    let mut s = format!(
        r#"set -u
R={r}
export AUTOFS_TEST_ROOT=$R
# The crash quirks leave their core files here, not in the test's directory.
mkdir -p "$R/cwd" && cd "$R/cwd" || exit 89
mount -t proc proc /proc || exit 90
mount -t tmpfs -o mode=755 tmpfs /run || exit 91
mount -t tmpfs -o mode=1777 tmpfs /tmp || exit 91
# Mount points for the cases live under /mnt.
mount -t tmpfs -o mode=755 tmpfs /mnt || exit 91
ip link set lo up || exit 92
# /etc: links to the host's files, then the case's own.
mkdir -p "$R/hostetc" && mount --bind /etc "$R/hostetc" || exit 93
mount -t tmpfs -o mode=755 tmpfs /etc || exit 94
for f in "$R"/hostetc/* "$R"/hostetc/.[!.]*; do
  [ -e "$f" ] || [ -L "$f" ] || continue
  case "${{f##*/}}" in autofs|conf.d) continue;; esac
  if [ -L "$f" ]; then cp -P "$f" /etc/; else ln -s "$f" /etc/; fi
done
mkdir -p /etc/autofs /etc/conf.d
(cd "$R/etc" && find . -type d | while read d; do mkdir -p "/etc/$d"; done
 find . -type f | while read f; do rm -f "/etc/$f"; cp -p "$f" "/etc/$f"; done) || exit 95
@IMPL_SETUP@
# The recorders.
for p in mount umount mount.nfs; do
  : >"$R/real/$p" && mount --bind "/usr/bin/$p" "$R/real/$p" && mount --bind "$R/bin/rec-$p" "/usr/bin/$p" || exit 96
done
"#
    );
    let imp_setup: String = imp.setup.iter().map(|l| at_t(l) + "\n").collect();
    s = s.replace("@IMPL_SETUP@\n", &imp_setup);
    for l in &case.setup {
        s.push_str(&at_t(l));
        s.push('\n');
    }
    s.push_str(": >\"$R/out/cmds\"\n");
    s.push_str(&format!(
        r#"(env {env} {wrap}"$R/bin/automount" {args}) >"$R/out/stdout" 2>"$R/out/stderr" </dev/null
echo "exit $?" >"$R/out/status"
(cd /tmp && find . -mindepth 1 | sort | while read f; do echo "$(stat -c '%A %U %G' "$f") $f"; done) >"$R/out/tmp" 2>&1
(cd /run && find . -mindepth 1 | sort | while read f; do echo "$(stat -c '%A %U %G' "$f") $f"; done) >"$R/out/run" 2>&1
(cd /mnt && find . -mindepth 1 | sort | while read f; do echo "$(stat -c '%A %U %G' "$f") $f"; done) >"$R/out/mnt" 2>&1
chown -R 0:0 "$R/out" 2>/dev/null
exit 0
"#,
        env = env.join(" "),
        wrap = case.wrap,
        args = args.join(" ")
    ));
    s
}

/// Remove a previous run's directory, from a sandbox if the host can't.
fn clean(t: &Path) {
    if !t.exists() || std::fs::remove_dir_all(t).is_ok() {
        return;
    }
    let null = std::fs::File::open("/dev/null").unwrap();
    use std::os::fd::AsRawFd;
    let fd = null.as_raw_fd();
    let script = format!("chown -R 0:0 {p} && chmod -R u+rwX {p}", p = q(t.to_str().unwrap()));
    let pid = spawn_in_sandbox(&[], &script, [fd, fd, fd]);
    wait(pid, Duration::from_secs(30));
    std::fs::remove_dir_all(t).unwrap_or_else(|e| panic!("can't clean {}: {e}", t.display()));
}

/// A syslog datagram, normalized: `<pri>` kept, the time stamp dropped, `[pid]`
/// replaced.
fn render_syslog(msg: &[u8]) -> String {
    let s = String::from_utf8_lossy(msg).to_string();
    let Some(end) = s.find('>') else { return s };
    let (pri, rest) = s.split_at(end + 1);
    let rest = rest.get(16..).unwrap_or(rest);
    let rest = match (rest.find('['), rest.find("]: ")) {
        (Some(a), Some(b)) if a < b => format!("{}[@PID@]{}", &rest[..a], &rest[b + 1..]),
        _ => rest.to_string(),
    };
    format!("{pri}{rest}")
}

fn read(t: &Path, f: &str) -> String {
    String::from_utf8_lossy(&std::fs::read(t.join(f)).unwrap_or_default()).to_string()
}

/// `mkdtemp()` names (`/tmp/autoXXXXXX`) as `/tmp/auto@N@`, numbered in order
/// of appearance.
fn normalize_tmp(s: &str, names: &mut Vec<String>) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(p) = rest.find("/tmp/auto") {
        out.push_str(&rest[..p]);
        let tail = &rest[p + 9..];
        let n: String = tail.chars().take(6).collect();
        if n.len() == 6 && n.chars().all(|c| c.is_ascii_alphanumeric()) {
            let idx = match names.iter().position(|x| *x == n) {
                Some(i) => i,
                None => {
                    names.push(n.clone());
                    names.len() - 1
                }
            };
            out.push_str(&format!("/tmp/auto@{idx}@"));
            rest = &tail[6..];
        } else {
            out.push_str("/tmp/auto");
            rest = tail;
        }
    }
    out.push_str(rest);
    out
}

/// Run one implementation of the case.
pub fn run(case: &Case, imp: &Impl) -> Outcome {
    use std::os::unix::fs::PermissionsExt;
    let label = imp.label;
    let base = workspace_dir().join("target/difftest").join(&case.name);
    let t = base.join(label);
    clean(&t);
    for d in ["bin", "out", "real", "etc"] {
        std::fs::create_dir_all(t.join(d)).unwrap();
    }
    // A hard link, not a copy: a copy is open for writing for a moment, and a
    // parallel test's fork() in that moment makes exec fail with ETXTBSY.
    let bin = imp.bin.canonicalize().unwrap();
    let dst = t.join("bin/automount");
    if std::fs::hard_link(&bin, &dst).is_err() {
        // Never copy onto an existing link: that would truncate the original.
        let _ = std::fs::remove_file(&dst);
        std::fs::copy(&bin, &dst).unwrap();
    }
    for p in ["mount", "umount", "mount.nfs"] {
        let src = recorder_file(p);
        std::fs::hard_link(&src, t.join(format!("bin/rec-{p}"))).unwrap();
    }
    let root_s = fixed_root().to_str().unwrap().to_string();
    for (p, c, mode) in &case.etc {
        let f = t.join("etc").join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        let c = String::from_utf8_lossy(c).replace("@T@", &root_s).into_bytes();
        std::fs::write(&f, &c).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(*mode)).unwrap();
    }
    for (p, c) in &case.files {
        let f = t.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(&f, c).unwrap();
    }
    let root = fixed_root();
    let mut binds = vec![(path_c(&t), path_c(&root))];
    let devlog = t.join("devlog");
    let log = UnixDatagram::bind(&devlog).unwrap();
    log.set_read_timeout(Some(Duration::from_millis(20))).unwrap();
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reader = {
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut got = Vec::new();
            let mut buf = vec![0u8; 65536];
            loop {
                match log.recv(&mut buf) {
                    Ok(n) => got.push(buf[..n].to_vec()),
                    Err(_) if stop.load(std::sync::atomic::Ordering::Relaxed) => break,
                    Err(_) => {}
                }
            }
            got
        })
    };
    binds.push((path_c(&devlog), cstr("/dev/log")));

    let err = std::fs::File::create(t.join("out/sandbox")).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    use std::os::fd::AsRawFd;
    let pid = spawn_in_sandbox(&binds, &script(case, imp, &root), [null.as_raw_fd(), err.as_raw_fd(), err.as_raw_fd()]);
    let st = wait(pid, Duration::from_secs(60));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
    let got = reader.join().unwrap();
    assert_eq!(st, "exit 0", "{}/{label}: sandbox {st}:\n{}", case.name, read(&t, "out/sandbox"));

    let mut names = Vec::new();
    let mut fix = |s: String| normalize_tmp(&s.replace(root.to_str().unwrap(), "@T@"), &mut names);
    Outcome {
        status: read(&t, "out/status").trim().to_string(),
        stdout: fix(read(&t, "out/stdout")),
        stderr: fix(read(&t, "out/stderr")),
        syslog: got.iter().map(|m| render_syslog(m)).collect::<Vec<_>>().into_iter().map(&mut fix).collect(),
        cmds: fix(read(&t, "out/cmds")),
        tmp: fix(read(&t, "out/tmp")),
        run: read(&t, "out/run"),
        mnt: read(&t, "out/mnt"),
    }
}

/// The C side: the reference daemon, its library and its modules.
pub fn c_impl() -> Impl {
    let lib = reference_file("lib/libautofs.so");
    let mods = reference_dir().join("modules");
    let mut setup =
        vec!["mkdir -p \"$R/cmod\" \"$R/clib\"".to_string(), format!("cp {} \"$R/clib/\"", q(lib.to_str().unwrap()))];
    for (name, target) in MODULES {
        match target {
            Some(t) => setup.push(format!("ln -s {t} \"$R/cmod/{name}\"")),
            None => setup.push(format!("cp {} \"$R/cmod/\"", q(mods.join(name).to_str().unwrap()))),
        }
    }
    setup.push("mount --bind \"$R/cmod\" /usr/lib64/autofs".to_string());
    Impl {
        label: "c",
        bin: reference_file("daemon/automount"),
        env: vec!["LD_LIBRARY_PATH=@T@/clib".to_string()],
        setup,
    }
}

/// Run `cmd` (a program and its arguments) and insist it works.
fn run_ok(cmd: &mut Command) {
    let st = cmd.status().unwrap_or_else(|e| panic!("{cmd:?}: {e}"));
    assert!(st.success(), "{cmd:?} failed");
}

/// The C driver (tests/drv/drv.c) linked with the reference daemon's objects,
/// and the recording mount modules (tests/drv/mount_fake.c), built once into
/// `target/difftest/.tools/cdrv/`.
fn c_driver_dir() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let dir = workspace_dir().join("target/difftest/.tools/cdrv");
            let tmp = workspace_dir().join(format!("target/difftest/.tools/cdrv.{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&tmp);
            std::fs::create_dir_all(tmp.join("mods")).unwrap();
            let r = reference_dir();
            let inc = format!("-I{}", r.join("include").display());
            run_ok(
                Command::new("objcopy")
                    .args(["--redefine-sym", "main=automount_real_main"])
                    .arg(r.join("daemon/automount.o"))
                    .arg(tmp.join("automount.o")),
            );
            let mut cc = Command::new("cc");
            cc.args([
                "-O2",
                "-D_GNU_SOURCE",
                "-D_REENTRANT",
                "-D_FILE_OFFSET_BITS=64",
                "-fPIE",
                "-pie",
                "-rdynamic",
                &inc,
                "-I/usr/include/tirpc",
                "-o",
            ])
            .arg(tmp.join("drv"))
            .arg(manifest_dir().join("tests/drv/drv.c"))
            .arg(tmp.join("automount.o"));
            for o in [
                "indirect",
                "direct",
                "spawn",
                "module",
                "mount",
                "master",
                "master_tok",
                "master_parse.tab",
                "lookup",
                "state",
                "flag",
            ] {
                cc.arg(r.join(format!("daemon/{o}.o")));
            }
            cc.arg(format!("-L{}", r.join("lib").display())).args(["-lautofs", "-ltirpc", "-ldl", "-lpthread"]);
            run_ok(&mut cc);
            for m in ["nfs", "bind", "generic", "autofs", "ext2", "afs", "changer"] {
                run_ok(
                    Command::new("cc")
                        .args([
                            "-O2",
                            "-shared",
                            "-fPIC",
                            "-D_GNU_SOURCE",
                            &inc,
                            "-I/usr/include/tirpc",
                            &format!("-DMODNAME=\"{m}\""),
                            "-o",
                        ])
                        .arg(tmp.join(format!("mods/mount_{m}.so")))
                        .arg(manifest_dir().join("tests/drv/mount_fake.c")),
                );
            }
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::rename(&tmp, &dir).unwrap();
            dir
        })
        .clone()
}

/// The C driver's side: the reference modules but the recording mount modules.
pub fn c_drv_impl() -> Impl {
    let mut c = c_impl();
    let d = c_driver_dir();
    c.bin = d.join("drv");
    for (name, target) in MODULES {
        if !name.starts_with("mount_") {
            continue;
        }
        let line = match target {
            Some(t) => format!("ln -s {t} \"$R/cmod/{name}\""),
            None => format!("cp {} \"$R/cmod/\"", q(mods_path(&d, name).to_str().unwrap())),
        };
        let real = match target {
            Some(_) => format!("ln -s {} \"$R/cmod/{name}\"", target.unwrap()),
            None => format!("cp {} \"$R/cmod/\"", q(reference_dir().join("modules").join(name).to_str().unwrap())),
        };
        if let Some(i) = c.setup.iter().position(|l| *l == real) {
            c.setup[i] = line;
        }
    }
    c.label = "c";
    c
}

fn mods_path(d: &Path, name: &str) -> PathBuf {
    d.join("mods").join(name)
}

/// The Rust driver's side.
pub fn r_drv_impl() -> Impl {
    Impl { label: "r", bin: PathBuf::from(env!("CARGO_BIN_EXE_automount-drv")), env: Vec::new(), setup: Vec::new() }
}

/// Run both drivers and compare; returns the C outcome.
pub fn check_drv(case: Case) -> Outcome {
    let c = run(&case, &c_drv_impl());
    let r = run(&case, &r_drv_impl());
    if std::env::var_os("AUTOFS_DIFF_SHOW").is_some() {
        eprintln!("=== {} ===\n{c:#?}", case.name);
    }
    compare(&case.name, &c, &r);
    c
}

/// The Rust side.
pub fn r_impl() -> Impl {
    Impl { label: "r", bin: rust_automount(), env: Vec::new(), setup: Vec::new() }
}

/// Run both and compare; returns the C outcome.
pub fn check(case: Case) -> Outcome {
    let c = run(&case, &c_impl());
    let r = run(&case, &r_impl());
    if std::env::var_os("AUTOFS_DIFF_SHOW").is_some() {
        eprintln!("=== {} ===\n{c:#?}", case.name);
    }
    compare(&case.name, &c, &r);
    c
}

fn compare(name: &str, c: &Outcome, r: &Outcome) {
    if c != r {
        let mut msg = format!("case {name} differs:\n");
        macro_rules! field {
            ($f:ident) => {
                if c.$f != r.$f {
                    msg.push_str(&format!("--- {}\n  C:    {:?}\n  Rust: {:?}\n", stringify!($f), c.$f, r.$f));
                }
            };
        }
        field!(status);
        field!(stdout);
        field!(stderr);
        field!(syslog);
        field!(cmds);
        field!(tmp);
        field!(run);
        field!(mnt);
        panic!("{msg}");
    }
}
