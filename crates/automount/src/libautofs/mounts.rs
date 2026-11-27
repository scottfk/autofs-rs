//! `lib/mounts.c`: the parts used so far: `is_mounted()` over the kernel's
//! mount table (`local_getmntent_r()`), the kernel protocol probe the daemon
//! makes at startup (`query_kproto_ver()`), the per-request user variables
//! (`set_tsd_user_vars()`) and the standard macros made from them
//! (`addstdenv()`), and `mkdir_path()`.

use crate::libautofs::cstr;
use crate::sys;

pub const MNTS_ALL: u32 = 0x0001;
pub const MNTS_REAL: u32 = 0x0002;
pub const MNTS_AUTOFS: u32 = 0x0004;

/// A mount table line's fields, decoded (`local_decode_name()`).
#[derive(Debug, Clone)]
pub struct Mnt {
    pub fsname: Vec<u8>,
    pub dir: Vec<u8>,
    pub ty: Vec<u8>,
    pub opts: Vec<u8>,
}

/// `local_decode_name()`: `\040`, `\011`, `\012`, `\134` and `\\`.
fn decode_name(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        let r = &s[i..];
        if r.starts_with(b"\\040") {
            out.push(b' ');
            i += 4;
        } else if r.starts_with(b"\\011") {
            out.push(b'\t');
            i += 4;
        } else if r.starts_with(b"\\012") {
            out.push(b'\n');
            i += 4;
        } else if r.starts_with(b"\\\\") {
            out.push(b'\\');
            i += 2;
        } else if r.starts_with(b"\\134") {
            out.push(b'\\');
            i += 4;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    out
}

/// The kernel's mount table, as `local_getmntent_r()` reads it.
pub fn read_mount_table(path: &[u8]) -> Option<Vec<Mnt>> {
    let data = match sys::read_file(path) {
        Ok(d) => d,
        Err(e) => {
            logerr!("open_fopen_r", "211", "failed to open file: {}", sys::strerror(e));
            return None;
        }
    };
    let mut out = Vec::new();
    for line in data.split(|&b| b == b'\n') {
        let line = cstr::c(line);
        let mut end = line.len();
        while end > 0 && (line[end - 1] == b' ' || line[end - 1] == b'\t') {
            end -= 1;
        }
        let line = &line[..end];
        let start = line.iter().position(|&b| b != b' ' && b != b'\t').unwrap_or(line.len());
        let head = &line[start..];
        if head.is_empty() || head[0] == b'#' {
            continue;
        }
        let mut f = head.split(|&b| b == b' ' || b == b'\t').filter(|s| !s.is_empty());
        let mut next = || f.next().map(decode_name).unwrap_or_default();
        out.push(Mnt { fsname: next(), dir: next(), ty: next(), opts: next() });
    }
    Some(out)
}

/// `table_is_mounted()`.
fn table_is_mounted(mp: &[u8], ty: u32) -> bool {
    if sys::stat(mp).is_none() && sys::errno() == libc::ENOENT {
        return false;
    }
    let mp = cstr::c(mp);
    if mp.is_empty() || mp.len() >= libc::PATH_MAX as usize {
        return false;
    }
    let Some(tab) = read_mount_table(b"/proc/mounts") else { return false };
    for m in tab {
        if ty != 0 {
            let autofs_fs = m.ty == b"autofs";
            if ty & MNTS_REAL != 0 && autofs_fs {
                continue;
            }
            if ty & MNTS_AUTOFS != 0 && !autofs_fs {
                continue;
            }
        }
        if m.dir == mp {
            return true;
        }
    }
    false
}

/// `is_mounted()`. The `/dev/autofs` `ISMOUNTPOINT` ioctl needs `CAP_SYS_ADMIN`
/// in the initial user namespace; C falls back to the mount table without it,
/// and so does this until the daemon's ioctl layer arrives (phase 3).
pub fn is_mounted(mp: &[u8], ty: u32) -> bool {
    table_is_mounted(mp, ty)
}

/// `query_kproto_ver()`: mount a test autofs file system and ask its protocol
/// version. Without `CAP_SYS_ADMIN` the mount fails and so does this.
pub fn query_kproto_ver() -> bool {
    let Some(t_dir) = sys::mkdtemp(b"/tmp/autoXXXXXX") else { return false };
    let ok = sys::autofs_test_mount(&t_dir);
    sys::rmdir(&t_dir);
    ok
}

/// A `struct thread_stdenv_vars`: who asked for the mount.
#[derive(Debug, Clone, Default)]
pub struct Tsv {
    pub uid: u32,
    pub gid: u32,
    pub user: Option<Vec<u8>>,
    pub group: Option<Vec<u8>>,
    pub home: Option<Vec<u8>>,
}

thread_local! {
    /// `key_thread_stdenv_vars`.
    static TSV: std::cell::RefCell<Option<Tsv>> = const { std::cell::RefCell::new(None) };
}

/// The current thread's user variables.
pub fn tsv() -> Option<Tsv> {
    TSV.with(|t| t.borrow().clone())
}

/// `set_tsd_user_vars()`. Without a passwd entry the thread keeps what it had.
pub fn set_tsd_user_vars(logopt: u32, uid: u32, gid: u32) {
    let Some((user, home)) = sys::getpwuid(uid) else {
        error!(logopt, "set_tsd_user_vars", "failed to get passwd info from getpwuid_r");
        return;
    };
    let group = sys::getgrgid(gid);
    if group.is_none() {
        error!(logopt, "set_tsd_user_vars", "failed to get group info from getgrgid_r");
    }
    TSV.with(|t| *t.borrow_mut() = Some(Tsv { uid, gid, user: Some(user), group, home: Some(home) }));
}

const MAX_ENV_NAME: usize = 15;

fn env_name(prefix: Option<&[u8]>, name: &[u8]) -> Option<Vec<u8>> {
    let mut n = prefix.unwrap_or(b"").to_vec();
    n.extend_from_slice(name);
    if n.len() + 1 > MAX_ENV_NAME { None } else { Some(n) }
}

/// `addstdenv()`: `UID`, `GID`, `USER`, `GROUP`, `HOME` and `SHOST` (with
/// `prefix`), from the thread's user variables.
pub fn addstdenv(sv: &mut crate::libautofs::macros::Table, prefix: Option<&[u8]>) {
    use crate::libautofs::macros::{macro_addvar, macro_findvar};
    let Some(t) = tsv() else { return };
    let mut add = |name: &[u8], val: Option<&[u8]>| {
        if let Some(n) = env_name(prefix, name) {
            macro_addvar(sv, &n, n.len(), val);
        }
    };
    add(b"UID", Some(t.uid.to_string().as_bytes()));
    add(b"GID", Some(t.gid.to_string().as_bytes()));
    add(b"USER", t.user.as_deref());
    add(b"GROUP", t.group.as_deref());
    add(b"HOME", t.home.as_deref());
    if let Some(mv) = macro_findvar(sv, b"HOST", 4) {
        let mut shost = mv.val.clone();
        if let Some(d) = cstr::strchr(&shost, b'.') {
            shost.truncate(d);
        }
        if let Some(n) = env_name(prefix, b"SHOST") {
            macro_addvar(sv, &n, n.len(), Some(&shost));
        }
    }
}

/// `removestdenv()`.
pub fn removestdenv(sv: &mut crate::libautofs::macros::Table, prefix: Option<&[u8]>) {
    for name in [&b"UID"[..], b"USER", b"HOME", b"GID", b"GROUP", b"SHOST"] {
        if let Some(n) = env_name(prefix, name) {
            crate::libautofs::macros::macro_removevar(sv, &n, n.len());
        }
    }
}
