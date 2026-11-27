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

// ---------------------------------------------------------------------------
// External mounts and the amd mount list (`ext_mounts_hash`, `mnts_hash`).

pub const MNTS_INDIRECT: u32 = 0x0008;
pub const MNTS_AMD_MOUNT: u32 = 0x0040;
pub const MNTS_MOUNTED: u32 = 0x0080;

/// A `struct ext_mount`: a mount amd made outside the autofs file system.
#[derive(Debug)]
struct ExtMount {
    mp: Vec<u8>,
    umount: Option<Vec<u8>>,
    refs: u32,
}

static EXT_MOUNTS: std::sync::Mutex<Vec<ExtMount>> = std::sync::Mutex::new(Vec::new());

/// `ext_mount_add()`: count a use of the external mount at `path`.
pub fn ext_mount_add(path: &[u8], umount: Option<&[u8]>) -> bool {
    let mut g = EXT_MOUNTS.lock().unwrap();
    if let Some(em) = g.iter_mut().find(|e| cstr::eq(&e.mp, path)) {
        em.refs += 1;
        return true;
    }
    g.push(ExtMount { mp: cstr::c(path).to_vec(), umount: umount.map(|u| cstr::c(u).to_vec()), refs: 1 });
    true
}

/// `ext_mount_remove()`: true when the last use went.
pub fn ext_mount_remove(path: &[u8]) -> bool {
    let mut g = EXT_MOUNTS.lock().unwrap();
    let Some(i) = g.iter().position(|e| cstr::eq(&e.mp, path)) else { return false };
    g[i].refs -= 1;
    if g[i].refs != 0 {
        return false;
    }
    g.remove(i);
    true
}

/// `ext_mount_inuse()`: the external mount's use count.
pub fn ext_mount_inuse(path: &[u8]) -> u32 {
    EXT_MOUNTS.lock().unwrap().iter().find(|e| cstr::eq(&e.mp, path)).map_or(0, |e| e.refs)
}

/// A `struct mnt_list`, as far as amd mounts use it.
#[derive(Debug, Clone, Default)]
pub struct MntList {
    pub mp: Vec<u8>,
    pub refs: u32,
    pub flags: u32,
    pub ext_mp: Option<Vec<u8>>,
    pub amd_pref: Option<Vec<u8>>,
    pub amd_type: Option<Vec<u8>>,
    pub amd_opts: Option<Vec<u8>>,
    pub amd_cache_opts: u32,
    /// Whether it's on its autofs point's `amdmounts` list.
    pub on_amdmounts: bool,
}

static MNTS: std::sync::Mutex<Vec<MntList>> = std::sync::Mutex::new(Vec::new());

/// `mnts_get_mount()`: a reference to the entry for `mp`, made if needed.
fn mnts_get_mount(g: &mut Vec<MntList>, mp: &[u8]) -> usize {
    if let Some(i) = g.iter().position(|m| cstr::eq(&m.mp, mp) && m.refs != 0) {
        g[i].refs += 1;
        return i;
    }
    g.push(MntList { mp: cstr::c(mp).to_vec(), refs: 1, ..MntList::default() });
    g.len() - 1
}

fn mnts_put_mount(g: &mut Vec<MntList>, i: usize) {
    g[i].refs -= 1;
    if g[i].refs == 0 {
        g.remove(i);
    }
}

/// `mnts_add_amdmount()`: the entry's mount point, flagged as an amd mount.
pub fn mnts_add_amdmount(entry: &crate::modules::amd_parse::AmdEntry) -> Option<Vec<u8>> {
    let path = entry.path.as_deref()?;
    let mut g = MNTS.lock().unwrap();
    let i = mnts_get_mount(&mut g, path);
    let m = &mut g[i];
    m.ext_mp = entry.fs.clone();
    m.amd_pref = entry.pref.clone();
    m.amd_type = entry.ty.clone();
    m.amd_opts = entry.opts.clone();
    m.amd_cache_opts = entry.cache_opts;
    m.flags |= MNTS_AMD_MOUNT;
    m.on_amdmounts = true;
    Some(m.mp.clone())
}

/// `mnts_remove_amdmount()`.
pub fn mnts_remove_amdmount(mp: &[u8]) {
    let mut g = MNTS.lock().unwrap();
    let Some(i) = g.iter().position(|m| cstr::eq(&m.mp, mp) && m.refs != 0) else { return };
    if g[i].flags & MNTS_AMD_MOUNT == 0 {
        return;
    }
    let m = &mut g[i];
    m.flags &= !MNTS_AMD_MOUNT;
    m.on_amdmounts = false;
    m.ext_mp = None;
    m.amd_type = None;
    m.amd_pref = None;
    m.amd_opts = None;
    m.amd_cache_opts = 0;
    mnts_put_mount(&mut g, i);
}

/// `mnts_find_amdmount()`.
pub fn mnts_find_amdmount(path: &[u8]) -> Option<MntList> {
    let g = MNTS.lock().unwrap();
    g.iter().find(|m| cstr::eq(&m.mp, path) && m.refs != 0 && m.flags & MNTS_AMD_MOUNT != 0).cloned()
}

/// `mnts_add_mount()`.
pub fn mnts_add_mount(ap_path: &[u8], name: &[u8], flags: u32) {
    let mp = if name.first() == Some(&b'/') { cstr::c(name).to_vec() } else { [ap_path, b"/", cstr::c(name)].concat() };
    let mut g = MNTS.lock().unwrap();
    let i = mnts_get_mount(&mut g, &mp);
    g[i].flags |= flags;
}

/// `mnts_remove_mount()`.
pub fn mnts_remove_mount(mp: &[u8], flags: u32) {
    let mut g = MNTS.lock().unwrap();
    if let Some(i) = g.iter().position(|m| cstr::eq(&m.mp, mp) && m.refs != 0)
        && g[i].flags & flags != 0
    {
        g[i].flags &= !flags;
        mnts_put_mount(&mut g, i);
    }
}

/// `umount_ent()` (the daemon isn't shutting down here): unmount `path`; what
/// `is_mounted()` says afterwards.
pub fn umount_ent(logopt: u32, path: &[u8]) -> i32 {
    let _rv = crate::daemon::spawn::spawn_umount(logopt, &[path]);
    let mounted = is_mounted(path, MNTS_REAL);
    if !mounted {
        mnts_remove_mount(path, MNTS_MOUNTED);
    }
    mounted as i32
}

/// `umount_amd_ext_mount()`: drop a use of an external mount, unmounting it
/// (with its `umount` command if it has one) with the last.
pub fn umount_amd_ext_mount(ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>, path: &[u8]) -> i32 {
    let logopt = ap.logopt();
    let (mp, umount) = {
        let g = EXT_MOUNTS.lock().unwrap();
        match g.iter().find(|e| cstr::eq(&e.mp, path)) {
            None => return 1,
            Some(e) => (e.mp.clone(), e.umount.clone()),
        }
    };
    if let Some(umount) = umount {
        let Some((prog, argv)) = crate::libautofs::parse_subs::construct_argv(&umount) else { return 1 };
        if !ext_mount_remove(&mp) {
            return 0;
        }
        let rv = crate::daemon::spawn::spawnv(logopt, &prog, &argv);
        if rv == -1 || (libc::WIFEXITED(rv) && libc::WEXITSTATUS(rv) != 0) {
            error!(logopt, "umount_amd_ext_mount", "failed to umount program mount at {}", mp);
            return rv;
        }
        debug!(logopt, "umount_amd_ext_mount", "umounted program mount at {}", mp);
        let dev = ap.lock().dev;
        crate::daemon::automount::rmdir_path(ap, &mp, dev);
        return 0;
    }
    let mut rv = 1;
    if ext_mount_remove(&mp) {
        rv = umount_ent(logopt, &mp);
        if rv != 0 {
            error!(logopt, "umount_amd_ext_mount", "failed to umount external mount {}", mp);
        } else {
            debug!(logopt, "umount_amd_ext_mount", "umounted external mount {}", mp);
        }
    }
    rv
}
