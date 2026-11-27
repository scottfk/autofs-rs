//! `lib/mounts.c`: `is_mounted()` (the `ISMOUNTPOINT` ioctl, or the kernel's
//! mount table through `local_getmntent_r()`), the kernel protocol probe,
//! the autofs mount options, the per-request user variables
//! (`set_tsd_user_vars()`) and the standard macros made from them
//! (`addstdenv()`), external mounts, and the mount lists the daemon keeps
//! (`mnts_hash`: what's mounted under each autofs point, amd mounts,
//! submounts).

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

/// `ioctl_is_mounted()`: the `ISMOUNTPOINT` ioctl, or the mount table when it
/// fails (it needs `CAP_SYS_ADMIN` in the initial user namespace).
fn ioctl_is_mounted(mp: &[u8], ty: u32) -> bool {
    match crate::libautofs::dev_ioctl::ismountpoint(-1, mp) {
        Some(Ok(mounted)) => {
            if mounted == 0 {
                return false;
            }
            match ty {
                MNTS_ALL => true,
                MNTS_AUTOFS => mounted & crate::libautofs::dev_ioctl::DEV_IOCTL_IS_AUTOFS != 0,
                MNTS_REAL => mounted & crate::libautofs::dev_ioctl::DEV_IOCTL_IS_OTHER != 0,
                _ => false,
            }
        }
        _ => table_is_mounted(mp, ty),
    }
}

/// `is_mounted()`.
pub fn is_mounted(mp: &[u8], ty: u32) -> bool {
    if crate::libautofs::dev_ioctl::has_version() { ioctl_is_mounted(mp, ty) } else { table_is_mounted(mp, ty) }
}

/// `struct kernel_mod_version`, from `query_kproto_ver()`.
static KVER: std::sync::Mutex<(u32, u32)> = std::sync::Mutex::new((0, 0));

pub fn get_kver_major() -> u32 {
    KVER.lock().unwrap().0
}

pub fn get_kver_minor() -> u32 {
    KVER.lock().unwrap().1
}

/// `linux_version_code()`.
pub fn linux_version_code() -> u32 {
    let rel = sys::uname_release();
    let mut it = rel.split(|&c| c == b'.').filter(|s| !s.is_empty());
    let kv = |p: u32, q: u32, r: u32| (p << 16) + (q << 8) + r.min(255);
    let Some(p) = it.next() else { return 0 };
    let p = cstr::atoi(p) as u32;
    let Some(q) = it.next() else { return kv(p, 0, 0) };
    let q = cstr::atoi(q) as u32;
    let Some(r) = it.next() else { return kv(p, q, 0) };
    kv(p, q, cstr::atoi(r) as u32)
}

/// `query_kproto_ver()`: mount a test autofs file system and ask its protocol
/// version and subversion. Without `CAP_SYS_ADMIN` the mount fails and so
/// does this.
pub fn query_kproto_ver() -> bool {
    use crate::libautofs::dev_ioctl as ops;
    let Some(t_dir) = sys::mkdtemp(b"/tmp/autoXXXXXX") else { return false };
    let Some(mnt) = sys::autofs_test_mount_keep(&t_dir) else {
        sys::rmdir(&t_dir);
        return false;
    };
    let (pipe_r, dev) = mnt;
    let cleanup = |close_ctl: bool| {
        sys::umount(&t_dir);
        sys::close(pipe_r);
        if close_ctl {
            ops::close_ioctl_ctl();
        }
        sys::rmdir(&t_dir);
    };
    let fd = match ops::open(dev, &t_dir) {
        Ok(fd) => fd,
        Err(_) => {
            cleanup(true);
            return false;
        }
    };
    ops::catatonic(fd);
    let Ok(major) = ops::protover(fd) else {
        ops::close(fd);
        cleanup(true);
        return false;
    };
    let Ok(minor) = ops::protosubver(fd) else {
        ops::close(fd);
        cleanup(true);
        return false;
    };
    *KVER.lock().unwrap() = (major, minor);
    ops::close(fd);
    cleanup(true);
    true
}

/// `open_ioctlfd()`.
pub fn open_ioctlfd(logopt: u32, path: &[u8], dev: u64) -> i32 {
    match crate::libautofs::dev_ioctl::open(dev, path) {
        Ok(fd) => fd,
        Err(e) => {
            if e == libc::ENOENT {
                return -1;
            }
            error!(logopt, "open_ioctlfd", "failed to open ioctlfd for {}, error: {}", path, sys::strerror(e));
            sys::set_errno(e);
            -1
        }
    }
}

const AUTOFS_MAX_PROTO_VERSION: u32 = 5;
pub const MOUNT_FLAG_STRICTEXPIRE: u32 = 0x0800;
pub const MOUNT_FLAG_IGNORE: u32 = 0x1000;

/// `cacl_max_options_len()`.
fn calc_max_options_len(flags: u32) -> usize {
    let (maj, min) = (get_kver_major(), get_kver_minor());
    let mut max_len = 79 + 1;
    if maj < 5 || (maj == 5 && min < 4) {
        return max_len;
    }
    if flags & MOUNT_FLAG_STRICTEXPIRE != 0 {
        max_len += 13;
    }
    if maj == 5 && min < 5 {
        return max_len;
    }
    if flags & MOUNT_FLAG_IGNORE != 0 {
        max_len += 7;
    }
    max_len
}

/// `make_options_string()`: the autofs mount options.
pub fn make_options_string(_path: &[u8], pipefd: i32, ty: Option<&str>, flags: u32) -> Vec<u8> {
    let (maj, min) = (get_kver_major(), get_kver_minor());
    let max_len = calc_max_options_len(flags);
    // SAFETY-free: getpgrp() via the sys layer.
    let pgrp = sys::getpgrp() as u32;
    let mut o = match ty {
        Some(t) => format!("fd={pipefd},pgrp={pgrp},minproto=5,maxproto={AUTOFS_MAX_PROTO_VERSION},{t}"),
        None => format!("fd={pipefd},pgrp={pgrp},minproto=5,maxproto={AUTOFS_MAX_PROTO_VERSION}"),
    }
    .into_bytes();
    let truncated = |mut o: Vec<u8>| {
        logerr!("make_options_string", "789", "buffer to small for options - truncated");
        o.truncate(max_len - 1);
        o
    };
    if o.len() >= max_len {
        return truncated(o);
    }
    if maj < 5 || (maj == 5 && min < 4) {
        return o;
    }
    if flags & MOUNT_FLAG_STRICTEXPIRE != 0 {
        o.extend_from_slice(b",strictexpire");
        if o.len() >= max_len {
            return truncated(o);
        }
    }
    if maj == 5 && min < 5 {
        return o;
    }
    if flags & MOUNT_FLAG_IGNORE != 0 {
        o.extend_from_slice(b",ignore");
        if o.len() >= max_len {
            return truncated(o);
        }
    }
    o
}

/// `mount_type_str()`.
pub fn mount_type_str(ty: u32) -> Option<&'static str> {
    const S: [&str; 3] = ["indirect", "direct", "offset"];
    let mut i = ty;
    for s in S {
        if i & 1 != 0 {
            return Some(s);
        }
        i >>= 1;
    }
    None
}

/// `notify_mount_result()`.
pub fn notify_mount_result(logopt: u32, runfreq: i64, path: &[u8], timeout: i64, ty: &str) {
    if timeout != 0 {
        info!(logopt, "mounted {} on {} with timeout {}, freq {} seconds", ty, path, timeout as u32, runfreq as u32);
    } else {
        info!(logopt, "mounted {} on {} with timeouts disabled", ty, path);
    }
}

pub const MNTS_DIRECT: u32 = 0x0010;
pub const MNTS_OFFSET: u32 = 0x0020;

/// An entry of `get_mnt_list()`.
#[derive(Debug, Clone)]
pub struct MntEnt {
    pub mp: Vec<u8>,
    pub flags: u32,
}

/// `get_mnt_list()`: the mounts at or under `path`, longest path first (later
/// lines first among equal lengths).
pub fn get_mnt_list(path: &[u8], include: bool) -> Option<Vec<MntEnt>> {
    let path = cstr::c(path);
    let pathlen = path.len();
    if pathlen == 0 || pathlen > libc::PATH_MAX as usize {
        return None;
    }
    let tab = read_mount_table(b"/proc/mounts")?;
    let mut list: Vec<MntEnt> = Vec::new();
    for m in tab {
        let len = m.dir.len();
        if (!include && len <= pathlen) || !m.dir.starts_with(path) {
            continue;
        }
        if pathlen > 1 && len > pathlen && m.dir[pathlen] != b'/' {
            continue;
        }
        let mut flags = 0;
        if m.ty == b"autofs" {
            flags |= MNTS_AUTOFS;
            if cstr::strstr(&m.opts, b"indirect").is_some() {
                flags |= MNTS_INDIRECT;
            } else if cstr::strstr(&m.opts, b"direct").is_some() {
                flags |= MNTS_DIRECT;
            } else if cstr::strstr(&m.opts, b"offset").is_some() {
                flags |= MNTS_OFFSET;
            }
        }
        let pos = list.iter().position(|e| len >= e.mp.len()).unwrap_or(list.len());
        list.insert(pos, MntEnt { mp: m.dir.clone(), flags });
    }
    if list.is_empty() {
        sys::set_errno(0);
        return None;
    }
    Some(list)
}

/// `unlink_mount_tree()`: detach whatever is mounted at or under `mp`.
pub fn unlink_mount_tree(logopt: u32, mp: &[u8]) -> bool {
    sys::set_errno(0);
    let Some(mnts) = get_mnt_list(mp, true) else {
        return sys::errno() == 0;
    };
    let mut ret = true;
    for mnt in mnts {
        let rv = if mnt.flags & MNTS_AUTOFS != 0 {
            sys::umount2(&mnt.mp, libc::MNT_DETACH)
        } else {
            crate::daemon::spawn::spawn_umount(logopt, &[b"-l", &mnt.mp])
        };
        if rv == -1 {
            debug!(logopt, "unlink_mount_tree", "can't unlink {} from mount tree", mnt.mp);
            match sys::errno() {
                libc::EINVAL => warn!(logopt, "bad superblock or not mounted"),
                libc::ENOENT | libc::EFAULT => {
                    ret = false;
                    warn!(logopt, "bad path for mount");
                }
                _ => {}
            }
        }
    }
    ret
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
    /// The autofs point whose `mounts` list it's on (its id; 0 for none), and
    /// when it was added there (the list is newest first).
    pub mount_ap: usize,
    pub mount_seq: u64,
    /// The submount it is (`MNTS_AUTOFS`).
    pub sub_ap: Option<std::sync::Weak<crate::daemon::master::AutofsPoint>>,
    /// When it went on its parent's `submounts` list (0: not on it).
    pub sub_seq: u64,
}

static MOUNT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

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

/// For a new amd submount: its amd mount's `pref` (taken: `mnt->amd_pref =
/// NULL`) and cache options.
pub fn mnts_take_amd_pref(path: &[u8]) -> Option<(Option<Vec<u8>>, u32)> {
    let mut g = MNTS.lock().unwrap();
    let m = g.iter_mut().find(|m| cstr::eq(&m.mp, path) && m.refs != 0 && m.flags & MNTS_AMD_MOUNT != 0)?;
    Some((m.amd_pref.take(), m.amd_cache_opts))
}

/// `mnts_find_amdmount()`.
pub fn mnts_find_amdmount(path: &[u8]) -> Option<MntList> {
    let g = MNTS.lock().unwrap();
    g.iter().find(|m| cstr::eq(&m.mp, path) && m.refs != 0 && m.flags & MNTS_AMD_MOUNT != 0).cloned()
}

/// `mnts_add_mount()`: `name` (under the autofs point unless absolute) with
/// `flags`, on the point's mounted list if it's `MNTS_MOUNTED`.
pub fn mnts_add_mount(ap: &crate::daemon::master::AutofsPoint, name: &[u8], flags: u32) -> Option<Vec<u8>> {
    let mp = if name.first() == Some(&b'/') {
        cstr::c(name).to_vec()
    } else {
        [&ap.path()[..], b"/", cstr::c(name)].concat()
    };
    let mut g = MNTS.lock().unwrap();
    let i = mnts_get_mount(&mut g, &mp);
    let m = &mut g[i];
    m.flags |= flags;
    if m.flags & MNTS_MOUNTED != 0 && m.mount_ap == 0 {
        m.mount_ap = ap.id;
        m.mount_seq = MOUNT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    Some(m.mp.clone())
}

/// `mnts_remove_mount()`.
pub fn mnts_remove_mount(mp: &[u8], flags: u32) {
    let mut g = MNTS.lock().unwrap();
    if let Some(i) = g.iter().position(|m| cstr::eq(&m.mp, mp) && m.refs != 0)
        && g[i].flags & flags != 0
    {
        g[i].flags &= !flags;
        if g[i].flags & MNTS_MOUNTED == 0 {
            g[i].mount_ap = 0;
        }
        mnts_put_mount(&mut g, i);
    }
}

/// `mnts_set_mounted_mount()`.
pub fn mnts_set_mounted_mount(ap: &crate::daemon::master::AutofsPoint, name: &[u8], flags: u32) {
    if mnts_add_mount(ap, name, flags).is_none() {
        error!(ap.logopt(), "mnts_set_mounted_mount", "failed to add mount {} to mounted list", name);
    }
}

/// `mnts_has_mounted_mounts()`.
pub fn mnts_has_mounted_mounts(ap: &crate::daemon::master::AutofsPoint) -> bool {
    MNTS.lock().unwrap().iter().any(|m| m.mount_ap == ap.id)
}

/// `mnts_get_expire_list()`: the point's mounted mounts, longest path first
/// (ties: the one mounted first), without paths ending in `/` (C builds a
/// tree ordered by length and lists it in order, each at the head).
pub fn mnts_get_expire_list(ap: &crate::daemon::master::AutofsPoint) -> Vec<MntList> {
    let g = MNTS.lock().unwrap();
    // The point's list, newest first, as C walks it.
    let mut l: Vec<MntList> =
        g.iter().filter(|m| m.mount_ap == ap.id && m.flags & MNTS_MOUNTED != 0).cloned().collect();
    l.sort_by_key(|a| std::cmp::Reverse(a.mount_seq));
    // In-order of the tree: by length, ties in insertion (list) order.
    l.sort_by_key(|m| m.mp.len());
    l.retain(|m| m.mp.last() != Some(&b'/'));
    l.reverse();
    l
}

/// `mnts_find_submount()`: the submount mounted at `path`.
pub fn mnts_find_submount(path: &[u8]) -> Option<std::sync::Arc<crate::daemon::master::AutofsPoint>> {
    let g = MNTS.lock().unwrap();
    g.iter()
        .find(|m| cstr::eq(&m.mp, path) && m.refs != 0 && m.flags & MNTS_AUTOFS != 0)
        .and_then(|m| m.sub_ap.as_ref().and_then(|w| w.upgrade()))
}

/// Whether a submount is mounted at `path` (`mnts_find_submount() != NULL`).
pub fn mnts_is_submount(path: &[u8]) -> bool {
    let g = MNTS.lock().unwrap();
    g.iter().any(|m| cstr::eq(&m.mp, path) && m.refs != 0 && m.flags & MNTS_AUTOFS != 0)
}

/// `mnts_remove_submount()`.
pub fn mnts_remove_submount(mp: &[u8]) {
    let mut g = MNTS.lock().unwrap();
    if let Some(i) = g.iter().position(|m| cstr::eq(&m.mp, mp) && m.refs != 0)
        && g[i].flags & MNTS_AUTOFS != 0
    {
        g[i].flags &= !MNTS_AUTOFS;
        g[i].sub_ap = None;
        g[i].sub_seq = 0;
        mnts_put_mount(&mut g, i);
    }
}

/// The submounts whose parent is `ap` (`ap->submounts`), in list order.
pub fn mnts_submounts_of(
    ap: &crate::daemon::master::AutofsPoint,
) -> Vec<std::sync::Arc<crate::daemon::master::AutofsPoint>> {
    let g = MNTS.lock().unwrap();
    let mut v: Vec<(u64, std::sync::Arc<crate::daemon::master::AutofsPoint>)> = g
        .iter()
        .filter(|m| m.sub_seq != 0)
        .filter_map(|m| m.sub_ap.as_ref().and_then(|w| w.upgrade()).map(|s| (m.sub_seq, s)))
        .filter(|(_, s)| s.parent.as_ref().is_some_and(|p| p.id == ap.id))
        .collect();
    v.sort_by_key(|(q, _)| *q);
    v.into_iter().map(|(_, s)| s).collect()
}

/// `mnt_find_submount_by_devid()`: depth first through `ap`'s submounts.
pub fn mnt_find_submount_by_devid(
    ap: &crate::daemon::master::AutofsPoint,
    devid: u64,
) -> Option<std::sync::Arc<crate::daemon::master::AutofsPoint>> {
    for s in mnts_submounts_of(ap) {
        if s.lock().dev == devid {
            return Some(s);
        }
        if let Some(f) = mnt_find_submount_by_devid(&s, devid) {
            return Some(f);
        }
    }
    None
}

/// `mnts_add_submount()`: the submount's entry, holding a reference, and on
/// its parent's list; `None` on an owner conflict.
pub fn mnts_add_submount(ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>) -> bool {
    let path = ap.path();
    let mut g = MNTS.lock().unwrap();
    let i = mnts_get_mount(&mut g, &path);
    match g[i].sub_ap.as_ref().and_then(|w| w.upgrade()) {
        None => g[i].sub_ap = Some(std::sync::Arc::downgrade(ap)),
        Some(o) => {
            let same_parent = match (&o.parent, &ap.parent) {
                (Some(a), Some(b)) => a.id == b.id,
                (None, None) => true,
                _ => false,
            };
            if o.id != ap.id || !same_parent {
                mnts_put_mount(&mut g, i);
                drop(g);
                error!(ap.logopt(), "mnts_add_submount", "conflict with submount owner: {}", path);
                return false;
            }
        }
    }
    g[i].flags |= MNTS_AUTOFS;
    if g[i].sub_seq == 0 {
        g[i].sub_seq = MOUNT_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    true
}

/// `umount_ent()` (the daemon isn't shutting down here): unmount `path`; what
/// `is_mounted()` says afterwards.
pub fn umount_ent(logopt: u32, path: &[u8]) -> i32 {
    umount_ent_state(logopt, path, crate::daemon::state::ST_INIT)
}

/// `umount_ent()` for a point in `state`: a forced shutdown unmounts lazily,
/// and a shutdown checks that the mount really went.
pub fn umount_ent_state(logopt: u32, path: &[u8], state: i32) -> i32 {
    use crate::daemon::state::{ST_SHUTDOWN, ST_SHUTDOWN_FORCE};
    let rv = if state != ST_SHUTDOWN_FORCE {
        crate::daemon::spawn::spawn_umount(logopt, &[path])
    } else {
        info!(logopt, "forcing umount of {}", path);
        crate::daemon::spawn::spawn_umount(logopt, &[b"-l", path])
    };
    let mut mounted = is_mounted(path, MNTS_REAL) as i32;
    if rv != 0 && (state == ST_SHUTDOWN_FORCE || state == ST_SHUTDOWN) && mounted != 0 {
        crit!(
            logopt,
            "umount_ent",
            "the umount binary reported that {} was unmounted, but there is still something mounted on this path.",
            path
        );
        mounted = -1;
    }
    if mounted == 0 {
        mnts_remove_mount(path, MNTS_MOUNTED);
    }
    mounted
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
        let state = ap.lock().state;
        rv = umount_ent_state(logopt, &mp, state);
        if rv != 0 {
            error!(logopt, "umount_amd_ext_mount", "failed to umount external mount {}", mp);
        } else {
            debug!(logopt, "umount_amd_ext_mount", "umounted external mount {}", mp);
        }
    }
    rv
}

const REMOUNT_SUCCESS: i32 = 0;
const REMOUNT_FAIL: i32 = 1;
const REMOUNT_OPEN_FAIL: i32 = 2;
const REMOUNT_STAT_FAIL: i32 = 4;
const REMOUNT_READ_MAP: i32 = 8;

/// `do_remount_indirect()`: reconnect to the mounts in a mount tree the daemon
/// finds already mounted.
fn do_remount_indirect(ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>, fd: i32, path: &[u8]) -> i32 {
    use crate::libautofs::dev_ioctl as ops;
    let logopt = ap.logopt();
    let mut status = REMOUNT_SUCCESS;
    let Some(names) = sys::scandir_alpha(path) else { return -1 };
    for name in names.iter().rev() {
        if name == b"." || name == b".." {
            continue;
        }
        let Some(buf) = crate::libautofs::cat_path::cat_path(4096 + 1, path, name) else { return -1 };
        let mounted = ops::ismountpoint(-1, &buf).and_then(|r| r.ok()).unwrap_or(0);
        if mounted == 0 {
            match sys::scandir_alpha(&buf) {
                None => continue,
                Some(n) if n.len() <= 2 => continue,
                _ => {}
            }
        }
        if let Some(Ok((uid, gid))) = ops::requester(fd, &buf)
            && uid != u32::MAX
            && gid != u32::MAX
        {
            set_tsd_user_vars(logopt, uid, gid);
        }
        if crate::daemon::lookup::lookup_nss_mount(ap, None, name) {
            mnts_set_mounted_mount(ap, &buf, MNTS_INDIRECT | MNTS_MOUNTED);
            info!(logopt, "re-connected to {}", buf);
            let rf = ap.lock().exp_runfreq;
            crate::libautofs::alarm::conditional_alarm_add(ap, rf);
        } else {
            status = REMOUNT_FAIL;
            info!(logopt, "failed to re-connect {}", buf);
        }
    }
    status
}

/// `do_remount_direct()`.
fn do_remount_direct(ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>, ty: u32, fd: i32, path: &[u8]) -> i32 {
    use crate::libautofs::dev_ioctl as ops;
    let logopt = ap.logopt();
    if let Some(Ok((uid, gid))) = ops::requester(fd, path)
        && uid != u32::MAX
        && gid != u32::MAX
    {
        set_tsd_user_vars(logopt, uid, gid);
    }
    if crate::daemon::lookup::lookup_nss_mount(ap, None, path) {
        let mut flags = MNTS_DIRECT | MNTS_MOUNTED;
        if ty == crate::libautofs::dev_ioctl::AUTOFS_TYPE_OFFSET {
            flags |= MNTS_OFFSET;
        }
        mnts_set_mounted_mount(ap, path, flags);
        info!(logopt, "re-connected to {}", path);
        let rf = ap.lock().exp_runfreq;
        crate::libautofs::alarm::conditional_alarm_add(ap, rf);
        REMOUNT_SUCCESS
    } else {
        info!(logopt, "failed to re-connect {}", path);
        REMOUNT_FAIL
    }
}

/// `remount_active_mount()`.
fn remount_active_mount(
    ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>,
    me: Option<(&Mc, u64)>,
    path: &[u8],
    devid: u64,
    ty: u32,
    ioctlfd: &mut i32,
) -> i32 {
    use crate::libautofs::dev_ioctl as ops;
    use crate::libautofs::dev_ioctl::AUTOFS_TYPE_INDIRECT;
    let logopt = ap.logopt();
    let str_type = mount_type_str(ty).unwrap_or("");
    *ioctlfd = -1;
    let fd = open_ioctlfd(logopt, path, devid);
    if fd == -1 {
        return REMOUNT_OPEN_FAIL;
    }
    let source = me
        .and_then(|(mc, id)| me_get(mc, id, |e| e.source))
        .and_then(|sid| crate::daemon::master::find_source(ap, sid));
    let timeout = crate::daemon::master::get_exp_timeout(ap, source.as_deref());
    if ap.lock().state == crate::daemon::state::ST_READMAP {
        debug!(logopt, "remount_active_mount", "already mounted, update timeout");
        ops::timeout(fd, timeout);
        ops::close(fd);
        return REMOUNT_READ_MAP;
    }
    debug!(logopt, "remount_active_mount", "trying to re-connect to mount {}", path);
    let fail = |msg: Vec<u8>, ret: i32| {
        crate::libautofs::log::log_error(logopt, &msg);
        debug!(logopt, "remount_active_mount", "couldn't re-connect to mount {}", path);
        ops::close(fd);
        ret
    };
    if ops::catatonic(fd) == -1 {
        let e = sys::strerror(sys::errno());
        return fail(bfmt!("remount_active_mount: set catatonic failed: {}", e), REMOUNT_OPEN_FAIL);
    }
    let kpipefd = ap.lock().kpipefd;
    if ops::setpipefd(fd, kpipefd) == Some(-1) {
        let e = sys::strerror(sys::errno());
        return fail(bfmt!("remount_active_mount: set pipefd failed: {}", e), REMOUNT_OPEN_FAIL);
    }
    ops::timeout(fd, timeout);
    let Some(st) = sys::fstat(fd) else {
        return fail(bfmt!("remount_active_mount: failed to stat {} mount {}", str_type, path), REMOUNT_STAT_FAIL);
    };
    if ty == AUTOFS_TYPE_INDIRECT {
        ap.lock().dev = st.st_dev;
    } else {
        let (mc, id) = me.expect("direct mount entry");
        let key = me_get(mc, id, |e| e.key.clone()).unwrap_or_default();
        if !cstr::eq(path, &key) {
            return fail(
                bfmt!("remount_active_mount: mount point path mismatch, path {} mapent {}", path, key),
                REMOUNT_STAT_FAIL,
            );
        }
        let mut c = mc.lock();
        if let Some(p) = c.by_id(id) {
            c.get_mut(p).dev = st.st_dev;
            c.get_mut(p).ino = st.st_ino;
            c.set_ino_index(p);
        }
    }
    let rf = ap.lock().exp_runfreq;
    notify_mount_result(logopt, rf, path, timeout, str_type);
    *ioctlfd = fd;
    let mounted = match ops::ismountpoint(fd, path) {
        Some(Ok(m)) => m,
        Some(Err(e)) => {
            return fail(
                bfmt!("remount_active_mount: ismountpoint {} failed: {}", path, sys::strerror(e)),
                REMOUNT_FAIL,
            );
        }
        None => 0,
    };
    if mounted == 0 {
        // Only an indirect mount keeps its descriptor without a mount.
        if ty != AUTOFS_TYPE_INDIRECT {
            ops::close(fd);
            *ioctlfd = -1;
        }
    } else if ty == AUTOFS_TYPE_INDIRECT {
        do_remount_indirect(ap, fd, path);
    } else {
        do_remount_direct(ap, ty, fd, path);
    }
    debug!(logopt, "remount_active_mount", "re-connected to mount {}", path);
    REMOUNT_SUCCESS
}

/// `try_remount()`: 1 when the mount is reconnected (or a map reread found
/// it), 0 when it's mounted but can't be, -1 (with `errno`) when there's no
/// mount.
pub fn try_remount(ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>, me: Option<(&Mc, u64)>, ty: u32) -> i32 {
    use crate::daemon::master::{MOUNT_FLAG_DIR_CREATED, MOUNT_FLAG_GHOST};
    use crate::libautofs::dev_ioctl::{AUTOFS_TYPE_INDIRECT, AUTOFS_TYPE_OFFSET};
    let logopt = ap.logopt();
    let path = if ty == AUTOFS_TYPE_INDIRECT {
        ap.path()
    } else {
        let (mc, id) = me.expect("direct mount entry");
        me_get(mc, id, |e| e.key.clone()).unwrap_or_default()
    };
    let (ret, devid) = crate::libautofs::dev_ioctl::mount_device(&path, ty);
    if ret == -1 || ret == 0 {
        return -1;
    }
    let mut fd = -1;
    let ret = remount_active_mount(ap, me, &path, devid, ty, &mut fd);
    if ty == AUTOFS_TYPE_INDIRECT {
        // A nobrowse mount point directory is removed at umount anyway.
        let mut a = ap.lock();
        if a.flags & MOUNT_FLAG_GHOST != 0 {
            a.flags &= !MOUNT_FLAG_DIR_CREATED;
        } else {
            a.flags |= MOUNT_FLAG_DIR_CREATED;
        }
    } else {
        let (mc, id) = me.unwrap();
        me_set(mc, id, |e| e.flags &= !MOUNT_FLAG_DIR_CREATED);
        // The multi-mount's parent for an offset (MM_PARENT), else the entry.
        let pid = me_get(mc, id, |e| if e.is_mm() { e.mm_parent.unwrap_or(e.id) } else { e.id }).unwrap_or(id);
        let pkey = me_get(mc, pid, |e| e.key.clone()).unwrap_or_default();
        let mounted = if pkey.first() == Some(&b'/') {
            is_mounted(&pkey, MNTS_REAL)
        } else {
            match mount_fullpath(4096, &ap.path(), &pkey) {
                Some(mp) => is_mounted(&mp, MNTS_REAL),
                None => {
                    error!(logopt, "try_remount", "mountpoint path too long");
                    return 0;
                }
            }
        };
        if !mounted {
            me_set(mc, id, |e| e.flags |= MOUNT_FLAG_DIR_CREATED);
        }
    }
    if ret == REMOUNT_READ_MAP {
        return 1;
    }
    if ret == REMOUNT_SUCCESS {
        if fd != -1 {
            if ty == AUTOFS_TYPE_INDIRECT {
                ap.lock().ioctlfd = fd;
            } else {
                let (mc, id) = me.unwrap();
                let key = me_get(mc, id, |e| e.key.clone()).unwrap_or_default();
                if ty == AUTOFS_TYPE_OFFSET && !is_mounted(&key, MNTS_REAL) {
                    crate::libautofs::dev_ioctl::close(fd);
                    fd = -1;
                }
                me_set(mc, id, |e| e.ioctlfd = fd);
            }
            return 1;
        }
        if ty != AUTOFS_TYPE_INDIRECT {
            return 1;
        }
    }
    0
}

/// `try_remount()` for the indirect mount itself.
pub fn try_remount_indirect(ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>) -> i32 {
    try_remount(ap, None, crate::libautofs::dev_ioctl::AUTOFS_TYPE_INDIRECT)
}

/// `set_mount_catatonic()`: the point's own mount, or an entry's (`me`).
pub fn set_mount_catatonic_me(ap: &crate::daemon::master::AutofsPoint, me: Option<(&Mc, u64)>, ioctlfd: i32) -> i32 {
    use crate::libautofs::dev_ioctl as ops;
    let logopt = ap.logopt();
    let (mut path, mut dev) = {
        let a = ap.lock();
        (a.path.clone(), a.dev)
    };
    let mut me_fd = -1;
    if let Some((mc, id)) = me
        && let Some((k, d, fd)) = me_get(mc, id, |e| (e.key.clone(), e.dev, e.ioctlfd))
    {
        if ap.ty() == crate::daemon::master::LKP_DIRECT || k.first() == Some(&b'/') {
            path = k;
            dev = d;
        }
        me_fd = fd;
    }
    let mut opened = false;
    let fd = if ioctlfd >= 0 {
        ioctlfd
    } else if me.is_some() && me_fd >= 0 {
        me_fd
    } else {
        let fd = open_ioctlfd(logopt, &path, dev);
        if fd == -1 {
            let e = sys::errno();
            return if e == libc::ENOENT { 0 } else { e };
        }
        opened = true;
        fd
    };
    let mut err = ops::catatonic(fd);
    if err == -1 {
        err = sys::errno();
        error!(logopt, "set_mount_catatonic", "failed to set {} catatonic, error: {}", path, sys::strerror(err));
    } else {
        debug!(logopt, "set_mount_catatonic", "set {} catatonic", path);
    }
    if opened {
        ops::close(fd);
    }
    err
}

fn set_mount_catatonic(ap: &crate::daemon::master::AutofsPoint) -> i32 {
    set_mount_catatonic_me(ap, None, -1)
}

/// `set_offset_tree_catatonic()`: every node of the multi-mount's tree.
pub fn set_offset_tree_catatonic(ap: &Ap, mc: &Mc, root: u64) {
    fn walk(ap: &Ap, mc: &Mc, n: u64) {
        let Some((l, r, fd)) = me_get(mc, n, |e| (e.left, e.right, e.ioctlfd)) else { return };
        if let Some(l) = l {
            walk(ap, mc, l);
        }
        set_mount_catatonic_me(ap, Some((mc, n)), fd);
        if let Some(r) = r {
            walk(ap, mc, r);
        }
    }
    walk(ap, mc, root);
}

/// `set_indirect_mount_tree_catatonic()`: so nothing hangs on the mounts once
/// the daemon has gone.
pub fn set_indirect_mount_tree_catatonic(ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>) {
    if !is_mounted(&ap.path(), MNTS_AUTOFS) {
        return;
    }
    for map in ap.entry().maps() {
        let mc = map.mc();
        let roots: Vec<u64> = {
            let c = mc.lock();
            let mut out = Vec::new();
            let mut p = c.enumerate(None);
            while let Some(q) = p {
                let e = c.get(q);
                // Skip negative and wildcard entries; only offsets need it.
                if e.mapent.is_some() && e.key != b"*" && e.is_mm_root() {
                    out.push(e.id);
                }
                p = c.enumerate(Some(q));
            }
            out
        };
        for r in roots {
            set_offset_tree_catatonic(ap, &mc, r);
        }
    }
    // ap->ioctlfd is closed by now.
    set_mount_catatonic(ap);
}

/// `mount_fullpath()`: the mount point for `name` under `root`; `None` (C's 0)
/// if it doesn't fit in `max_len`.
pub fn mount_fullpath(max_len: usize, root: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    let root = cstr::c(root);
    let name = cstr::c(name);
    // A multi-mount's root offset, or a direct or offset mount: the root (or
    // the name) is the whole path.
    let p = if root.last() == Some(&b'/') {
        root.to_vec()
    } else if name.first() == Some(&b'/') {
        name.to_vec()
    } else {
        [root, b"/", name].concat()
    };
    if p.len() >= max_len {
        return None;
    }
    Some(p)
}

// ---------------------------------------------------------------------------
// Multi-mount offset trees (`tree_mapent_*`). The tree is a binary search
// tree of cache entries linked by id (`left`, `right`); `mm_root` is the
// multi-mount's owner and `mm_parent` an offset's nesting point. The cache
// lock is only held for each read or change, as the work functions mount and
// unmount (and look entries up again) in between.

use crate::libautofs::cache::Cache;

type Mc = std::sync::Arc<Cache>;
type Ap = std::sync::Arc<crate::daemon::master::AutofsPoint>;

/// An entry's fields the tree code needs, by id.
fn me_get<T>(mc: &Mc, id: u64, f: impl FnOnce(&crate::libautofs::cache::Mapent) -> T) -> Option<T> {
    let c = mc.lock();
    c.by_id(id).map(|p| f(c.get(p)))
}

fn me_set(mc: &Mc, id: u64, f: impl FnOnce(&mut crate::libautofs::cache::Mapent)) {
    let mut c = mc.lock();
    if let Some(p) = c.by_id(id) {
        f(c.get_mut(p));
    }
}

/// `tree_mapent_cmp(n, me)`: a key below another sorts after it.
fn tree_mapent_cmp(n_key: &[u8], key: &[u8]) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    if cstr::neq(key, n_key, n_key.len()) {
        if key.len() < n_key.len() {
            return Less;
        } else if key.len() > n_key.len() {
            return Greater;
        }
    }
    cstr::c(key).cmp(cstr::c(n_key))
}

/// `tree_mapent_root()`: make the entry the root of its own tree.
pub fn tree_mapent_root(c: &mut crate::libautofs::cache::CacheInner, p: crate::libautofs::cache::Pos) {
    let e = c.get_mut(p);
    e.left = None;
    e.right = None;
    e.mm_root = Some(e.id);
}

/// `tree_mapent_add_node()`.
pub fn tree_mapent_add_node(c: &mut crate::libautofs::cache::CacheInner, root: u64, me: u64) -> bool {
    let Some(mp) = c.by_id(me) else { return false };
    let key = c.get(mp).key.clone();
    let mut cur = root;
    loop {
        let Some(np) = c.by_id(cur) else { return false };
        let ord = tree_mapent_cmp(&c.get(np).key.clone(), &key);
        use std::cmp::Ordering::*;
        match ord {
            Equal => break,
            Less => match c.get(np).left {
                Some(l) => cur = l,
                None => {
                    c.get_mut(np).left = Some(me);
                    let e = c.get_mut(mp);
                    e.left = None;
                    e.right = None;
                    break;
                }
            },
            Greater => match c.get(np).right {
                Some(r) => cur = r,
                None => {
                    c.get_mut(np).right = Some(me);
                    let e = c.get_mut(mp);
                    e.left = None;
                    e.right = None;
                    break;
                }
            },
        }
    }
    let parent = c.get_offset_parent(&key).map(|p| c.get(p).id).unwrap_or(root);
    let Some(mp) = c.by_id(me) else { return false };
    let e = c.get_mut(mp);
    e.mm_root = Some(root);
    e.mm_parent = Some(parent);
    true
}

/// `tree_mapent_is_root()`: the multi-mount's owner or its `/` offset.
fn tree_mapent_is_root(mc: &Mc, id: u64) -> bool {
    me_get(mc, id, |e| e.key.last() == Some(&b'/') || e.mm_root == Some(e.id)).unwrap_or(false)
}

/// `tree_mapent_traverse_subtree()`: `work` on the offsets nested directly in
/// `base`, in order; the last result (-1 when there was none).
fn traverse_subtree(mc: &Mc, n: u64, base: u64, strict: bool, work: &mut dyn FnMut(u64) -> i32) -> i32 {
    let mut ret = -1;
    let (left, right, parent) = match me_get(mc, n, |e| (e.left, e.right, e.mm_parent)) {
        Some(v) => v,
        None => return ret,
    };
    if let Some(l) = left {
        ret = traverse_subtree(mc, l, base, strict, work);
        if ret == 0 && strict {
            return ret;
        }
    }
    if !tree_mapent_is_root(mc, n) && parent == Some(base) {
        ret = work(n);
        if ret == 0 && strict {
            return ret;
        }
    }
    if let Some(r) = right {
        ret = traverse_subtree(mc, r, base, strict, work);
        if ret == 0 && strict {
            return ret;
        }
    }
    ret
}

/// `tree_mapent_delete_offset_tree()`.
fn delete_offset_tree(ap: &Ap, mc: &Mc, root: u64) -> bool {
    let logopt = ap.logopt();
    let Some((left, right)) = me_get(mc, root, |e| (e.left, e.right)) else { return false };
    if let Some(l) = left {
        if !delete_offset_tree(ap, mc, l) {
            return false;
        }
        me_set(mc, root, |e| e.left = None);
    }
    if let Some(r) = right {
        if !delete_offset_tree(ap, mc, r) {
            return false;
        }
        me_set(mc, root, |e| e.right = None);
    }
    let Some((key, mm_root, id)) = me_get(mc, root, |e| (e.key.clone(), e.mm_root, e.id)) else { return false };
    if mm_root != Some(id) {
        debug!(logopt, "tree_mapent_delete_offset_tree", "deleting offset key {}", key);
        // cache_delete() won't delete an active offset.
        let mut c = mc.lock();
        if let Some(p) = c.by_id(id) {
            c.get_mut(p).mm_root = None;
        }
        let ret = c.delete(&key);
        if ret != crate::libautofs::cache::CHE_OK {
            if let Some(p) = c.by_id(id) {
                c.get_mut(p).mm_root = mm_root;
            }
            drop(c);
            warn!(logopt, "failed to delete offset {}", key);
            return false;
        }
        true
    } else {
        me_set(mc, root, |e| {
            e.mm_root = None;
            e.mm_parent = None;
        });
        true
    }
}

/// `tree_mapent_delete_offsets()`.
pub fn tree_mapent_delete_offsets(ap: &Ap, mc: &Mc, key: &[u8]) -> bool {
    let logopt = ap.logopt();
    let me = {
        let c = mc.lock();
        c.lookup_distinct(key).map(|p| (c.get(p).id, c.get(p).mm_root))
    };
    let Some((id, root)) = me else {
        error!(logopt, "tree_mapent_delete_offsets", "failed to find multi-mount root for key {}", key);
        return false;
    };
    if root != Some(id) {
        error!(logopt, "tree_mapent_delete_offsets", "mapent for key {} is not multi-mount owner", key);
        return false;
    }
    if !delete_offset_tree(ap, mc, id) {
        error!(logopt, "tree_mapent_delete_offsets", "could not delete map entry offsets for key {}", key);
        return false;
    }
    true
}

/// `tree_mapent_umount_mount()`.
fn tree_mapent_umount_mount(ap: &Ap, mp: &[u8]) {
    if is_mounted(mp, MNTS_ALL) && sys::umount(mp) != 0 {
        error!(ap.logopt(), "tree_mapent_umount_mount", "error recovering from mount fail");
        error!(ap.logopt(), "tree_mapent_umount_mount", "cannot umount {}", mp);
    }
}

/// `tree_mapent_cleanup_offsets()`: unmount the offsets of a failed mount.
pub fn tree_mapent_cleanup_offsets(ap: &Ap, mc: &Mc, oe: u64) {
    traverse_subtree(mc, oe, oe, false, &mut |n| {
        if let Some(k) = me_get(mc, n, |e| e.key.clone()) {
            tree_mapent_umount_mount(ap, &k);
        }
        1
    });
    let Some(key) = me_get(mc, oe, |e| e.key.clone()) else { return };
    if key.first() == Some(&b'/') {
        tree_mapent_umount_mount(ap, &key);
    } else {
        match mount_fullpath(4096, &ap.path(), &key) {
            None => error!(ap.logopt(), "tree_mapent_cleanup_offsets", "mount path is too long"),
            Some(mp) => tree_mapent_umount_mount(ap, &mp),
        }
    }
}

/// `tree_mapent_rmdir_path_offset()`.
fn rmdir_path_offset(ap: &Ap, mc: &Mc, oe: u64) -> i32 {
    let Some((key, root)) = me_get(mc, oe, |e| (e.key.clone(), e.mm_root)) else { return -1 };
    let (root_dev, root_len) = root.and_then(|r| me_get(mc, r, |e| (e.dev, e.key.len()))).unwrap_or((0, 0));
    if ap.ty() == crate::daemon::master::LKP_DIRECT {
        return crate::daemon::automount::rmdir_path(ap, &key, root_dev);
    }
    let (ap_len, flags, dev) = {
        let a = ap.lock();
        (a.path.len(), a.flags, a.dev)
    };
    let split = if flags & crate::daemon::master::MOUNT_FLAG_GHOST != 0 { ap_len + root_len + 1 } else { ap_len };
    let dir = key[..split.min(key.len())].to_vec();
    let path = key.get(split + 1..).unwrap_or(&[]).to_vec();
    if sys::chdir(&dir) == -1 {
        error!(ap.logopt(), "tree_mapent_rmdir_path_offset", "failed to chdir to {}", dir);
        return -1;
    }
    let ret = crate::daemon::automount::rmdir_path(ap, &path, dev);
    if sys::chdir(b"/") == -1 {
        error!(ap.logopt(), "tree_mapent_rmdir_path_offset", "failed to chdir to /");
    }
    ret
}

/// `tree_mapent_mount_offset()`.
fn tree_mapent_mount_offset(ap: &Ap, mc: &Mc, oe: u64) -> i32 {
    use crate::daemon::direct::{MOUNT_OFFSET_IGNORE, MOUNT_OFFSET_OK};
    let key = me_get(mc, oe, |e| e.key.clone()).unwrap_or_default();
    debug!(ap.logopt(), "tree_mapent_mount_offset", "mount offset {}", key);
    let ret = crate::daemon::direct::mount_autofs_offset(ap, mc, oe);
    if ret < MOUNT_OFFSET_OK {
        if ret != MOUNT_OFFSET_IGNORE {
            warn!(ap.logopt(), "failed to mount offset");
            return 0;
        }
        debug!(ap.logopt(), "tree_mapent_mount_offset", "ignoring \"nohide\" trigger {}", key);
        me_set(mc, oe, |e| e.mapent = None);
    }
    1
}

/// `tree_mapent_umount_offset()`.
fn tree_mapent_umount_offset(ap: &Ap, mc: &Mc, oe: u64) -> i32 {
    let logopt = ap.logopt();
    // Subtree offsets left by a nonstrict mount fail.
    let ret = tree_mapent_umount_offsets(ap, mc, oe);
    if ret == 0 {
        return 0;
    }
    let Some((key, ioctlfd)) = me_get(mc, oe, |e| (e.key.clone(), e.ioctlfd)) else { return ret };
    // An offset removed from the multi-mount with an active mount: invalidate
    // it rather than mount it again.
    if (ioctlfd != -1 || is_mounted(&key, MNTS_REAL)) && umount_ent_state(logopt, &key, ap.lock().state) != 0 {
        debug!(logopt, "tree_mapent_umount_offset", "offset {} has active mount, invalidate", key);
        me_set(mc, oe, |e| e.mapent = None);
        return 0;
    }
    if !is_mounted(&key, MNTS_AUTOFS) {
        return ret;
    }
    debug!(logopt, "tree_mapent_umount_offset", "umount offset {}", key);
    if crate::daemon::direct::umount_autofs_offset(ap, mc, oe) != 0 {
        warn!(logopt, "failed to umount offset");
        return 0;
    }
    let created = me_get(mc, oe, |e| e.flags & crate::daemon::master::MOUNT_FLAG_DIR_CREATED != 0).unwrap_or(false);
    if !created {
        return ret;
    }
    // A partial directory removal is fine; remount only if the mount point
    // is still there.
    if rmdir_path_offset(ap, mc, oe) == -1 && sys::stat(&key).is_some() {
        tree_mapent_mount_offset(ap, mc, oe);
        me_set(mc, oe, |e| e.flags |= crate::daemon::master::MOUNT_FLAG_DIR_CREATED);
    }
    ret
}

/// `tree_mapent_mount_offsets()`: the offsets nested directly in `oe`.
pub fn tree_mapent_mount_offsets(ap: &Ap, mc: &Mc, oe: u64, nonstrict: bool) -> i32 {
    let strict = !nonstrict;
    traverse_subtree(mc, oe, oe, strict, &mut |n| {
        let Some((has_mapent, age, root)) = me_get(mc, n, |e| (e.mapent.is_some(), e.age, e.mm_root)) else {
            return 1;
        };
        if !has_mapent {
            return 1;
        }
        let root_age = root.and_then(|r| me_get(mc, r, |e| e.age)).unwrap_or(age);
        // A stale offset, no longer in the map entry.
        if age != root_age {
            tree_mapent_umount_offset(ap, mc, n);
            return 1;
        }
        let ret = tree_mapent_mount_offset(ap, mc, n);
        // Reconstructing a multi-mount walks into nested mounts.
        let (st, flags) = {
            let a = ap.lock();
            (a.state, a.flags)
        };
        if st == crate::daemon::state::ST_READMAP && flags & crate::daemon::master::MOUNT_FLAG_REMOUNT != 0 {
            let (k, fd) = me_get(mc, n, |e| (e.key.clone(), e.ioctlfd)).unwrap_or_default();
            if fd != -1 || is_mounted(&k, MNTS_REAL) {
                tree_mapent_mount_offsets(ap, mc, n, !strict);
            }
        }
        if strict { ret } else { 1 }
    })
}

/// `tree_mapent_umount_offsets()`: the offsets nested directly in `oe`, then
/// for a multi-mount root its own mount.
pub fn tree_mapent_umount_offsets(ap: &Ap, mc: &Mc, oe: u64) -> i32 {
    let logopt = ap.logopt();
    let ret = traverse_subtree(mc, oe, oe, true, &mut |n| tree_mapent_umount_offset(ap, mc, n));
    if ret != 0 && tree_mapent_is_root(mc, oe) {
        let key = me_get(mc, oe, |e| e.key.clone()).unwrap_or_default();
        let Some(mp) = mount_fullpath(4096, &ap.path(), &key) else {
            error!(logopt, "tree_mapent_umount_offsets", "mount path is too long");
            return 0;
        };
        // A root that can't be unmounted keeps its offsets: put the
        // triggers back.
        if is_mounted(&mp, MNTS_REAL) {
            info!(logopt, "unmounting dir = {}", mp);
            if umount_ent_state(logopt, &mp, ap.lock().state) != 0 {
                if tree_mapent_mount_offsets(ap, mc, oe, true) == 0 {
                    warn!(logopt, "failed to remount offset triggers");
                }
                return 0;
            }
        }
        mnts_remove_mount(&mp, MNTS_MOUNTED);
    }
    ret
}
