//! `lib/macros.c`: the `$` variables: the read-only system table (`ARCH`, `CPU`,
//! `HOST`, `OSNAME`, `OSREL`, `OSVERS`, `dollar`, `true`, `false`, `byte`,
//! `host`, `xhost`, `domain`, `hostd`), the amd ones `macro_init()` adds, the
//! global ones from `-D`, and the per-map tables the parse modules keep.
//!
//! Tables are lists searched from the head, as in C; a name matches when its
//! first `len` bytes do and it is exactly `len` long (`strncmp() &&
//! def[len] == '\0'`).

use std::sync::Mutex;

use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::sys;

/// A `struct substvar`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstVar {
    pub def: Vec<u8>,
    pub val: Vec<u8>,
    pub readonly: bool,
}

/// A local table, head first.
pub type Table = Vec<SubstVar>;

#[derive(Debug)]
struct Global {
    table: Table,
    init_done: bool,
}

static GLOBAL: Mutex<Global> = Mutex::new(Global { table: Vec::new(), init_done: false });
static MACRO_LOCK: Mutex<()> = Mutex::new(());

const HOST_NAME_MAX: usize = 64;

/// `def` matches `str[..len]` as C compares them.
fn matches(def: &[u8], s: &[u8], len: usize) -> bool {
    cstr::neq(s, def, len) && def.get(len).copied().unwrap_or(0) == 0 && cstr::c(def).len() == len
}

fn system_table(un: &sys::Uname, processor: &[u8], host: &[u8], domain: &[u8], hostd: &[u8], endian: &[u8]) -> Table {
    let v = |d: &[u8], val: &[u8]| SubstVar { def: d.to_vec(), val: val.to_vec(), readonly: true };
    // Head first: sv_hostd ... sv_arch.
    vec![
        v(b"hostd", hostd),
        v(b"domain", domain),
        v(b"xhost", host),
        v(b"host", host),
        v(b"byte", endian),
        v(b"false", b"0"),
        v(b"true", b"1"),
        v(b"dollar", b"$"),
        v(b"OSVERS", &un.version),
        v(b"OSREL", &un.release),
        v(b"OSNAME", &un.sysname),
        v(b"HOST", &un.nodename),
        v(b"CPU", processor),
        v(b"ARCH", &un.machine),
    ]
}

/// `macro_init()`.
pub fn macro_init() {
    let _l = MACRO_LOCK.lock().unwrap();
    if GLOBAL.lock().unwrap().init_done {
        return;
    }
    let (_, un) = sys::uname();
    let mut processor = un.machine.clone();
    processor.truncate(64);
    if processor.len() == 4 && processor[0] == b'i' && processor[1] >= b'3' && &processor[2..] == b"86" {
        processor[1] = b'3';
    }
    let local_domain = defaults::conf_amd_get_sub_domain();
    let mut host = Vec::new();
    let mut domain = Vec::new();
    let mut hostd = Vec::new();
    let (r, name) = sys::gethostname(HOST_NAME_MAX);
    if r == 0 {
        let mut hostname = cstr::c(&name).to_vec();
        if let Some(dot) = hostname.iter().position(|&b| b == b'.') {
            domain = hostname[dot + 1..].to_vec();
            hostname.truncate(dot);
        }
        host = hostname.clone();
        hostd = host.clone();
        if !domain.is_empty() || local_domain.is_some() {
            hostd.push(b'.');
            match &local_domain {
                None => hostd.extend_from_slice(&domain),
                Some(ld) => {
                    hostd.extend_from_slice(ld);
                    domain = ld.clone();
                }
            }
        }
    }
    let endian: &[u8] = if cfg!(target_endian = "little") { b"little" } else { b"big" };
    {
        let mut g = GLOBAL.lock().unwrap();
        // Variables defined before (-D) stay in front of the system ones.
        let mut t = std::mem::take(&mut g.table);
        t.extend(system_table(&un, &processor, &host, &domain, &hostd, endian));
        g.table = t;
    }
    add_std_amd_vars();
    GLOBAL.lock().unwrap().init_done = true;
}

/// `add_std_amd_vars()` (from `lib/mounts.c`).
fn add_std_amd_vars() {
    let add = |name: &[u8], v: Option<Vec<u8>>| {
        if let Some(v) = v {
            macro_global_addvar(name, name.len(), &v);
        }
    };
    add(b"arch", defaults::conf_amd_get_arch());
    add(b"karch", defaults::conf_amd_get_karch());
    add(b"os", defaults::conf_amd_get_os());
    add(b"full_os", defaults::conf_amd_get_full_os());
    add(b"osver", defaults::conf_amd_get_os_ver());
    add(b"vendor", defaults::conf_amd_get_vendor());
    match defaults::conf_amd_get_cluster() {
        Some(c) => {
            macro_global_addvar(b"cluster", 7, &c);
        }
        None => {
            // QUIRK: looks up "domain" with a length of 4, which nothing matches.
            let v = macro_findvar(&[], b"domain", 4);
            if let Some(v) = v
                && !v.val.is_empty()
            {
                macro_global_addvar(b"cluster", 7, &v.val);
            }
        }
    }
    add(b"autodir", Some(defaults::conf_amd_get_auto_dir()));
}

/// `macro_is_systemvar()`.
pub fn macro_is_systemvar(s: &[u8], len: usize) -> bool {
    GLOBAL.lock().unwrap().table.iter().any(|sv| matches(&sv.def, s, len))
}

/// `macro_global_addvar()`.
pub fn macro_global_addvar(s: &[u8], len: usize, value: &[u8]) -> bool {
    let mut g = GLOBAL.lock().unwrap();
    let pos = g.table.iter().position(|sv| matches(&sv.def, s, len));
    match pos {
        Some(i) if !g.table[i].readonly => {
            g.table[i].val = cstr::c(value).to_vec();
        }
        _ => {
            let mut def = cstr::c(s).to_vec();
            def.truncate(len);
            g.table.insert(0, SubstVar { def, val: cstr::c(value).to_vec(), readonly: false });
        }
    }
    true
}

/// `macro_parse_globalvar()` (`-D name=value`).
pub fn macro_parse_globalvar(define: &[u8]) -> bool {
    const MAX_MACRO_STRING: usize = 128;
    let define = cstr::c(define);
    if define.len() >= MAX_MACRO_STRING {
        return false;
    }
    match define.iter().position(|&b| b == b'=') {
        Some(eq) => {
            let name = &define[..eq];
            macro_global_addvar(name, name.len(), &define[eq + 1..])
        }
        None => {
            // QUIRK: C's loop (`while (pbuf)`) never ends without an '=': it
            // walks off the end of its stack buffer. glibc's stack protector
            // isn't involved, so it reads until it finds one or faults; neither
            // can be reproduced, so a definition without a value is ignored.
            false
        }
    }
}

/// `macro_addvar()` on a local table: update `str[..len]` or push a new entry.
pub fn macro_addvar(table: &mut Table, s: &[u8], len: usize, value: Option<&[u8]>) {
    let val = cstr::c(value.unwrap_or(b"")).to_vec();
    if let Some(lv) = table.iter_mut().find(|lv| matches(&lv.def, s, len)) {
        lv.val = val;
        return;
    }
    let mut def = cstr::c(s).to_vec();
    def.truncate(len);
    table.insert(0, SubstVar { def, val, readonly: false });
}

/// `macro_removevar()` on a local table.
pub fn macro_removevar(table: &mut Table, s: &[u8], len: usize) {
    if let Some(i) = table.iter().position(|lv| matches(&lv.def, s, len)) {
        table.remove(i);
    }
}

/// `macro_global_removevar()`.
pub fn macro_global_removevar(s: &[u8], len: usize) {
    let mut g = GLOBAL.lock().unwrap();
    if let Some(i) = g.table.iter().position(|sv| matches(&sv.def, s, len))
        && !g.table[i].readonly
    {
        g.table.remove(i);
    }
}

/// `macro_free_global_table()`.
///
/// QUIRK: the table then starts at `OSVERS`, as C resets it to `&sv_osvers`:
/// `hostd`, `domain`, `xhost`, `host`, `byte`, `false`, `true` and `dollar`
/// are gone after it.
pub fn macro_free_global_table() {
    let mut g = GLOBAL.lock().unwrap();
    g.table.retain(|sv| sv.readonly);
    if let Some(i) = g.table.iter().position(|sv| sv.def == b"OSVERS") {
        g.table.drain(..i);
    }
}

/// `macro_findvar()`: the local table first, then the system one.
pub fn macro_findvar(table: &[SubstVar], s: &[u8], len: usize) -> Option<SubstVar> {
    if let Some(lv) = table.iter().find(|lv| matches(&lv.def, s, len)) {
        return Some(lv.clone());
    }
    GLOBAL.lock().unwrap().table.iter().find(|sv| matches(&sv.def, s, len)).cloned()
}

/// `macro_setenv()`: the system table, then the local one, into the environment.
pub fn macro_setenv(table: &[SubstVar]) {
    let g = GLOBAL.lock().unwrap().table.clone();
    for sv in g.iter().chain(table) {
        sys::setenv(&sv.def, &sv.val, true);
    }
}

/// `macro_lock()`/`macro_unlock()`.
pub fn macro_lock() -> std::sync::MutexGuard<'static, ()> {
    MACRO_LOCK.lock().unwrap()
}

/// The global (system) table, head first.
pub fn global_table() -> Table {
    GLOBAL.lock().unwrap().table.clone()
}
