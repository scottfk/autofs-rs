//! `modules/lookup_multi.c`: several maps, separated by `--`, looked up in turn.
//! This phase has the setup and the map read.
//!
//! QUIRKs kept: a map type with a format (`file,sun`) is opened under its whole
//! name, which no module has, so it fails; a type word of 20 bytes or more
//! (anything starting `file`, `yp`, `nis`...) trips `_FORTIFY_SOURCE`; and the
//! map read checks each map's NSS status with `LKP_FAIL` (1), so `NOTFOUND` and
//! `TRYAGAIN` count as failures but `UNAVAIL` as a success. All the maps read
//! into the multi map's one cache, under the multi map source.

use std::sync::Arc;

use crate::daemon::master::{AutofsPoint, MapSource, Master};
use crate::daemon::module::{self, LookupMod};
use crate::libautofs::args::Argv;
use crate::libautofs::cstr;
use crate::libautofs::defaults::AUTOFS_MAP_DIR;
use crate::libautofs::nsswitch::{self, NSS_STATUS_NOTFOUND, NSS_STATUS_SUCCESS, NSS_STATUS_UNKNOWN};
use crate::sys;

const MODPREFIX: &[u8] = b"lookup(multi): ";
const MAX_MAP_TYPE_STRING: usize = 20;
const LKP_FAIL: i32 = 0x0001;
const LKP_NOTSUP: i32 = 0x8000;

/// A `struct module_info`: the map's arguments and its open module (with the
/// name it was opened as, C's `mod->type`).
#[derive(Debug)]
struct ModuleInfo {
    argv: Argv,
    module: Option<(Vec<u8>, module::Lookup)>,
}

#[derive(Debug)]
pub struct LookupMulti {
    m: std::sync::Mutex<Vec<ModuleInfo>>,
}

impl LookupMulti {
    /// The maps' modules, in order (the lock isn't held while they're used).
    fn modules(&self) -> Vec<module::Lookup> {
        self.m.lock().unwrap().iter().map(|i| i.module.as_ref().expect("multi map module").1.clone()).collect()
    }
}

/// `alloc_context()`: split the arguments at `--`.
fn alloc_context(argv: &Argv) -> Option<Vec<ModuleInfo>> {
    if argv.is_empty() {
        logerr!("alloc_context", "63", "lookup(multi): No map list");
        return None;
    }
    let mut m = vec![ModuleInfo { argv: Vec::new(), module: None }];
    for a in argv {
        if a.as_deref().is_some_and(|a| cstr::eq(a, b"--")) {
            m.push(ModuleInfo { argv: Vec::new(), module: None });
        } else {
            m.last_mut().unwrap().argv.push(a.clone());
        }
    }
    Some(m)
}

fn open(name: &[u8], fmt: Option<&[u8]>, argv: &Argv) -> Option<(Vec<u8>, module::Lookup)> {
    module::open_lookup(name, Some(MODPREFIX), fmt, argv).ok().map(|m| (cstr::c(name).to_vec(), m))
}

/// `nss_open_lookup()`.
fn nss_open_lookup(format: Option<&[u8]>, argv: &mut Argv) -> Option<(Vec<u8>, module::Lookup)> {
    let a0 = argv.first().cloned().flatten()?;
    if a0.first() == Some(&b'/') {
        return open(b"file", format, argv);
    }
    let pre = |p: &[u8]| cstr::neq(&a0, p, p.len());
    if pre(b"file") || pre(b"yp") || pre(b"nisplus") || pre(b"nis") || pre(b"ldaps") || pre(b"ldap") || pre(b"sss") {
        // strcpy(type, argv[0]) into a 20-byte buffer, fortified.
        if cstr::c(&a0).len() >= MAX_MAP_TYPE_STRING {
            sys::chk_fail();
        }
        let fmt = match cstr::strchr(&a0, b',') {
            Some(c) => Some(a0[c + 1..].to_vec()),
            None => format.map(|f| f.to_vec()),
        };
        // QUIRK: opened as argv[0], not as the type cut at the comma.
        let rest: Argv = argv[1..].to_vec();
        return open(&a0, fmt.as_deref(), &rest);
    }
    let mut nsslist = Vec::new();
    if nsswitch::nsswitch_parse(&mut nsslist).is_err() {
        logerr!("nss_open_lookup", "216", "can't to read name service switch config.");
        return None;
    }
    for this in &nsslist {
        if cstr::eq(&this.source, b"files") {
            let mut path = AUTOFS_MAP_DIR.to_vec();
            path.push(b'/');
            path.extend_from_slice(&a0);
            if let Some(st) = sys::stat(&path)
                && st.st_mode & libc::S_IFMT == libc::S_IFREG
            {
                let ty: &[u8] = if st.st_mode & libc::S_IEXEC != 0 { b"program" } else { b"file" };
                let save = argv[0].clone();
                argv[0] = Some(path);
                match module::open_lookup(ty, Some(MODPREFIX), format, argv) {
                    Ok(m) => return Some((ty.to_vec(), m)),
                    Err(status) => {
                        argv[0] = save;
                        if nsswitch::check_nss_result(this, status) >= 0 {
                            break;
                        }
                    }
                }
            } else {
                continue;
            }
        }
        match module::open_lookup(&this.source, Some(MODPREFIX), format, argv) {
            Ok(m) => return Some((this.source.clone(), m)),
            Err(status) => {
                if nsswitch::check_nss_result(this, status) >= 0 {
                    break;
                }
            }
        }
    }
    None
}

/// `lookup_init()`.
pub fn lookup_init(mapfmt: Option<&[u8]>, argv: &Argv) -> Option<LookupMulti> {
    let mut m = alloc_context(argv)?;
    for info in m.iter_mut() {
        info.module = nss_open_lookup(mapfmt, &mut info.argv);
        if info.module.is_none() {
            logerr!("lookup_init", "306", "lookup(multi): error opening module");
            for i in m.iter_mut() {
                if let Some((_, md)) = i.module.take() {
                    md.done();
                }
            }
            return None;
        }
    }
    Some(LookupMulti { m: std::sync::Mutex::new(m) })
}

impl LookupMod for LookupMulti {
    fn reinit(&self, _mapfmt: Option<&[u8]>, _argv: &Argv) -> i32 {
        panic!("lookup(multi) reinit isn't ported yet (phase 3, map reloads)");
    }

    fn read_master(&self, _master: &Arc<Master>, _age: i64) -> i32 {
        NSS_STATUS_UNKNOWN
    }

    /// `lookup_read_map()`.
    fn read_map(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, age: i64) -> i32 {
        let mut at_least_1 = false;
        for md in self.modules() {
            let ret = md.read_map(ap, map, age);
            if ret & LKP_FAIL != 0 || ret == LKP_NOTSUP {
                continue;
            }
            at_least_1 = true;
        }
        if !at_least_1 { NSS_STATUS_NOTFOUND } else { NSS_STATUS_SUCCESS }
    }

    /// `lookup_mount()`: the first map that mounts the key.
    fn mount(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        for md in self.modules() {
            if md.mount(ap, map, name) == 0 {
                return NSS_STATUS_SUCCESS;
            }
        }
        NSS_STATUS_NOTFOUND
    }

    /// `lookup_done()`.
    fn done(&self) -> i32 {
        let mut rv = 0;
        for info in std::mem::take(&mut *self.m.lock().unwrap()) {
            if let Some((_, md)) = info.module {
                // rv = rv || close_lookup(): once one fails, the rest stay open.
                if rv == 0 {
                    rv = (md.done() != 0) as i32;
                } else {
                    std::mem::forget(md);
                }
            }
        }
        rv
    }
}
