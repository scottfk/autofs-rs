//! `daemon/module.c`: opening the lookup, parse and mount modules.
//!
//! The modules are built in. A name that upstream's build has a module for
//! (`lookup_file.so` and so on, and the compatibility symlinks `lookup_files.so`,
//! `lookup_nis.so`, `mount_nfs4.so`, `mount_ext3.so`, `mount_ext4.so`) opens it;
//! any other name fails as `dlopen()` fails for a missing file, with the same
//! message. `lookup_nisplus.so` is built but can't be loaded on hydra (libnsl 2
//! has no NIS+ functions), so `nisplus` fails with that `dlopen()` message.

use std::sync::Arc;

use crate::daemon::master::{AutofsPoint, MapSource, Master};
use crate::libautofs::args::Argv;
use crate::libautofs::cstr;
use crate::libautofs::defaults::AUTOFS_LIB_DIR;
use crate::libautofs::nsswitch::NSS_STATUS_SUCCESS;
use crate::libautofs::nsswitch::NSS_STATUS_UNKNOWN;
use crate::modules;

/// A lookup module's entry points (`lookup_init()` is its constructor).
pub trait LookupMod: Send + std::fmt::Debug {
    fn reinit(&mut self, mapfmt: Option<&[u8]>, argv: &Argv) -> i32;
    fn read_master(&mut self, master: &Arc<Master>, age: i64) -> i32;
    fn read_map(&mut self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, age: i64) -> i32;
    fn done(self: Box<Self>) -> i32;
}

/// A parse module's entry points.
pub trait ParseMod: Send + std::fmt::Debug {
    fn reinit(&mut self, argv: &Argv) -> i32;
    fn done(self: Box<Self>) -> i32;
}

/// A mount module's entry points.
pub trait MountMod: Send + std::fmt::Debug {
    fn done(self: Box<Self>) -> i32;
}

/// `dlerror()` for a module file that doesn't exist.
fn dlerror_missing(kind: &str, name: &[u8]) -> Vec<u8> {
    bfmt!("{}/{}_{}.so: cannot open shared object file: No such file or directory", AUTOFS_LIB_DIR, kind, name)
}

/// The module file name `name` would open, if upstream's build has it.
fn lookup_name(name: &[u8]) -> Option<&'static str> {
    Some(match cstr::c(name) {
        b"file" | b"files" => "file",
        b"program" => "program",
        b"dir" => "dir",
        b"yp" | b"nis" => "yp",
        b"hosts" => "hosts",
        b"multi" => "multi",
        b"userhome" => "userhome",
        _ => return None,
    })
}

/// `open_lookup()`: `Ok(module)` or `Err(NSS_STATUS_UNKNOWN)`.
pub fn open_lookup(
    name: &[u8],
    err_prefix: Option<&[u8]>,
    mapfmt: Option<&[u8]>,
    argv: &Argv,
) -> Result<Box<dyn LookupMod>, i32> {
    if cstr::eq(name, b"nisplus") {
        if let Some(p) = err_prefix {
            logerr!(
                "open_lookup",
                "68",
                "{}cannot open lookup module nisplus ({}/lookup_nisplus.so: undefined symbol: nis_list)",
                p,
                AUTOFS_LIB_DIR
            );
        }
        return Err(NSS_STATUS_UNKNOWN);
    }
    let which = match lookup_name(name) {
        Some(w) => w,
        None => {
            if let Some(p) = err_prefix {
                logerr!(
                    "open_lookup",
                    "68",
                    "{}cannot open lookup module {} ({})",
                    p,
                    name,
                    dlerror_missing("lookup", name)
                );
            }
            return Err(NSS_STATUS_UNKNOWN);
        }
    };
    let m: Option<Box<dyn LookupMod>> = match which {
        "file" => modules::lookup_file::lookup_init(mapfmt, argv).map(|m| Box::new(m) as Box<dyn LookupMod>),
        "dir" => modules::lookup_dir::lookup_init(mapfmt, argv).map(|m| Box::new(m) as Box<dyn LookupMod>),
        "program" => modules::lookup_program::lookup_init(mapfmt, argv).map(|m| Box::new(m) as Box<dyn LookupMod>),
        "yp" => modules::lookup_yp::lookup_init(mapfmt, argv).map(|_| unreachable!()),
        "hosts" => modules::lookup_hosts::lookup_init(mapfmt, argv).map(|m| Box::new(m) as Box<dyn LookupMod>),
        "multi" => modules::lookup_multi::lookup_init(mapfmt, argv).map(|m| Box::new(m) as Box<dyn LookupMod>),
        other => panic!("lookup module {other} isn't ported yet (phase 2)"),
    };
    m.ok_or(NSS_STATUS_UNKNOWN)
}

/// `close_lookup()`.
pub fn close_lookup(m: Box<dyn LookupMod>) -> i32 {
    m.done()
}

/// `open_parse()`.
pub fn open_parse(name: &[u8], err_prefix: Option<&[u8]>, argv: &Argv) -> Option<Box<dyn ParseMod>> {
    match cstr::c(name) {
        b"sun" => modules::parse_sun::parse_init(argv).map(|m| Box::new(m) as Box<dyn ParseMod>),
        b"amd" => modules::parse_amd::parse_init(argv).map(|m| Box::new(m) as Box<dyn ParseMod>),
        _ => {
            if let Some(p) = err_prefix {
                logerr!(
                    "open_parse",
                    "169",
                    "{}cannot open parse module {} ({})",
                    p,
                    name,
                    dlerror_missing("parse", name)
                );
            }
            None
        }
    }
}

/// `reinit_parse()`.
pub fn reinit_parse(m: &mut dyn ParseMod, name: &[u8], err_prefix: Option<&[u8]>, argv: &Argv) -> i32 {
    if m.reinit(argv) != 0 {
        if let Some(p) = err_prefix {
            logerr!("reinit_parse", "211", "{}could not reinit parse module {}", p, name);
        }
        return 1;
    }
    0
}

/// `close_parse()`.
pub fn close_parse(m: Box<dyn ParseMod>) -> i32 {
    m.done()
}

/// `open_mount()`.
pub fn open_mount(name: &[u8], err_prefix: Option<&[u8]>) -> Option<Box<dyn MountMod>> {
    match cstr::c(name) {
        b"nfs" | b"nfs4" => modules::mount_nfs::mount_init().map(|m| Box::new(m) as Box<dyn MountMod>),
        b"bind" => modules::mount_bind::mount_init().map(|m| Box::new(m) as Box<dyn MountMod>),
        b"generic" | b"autofs" | b"ext2" | b"ext3" | b"ext4" | b"afs" | b"changer" => {
            panic!("mount module {} isn't ported yet (phase 3)", String::from_utf8_lossy(name))
        }
        _ => {
            if let Some(p) = err_prefix {
                logerr!(
                    "open_mount",
                    "258",
                    "{}cannot open mount module {} ({})",
                    p,
                    name,
                    dlerror_missing("mount", name)
                );
            }
            None
        }
    }
}

/// `close_mount()`.
pub fn close_mount(m: Box<dyn MountMod>) -> i32 {
    m.done()
}

pub const _OK: i32 = NSS_STATUS_SUCCESS;
