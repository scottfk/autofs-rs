//! `modules/parse_amd.c`: the amd map entry parser. An entry is a list of
//! locations; the first whose selectors all match is mounted, after the map's
//! `/defaults` entry (or `map_defaults`, or the internal `opts:=rw,defaults`)
//! has filled in what it doesn't say and the `${...}` variables are expanded.
//!
//! The module takes no options, and `parse_reinit()` does nothing. It keeps
//! its own reference to the NFS mount module (a separate count from the sun
//! parser's, as each `.so` has its own statics).
//!
//! QUIRKs kept:
//! - `match_selectors()` evaluates the list's *first* selector once for each
//!   selector in the list (with `add_selector()`'s linking, the latest one).
//! - A location that gives no file system type gets `nfs`, and its other
//!   flags (`||`, the cut) are cleared with it.
//! - `sublink` is never taken from the variables: it's looked up with a
//!   length of 2 (`su`). `umount` goes into them as `umoun`.
//! - With `selectors_in_defaults`, a `-` location in `/defaults` dereferences
//!   a NULL defaults entry (`SIGSEGV`); without it, a `/defaults` entry of more
//!   than one location is ignored for the internal defaults.
//! - The `nfsl` type only links when `${host}` and `${hostd}` both equal
//!   `rhost` (`strcasecmp(...) || strcasecmp(...)`).

use std::sync::{Arc, Mutex};

use crate::daemon::automount::rmdir_path;
use crate::daemon::lookup;
use crate::daemon::master::{self, AutofsPoint, MapSource, cstr_or_null};
use crate::daemon::module::{self, MountMod, ParseMod};
use crate::daemon::mount::do_mount;
use crate::daemon::spawn;
use crate::daemon::state;
use crate::libautofs::args::Argv;
use crate::libautofs::cstr;
use crate::libautofs::defaults::{self, CONF_AUTOFS_USE_LOFS, CONF_DOMAIN_STRIP, CONF_NORMALIZE_HOSTNAMES};
use crate::libautofs::macros::{self, Table};
use crate::libautofs::mounts::{self, MNTS_INDIRECT, MNTS_MOUNTED, MNTS_REAL};
use crate::libautofs::parse_subs::{self, *};
use crate::modules::amd_parse::*;
use crate::sys;

const MODPREFIX: &[u8] = b"parse(amd): ";
const PATH_MAX: usize = 4096;
const NI_MAXHOST: usize = 1025;
const MP_MODE: u32 = 0o755;

/// `mount_nfs` and `init_ctr`.
static NFS: Mutex<(Option<Box<dyn MountMod>>, u32)> = Mutex::new((None, 0));

/// A `struct parse_context`.
#[derive(Debug, Default)]
pub struct ParseAmd {
    pub optstr: Option<Vec<u8>>,
    pub macros: Option<Vec<u8>>,
}

/// `parse_init()`.
pub fn parse_init(_argv: &Argv) -> Option<ParseAmd> {
    let mut g = NFS.lock().unwrap();
    if g.0.is_some() {
        g.1 += 1;
    } else {
        drop(g);
        let m = module::open_mount(b"nfs", Some(MODPREFIX))?;
        let mut g = NFS.lock().unwrap();
        g.0 = Some(m);
        g.1 += 1;
    }
    Some(ParseAmd::default())
}

fn s(v: &Option<Vec<u8>>) -> Vec<u8> {
    cstr_or_null(v)
}

fn nonempty(v: &Option<Vec<u8>>) -> bool {
    v.as_deref().is_some_and(|x| !x.is_empty())
}

fn addvar(sv: &mut Table, name: &[u8], len: usize, val: &[u8]) {
    macros::macro_addvar(sv, name, len, Some(val));
}

/// `add_lookup_vars()`: `${path}`, `${key}`, `${map}`, `${uid}`, `${gid}`,
/// `${fs}` and `${rfs}` for a lookup of `key`.
fn add_lookup_vars(ap: &Arc<AutofsPoint>, key: &[u8], source: &Arc<MapSource>) -> Option<Table> {
    let logopt = ap.logopt();
    let (ap_path, pref) = {
        let a = ap.lock();
        (a.path.clone(), a.pref.clone())
    };
    let key = cstr::c(key);
    if ap_path.len() + 1 + key.len() + 1 > PATH_MAX {
        error!(logopt, "add_lookup_vars", "parse(amd): error: lookup key is greater than PATH_MAX");
        return None;
    }
    let lkp_key = match &pref {
        Some(p) => [cstr::c(p), key].concat(),
        None => key.to_vec(),
    };
    if lkp_key.len() > PATH_MAX {
        error!(logopt, "add_lookup_vars", "parse(amd): key too long");
        return None;
    }
    let path = if key.first() == Some(&b'/') { key.to_vec() } else { [&ap_path[..], b"/", key].concat() };
    let mut list = Table::new();
    addvar(&mut list, b"path", 4, &path);
    {
        let mc = source.mc();
        let c = mc.lock();
        if let Some(p) = c.lookup_distinct(&lkp_key) {
            let k = c.get(p).key.clone();
            addvar(&mut list, b"key", 3, &k);
        } else {
            let mut found = false;
            let mut m = lkp_key.clone();
            while let Some(pre) = cstr::strrchr(&m, b'/') {
                m.truncate(pre);
                if c.partial_match_wild(&m).is_some() {
                    addvar(&mut list, b"key", 3, &lkp_key);
                    found = true;
                    break;
                }
            }
            if !found && c.lookup_distinct(b"*").is_some() {
                addvar(&mut list, b"key", 3, &lkp_key);
            }
        }
    }
    {
        let sd = source.lock();
        if let Some(n) = &sd.name {
            addvar(&mut list, b"map", 3, n);
        } else if let Some(Some(a0)) = sd.argv.first()
            && !a0.is_empty()
        {
            addvar(&mut list, b"map", 3, a0);
        }
    }
    if let Some(tsv) = mounts::tsv() {
        addvar(&mut list, b"uid", 3, tsv.uid.to_string().as_bytes());
        addvar(&mut list, b"gid", 3, tsv.gid.to_string().as_bytes());
    }
    addvar(&mut list, b"fs", 2, b"${autodir}/${rhost}${rfs}");
    addvar(&mut list, b"rfs", 3, &path);
    Some(list)
}

/// `match_my_name()`: whether `name` is this host (by name or address).
fn match_my_name(logopt: u32, name: &[u8], sv: &Table) -> bool {
    let exp_name = expand_selectors(logopt, Some(name), sv).unwrap_or_else(|| cstr::c(name).to_vec());
    let v = macros::macro_findvar(sv, b"host", 4);
    if let Some(v) = &v
        && cstr::eq(&v.val, &exp_name)
    {
        return true;
    }
    let Some(v) = v else {
        error!(logopt, "match_my_name", "parse(amd): error: ${host} not set");
        return false;
    };
    let cni = match sys::getaddrinfo(&v.val, libc::AF_UNSPEC, libc::SOCK_DGRAM, libc::AI_CANONNAME) {
        Ok(c) => c,
        Err(e) => {
            error!(
                logopt,
                "match_my_name",
                "parse(amd): hostname lookup for {} failed: {}\n",
                v.val,
                sys::gai_strerror(e)
            );
            return false;
        }
    };
    let flags = libc::AI_V4MAPPED | libc::AI_ADDRCONFIG | libc::AI_CANONNAME;
    let ni = match sys::getaddrinfo(&exp_name, libc::AF_UNSPEC, libc::SOCK_DGRAM, flags) {
        Ok(n) => n,
        Err(e) => {
            error!(
                logopt,
                "match_my_name",
                "parse(amd): hostname lookup for {} failed: {}\n",
                exp_name,
                sys::gai_strerror(e)
            );
            return false;
        }
    };
    let canon = cni.first().and_then(|c| c.canonname.clone());
    for haddr in &ni {
        if let Err(e) = sys::getnameinfo(&haddr.addr, NI_MAXHOST + 1, libc::NI_NUMERICHOST) {
            error!(logopt, "match_my_name", "parse(amd): host address info lookup failed: {}\n", sys::gai_strerror(e));
            continue;
        }
        let host = match sys::getnameinfo(&haddr.addr, NI_MAXHOST, 0) {
            Ok(h) => h,
            Err(e) => {
                error!(
                    logopt,
                    "match_my_name",
                    "parse(amd): host address info lookup failed: {}\n",
                    sys::gai_strerror(e)
                );
                continue;
            }
        };
        if canon.as_deref().is_some_and(|c| cstr::eq(&host, c)) {
            return true;
        }
    }
    false
}

/// `sel_strcmp()`.
fn sel_strcmp(logopt: u32, v: &macros::SubstVar, sel: &Selector, sv: &Table) -> bool {
    let value = sel.arg1.clone().unwrap_or_default();
    let expand = expand_selectors(logopt, Some(&value), sv);
    let shown = expand.clone().unwrap_or_else(|| value.clone());
    let res = !cstr::eq(&v.val, &shown);
    if sel.compare & SEL_COMP_EQUAL != 0 && !res {
        debug!(logopt, "sel_strcmp", "parse(amd): matched selector {}({}) == {}", v.def, v.val, shown);
        true
    } else if sel.compare & SEL_COMP_NOTEQUAL != 0 && res {
        debug!(logopt, "sel_strcmp", "parse(amd): matched selector {}({}) != {}", v.def, v.val, shown);
        true
    } else {
        let op: &[u8] = if sel.compare & SEL_COMP_EQUAL != 0 { b"==" } else { b"!=" };
        debug!(logopt, "sel_strcmp", "parse(amd): did not match selector {}({}) {} {}", v.def, v.val, op, shown);
        false
    }
}

/// The debug lines of the one-argument selector functions.
fn sel_result(logopt: u32, func: &str, sel: &Selector, ret: bool, arg: &[u8]) {
    let msg = if ret {
        bfmt!("{}: parse(amd): matched selector {}({})", func, sel.sel.name, arg)
    } else {
        bfmt!("{}: parse(amd): did not match selector {}({})", func, sel.sel.name, arg)
    };
    crate::libautofs::log::log_debug(logopt, &msg);
}

/// `sel_lstat()`.
fn sel_lstat(logopt: u32, sel: &Selector, sv: &Table) -> bool {
    let expand = expand_selectors(logopt, sel.arg1.as_deref(), sv);
    let arg = expand.clone().or_else(|| sel.arg1.clone()).unwrap_or_default();
    let mut ret = sys::lstat(&arg).is_some();
    if sel.compare == SEL_COMP_NOT {
        ret = !ret;
    }
    sel_result(logopt, "sel_lstat", sel, ret, &arg);
    ret
}

/// `sel_in_network()`.
fn sel_in_network(logopt: u32, sel: &Selector, sv: &Table) -> bool {
    let expand = expand_selectors(logopt, sel.arg1.as_deref(), sv);
    let arg = expand.clone().or_else(|| sel.arg1.clone()).unwrap_or_default();
    let mut ret = in_network(&arg);
    if sel.compare == SEL_COMP_NOT {
        ret = !ret;
    }
    sel_result(logopt, "sel_in_network", sel, ret, &arg);
    ret
}

/// `sel_netgrp()`.
fn sel_netgrp(logopt: u32, sel: &Selector, sv: &Table) -> bool {
    let exp_arg2 = sel.arg2.as_ref().and_then(|a| expand_selectors(logopt, Some(a), sv));
    let host = match &sel.arg2 {
        Some(a2) => exp_arg2.clone().unwrap_or_else(|| a2.clone()),
        None => {
            let v = if sel.sel.selector == SEL_NETGRP {
                macros::macro_findvar(sv, b"host", 4)
            } else {
                macros::macro_findvar(sv, b"hostd", 5)
            };
            match v {
                Some(v) if !v.val.is_empty() => v.val,
                _ => {
                    error!(logopt, "sel_netgrp", "parse(amd): failed to get value of ${host}");
                    return false;
                }
            }
        }
    };
    let arg1 = sel.arg1.clone().unwrap_or_default();
    let exp_arg1 = expand_selectors(logopt, Some(&arg1), sv);
    let a1 = exp_arg1.unwrap_or(arg1);
    let mut ret = sys::innetgr_host(&a1, &host);
    if sel.compare == SEL_COMP_NOT {
        ret = !ret;
    }
    let what: &str = if ret { "matched" } else { "did not match" };
    match &sel.arg2 {
        None => {
            let m = bfmt!("sel_netgrp: parse(amd): {} selector {}({})", what, sel.sel.name, a1);
            crate::libautofs::log::log_debug(logopt, &m);
        }
        Some(a2) => {
            let a2 = exp_arg2.unwrap_or_else(|| a2.clone());
            let m = bfmt!("sel_netgrp: parse(amd): {} selector {}({},{})", what, sel.sel.name, a1, a2);
            crate::libautofs::log::log_debug(logopt, &m);
        }
    }
    ret
}

/// `eval_selector()`: the entry's first selector.
fn eval_selector(logopt: u32, this: &AmdEntry, sv: &Table) -> bool {
    let sel = &this.selector[0];
    let s_type = sel.sel.flags & SEL_FLAGS_TYPE_MASK;
    match s_type {
        SEL_FLAG_MACRO => {
            let Some(v) = macros::macro_findvar(sv, sel.sel.name, sel.sel.name.len()) else {
                error!(logopt, "eval_selector", "parse(amd): failed to get selector {}", sel.sel.name);
                return false;
            };
            match sel.sel.flags & SEL_FLAGS_VALUE_MASK {
                SEL_FLAG_STR => sel_strcmp(logopt, &v, sel, sv),
                SEL_FLAG_NUM => {
                    let value = sel.arg1.clone().unwrap_or_default();
                    let (res, val) = if value.is_empty() { (1, 0) } else { (cstr::atoi(&v.val), cstr::atoi(&value)) };
                    if sel.compare & SEL_COMP_EQUAL != 0 && res == val {
                        debug!(
                            logopt,
                            "eval_selector", "parse(amd): matched selector {}({}) equal to {}", v.def, v.val, value
                        );
                        return true;
                    } else if sel.compare & SEL_COMP_NOTEQUAL != 0 && res != val {
                        debug!(
                            logopt,
                            "eval_selector", "parse(amd): matched selector {}({}) not equal to {}", v.def, v.val, value
                        );
                        return true;
                    }
                    let op: &[u8] = if sel.compare & SEL_COMP_EQUAL != 0 { b"==" } else { b"!=" };
                    debug!(
                        logopt,
                        "eval_selector", "parse(amd): did not match selector {}({}) {} {}", v.def, v.val, op, value
                    );
                    false
                }
                _ => false,
            }
        }
        SEL_FLAG_FUNC1 => {
            let id = sel.sel.selector;
            if id != SEL_TRUE && id != SEL_FALSE && sel.arg1.is_none() {
                error!(logopt, "eval_selector", "parse(amd): expected argument missing for selector {}", sel.sel.name);
                return false;
            }
            let a1 = s(&sel.arg1);
            match id {
                SEL_TRUE | SEL_FALSE => {
                    let mut ret = id == SEL_TRUE;
                    if sel.compare == SEL_COMP_NOT {
                        ret = !ret;
                    }
                    sel_result(logopt, "eval_selector", sel, ret, &a1);
                    ret
                }
                SEL_XHOST => {
                    let mut ret = match_my_name(logopt, &a1, sv);
                    if sel.compare == SEL_COMP_NOT {
                        ret = !ret;
                    }
                    if ret {
                        debug!(
                            logopt,
                            "eval_selector", "parse(amd): matched selector {}({}) to host name", sel.sel.name, a1
                        );
                    } else {
                        debug!(
                            logopt,
                            "eval_selector", "parse(amd): did not match selector {}({}) to host name", sel.sel.name, a1
                        );
                    }
                    ret
                }
                SEL_EXISTS => sel_lstat(logopt, sel, sv),
                SEL_IN_NETWORK => sel_in_network(logopt, sel, sv),
                _ => false,
            }
        }
        SEL_FLAG_FUNC2 => {
            if sel.arg1.is_none() {
                error!(logopt, "eval_selector", "parse(amd): expected argument missing for selector {}", sel.sel.name);
                return false;
            }
            match sel.sel.selector {
                SEL_NETGRP | SEL_NETGRPD => sel_netgrp(logopt, sel, sv),
                _ => false,
            }
        }
        _ => false,
    }
}

/// `match_selectors()`. QUIRK: the first selector is evaluated each time.
fn match_selectors(logopt: u32, entry: &AmdEntry, sv: &Table) -> bool {
    if entry.selector.is_empty() {
        debug!(logopt, "match_selectors", "parse(amd): no selectors found in location");
        return true;
    }
    for _ in &entry.selector {
        if !eval_selector(logopt, entry, sv) {
            return false;
        }
    }
    true
}

/// `update_with_defaults()`.
fn update_with_defaults(defaults: &AmdEntry, entry: &mut AmdEntry, sv: &Table) {
    let findvar = |n: &[u8], len: usize| macros::macro_findvar(sv, n, len).map(|v| v.val);
    if entry.flags & AMD_MOUNT_TYPE_MASK == AMD_MOUNT_TYPE_NONE {
        let deftype = defaults.flags & AMD_MOUNT_TYPE_MASK;
        if deftype != AMD_MOUNT_TYPE_NONE {
            entry.flags |= deftype;
        } else {
            entry.flags = AMD_MOUNT_TYPE_NFS;
            entry.ty = Some(b"nfs".to_vec());
        }
    }
    if entry.ty.is_none() && defaults.ty.is_some() {
        entry.ty = defaults.ty.clone();
    }
    if entry.map_type.is_none() && defaults.map_type.is_some() {
        entry.map_type = defaults.map_type.clone();
    }
    if entry.pref.is_none() && defaults.pref.is_some() {
        entry.pref = defaults.pref.clone();
    }
    if entry.fs.is_none() {
        entry.fs = if defaults.fs.is_some() { defaults.fs.clone() } else { findvar(b"fs", 2) };
    }
    if entry.rfs.is_none() {
        entry.rfs = if defaults.rfs.is_some() { defaults.rfs.clone() } else { findvar(b"rfs", 3) };
    }
    if entry.rhost.is_none() {
        entry.rhost = if defaults.rhost.is_some() { defaults.rhost.clone() } else { findvar(b"host", 4) };
    }
    if entry.dev.is_none() && defaults.dev.is_some() {
        entry.dev = defaults.dev.clone();
    }
    if entry.opts.is_none()
        && defaults.opts.is_some()
        && let Some(t) = merge_options(defaults.opts.as_deref(), entry.opts.as_deref())
    {
        entry.opts = Some(t);
    }
    if entry.addopts.is_none()
        && defaults.addopts.is_some()
        && let Some(t) = merge_options(defaults.addopts.as_deref(), entry.addopts.as_deref())
    {
        entry.addopts = Some(t);
    }
    if entry.remopts.is_none() {
        entry.remopts = if defaults.remopts.is_some() { defaults.remopts.clone() } else { findvar(b"remopts", 7) };
    }
    if entry.sublink.is_none() {
        // QUIRK: looked up with a length of 2.
        entry.sublink = if defaults.sublink.is_some() { defaults.sublink.clone() } else { findvar(b"sublink", 2) };
    }
}

/// `normalize_hostname()`.
fn normalize_hostname(logopt: u32, host: &[u8], flags: u64, sv: &Table) -> Option<Vec<u8>> {
    let mut name = if flags & CONF_NORMALIZE_HOSTNAMES == 0 {
        cstr::c(host).to_vec()
    } else {
        match sys::getaddrinfo(host, libc::AF_UNSPEC, libc::SOCK_DGRAM, libc::AI_CANONNAME) {
            Err(e) => {
                error!(
                    logopt,
                    "normalize_hostname",
                    "parse(amd): hostname lookup for {} failed: {}",
                    host,
                    sys::gai_strerror(e)
                );
                return None;
            }
            Ok(ni) => ni.first().and_then(|n| n.canonname.clone())?,
        }
    };
    if flags & CONF_DOMAIN_STRIP != 0
        && let Some(v) = macros::macro_findvar(sv, b"hostd", 5)
        && let Some(d1) = cstr::strchr(&name, b'.')
        && let Some(d2) = cstr::strchr(&v.val, b'.')
        && cstr::eq(&name[d1..], &v.val[d2..])
    {
        name.truncate(d1);
    }
    Some(name)
}

/// One field of `expand_entry()`: expand it and add it to the variables.
fn expand_field(logopt: u32, field: &mut Option<Vec<u8>>, label: &str, var: &[u8], sv: &mut Table) {
    if let Some(e) = expand_selectors(logopt, field.as_deref(), sv) {
        let m = bfmt!("expand_entry: parse(amd): {} expand(\"{}\") -> {}", label, s(field), e);
        crate::libautofs::log::log_debug(logopt, &m);
        *field = Some(e);
    }
    let val = field.clone().unwrap_or_default();
    addvar(sv, var, var.len(), &val);
}

/// `expand_entry()`.
fn expand_entry(ap: &Arc<AutofsPoint>, entry: &mut AmdEntry, flags: u64, sv: &mut Table) {
    let logopt = ap.logopt();
    if nonempty(&entry.rhost) {
        let mut host = entry.rhost.clone().unwrap();
        if let Some(e) = expand_selectors(logopt, Some(&host), sv) {
            host = e;
        }
        match normalize_hostname(logopt, &host, flags, sv) {
            None => addvar(sv, b"rhost", 5, &host),
            Some(nn) => {
                addvar(sv, b"rhost", 5, &nn);
                host = nn;
            }
        }
        debug!(logopt, "expand_entry", "parse(amd): rhost expand(\"{}\") -> {}", s(&entry.rhost), host);
        entry.rhost = Some(host);
    }
    if entry.pref.is_some() {
        expand_field(logopt, &mut entry.pref, "pref", b"pref", sv);
    }
    if entry.sublink.is_some() {
        expand_field(logopt, &mut entry.sublink, "sublink", b"sublink", sv);
    }
    if nonempty(&entry.rfs) {
        expand_field(logopt, &mut entry.rfs, "rfs", b"rfs", sv);
    }
    if nonempty(&entry.fs) {
        expand_field(logopt, &mut entry.fs, "fs", b"fs", sv);
    }
    if nonempty(&entry.opts) {
        expand_field(logopt, &mut entry.opts, "ops", b"opts", sv);
    }
    if nonempty(&entry.addopts) {
        expand_field(logopt, &mut entry.addopts, "addopts", b"addopts", sv);
    }
    if nonempty(&entry.remopts) {
        expand_field(logopt, &mut entry.remopts, "remopts", b"remopts", sv);
    }
    if entry.mount.is_some() {
        let Some(e) = expand_selectors(logopt, entry.mount.as_deref(), sv) else {
            entry.mount = None;
            entry.umount = None;
            return;
        };
        debug!(logopt, "expand_entry", "parse(amd): mount expand(\"{}\") -> {}", s(&entry.mount), e);
        entry.mount = Some(e.clone());
        addvar(sv, b"mount", 5, &e);
    }
    if entry.umount.is_some() {
        let Some(e) = expand_selectors(logopt, entry.umount.as_deref(), sv) else {
            entry.umount = None;
            return;
        };
        debug!(logopt, "expand_entry", "parse(amd): umount expand(\"{}\") -> {}", s(&entry.umount), e);
        entry.umount = Some(e.clone());
        // QUIRK: a length of 5 makes the variable `umoun`.
        addvar(sv, b"umount", 5, &e);
    }
}

/// `expand_merge_options()`.
fn expand_merge_options(logopt: u32, entry: &mut AmdEntry, sv: &Table) {
    for (field, what) in [(&mut entry.opts, "opts"), (&mut entry.addopts, "addopts"), (&mut entry.remopts, "remopts")] {
        if nonempty(field) {
            match expand_selectors(logopt, field.as_deref(), sv) {
                None => {
                    let m = bfmt!("expand_merge_options: parse(amd): failed to expand {}", what);
                    crate::libautofs::log::log_error(logopt, &m);
                }
                Some(t) => *field = Some(t),
            }
        }
    }
}

/// `merge_entry_options()`: fold `addopts` into `opts` and `remopts`.
fn merge_entry_options(logopt: u32, entry: &mut AmdEntry, sv: &mut Table) {
    if entry.addopts.is_none() {
        return;
    }
    if entry.opts.is_some()
        && entry.remopts.is_some()
        && cstr::eq(entry.opts.as_ref().unwrap(), entry.remopts.as_ref().unwrap())
    {
        expand_merge_options(logopt, entry, sv);
        if let Some(t) = merge_options(entry.opts.as_deref(), entry.addopts.as_deref()) {
            info!(
                logopt,
                "parse(amd): merge remopts \"{}\" addopts \"{}\" => \"{}\"",
                s(&entry.opts),
                s(&entry.addopts),
                t
            );
            entry.opts = Some(t.clone());
            addvar(sv, b"opts", 4, &t);
        }
        if nonempty(&entry.opts) {
            let t = entry.opts.clone().unwrap();
            entry.remopts = Some(t.clone());
            addvar(sv, b"remopts", 7, &t);
        }
        return;
    }
    expand_merge_options(logopt, entry, sv);
    if entry.opts.is_some() && entry.addopts.is_some() {
        if let Some(t) = merge_options(entry.opts.as_deref(), entry.addopts.as_deref()) {
            info!(
                logopt,
                "parse(amd): merge opts \"{}\" addopts \"{}\" => \"{}\"",
                s(&entry.opts),
                s(&entry.addopts),
                t
            );
            entry.opts = Some(t.clone());
            addvar(sv, b"opts", 4, &t);
        }
    } else if nonempty(&entry.addopts) {
        let t = entry.addopts.clone().unwrap();
        info!(logopt, "parse(amd): opts add addopts \"{}\" => \"{}\"", t, t);
        entry.opts = Some(t.clone());
        addvar(sv, b"opts", 4, &t);
    }
    expand_merge_options(logopt, entry, sv);
    if entry.remopts.is_some() && entry.addopts.is_some() {
        if let Some(t) = merge_options(entry.remopts.as_deref(), entry.addopts.as_deref()) {
            info!(
                logopt,
                "parse(amd): merge remopts \"{}\" addopts \"{}\" => \"{}\"",
                s(&entry.remopts),
                s(&entry.addopts),
                t
            );
            entry.remopts = Some(t.clone());
            addvar(sv, b"remopts", 7, &t);
        }
    } else if nonempty(&entry.addopts) {
        let t = entry.addopts.clone().unwrap();
        info!(logopt, "parse(amd): remopts add addopts \"{}\" => \"{}\"", t, t);
        entry.remopts = Some(t.clone());
        addvar(sv, b"remopts", 7, &t);
    }
}

/// `snprintf(target, PATH_MAX, ...)`: what fits, or `None` past `PATH_MAX`.
fn path_max(t: Vec<u8>) -> Option<Vec<u8>> {
    if t.len() > PATH_MAX {
        return None;
    }
    let mut t = t;
    t.truncate(PATH_MAX - 1);
    Some(t)
}

/// `do_auto_mount()`: an autofs submount of `fs`.
fn do_auto_mount(ap: &Arc<AutofsPoint>, name: &[u8], entry: &AmdEntry) -> i32 {
    let logopt = ap.logopt();
    let target = match &entry.map_type {
        None => match path_max(s(&entry.fs)) {
            Some(t) => t,
            None => {
                error!(logopt, "do_auto_mount", "parse(amd): error: fs option length is too long");
                return 0;
            }
        },
        Some(mt) => match path_max(bfmt!("{},amd:{}", mt, s(&entry.fs))) {
            Some(t) => t,
            None => {
                error!(logopt, "do_auto_mount", "parse(amd): error: fs + maptype options length is too long");
                return 0;
            }
        },
    };
    do_mount(ap, &ap.path(), name, Some(&target), b"autofs", entry.opts.as_deref())
}

/// `do_link_mount()`: a bind mount (with `autofs_use_lofs`) or a symlink to
/// `sublink` or `fs`.
fn do_link_mount(ap: &Arc<AutofsPoint>, name: &[u8], entry: &AmdEntry, flags: u64) -> i32 {
    let logopt = ap.logopt();
    let opts = entry.opts.as_deref().filter(|o| !o.is_empty());
    let target = if let Some(sl) = &entry.sublink {
        if sl.len() > PATH_MAX {
            error!(logopt, "do_link_mount", "parse(amd): error: sublink option length is too long");
            return 0;
        }
        sl.clone()
    } else {
        let fs = s(&entry.fs);
        if fs.len() > PATH_MAX {
            error!(logopt, "do_link_mount", "parse(amd): error: fs option length is too long");
            return 0;
        }
        fs
    };
    let path = ap.path();
    if flags & CONF_AUTOFS_USE_LOFS != 0 {
        let ret = do_mount(ap, &path, name, Some(&target), b"bind", opts);
        if ret == 0 {
            return 0;
        }
        debug!(logopt, "do_link_mount", "parse(amd): bind mount failed, symlinking");
    }
    let ret = do_mount(ap, &path, name, Some(&target), b"bind", Some(b"symlink"));
    if ret == 0 {
        return 0;
    }
    error!(logopt, "do_link_mount", "parse(amd): failed to symlink {} to {}", s(&entry.path), target);
    if entry.sublink.is_some() {
        mounts::umount_amd_ext_mount(ap, &s(&entry.fs));
    }
    ret
}

/// `do_linkx_mount()`: a link, if its target exists.
fn do_linkx_mount(ap: &Arc<AutofsPoint>, name: &[u8], entry: &AmdEntry, flags: u64) -> i32 {
    let target = entry.sublink.clone().unwrap_or_else(|| s(&entry.fs));
    if sys::lstat(&target).is_none() {
        return sys::errno();
    }
    do_link_mount(ap, name, entry, flags)
}

/// `do_generic_mount()`: mount `target`, at `fs` (then linked) if it's given.
fn do_generic_mount(ap: &Arc<AutofsPoint>, name: &[u8], entry: &AmdEntry, target: &[u8], flags: u64) -> i32 {
    let opts = entry.opts.as_deref().filter(|o| !o.is_empty());
    let ty = entry.ty.clone().unwrap_or_default();
    let Some(fs) = entry.fs.clone() else {
        return do_mount(ap, &ap.path(), name, Some(target), &ty, opts);
    };
    let mut umount = false;
    if !mounts::is_mounted(&fs, MNTS_REAL) {
        let ret = do_mount(ap, &fs, &fs, Some(target), &ty, opts);
        if ret != 0 {
            return ret;
        }
        umount = true;
    }
    if umount && !mounts::ext_mount_add(&fs, entry.umount.as_deref()) {
        mounts::umount_ent(ap.logopt(), &fs);
        error!(ap.logopt(), "do_generic_mount", "parse(amd): error: could not add external mount {}", fs);
        return 1;
    }
    do_link_mount(ap, name, entry, flags)
}

/// The NFS mount module's `mount_mount()`.
fn nfs_mount(ap: &Arc<AutofsPoint>, root: &[u8], name: &[u8], what: &[u8], ty: &[u8], opts: Option<&[u8]>) -> i32 {
    let mut g = NFS.lock().unwrap();
    let m = g.0.as_mut().expect("parse(amd)'s NFS mount module");
    m.mount(ap, root, name, Some(what), ty, opts)
}

/// `do_nfs_mount()`: `rhost:rfs`, with `remopts` for a host off the local
/// networks.
fn do_nfs_mount(ap: &Arc<AutofsPoint>, name: &[u8], entry: &AmdEntry, flags: u64) -> i32 {
    let logopt = ap.logopt();
    let Some(target) = path_max(bfmt!("{}:{}", s(&entry.rhost), s(&entry.rfs))) else {
        error!(logopt, "do_nfs_mount", "parse(amd): error: rhost + rfs options length is too long");
        return 1;
    };
    let mut opts = entry.opts.as_deref().filter(|o| !o.is_empty());
    let proximity = get_network_proximity(entry.rhost.as_deref());
    if proximity == PROXIMITY_OTHER && nonempty(&entry.remopts) {
        opts = entry.remopts.as_deref();
    }
    let ty = entry.ty.clone().unwrap_or_default();
    let Some(fs) = entry.fs.clone() else {
        return nfs_mount(ap, &ap.path(), name, &target, &ty, opts);
    };
    let mut umount = false;
    if !mounts::is_mounted(&fs, MNTS_REAL) {
        let ret = nfs_mount(ap, &fs, &fs, &target, &ty, opts);
        if ret != 0 {
            return ret;
        }
        umount = true;
    }
    if umount && !mounts::ext_mount_add(&fs, entry.umount.as_deref()) {
        mounts::umount_ent(logopt, &fs);
        error!(logopt, "do_nfs_mount", "parse(amd): error: could not add external mount {}", fs);
        return 1;
    }
    do_link_mount(ap, name, entry, flags)
}

/// `do_nfsl_mount()`: a link when `rhost` is this host and the target exists,
/// else NFS.
fn do_nfsl_mount(ap: &Arc<AutofsPoint>, name: &[u8], entry: &AmdEntry, sv: &Table, flags: u64) -> i32 {
    let Some(host) = macros::macro_findvar(sv, b"host", 4) else {
        return do_nfs_mount(ap, name, entry, flags);
    };
    let hostd = match macros::macro_findvar(sv, b"hostd", 5) {
        Some(h) if !h.val.is_empty() => h,
        _ => return do_nfs_mount(ap, name, entry, flags),
    };
    let target = entry.sublink.clone().unwrap_or_else(|| s(&entry.fs));
    let rhost = s(&entry.rhost);
    if !cstr::caseeq(&host.val, &rhost) || !cstr::caseeq(&hostd.val, &rhost) || sys::lstat(&target).is_none() {
        return do_nfs_mount(ap, name, entry, flags);
    }
    do_link_mount(ap, name, entry, flags)
}

/// `do_program_mount()`: run `mount` (which mounts at `fs`), then link to it.
fn do_program_mount(ap: &Arc<AutofsPoint>, entry: &AmdEntry, name: &[u8]) -> i32 {
    let logopt = ap.logopt();
    let ty = s(&entry.ty);
    let fs = s(&entry.fs);
    let Some((prog, argv)) = construct_argv(&s(&entry.mount)) else {
        error!(logopt, "do_program_mount", "parse(amd): {}: error creating mount arguments", ty);
        return 1;
    };
    let mut rv: i32;
    if mounts::ext_mount_inuse(&fs) != 0 {
        rv = 0;
        mounts::ext_mount_add(&fs, entry.umount.as_deref());
    } else {
        rv = 0;
        let mut fail = false;
        if let Err(e) = lookup::mkdir_path(&fs, MP_MODE) {
            rv = -1;
            if e != libc::EEXIST {
                error!(
                    logopt,
                    "do_program_mount",
                    "parse(amd): {}: mkdir_path {} failed: {}",
                    ty,
                    fs,
                    sys::strerror(e)
                );
                fail = true;
            }
        }
        if fail {
            return rv;
        }
        rv = spawn::spawnv(logopt, &prog, &argv);
        let ok = libc::WIFEXITED(rv) && libc::WEXITSTATUS(rv) == 0;
        if ok && mounts::ext_mount_add(&fs, entry.umount.as_deref()) {
            debug!(logopt, "do_program_mount", "parse(amd): {}: mounted {}", ty, fs);
            rv = 0;
        } else {
            if ok {
                mounts::umount_ent(logopt, &fs);
            }
            if mounts::ext_mount_inuse(&fs) == 0 {
                let dev = ap.lock().dev;
                rmdir_path(ap, &fs, dev);
            }
            error!(logopt, "do_program_mount", "parse(amd): {}: failed to mount using {}", ty, s(&entry.mount));
        }
    }
    if rv != 0 {
        return rv;
    }
    rv = do_link_mount(ap, name, entry, 0);
    if rv == 0 {
        return 0;
    }
    if mounts::umount_amd_ext_mount(ap, &fs) != 0 {
        if mounts::ext_mount_inuse(&fs) == 0 {
            let dev = ap.lock().dev;
            rmdir_path(ap, &fs, dev);
        }
        debug!(logopt, "do_program_mount", "parse(amd): {}: failed to umount external mount at {}", ty, fs);
    }
    rv
}

/// `validate_auto_options()` (also `validate_link_options()`).
fn validate_auto_options(logopt: u32, entry: &AmdEntry) -> bool {
    match &entry.fs {
        None => {
            error!(logopt, "validate_auto_options", "parse(amd): {}: file system not given", s(&entry.ty));
            false
        }
        Some(fs) => !fs.is_empty(),
    }
}

/// `validate_nfs_options()`.
fn validate_nfs_options(logopt: u32, entry: &mut AmdEntry) -> bool {
    if !nonempty(&entry.rfs) {
        if entry.rfs.is_some() {
            return false;
        }
        // The map option fs has been left blank on purpose.
        if entry.fs.as_deref().is_some_and(|f| f.is_empty()) {
            return false;
        }
        match &entry.fs {
            Some(fs) => entry.rfs = Some(fs.clone()),
            None => {
                // strdup(NULL).
                sys::die_by_signal(libc::SIGSEGV);
            }
        }
    }
    if entry.sublink.is_some() && entry.fs.is_none() {
        // C's format has a second %s without an argument.
        error!(logopt, "validate_nfs_options", "parse(amd): {}: sublink option requires option fs", s(&entry.ty));
        return false;
    }
    true
}

/// `validate_generic_options()`.
fn validate_generic_options(logopt: u32, fstype: u64, entry: &AmdEntry) -> bool {
    if fstype != AMD_MOUNT_TYPE_LOFS {
        match &entry.dev {
            None => {
                error!(logopt, "validate_generic_options", "parse(amd): {}: mount device not given", s(&entry.ty));
                return false;
            }
            Some(d) if d.is_empty() => return false,
            _ => {}
        }
    } else {
        match &entry.rfs {
            None => {
                error!(logopt, "validate_generic_options", "parse(amd): lofs: mount device not given");
                return false;
            }
            Some(r) if r.is_empty() => return false,
            _ => {}
        }
    }
    if entry.sublink.is_some() && entry.fs.is_none() {
        // C's format has a second %s without an argument.
        error!(logopt, "validate_generic_options", "parse(amd): {}: sublink option requires option fs", s(&entry.ty));
        return false;
    }
    true
}

/// `validate_ufs_fstype()`.
fn validate_ufs_fstype(logopt: u32, entry: &AmdEntry) -> bool {
    let ty = s(&entry.ty);
    if [&b"ext"[..], b"ext2", b"ext3", b"ext4", b"xfs", b"jfs"].iter().any(|t| cstr::eq(&ty, t)) {
        return true;
    }
    // C's format has three %s and two arguments.
    error!(logopt, "validate_ufs_fstype", "parse(amd): {}: mount type {} not valid as ufs mount type on Linux", ty, ty);
    false
}

/// `validate_host_options()`.
fn validate_host_options(logopt: u32, entry: &AmdEntry) -> bool {
    match &entry.rhost {
        None => {
            error!(logopt, "validate_host_options", "parse(amd): {}: remote host name not given", s(&entry.ty));
            false
        }
        Some(r) => !r.is_empty(),
    }
}

/// `validate_program_options()`.
fn validate_program_options(logopt: u32, entry: &AmdEntry) -> bool {
    if entry.mount.is_none() {
        error!(logopt, "validate_program_options", "parse(amd): {}: mount program invalid or not set", s(&entry.ty));
        return false;
    }
    if !nonempty(&entry.fs) {
        error!(
            logopt,
            "validate_program_options",
            "parse(amd): {}: ${fs} must be used as the mount point but is not set",
            s(&entry.ty)
        );
        return false;
    }
    true
}

/// `wait_for_expire()`: wait out an expire; false if the autofs point is
/// shutting down.
fn wait_for_expire(ap: &Arc<AutofsPoint>) -> bool {
    state::st_wait_task(ap, state::ST_EXPIRE, 0);
    state::st_mutex_lock();
    let st = ap.lock().state;
    state::st_mutex_unlock();
    st != state::ST_SHUTDOWN && st != state::ST_SHUTDOWN_PENDING && st != state::ST_SHUTDOWN_FORCE
}

/// `do_host_mount()`: the host's exports, through an instance of the hosts
/// map, under the autofs point; a key other than the host's name becomes a
/// symlink to it.
fn do_host_mount(ap: &Arc<AutofsPoint>, name: &[u8], entry: &mut AmdEntry, source: &Arc<MapSource>) -> i32 {
    let logopt = ap.logopt();
    let rhost = s(&entry.rhost);
    let mut mnt: Option<Vec<u8>> = None;
    let mut ret = 1;
    'out: {
        // A mount point name that isn't the host's: point entry.path at the
        // base of the host's mount tree (lookup_nss_mount() finds it there)
        // and symlink to it after the mount.
        if !cstr::eq(name, &rhost) {
            entry.path = Some(bfmt!("{}/{}", ap.path(), rhost));
            // An mnt_list entry for the updated path.
            match mounts::mnts_add_amdmount(entry) {
                Some(mp) => mnt = Some(mp),
                None => {
                    error!(logopt, "do_host_mount", "parse(amd): failed to update mount mnt_list entry");
                    break 'out;
                }
            }
            // Wait for any expire before racing to mount the export tree, or
            // bail out if shutting down.
            if !wait_for_expire(ap) {
                break 'out;
            }
        }
        let argv: Argv = match entry.opts.as_deref() {
            Some(o) if !o.is_empty() => vec![Some(o.to_vec())],
            _ => Vec::new(),
        };
        let pargv = if argv.is_empty() { None } else { Some(&argv) };
        let instance = match master::master_find_source_instance(source, Some(b"hosts"), Some(b"sun"), pargv) {
            Some(i) => i,
            None => {
                master::master_add_source_instance(source, Some(b"hosts"), Some(b"sun"), sys::monotonic_time(), &argv)
            }
        };
        if instance.lock().lookup.is_none() {
            match module::open_lookup(b"hosts", Some(MODPREFIX), None, &argv) {
                Ok(l) => instance.lock().lookup = Some(l),
                Err(_) => {
                    debug!(logopt, "do_host_mount", "open lookup module hosts failed");
                    break 'out;
                }
            }
        }
        {
            let mc = source.mc();
            let mut c = mc.lock();
            if let Some(p) = c.lookup_distinct(name) {
                c.push_mapent(p, None);
            }
        }
        let l = instance.lock().lookup.clone().unwrap();
        ret = l.mount(ap, &instance, &rhost);
        if cstr::eq(name, &rhost) {
            break 'out;
        }
        let path = s(&entry.path);
        if do_mount(ap, &ap.path(), name, Some(&path), b"bind", Some(b"symlink")) != 0 {
            warn!(logopt, "parse(amd): failed to create symlink to hosts mount base");
        }
    }
    if ret != 0
        && let Some(mp) = mnt
    {
        mounts::mnts_remove_amdmount(&mp);
    }
    ret
}

/// `amd_mount()`: mount one location by its type.
fn amd_mount(
    ap: &Arc<AutofsPoint>,
    name: &[u8],
    entry: &mut AmdEntry,
    source: &Arc<MapSource>,
    sv: &Table,
    flags: u64,
) -> i32 {
    let logopt = ap.logopt();
    let fstype = entry.flags & AMD_MOUNT_TYPE_MASK;
    match fstype {
        AMD_MOUNT_TYPE_AUTO => {
            if !validate_auto_options(logopt, entry) {
                return 1;
            }
            do_auto_mount(ap, name, entry)
        }
        AMD_MOUNT_TYPE_LOFS => {
            if !validate_generic_options(logopt, fstype, entry) {
                return 1;
            }
            let t = s(&entry.rfs);
            do_generic_mount(ap, name, entry, &t, flags)
        }
        AMD_MOUNT_TYPE_UFS | AMD_MOUNT_TYPE_EXT | AMD_MOUNT_TYPE_XFS | AMD_MOUNT_TYPE_CDFS => {
            if fstype == AMD_MOUNT_TYPE_UFS && !validate_ufs_fstype(logopt, entry) {
                return 1;
            }
            if !validate_generic_options(logopt, fstype, entry) {
                return 1;
            }
            let t = s(&entry.dev);
            do_generic_mount(ap, name, entry, &t, flags)
        }
        AMD_MOUNT_TYPE_NFS => {
            if !validate_nfs_options(logopt, entry) {
                return 1;
            }
            do_nfs_mount(ap, name, entry, flags)
        }
        AMD_MOUNT_TYPE_NFSL => {
            if !validate_nfs_options(logopt, entry) || !validate_auto_options(logopt, entry) {
                return 1;
            }
            do_nfsl_mount(ap, name, entry, sv, flags)
        }
        AMD_MOUNT_TYPE_LINK => {
            if !validate_auto_options(logopt, entry) {
                return 1;
            }
            do_link_mount(ap, name, entry, flags)
        }
        AMD_MOUNT_TYPE_LINKX => {
            if !validate_auto_options(logopt, entry) {
                return 1;
            }
            do_linkx_mount(ap, name, entry, flags)
        }
        AMD_MOUNT_TYPE_HOST => {
            if !validate_host_options(logopt, entry) {
                return 1;
            }
            do_host_mount(ap, name, entry, source)
        }
        AMD_MOUNT_TYPE_PROGRAM => {
            if !validate_program_options(logopt, entry) {
                return 1;
            }
            do_program_mount(ap, entry, name)
        }
        _ => {
            info!(logopt, "parse(amd): unknown file system type {}", format!("{fstype:x}"));
            1
        }
    }
}

/// `dequote_entry()`.
fn dequote_entry(logopt: u32, entry: &mut AmdEntry) {
    let fields: [(&mut Option<Vec<u8>>, &str, bool); 7] = [
        (&mut entry.pref, "pref", false),
        (&mut entry.sublink, "sublink", false),
        (&mut entry.fs, "fs", true),
        (&mut entry.rfs, "rfs", true),
        (&mut entry.opts, "ops", true),
        (&mut entry.remopts, "remopts", true),
        (&mut entry.addopts, "addopts", true),
    ];
    for (field, label, need_nonempty) in fields {
        let Some(v) = field.clone() else { continue };
        if need_nonempty && v.is_empty() {
            continue;
        }
        if let Some(res) = parse_subs::dequote(&v, v.len(), logopt) {
            let m = bfmt!("dequote_entry: parse(amd): {} dequote(\"{}\") -> {}", label, v, res);
            crate::libautofs::log::log_debug(logopt, &m);
            *field = Some(res);
        }
    }
}

/// `normalize_sublink()`: a relative `sublink` is under `fs`.
fn normalize_sublink(logopt: u32, entry: &mut AmdEntry) {
    let fs = s(&entry.fs);
    match &entry.fs {
        Some(f) if !f.is_empty() => {}
        None => sys::die_by_signal(libc::SIGSEGV),
        _ => return,
    }
    if let Some(sl) = &entry.sublink
        && sl.first() != Some(&b'/')
    {
        let new = bfmt!("{}/{}", fs, sl);
        debug!(logopt, "normalize_sublink", "parse(amd): rfs dequote(\"{}\") -> {}", sl, new);
        entry.sublink = Some(new);
    }
}

/// `update_prefix()`: without a `pref`, the parent's prefix plus `name/`.
fn update_prefix(ap: &Arc<AutofsPoint>, entry: &mut AmdEntry, name: &[u8]) {
    if entry.pref.is_none()
        && let Some(p) = ap.lock().pref.clone()
    {
        entry.pref = Some(bfmt!("{}{}/", p, cstr::c(name)));
    }
}

/// `dup_defaults_entry()`: the defaults, without selectors, sublink or programs.
fn dup_defaults_entry(defaults: &AmdEntry) -> AmdEntry {
    let ne = |v: &Option<Vec<u8>>| v.clone().filter(|x| !x.is_empty());
    AmdEntry {
        flags: defaults.flags,
        ty: defaults.ty.clone(),
        map_type: defaults.map_type.clone(),
        pref: defaults.pref.clone(),
        fs: defaults.fs.clone(),
        rfs: ne(&defaults.rfs),
        rhost: ne(&defaults.rhost),
        dev: ne(&defaults.dev),
        opts: ne(&defaults.opts),
        addopts: ne(&defaults.addopts),
        remopts: ne(&defaults.remopts),
        ..AmdEntry::default()
    }
}

/// `make_default_entry()`: `opts:=rw,defaults`, with the configured map type.
fn make_default_entry(ap: &Arc<AutofsPoint>, sv: &Table) -> Option<AmdEntry> {
    let mut dflts = Vec::new();
    if amd_parse_list(ap, b"opts:=rw,defaults", &mut dflts, sv) != 0 {
        return None;
    }
    let mut e = dflts.into_iter().next()?;
    if let Some(mt) = defaults::conf_amd_get_map_type(Some(&ap.path())) {
        let hesiod = cstr::eq(&mt, b"hesiod");
        e.map_type = Some(mt);
        if hesiod {
            warn!(ap.logopt(), "parse(amd): hesiod support not built in, defaults map entry not set");
            return None;
        }
    }
    Some(e)
}

/// `select_default_entry()`: which of the parsed `/defaults` locations to use.
fn select_default_entry(ap: &Arc<AutofsPoint>, mut entries: Vec<AmdEntry>, sv: &Table) -> Option<AmdEntry> {
    let logopt = ap.logopt();
    let flags = defaults::conf_amd_get_flags(Some(&ap.path()));
    if flags & defaults::CONF_SELECTORS_IN_DEFAULTS == 0 {
        if entries.is_empty() {
            return make_default_entry(ap, sv);
        }
        let first = entries.remove(0);
        if !entries.is_empty() {
            return make_default_entry(ap, sv);
        }
        return Some(first);
    }
    let mut entry_default: Option<AmdEntry> = None;
    let mut defaults_entry: Option<AmdEntry> = None;
    for this in entries {
        if this.flags & AMD_DEFAULTS_MERGE != 0 {
            entry_default = Some(this);
            continue;
        } else if this.flags & AMD_DEFAULTS_RESET != 0 {
            // QUIRK: dup_defaults_entry(defaults_entry), which is NULL here.
            match &defaults_entry {
                None => sys::die_by_signal(libc::SIGSEGV),
                Some(d) => entry_default = Some(dup_defaults_entry(d)),
            }
            continue;
        }
        if this.selector.is_empty() {
            continue;
        }
        if match_selectors(logopt, &this, sv) {
            defaults_entry = Some(this);
            break;
        }
    }
    if defaults_entry.is_none() && entry_default.is_some() {
        return entry_default;
    }
    if defaults_entry.is_none() {
        debug!(
            logopt,
            "select_default_entry", "parse(amd): no matching selector(s) found in defaults, using internal defaults"
        );
        return make_default_entry(ap, sv);
    }
    defaults_entry
}

/// `get_defaults_entry()`.
fn get_defaults_entry(ap: &Arc<AutofsPoint>, defaults: Option<&[u8]>, sv: &Table) -> Option<AmdEntry> {
    let logopt = ap.logopt();
    let Some(defaults) = defaults else { return make_default_entry(ap, sv) };
    let Some(expand) = expand_selectors(logopt, Some(defaults), sv) else { return make_default_entry(ap, sv) };
    let mut dflts = Vec::new();
    if amd_parse_list(ap, &expand, &mut dflts, sv) != 0 {
        error!(
            logopt,
            "get_defaults_entry", "parse(amd): failed to parse defaults entry, attempting to use internal default"
        );
        return make_default_entry(ap, sv);
    }
    let mut entry = select_default_entry(ap, dflts, sv);
    if let Some(e) = entry.as_mut()
        && e.map_type.is_none()
        && let Some(mt) = defaults::conf_amd_get_map_type(Some(&ap.path()))
    {
        let hesiod = cstr::eq(&mt, b"hesiod");
        e.map_type = Some(mt);
        if hesiod {
            warn!(logopt, "parse(amd): hesiod support not built in, attempting to use internal default");
            return make_default_entry(ap, sv);
        }
    }
    entry
}

/// `setup_defaults()`: the lookup's variables and its defaults entry.
fn setup_defaults(ap: &Arc<AutofsPoint>, name: &[u8], source: &Arc<MapSource>) -> (Option<AmdEntry>, Option<Table>) {
    let logopt = ap.logopt();
    let Some(nsv) = add_lookup_vars(ap, name, source) else { return (None, None) };
    let path = ap.path();
    let mut defaults = defaults::conf_amd_get_map_defaults(Some(&path));
    if let Some(d) = &defaults {
        debug!(logopt, "setup_defaults", "parse(amd): using map_defaults {} for {}", d, path);
    } else {
        let mc = source.mc();
        let c = mc.lock();
        if let Some(p) = c.lookup_distinct(b"/defaults") {
            let m = c.get(p).mapent.clone();
            match m {
                // strdup(NULL).
                None => sys::die_by_signal(libc::SIGSEGV),
                Some(m) => {
                    debug!(logopt, "setup_defaults", "parse(amd): using /defaults {} from map", m);
                    defaults = Some(m);
                }
            }
        }
    }
    match get_defaults_entry(ap, defaults.as_deref(), &nsv) {
        Some(d) => (Some(d), Some(nsv)),
        None => {
            error!(logopt, "setup_defaults", "parse(amd): failed to get a defaults entry");
            (None, None)
        }
    }
}

impl ParseAmd {
    /// `parse_mount()`.
    fn mount_impl(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>, name: &[u8], mapent: Option<&[u8]>) -> i32 {
        let logopt = ap.logopt();
        let flags = defaults::conf_amd_get_flags(Some(&ap.path())) & 0xffff_ffff;
        let Some(mapent) = mapent else {
            warn!(logopt, "parse(amd): error: empty map entry");
            return 1;
        };
        let (defaults_entry, sv) = setup_defaults(ap, name, source);
        let Some(mut defaults_entry) = defaults_entry else {
            error!(logopt, "parse_mount", "parse(amd): failed to setup defaults entry");
            return 1;
        };
        let mut sv = sv.unwrap_or_default();
        let mut entries = Vec::new();
        if amd_parse_list(ap, mapent, &mut entries, &sv) != 0 {
            error!(logopt, "parse_mount", "parse(amd): failed to parse entry: {}", mapent);
            return 1;
        }
        if entries.is_empty() {
            error!(logopt, "parse_mount", "parse(amd): no location found after parse");
            return 1;
        }
        let mut cur_defaults = dup_defaults_entry(&defaults_entry);
        let mut at_least_one = false;
        let mut rv = 1;
        for mut this in entries {
            if this.flags & AMD_DEFAULTS_MERGE != 0 {
                cur_defaults = this;
                update_with_defaults(&defaults_entry, &mut cur_defaults, &sv);
                debug!(logopt, "parse_mount", "merged /defaults entry with defaults");
                continue;
            } else if this.flags & AMD_DEFAULTS_RESET != 0 {
                if let (Some(nd), Some(nsv)) = setup_defaults(ap, name, source) {
                    defaults_entry = nd;
                    sv = nsv;
                }
                cur_defaults = dup_defaults_entry(&defaults_entry);
                continue;
            }
            debug!(logopt, "parse_mount", "expand defaults entry");
            expand_entry(ap, &mut cur_defaults, flags, &mut sv);
            if this.flags & AMD_ENTRY_CUT != 0 && at_least_one {
                info!(logopt, "parse(amd): at least one entry tried before cut selector, not continuing");
                break;
            }
            if !match_selectors(logopt, &this, &sv) {
                continue;
            }
            at_least_one = true;
            debug!(logopt, "parse_mount", "update mount entry with defaults");
            update_with_defaults(&cur_defaults, &mut this, &sv);
            debug!(logopt, "parse_mount", "expand mount entry");
            expand_entry(ap, &mut this, flags, &mut sv);
            merge_entry_options(logopt, &mut this, &mut sv);
            normalize_sublink(logopt, &mut this);
            update_prefix(ap, &mut this, name);
            dequote_entry(logopt, &mut this);
            let Some(mnt_mp) = mounts::mnts_add_amdmount(&this) else {
                error!(logopt, "parse_mount", "parse(amd): failed to add mount to mnt_list");
                break;
            };
            rv = amd_mount(ap, name, &mut this, source, &sv, flags);
            if rv == 0 {
                if !cstr::eq(&s(&this.path), &mnt_mp) {
                    mounts::mnts_add_mount(ap, &s(&this.rhost), MNTS_INDIRECT | MNTS_MOUNTED);
                }
                break;
            }
            mounts::mnts_remove_amdmount(&s(&this.path));
        }
        if rv != 0 {
            debug!(logopt, "parse_mount", "parse(amd): no more locations to try, returning fail");
        }
        rv
    }
}

impl ParseMod for ParseAmd {
    fn reinit(&self, _argv: &Argv) -> i32 {
        0
    }

    fn mount(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8], mapent: Option<&[u8]>) -> i32 {
        self.mount_impl(ap, map, name, mapent)
    }

    fn done(&self) -> i32 {
        let m = {
            let mut g = NFS.lock().unwrap();
            g.1 = g.1.wrapping_sub(1);
            if g.1 == 0 { g.0.take() } else { None }
        };
        m.map_or(0, module::close_mount)
    }
}
