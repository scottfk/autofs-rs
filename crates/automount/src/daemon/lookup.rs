//! `daemon/lookup.c`: nsswitch semantics for reading the master map and the
//! maps. (Mount lookups come with the daemon, in phase 3.)

use std::sync::Arc;

use crate::daemon::master::{self, AutofsPoint, LKP_INDIRECT, MAP_FLAG_FORMAT_AMD, MapSource, Master};
use crate::daemon::module;
use crate::libautofs::args::{self, Argv};
use crate::libautofs::cstr;
use crate::libautofs::defaults::{self, AUTOFS_MAP_DIR};
use crate::libautofs::nsswitch::{
    self, NSS_STATUS_NOTFOUND, NSS_STATUS_SUCCESS, NSS_STATUS_TRYAGAIN, NSS_STATUS_UNAVAIL, NSS_STATUS_UNKNOWN,
};
use crate::sys;

/// `do_read_master()`.
fn do_read_master(master: &Arc<Master>, ty: &[u8], age: i64) -> i32 {
    let argv: Argv = vec![Some(master.name())];
    let mut lookup = match module::open_lookup(ty, Some(b""), None, &argv) {
        Ok(l) => l,
        Err(s) => return s,
    };
    let status = lookup.read_master(master, age);
    module::close_lookup(lookup);
    status
}

/// `find_map_path()`.
fn find_map_path(ap: &Arc<AutofsPoint>, map: &MapSource) -> Option<Vec<u8>> {
    let (mname, flags) = {
        let m = map.lock();
        (args::arg(&m.argv, 0).unwrap_or(b"").to_vec(), m.flags)
    };
    if mname.first() == Some(&b'/') {
        return Some(mname);
    }
    let mut search_path = AUTOFS_MAP_DIR.to_vec();
    if flags & MAP_FLAG_FORMAT_AMD != 0 {
        let mut pap = ap.clone();
        while let Some(p) = pap.parent.clone() {
            pap = p;
        }
        if let Some(t) = defaults::conf_amd_get_search_path(Some(&pap.path())) {
            search_path = t;
        }
    }
    for tok in search_path.split(|&b| b == b':').filter(|t| !t.is_empty()) {
        let mut this = tok.to_vec();
        this.push(b'/');
        this.extend_from_slice(&mname);
        if sys::stat(&this).is_some() {
            return Some(this);
        }
    }
    None
}

/// `read_master_map()`.
fn read_master_map(master: &Arc<Master>, ty: &[u8], age: i64) -> i32 {
    let logopt = master.logopt();
    if !cstr::caseeq(ty, b"files") {
        return do_read_master(master, ty, age);
    }
    let name = master.name();
    if cstr::strchr(&name, b'/').is_some() {
        error!(logopt, "read_master_map", "relative path invalid in files map name");
        return NSS_STATUS_NOTFOUND;
    }
    let mut path = AUTOFS_MAP_DIR.to_vec();
    path.push(b'/');
    path.extend_from_slice(&name);
    master.set_name(path);
    let result = do_read_master(master, ty, age);
    master.set_name(name);
    result
}

/// `lookup_nss_read_master()`.
pub fn lookup_nss_read_master(master: &Arc<Master>, age: i64) -> i32 {
    let logopt = master.logopt();
    let name = master.name();
    if name.first() == Some(&b'/') {
        let result = if name.get(1) == Some(&b'/') {
            info!(logopt, "reading ldap master {}", name);
            do_read_master(master, b"ldap", age)
        } else {
            debug!(logopt, "lookup_nss_read_master", "reading master file {}", name);
            do_read_master(master, b"file", age)
        };
        if result == NSS_STATUS_UNAVAIL {
            master.lock().read_fail = true;
        }
        return result;
    }
    // Old style name specification will remain I think.
    if let Some(colon) = cstr::strchr(&name, b':') {
        let at = |i: usize| name.get(i).copied().unwrap_or(0);
        let pre = |p: &[u8], n: usize| cstr::neq(&name, p, n) && (at(n) == b',' || at(n) == b':');
        // QUIRK: the sss test is `||` where the others are `&&`, so any name
        // with ',' or ':' at offset 3 matches.
        if pre(b"file", 4)
            || pre(b"yp", 2)
            || pre(b"nis", 3)
            || pre(b"nisplus", 7)
            || pre(b"ldap", 4)
            || pre(b"ldaps", 5)
            || (cstr::neq(&name, b"sss", 3) || at(3) == b',' || at(3) == b':')
            || pre(b"dir", 3)
        {
            let source = name[..colon.min(9)].to_vec();
            if !cstr::neq(&name, b"ldap", 4) {
                master.set_name(name[colon + 1..].to_vec());
                info!(logopt, "reading {} master {}", source, master.name());
            } else {
                debug!(logopt, "lookup_nss_read_master", "reading master {} {}", source, &name[colon + 1..]);
            }
            let result = do_read_master(master, &source, age);
            master.set_name(name);
            if result == NSS_STATUS_UNAVAIL {
                master.lock().read_fail = true;
            }
            return result;
        }
    }
    let mut nsslist = Vec::new();
    if nsswitch::nsswitch_parse(&mut nsslist).is_err() {
        error!(logopt, "lookup_nss_read_master", "can't to read name service switch config.");
        return NSS_STATUS_UNAVAIL;
    }
    let mut result = NSS_STATUS_SUCCESS;
    for this in &nsslist {
        let src = &this.source;
        if !cstr::neq(src, b"files", 5)
            && !cstr::neq(src, b"nis", 3)
            && !cstr::neq(src, b"nisplus", 7)
            && !cstr::neq(src, b"ldap", 4)
            && !cstr::neq(src, b"sss", 3)
        {
            continue;
        }
        info!(logopt, "reading {} master {}", src, master.name());
        result = read_master_map(master, src, age);
        let depth = master.lock().depth;
        if result != NSS_STATUS_SUCCESS && depth == 0 && !defaults::defaults_master_set() {
            let mname = master.name();
            if let Some(dot) = cstr::strchr(&mname, b'.') {
                debug!(logopt, "lookup_nss_read_master", "{} not found, replacing '.' with '_'", mname);
                let mut n = mname.clone();
                n[dot] = b'_';
                master.set_name(n);
                result = read_master_map(master, src, age);
                if result != NSS_STATUS_SUCCESS {
                    master.set_name(mname);
                }
            }
        }
        if result == NSS_STATUS_TRYAGAIN {
            result = NSS_STATUS_SUCCESS;
            continue;
        }
        if result == NSS_STATUS_UNKNOWN || result == NSS_STATUS_NOTFOUND {
            debug!(logopt, "lookup_nss_read_master", "no map - continuing to next source");
            result = NSS_STATUS_SUCCESS;
            continue;
        }
        if result == NSS_STATUS_UNAVAIL {
            master.lock().read_fail = true;
        }
        if nsswitch::check_nss_result(this, result) >= 0 {
            break;
        }
    }
    result
}

/// `do_read_map()`.
fn do_read_map(ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, age: i64) -> i32 {
    let logopt = ap.logopt();
    if !map.lock().stale {
        return NSS_STATUS_SUCCESS;
    }
    let has_lookup = map.lock().lookup.is_some();
    if !has_lookup {
        let (ty, format, argv) = {
            let m = map.lock();
            (m.ty.clone().unwrap_or_default(), m.format.clone(), m.argv.clone())
        };
        match module::open_lookup(&ty, Some(b""), format.as_deref(), &argv) {
            Ok(l) => map.lock().lookup = Some(l),
            Err(status) => {
                debug!(logopt, "do_read_map", "lookup module {} open failed", ty);
                return status;
            }
        }
    } else {
        let (format, argv) = {
            let m = map.lock();
            (m.format.clone(), m.argv.clone())
        };
        let mut l = map.lock().lookup.take().unwrap();
        let status = l.reinit(format.as_deref(), &argv);
        map.lock().lookup = Some(l);
        if status != 0 {
            warn!(logopt, "lookup module {} reinit failed", map.ty().unwrap_or_default());
            return status;
        }
    }
    let mut l = map.lock().lookup.take().unwrap();
    let status = l.read_map(ap, map, age);
    map.lock().lookup = Some(l);
    if status != NSS_STATUS_SUCCESS {
        map.lock().stale = false;
    }
    if status == NSS_STATUS_UNKNOWN || (ap.ty() == LKP_INDIRECT && status == NSS_STATUS_UNAVAIL) {
        return NSS_STATUS_SUCCESS;
    }
    status
}

/// `read_file_source_instance()`.
fn read_file_source_instance(ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, age: i64) -> i32 {
    let logopt = ap.logopt();
    if map.argv().is_empty() {
        error!(logopt, "read_file_source_instance", "invalid arguments for autofs_point");
        return NSS_STATUS_UNKNOWN;
    }
    let Some(path) = find_map_path(ap, map) else { return NSS_STATUS_UNKNOWN };
    let Some(st) = sys::stat(&path) else {
        warn!(logopt, "file map {} not found", path);
        return NSS_STATUS_NOTFOUND;
    };
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return NSS_STATUS_NOTFOUND;
    }
    let ty: &[u8] = if st.st_mode & libc::S_IEXEC != 0 { b"program" } else { b"file" };
    let format = map.format();
    let instance = match master::master_find_source_instance(map, Some(ty), format.as_deref(), None) {
        Some(i) => i,
        None => {
            let mut argv = map.argv();
            argv[0] = Some(path);
            let i = master::master_add_source_instance(map, Some(ty), format.as_deref(), age, &argv);
            let (recurse, depth) = {
                let m = map.lock();
                (m.recurse, m.depth)
            };
            let mut il = i.lock();
            il.recurse = recurse;
            il.depth = depth;
            drop(il);
            i
        }
    };
    let stale = map.lock().stale;
    instance.lock().stale = stale;
    do_read_map(ap, &instance, age)
}

/// `read_source_instance()`.
fn read_source_instance(ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, ty: &[u8], age: i64) -> i32 {
    let format = map.format();
    let instance = match master::master_find_source_instance(map, Some(ty), format.as_deref(), None) {
        Some(i) => i,
        None => {
            let argv = map.argv();
            let i = master::master_add_source_instance(map, Some(ty), format.as_deref(), age, &argv);
            let (recurse, depth) = {
                let m = map.lock();
                (m.recurse, m.depth)
            };
            let mut il = i.lock();
            il.recurse = recurse;
            il.depth = depth;
            drop(il);
            i
        }
    };
    let stale = map.lock().stale;
    instance.lock().stale = stale;
    do_read_map(ap, &instance, age)
}

/// `lookup_map_read_map()`.
fn lookup_map_read_map(ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, age: i64) -> i32 {
    let (ty, a0) = {
        let m = map.lock();
        (m.ty.clone().unwrap_or_default(), args::arg(&m.argv, 0).map(|a| a.to_vec()))
    };
    let Some(a0) = a0 else {
        if cstr::eq(&ty, b"hosts") {
            return do_read_map(ap, map, age);
        }
        return NSS_STATUS_UNKNOWN;
    };
    if !cstr::neq(&ty, b"file", 4) {
        return do_read_map(ap, map, age);
    }
    if a0.first() == Some(&b'/') {
        return do_read_map(ap, map, age);
    }
    let Some(path) = find_map_path(ap, map) else { return NSS_STATUS_UNKNOWN };
    map.lock().argv[0] = Some(path);
    do_read_map(ap, map, age)
}

/// `read_map_source()`.
fn read_map_source(this: &nsswitch::NssSource, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, age: i64) -> i32 {
    if !cstr::caseeq(&this.source, b"files") {
        return read_source_instance(ap, map, &this.source, age);
    }
    let a0 = args::arg(&map.argv(), 0).unwrap_or(b"").to_vec();
    if cstr::strchr(&a0, b'/').is_some() {
        error!(ap.logopt(), "read_map_source", "relative path invalid in files map name");
        return NSS_STATUS_NOTFOUND;
    }
    read_file_source_instance(ap, map, age)
}

/// `lookup_nss_read_map()`: true (C's 1) if the maps were read.
pub fn lookup_nss_read_map(ap: &Arc<AutofsPoint>, source: Option<&Arc<MapSource>>, age: i64) -> bool {
    let logopt = ap.logopt();
    let entry = ap.entry();
    // C walks `map->next` from `source`: the rest of the entry's list, or for an
    // instance (an included map) the rest of the instance list it's in, the
    // instances added before it.
    fn tail_in(list: &[Arc<MapSource>], s: &Arc<MapSource>) -> Option<Vec<Arc<MapSource>>> {
        if let Some(i) = list.iter().position(|m| Arc::ptr_eq(m, s)) {
            return Some(list[i..].to_vec());
        }
        list.iter().find_map(|m| tail_in(&m.instances(), s))
    }
    let maps: Vec<Arc<MapSource>> = match source {
        Some(s) => tail_in(&entry.maps(), s).unwrap_or_else(|| vec![s.clone()]),
        None => entry.maps(),
    };
    let mut result = 0;
    let mut at_least_one = false;
    let entry_age = entry.lock().age;
    let mut i = 0;
    while i < maps.len() {
        let map = &maps[i];
        let (stale, mage, ty, a0) = {
            let m = map.lock();
            (m.stale, m.age, m.ty.clone(), args::arg(&m.argv, 0).map(|a| a.to_vec()))
        };
        if !stale || entry_age > mage {
            i += 1;
            continue;
        }
        if let Some(t) = &ty {
            if cstr::neq(t, b"multi", 5) {
                debug!(logopt, "lookup_nss_read_map", "reading multi map");
            } else {
                info!(logopt, "reading {} map {}", t, master::cstr_or_null(&a0));
            }
            result = lookup_map_read_map(ap, map, age);
            i += 1;
            continue;
        }
        if let Some(a0) = &a0
            && a0.first() == Some(&b'/')
        {
            if a0.get(1) == Some(&b'/') {
                map.lock().ty = Some(b"ldap".to_vec());
                info!(logopt, "reading {} map {}", "ldap", a0);
                result = do_read_map(ap, map, age);
            } else {
                debug!(logopt, "lookup_nss_read_map", "reading map file {}", a0);
                result = read_file_source_instance(ap, map, age);
            }
            i += 1;
            continue;
        }
        let mut nsslist = Vec::new();
        if nsswitch::nsswitch_parse(&mut nsslist).is_err() {
            error!(logopt, "lookup_nss_read_map", "can't to read name service switch config.");
            result = 1;
            break;
        }
        let mut stop = false;
        for this in &nsslist {
            if map.lock().flags & MAP_FLAG_FORMAT_AMD != 0 && cstr::eq(&this.source, b"sss") {
                warn!(logopt, "source sss is not available for amd maps.");
                continue;
            }
            info!(logopt, "reading {} map {}", this.source, master::cstr_or_null(&a0));
            result = read_map_source(this, ap, map, age);
            if result == NSS_STATUS_UNKNOWN {
                continue;
            }
            if result == NSS_STATUS_UNAVAIL {
                map.lock().stale = false;
            }
            if result == NSS_STATUS_SUCCESS {
                at_least_one = true;
                result = NSS_STATUS_TRYAGAIN;
            }
            if nsswitch::check_nss_result(this, result) >= 0 {
                stop = true;
                break;
            }
            result = NSS_STATUS_SUCCESS;
        }
        if stop {
            break;
        }
        i += 1;
    }
    result == 0 || at_least_one
}

/// `lookup_close_lookup()`.
pub fn lookup_close_lookup(ap: &Arc<AutofsPoint>) {
    fn close_instances(map: &MapSource) {
        for inst in map.instances() {
            close_instances(&inst);
        }
        let l = map.lock().lookup.take();
        if let Some(l) = l {
            module::close_lookup(l);
        }
    }
    for map in ap.entry().maps() {
        close_instances(&map);
    }
}

/// `lookup_prune_cache()`.
///
/// Map reads mark every entry they see with the read's age, so in a dump there
/// is nothing older to prune; pruning what a reread no longer has (and the
/// mounts that keep entries alive) comes with the daemon in phase 3. What's
/// here is the part a dump does: resetting the status of current entries, and
/// clearing the stale flags.
pub fn lookup_prune_cache(ap: &Arc<AutofsPoint>, age: i64) -> bool {
    for map in ap.entry().maps() {
        if !map.lock().stale && !master::check_stale_instances(&map) {
            continue;
        }
        let mc = map.mc();
        {
            let mut c = mc.lock();
            let mut p = c.enumerate(None);
            while let Some(pos) = p {
                if c.get(pos).age >= age {
                    let reset = c.get(pos).mapent.is_some() || c.lookup(b"*").is_some();
                    if reset {
                        c.get_mut(pos).status = 0;
                    }
                }
                p = c.enumerate(Some(pos));
            }
        }
        master::clear_stale_instances(&map);
        map.lock().stale = false;
    }
    true
}
