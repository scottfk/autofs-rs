//! `daemon/lookup.c`: nsswitch semantics for reading the master map and the
//! maps, and for looking keys up (`lookup_nss_mount()`), with the negative
//! cache and the browse directories (`lookup_ghost()`).

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
    let lookup = match module::open_lookup(ty, Some(b""), None, &argv) {
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
        let l = map.lock().lookup.clone().unwrap();
        let status = l.reinit(format.as_deref(), &argv);
        if status != 0 {
            warn!(logopt, "lookup module {} reinit failed", map.ty().unwrap_or_default());
            return status;
        }
    }
    let l = map.lock().lookup.clone().unwrap();
    let status = l.read_map(ap, map, age);
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

/// `make_fullpath()`: a key's mount point.
fn make_fullpath(ap: &Arc<AutofsPoint>, key: &[u8]) -> Option<Vec<u8>> {
    if key.first() != Some(&b'/') {
        let (path, pref) = {
            let a = ap.lock();
            (a.path.clone(), a.pref.clone())
        };
        make_browse_path(&path, key, pref.as_deref())
    } else {
        if key.len() + 1 > 255 {
            return None;
        }
        Some(key.to_vec())
    }
}

/// `lookup_source_valid_mapent()`: the first entry for `key` in a map source
/// read since the master map entry changed.
pub fn lookup_source_valid_mapent(
    ap: &Arc<AutofsPoint>,
    key: &[u8],
    distinct: bool,
) -> Option<(Arc<crate::libautofs::cache::Cache>, crate::libautofs::cache::Pos)> {
    let entry = ap.entry();
    let eage = entry.lock().age;
    for map in entry.maps() {
        if eage > map.lock().age {
            continue;
        }
        let mc = map.mc();
        let p = {
            let c = mc.lock();
            if distinct { c.lookup_distinct(key) } else { c.lookup(key) }
        };
        if let Some(p) = p {
            return Some((mc, p));
        }
    }
    None
}

/// `lookup_prune_one_cache()`: drop the entries a map read didn't see, unless
/// they're mounted (or, without browsing, younger than the positive timeout).
pub fn lookup_prune_one_cache(ap: &Arc<AutofsPoint>, mc: &Arc<crate::libautofs::cache::Cache>, age: i64) {
    use crate::daemon::master::{MOUNT_FLAG_AMD_CACHE_ALL, MOUNT_FLAG_GHOST};
    use crate::libautofs::cache::CHE_FAIL;
    use crate::libautofs::mounts::{MNTS_AUTOFS, MNTS_REAL};
    let logopt = ap.logopt();
    let (ty, flags, positive_timeout) = {
        let a = ap.lock();
        (a.ty, a.flags, a.positive_timeout as i64)
    };
    let mut cur = mc.lock().enumerate(None);
    while let Some(p) = cur {
        let e = {
            let mut c = mc.lock();
            if p.0 >= c.hash.len() || p.1 >= c.hash[p.0].len() {
                break;
            }
            let e = c.get(p).clone();
            let mut skip = false;
            if e.age >= age {
                // Retry valid entries (and ones a failed wildcard lookup made).
                if e.mapent.is_some() || c.lookup(b"*").is_some() {
                    c.get_mut(p).status = 0;
                }
                skip = true;
            } else if ty == LKP_INDIRECT {
                // Offsets are managed by expire; a multi-mount's owner stays.
                if e.key.first() == Some(&b'/') || e.is_mm_root() {
                    skip = true;
                } else if flags & (MOUNT_FLAG_GHOST | MOUNT_FLAG_AMD_CACHE_ALL) == 0 {
                    // An unread map keeps entries for the positive timeout.
                    let until = e.age + positive_timeout;
                    if age - until < 0 {
                        skip = true;
                    }
                }
            }
            if !skip && cstr::strchr(&e.key, b'*').is_some() {
                skip = true;
            }
            if skip {
                cur = c.enumerate(Some(p));
                continue;
            }
            e
        };
        let key = cstr::c(&e.key).to_vec();
        let Some(path) = make_fullpath(ap, &key) else {
            warn!(logopt, "can't malloc storage for path");
            cur = mc.lock().enumerate(Some(p));
            continue;
        };
        // Another valid entry for the key takes the mount (or this is just
        // a stale indirect entry).
        let mut valid = lookup_source_valid_mapent(ap, &key, true);
        if let Some((vmc, vp)) = &valid
            && Arc::ptr_eq(vmc, mc)
        {
            debug!(logopt, "lookup_prune_one_cache", "removed map entry detected, mark negative");
            vmc.lock().get_mut(*vp).mapent = None;
            valid = None;
        }
        if valid.is_none() && crate::libautofs::mounts::is_mounted(&path, MNTS_REAL) {
            debug!(logopt, "lookup_prune_one_cache", "prune postponed, {} mounted", path);
            cur = mc.lock().enumerate(Some(p));
            continue;
        }
        let next_key = {
            let c = mc.lock();
            c.enumerate(Some(p)).map(|n| c.get(n).key.clone())
        };
        let this = {
            let c = mc.lock();
            c.lookup_distinct(&key).map(|q| (c.get(q).ioctlfd, c.get(q).dev))
        };
        if let Some((ioctlfd, edev)) = this {
            if valid.is_some() {
                mc.lock().delete(&key);
            } else if !crate::libautofs::mounts::is_mounted(&path, MNTS_AUTOFS) {
                let devid = if ty == master::LKP_DIRECT { edev } else { ap.lock().dev };
                let mut status = CHE_FAIL;
                if ioctlfd == -1 {
                    status = mc.lock().delete(&key);
                }
                if status != CHE_FAIL && (ty != LKP_INDIRECT || flags & MOUNT_FLAG_GHOST != 0) {
                    crate::daemon::automount::rmdir_path(ap, &path, devid);
                }
            }
        }
        cur = match next_key {
            Some(k) => mc.lock().lookup_distinct(&k),
            None => None,
        };
    }
}

/// `lookup_prune_cache()`.
pub fn lookup_prune_cache(ap: &Arc<AutofsPoint>, age: i64) -> bool {
    let entry = ap.entry();
    entry.source_readlock();
    for map in entry.maps() {
        if !map.lock().stale && !master::check_stale_instances(&map) {
            continue;
        }
        let mc = map.mc();
        lookup_prune_one_cache(ap, &mc, age);
        master::clear_stale_instances(&map);
        map.lock().stale = false;
    }
    entry.source_unlock();
    true
}

/// `lookup_source_mapent()`: the first map source's cache entry for `key`
/// (`distinct`: no wildcard), with the cache it's in.
pub fn lookup_source_mapent(
    ap: &Arc<AutofsPoint>,
    key: &[u8],
    distinct: bool,
) -> Option<(Arc<crate::libautofs::cache::Cache>, crate::libautofs::cache::Pos)> {
    for map in ap.entry().maps() {
        let mc = map.mc();
        let p = {
            let c = mc.lock();
            if distinct { c.lookup_distinct(key) } else { c.lookup(key) }
        };
        if let Some(p) = p {
            return Some((mc, p));
        }
    }
    None
}

/// `do_lookup_mount()`.
pub fn do_lookup_mount(ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
    if map.lock().lookup.is_none() {
        let (ty, format, argv) = {
            let m = map.lock();
            (m.ty.clone().unwrap_or_default(), m.format.clone(), m.argv.clone())
        };
        match module::open_lookup(&ty, Some(b""), format.as_deref(), &argv) {
            Ok(l) => map.lock().lookup = Some(l),
            Err(status) => {
                debug!(ap.logopt(), "do_lookup_mount", "lookup module {} open failed", ty);
                return status;
            }
        }
    }
    // Shared with any other lookup in this map, nested or concurrent.
    let l = map.lock().lookup.clone().unwrap();
    l.mount(ap, map, name)
}

/// `lookup_name_file_source_instance()`.
fn lookup_name_file_source_instance(ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
    let logopt = ap.logopt();
    let age = sys::monotonic_time();
    if name.first() == Some(&b'/') && map.lock().flags & MAP_FLAG_FORMAT_AMD != 0 {
        panic!("amd host instance lookups aren't ported yet (phase 5, with the hosts map)");
    }
    if map.argv().is_empty() {
        error!(logopt, "lookup_name_file_source_instance", "invalid arguments for autofs_point");
        return NSS_STATUS_UNKNOWN;
    }
    let Some(path) = find_map_path(ap, map) else { return NSS_STATUS_UNKNOWN };
    let Some(st) = sys::stat(&path) else {
        debug!(logopt, "lookup_name_file_source_instance", "file map not found");
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
    do_lookup_mount(ap, &instance, name)
}

/// `lookup_name_source_instance()`.
fn lookup_name_source_instance(ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, ty: &[u8], name: &[u8]) -> i32 {
    let age = sys::monotonic_time();
    if name.first() == Some(&b'/') && map.lock().flags & MAP_FLAG_FORMAT_AMD != 0 {
        panic!("amd host instance lookups aren't ported yet (phase 5, with the hosts map)");
    }
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
    do_lookup_mount(ap, &instance, name)
}

/// `do_name_lookup_mount()`.
fn do_name_lookup_mount(ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
    let (ty, a0, flags) = {
        let m = map.lock();
        (m.ty.clone().unwrap_or_default(), args::arg(&m.argv, 0).map(|a| a.to_vec()), m.flags)
    };
    let Some(a0) = a0 else {
        if cstr::eq(&ty, b"hosts") {
            return do_lookup_mount(ap, map, name);
        }
        return NSS_STATUS_UNKNOWN;
    };
    if name.first() == Some(&b'/') && flags & MAP_FLAG_FORMAT_AMD != 0 {
        panic!("amd host instance lookups aren't ported yet (phase 5, with the hosts map)");
    }
    if !cstr::neq(&ty, b"file", 4) || a0.first() == Some(&b'/') {
        return do_lookup_mount(ap, map, name);
    }
    let Some(path) = find_map_path(ap, map) else { return NSS_STATUS_UNKNOWN };
    map.lock().argv[0] = Some(path);
    do_lookup_mount(ap, map, name)
}

/// `lookup_map_name()`.
fn lookup_map_name(this: &nsswitch::NssSource, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
    if !cstr::caseeq(&this.source, b"files") {
        return lookup_name_source_instance(ap, map, &this.source, name);
    }
    let a0 = args::arg(&map.argv(), 0).unwrap_or(b"").to_vec();
    if cstr::strchr(&a0, b'/').is_some() {
        error!(ap.logopt(), "lookup_map_name", "relative path invalid in files map name");
        return NSS_STATUS_NOTFOUND;
    }
    lookup_name_file_source_instance(ap, map, name)
}

/// `lookup_get_map_source()`.
fn lookup_get_map_source(ap: &Arc<AutofsPoint>) -> Option<Arc<MapSource>> {
    let map = ap.entry().maps().first()?.clone();
    let (ty, a0, format) = {
        let m = map.lock();
        (m.ty.clone(), args::arg(&m.argv, 0).map(|a| a.to_vec()), m.format.clone())
    };
    let a0 = a0.unwrap_or_default();
    if ty.is_some() || a0.first() != Some(&b'/') || a0.get(1) == Some(&b'/') {
        return Some(map);
    }
    let st = sys::stat(&a0)?;
    if st.st_mode & libc::S_IFMT != libc::S_IFREG {
        return None;
    }
    let t: &[u8] = if st.st_mode & libc::S_IEXEC != 0 { b"program" } else { b"file" };
    master::master_find_source_instance(&map, Some(t), format.as_deref(), None)
}

/// `update_negative_cache()`.
fn update_negative_cache(ap: &Arc<AutofsPoint>, source: Option<&Arc<MapSource>>, name: &[u8]) {
    if let Some(s) = source
        && s.lock().depth > 0
    {
        return;
    }
    if name == b"*" {
        return;
    }
    if lookup_source_mapent(ap, name, true).is_some() {
        return;
    }
    if defaults::defaults_disable_not_found_message() == 0 {
        logmsg!("key \"{}\" not found in map source(s).", name);
    }
    let map = match source {
        Some(s) => Some(s.clone()),
        None => lookup_get_map_source(ap),
    };
    if let Some(map) = map {
        let now = sys::monotonic_time();
        let nt = ap.lock().negative_timeout as i64;
        let mc = map.mc();
        let mut c = mc.lock();
        let rv = match c.lookup_distinct(name) {
            Some(p) => c.push_mapent(p, None),
            None => c.update(map.id, name, None, now),
        };
        if rv != crate::libautofs::cache::CHE_FAIL
            && let Some(p) = c.lookup_distinct(name)
        {
            c.get_mut(p).status = now + nt;
        }
    }
}

/// `lookup_nss_mount()`: true (C's nonzero) if the key was mounted.
pub fn lookup_nss_mount(ap: &Arc<AutofsPoint>, source: Option<&Arc<MapSource>>, name: &[u8]) -> bool {
    let logopt = ap.logopt();
    let entry = ap.entry();
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
    let entry_age = entry.lock().age;
    let mut result = NSS_STATUS_UNKNOWN;
    let mut i = 0;
    'maps: while i < maps.len() {
        let map = &maps[i];
        let (mage, ty, a0, flags) = {
            let m = map.lock();
            (m.age, m.ty.clone(), args::arg(&m.argv, 0).map(|a| a.to_vec()), m.flags)
        };
        if entry_age > mage {
            i += 1;
            continue;
        }
        if ty.is_some() {
            result = do_name_lookup_mount(ap, map, name);
            if result == NSS_STATUS_SUCCESS {
                break;
            }
            i += 1;
            continue;
        }
        let a0 = a0.unwrap_or_default();
        if a0.first() == Some(&b'/') {
            if a0.get(1) == Some(&b'/') {
                map.lock().ty = Some(b"ldap".to_vec());
                result = do_lookup_mount(ap, map, name);
            } else {
                result = lookup_name_file_source_instance(ap, map, name);
            }
            if result == NSS_STATUS_SUCCESS {
                break;
            }
            i += 1;
            continue;
        }
        let mut nsslist = Vec::new();
        if nsswitch::nsswitch_parse(&mut nsslist).is_err() {
            error!(logopt, "lookup_nss_mount", "can't to read name service switch config.");
            result = 1;
            break;
        }
        for this in &nsslist {
            if flags & MAP_FLAG_FORMAT_AMD != 0 && cstr::eq(&this.source, b"sss") {
                warn!(logopt, "source sss is not available for amd maps.");
                result = NSS_STATUS_UNAVAIL;
                continue;
            }
            result = lookup_map_name(this, ap, map, name);
            if result == NSS_STATUS_UNKNOWN {
                continue;
            }
            if nsswitch::check_nss_result(this, result) >= 0 {
                break 'maps;
            }
        }
        i += 1;
    }
    if ap.lock().state != crate::daemon::state::ST_INIT {
        master::send_map_update_request(ap);
    }
    if result == NSS_STATUS_NOTFOUND || result == NSS_STATUS_UNAVAIL {
        update_negative_cache(ap, source, name);
    }
    result == 0
}

/// `make_browse_path()`.
fn make_browse_path(root: &[u8], key: &[u8], prefix: Option<&[u8]>) -> Option<Vec<u8>> {
    let mut k = key;
    if let Some(p) = prefix {
        if p.len() > key.len() || !key.starts_with(p) {
            return None;
        }
        k = &key[p.len()..];
    }
    if cstr::strchr(k, b'/').is_some() {
        return None;
    }
    if root.len() + k.len() > 255 {
        return None;
    }
    let mut path = root.to_vec();
    path.push(b'/');
    path.extend_from_slice(k);
    Some(path)
}

/// `mkdir_path()` (in `automount.c`), with its `errno` as the error.
pub fn mkdir_path(path: &[u8], mode: u32) -> Result<(), i32> {
    if crate::daemon::automount::mkdir_path(path, mode) == 0 { Ok(()) } else { Err(sys::errno()) }
}

/// `lookup_ghost()`: make the browse directories of an indirect map.
pub fn lookup_ghost(ap: &Arc<AutofsPoint>) -> u32 {
    let path = ap.path();
    if path == b"/-" {
        return 0x0001 | master::LKP_DIRECT;
    }
    let (flags, logopt, pref) = {
        let a = ap.lock();
        (a.flags, a.logopt, a.pref.clone())
    };
    if flags & master::MOUNT_FLAG_GHOST == 0 {
        return LKP_INDIRECT;
    }
    let entry = ap.entry();
    let entry_age = entry.lock().age;
    for map in entry.maps() {
        if entry_age > map.lock().age {
            continue;
        }
        let amd = map.lock().flags & MAP_FLAG_FORMAT_AMD != 0;
        let mc = map.mc();
        let mut c = mc.lock();
        let mut p = c.enumerate(None);
        while let Some(pos) = p {
            let (key, mapent, mm) = {
                let e = c.get(pos);
                (e.key.clone(), e.mapent.clone(), e.is_mm())
            };
            let skip = match &mapent {
                None => true,
                Some(m) => {
                    if cstr::strchr(&key, b'*').is_some() {
                        true
                    } else if key.first() == Some(&b'/') {
                        if !amd && mm {
                            error!(logopt, "lookup_ghost", "invalid key {}", key);
                        }
                        true
                    } else {
                        crate::libautofs::parse_subs::starts_with_null_opt(m)
                    }
                }
            };
            if !skip && let Some(full) = make_browse_path(&path, &key, pref.as_deref()) {
                let mp_mode = 0o755;
                match mkdir_path(&full, mp_mode) {
                    Err(e) if e != libc::EEXIST => {
                        warn!(logopt, "mkdir_path {} failed: {}", full, sys::strerror(e));
                    }
                    Err(_) => {}
                    Ok(()) => {
                        if let Some(st) = sys::stat(&full) {
                            let e = c.get_mut(pos);
                            e.dev = st.st_dev;
                            e.ino = st.st_ino;
                        }
                    }
                }
            }
            p = c.enumerate(Some(pos));
        }
    }
    LKP_INDIRECT
}

/// `lookup_source_close_ioctlfd()`: close the descriptor of `key`'s entry in
/// the first map that has it; whether one did.
pub fn lookup_source_close_ioctlfd(ap: &AutofsPoint, key: &[u8]) -> bool {
    for map in ap.entry().maps() {
        let mc = map.mc();
        let mut c = mc.lock();
        if let Some(p) = c.lookup_distinct(key) {
            let fd = c.get(p).ioctlfd;
            if fd != -1 {
                crate::libautofs::dev_ioctl::close(fd);
                c.get_mut(p).ioctlfd = -1;
            }
            return true;
        }
    }
    false
}
