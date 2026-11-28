//! `modules/lookup_hosts.c`: the `-hosts` map. A map read lists every host
//! `gethostent()` gives (the hosts database, as nsswitch enumerates it) as a
//! key; a lookup asks the host's mount daemon for its export list
//! (`MOUNTPROC_EXPORT`) and mounts it as a multi-mount entry of one offset
//! per export, `"/dir" "host:/dir"`, shortest paths first.

use std::sync::{Arc, Mutex};

use crate::daemon::lookup;
use crate::daemon::master::{AutofsPoint, LKP_DIRECT, MOUNT_FLAG_GHOST, MOUNT_FLAG_REMOUNT, MapSource, Master};
use crate::daemon::module::{self, LookupMod};
use crate::libautofs::args::Argv;
use crate::libautofs::cache::{CHE_FAIL, CHE_UNAVAIL};
use crate::libautofs::cstr;
use crate::libautofs::log::LOGOPT_ANY;
use crate::libautofs::nsswitch::{
    NSS_STATUS_NOTFOUND, NSS_STATUS_SUCCESS, NSS_STATUS_TRYAGAIN, NSS_STATUS_UNAVAIL, NSS_STATUS_UNKNOWN,
};
use crate::libautofs::rpc_subs::{self, RPC_CLOSE_NOLINGER};
use crate::sys;

const MODPREFIX: &[u8] = b"lookup(hosts): ";

/// `hostent_mutex`: one host enumeration at a time.
static HOSTENT_MUTEX: Mutex<()> = Mutex::new(());

#[derive(Debug)]
pub struct LookupHosts {
    parse: Mutex<Option<module::Parse>>,
}

impl LookupHosts {
    /// The parse context (shared: the lock isn't held while it's used).
    fn parse(&self) -> module::Parse {
        self.parse.lock().unwrap().clone().expect("parse context")
    }
}

/// `lookup_init()`.
pub fn lookup_init(_mapfmt: Option<&[u8]>, argv: &Argv) -> Option<LookupHosts> {
    match module::open_parse(b"sun", Some(MODPREFIX), argv) {
        Some(p) => Some(LookupHosts { parse: Mutex::new(Some(p)) }),
        None => {
            logerr!("lookup_init", "57", "lookup(hosts): failed to open parse context");
            None
        }
    }
}

/// `get_exports()`: the host's exports as a multi-mount entry, or `None` if
/// there are none (or the server can't be asked).
///
/// The exports go in a tree (lib/mounts.c `tree_host_*`) that orders them by
/// path length only, an equal length going right, and drops (with an error)
/// a path seen before; walked in order, that's the list sorted by length,
/// stably, without the duplicates.
pub fn get_exports(ap: &Arc<AutofsPoint>, host: &[u8]) -> Option<Vec<u8>> {
    debug!(ap.logopt(), "get_exports", "lookup(hosts): fetchng export list for {}", host);
    let exp = rpc_subs::rpc_get_exports(host, 10, 0, RPC_CLOSE_NOLINGER).unwrap_or_default();
    let mut tree: Vec<&[u8]> = Vec::new();
    for e in &exp {
        let dir = cstr::c(&e.dir);
        if tree.iter().any(|d| cstr::eq(d, dir)) {
            error!(LOGOPT_ANY, "tree_host_cmp", "duplicate entry {} ignored", dir);
            continue;
        }
        tree.push(dir);
    }
    if tree.is_empty() {
        return None;
    }
    tree.sort_by_key(|d| d.len());
    let host = cstr::c(host);
    let mut mapent = Vec::new();
    for dir in tree {
        if !mapent.is_empty() {
            mapent.push(b' ');
        }
        mapent.extend_from_slice(&bfmt!("\"{}\" \"{}:{}\"", dir, host, dir));
    }
    Some(mapent)
}

impl LookupHosts {
    /// `do_parse_mount()`.
    fn do_parse_mount(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>, name: &[u8], mapent: &[u8]) -> i32 {
        let ret = self.parse().mount(ap, source, name, Some(mapent));
        if ret != 0 {
            // Don't update the negative cache when reconnecting.
            if ap.lock().flags & MOUNT_FLAG_REMOUNT != 0 {
                return NSS_STATUS_TRYAGAIN;
            }
            let nt = ap.lock().negative_timeout as i64;
            source.mc().lock().update_negative(source.id, name, nt);
            return NSS_STATUS_TRYAGAIN;
        }
        NSS_STATUS_SUCCESS
    }

    /// `update_hosts_mounts()`: fetch the export lists of the hosts already
    /// mounted (expanded into multi-mounts) and remount any that changed.
    fn update_hosts_mounts(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>, age: i64) {
        let logopt = ap.logopt();
        let mc = source.mc();
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        {
            // As in C, the cache stays locked across the RPC calls.
            let mut c = mc.lock();
            let mut me = c.lookup_first();
            while let Some(p) = me {
                // Hosts map entry not yet expanded or already expired.
                if c.get(p).is_mm() {
                    let key = c.get(p).key.clone();
                    debug!(logopt, "update_hosts_mounts", "lookup(hosts): get list of exports for {}", key);
                    if let Some(mapent) = get_exports(ap, &key) {
                        let ret = c.update(source.id, &key, Some(&mapent), age);
                        if c.get(p).is_mm_root() && ret != CHE_FAIL {
                            let e = c.get(p);
                            // QUIRK: in a browsable map the host list read
                            // just now cleared the entry (same age, so the
                            // update above changed nothing), and C's
                            // strdup() of the NULL mapent crashes: a HUP
                            // with a host mounted kills the daemon.
                            let Some(m) = e.mapent.clone() else { sys::die_by_signal(libc::SIGSEGV) };
                            entries.push((e.key.clone(), m));
                        }
                    }
                }
                me = c.lookup_next(p);
            }
        }
        for (key, entry) in entries {
            debug!(logopt, "update_hosts_mounts", "lookup(hosts): attempt to update exports for {}", key);
            ap.lock().flags |= MOUNT_FLAG_REMOUNT;
            let ret = self.parse().mount(ap, source, &key, Some(&entry));
            if ret != 0 {
                warn!(logopt, "lookup(hosts): failed to parse mount {}", entry);
            }
            ap.lock().flags &= !MOUNT_FLAG_REMOUNT;
        }
    }

    /// `lookup_mount()`.
    fn mount_impl(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        let source = map;
        let mc = source.mc();
        let logopt = ap.logopt();
        let now = sys::monotonic_time();
        let name = cstr::c(name);
        // Check if we recorded a mount fail for this key anywhere.
        if let Some((mc2, p)) = lookup::lookup_source_mapent(ap, name, true)
            && mc2.lock().lookup_negative(p, name) == CHE_UNAVAIL
        {
            return NSS_STATUS_NOTFOUND;
        }
        let mut mapent: Option<Vec<u8>> = None;
        let found = {
            let c = mc.lock();
            c.lookup_distinct(name).map(|p| c.get(p).mapent.clone())
        };
        match found {
            None => {
                if ap.lock().flags & MOUNT_FLAG_GHOST == 0 {
                    // We haven't read the list of hosts into the cache, so
                    // straight to the lookup. A name with a '/' in it is an
                    // offset that isn't in the export list.
                    if name.first() != Some(&b'/') && cstr::strchr(name, b'/').is_some() {
                        return NSS_STATUS_NOTFOUND;
                    }
                } else {
                    if name.first() == Some(&b'/') {
                        info!(logopt, "lookup(hosts): can't find path in hosts map {}", name);
                    } else {
                        let path = ap.path();
                        info!(logopt, "lookup(hosts): can't find path in hosts map {}/{}", path, name);
                    }
                    debug!(logopt, "lookup_mount", "lookup(hosts): lookup failed - update exports list");
                }
            }
            Some(m) => {
                // Export entries are in the cache as direct mounts: a name
                // starting with a slash is a mount of one of them.
                if name.first() == Some(&b'/') {
                    mapent = m;
                }
            }
        }
        debug!(
            logopt,
            "lookup_mount",
            "lookup(hosts): {} -> {}",
            name,
            mapent.clone().unwrap_or_else(|| b"(null)".to_vec())
        );
        let mapent = match mapent {
            Some(m) => m,
            None => {
                // Get the exports list and update the cache.
                let Some(m) = get_exports(ap, name) else {
                    // The exports lookup failed, so we're out of here.
                    return NSS_STATUS_UNAVAIL;
                };
                mc.lock().update(source.id, name, Some(&m), now);
                m
            }
        };
        self.do_parse_mount(ap, source, name, &mapent)
    }
}

impl LookupMod for LookupHosts {
    fn reinit(&self, _mapfmt: Option<&[u8]>, argv: &Argv) -> i32 {
        let p = self.parse();
        if module::reinit_parse(&*p, b"sun", Some(MODPREFIX), argv) != 0 {
            return 1;
        }
        0
    }

    fn read_master(&self, _master: &Arc<Master>, _age: i64) -> i32 {
        NSS_STATUS_UNKNOWN
    }

    /// `lookup_read_map()`.
    fn read_map(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, age: i64) -> i32 {
        let source = map;
        let mc = source.mc();
        let logopt = ap.logopt();
        debug!(logopt, "lookup_read_map", "lookup(hosts): read hosts map");
        let (flags, ty) = {
            let a = ap.lock();
            (a.flags, a.ty)
        };
        // No use reading the map unless directories are made, but direct
        // mounts always need the whole map for their triggers.
        if flags & MOUNT_FLAG_GHOST == 0 && ty != LKP_DIRECT {
            debug!(logopt, "lookup_read_map", "lookup(hosts): map not browsable, update existing host entries only");
            self.update_hosts_mounts(ap, source, age);
            source.lock().age = age;
            return NSS_STATUS_SUCCESS;
        }
        {
            let _g = HOSTENT_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            for name in sys::host_names() {
                mc.lock().update(source.id, &name, None, age);
            }
        }
        self.update_hosts_mounts(ap, source, age);
        source.lock().age = age;
        NSS_STATUS_SUCCESS
    }

    fn mount(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        self.mount_impl(ap, map, name)
    }

    fn done(&self) -> i32 {
        self.parse.lock().unwrap().take().map_or(0, module::close_parse)
    }
}
