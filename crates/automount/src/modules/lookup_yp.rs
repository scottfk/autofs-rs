//! `modules/lookup_yp.c` (also `nis`): NIS maps, master and indirect/direct,
//! through the YP client in [`crate::libautofs::yp`]. Map reads are
//! `yp_all()`s; key lookups are `yp_match()`s of the key (and for amd maps
//! its `prefix/*` parents), the wildcard and `/defaults`, rereading only when
//! the map's `YP_LAST_MODIFIED` order number goes up. A map name with `_` in
//! it that the server doesn't have is tried again with `.`s.

use std::sync::{Arc, Mutex};

use crate::daemon::lookup;
use crate::daemon::master::{
    self, AutofsPoint, LKP_DIRECT, MAP_FLAG_FORMAT_AMD, MOUNT_FLAG_AMD_CACHE_ALL, MOUNT_FLAG_GHOST, MOUNT_FLAG_REMOUNT,
    MapSource, Master,
};
use crate::daemon::master_parse;
use crate::daemon::module::{self, LookupMod};
use crate::libautofs::args::Argv;
use crate::libautofs::cache::{CHE_FAIL, CHE_MISSING, CHE_OK, CHE_UNAVAIL, CHE_UPDATED};
use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::libautofs::nsswitch::{NSS_STATUS_NOTFOUND, NSS_STATUS_SUCCESS, NSS_STATUS_TRYAGAIN, NSS_STATUS_UNAVAIL};
use crate::libautofs::parse_subs::{self, sanitize_path};
use crate::libautofs::yp::{
    self, YP_TRUE, YPERR_DOMAIN, YPERR_KEY, YPERR_MAP, YPERR_PMAP, YPERR_SUCCESS, YPERR_YPSERV, yperr_string,
};
use crate::sys;

const MODPREFIX: &[u8] = b"lookup(yp): ";
const KEY_MAX_LEN: usize = 255;

/// `defaults_mutex` (one for the module, as in C).
static DEFAULTS_MUTEX: Mutex<()> = Mutex::new(());

/// The `struct lookup_context` fields a reinit replaces.
#[derive(Debug, Clone)]
struct Ctxt {
    domainname: Vec<u8>,
    mapname: Vec<u8>,
    order: u32,
    check_defaults: bool,
}

#[derive(Debug)]
pub struct LookupYp {
    ctxt: Mutex<Ctxt>,
    parse: Mutex<Option<module::Parse>>,
}

/// `_` to `.` in a map name.
fn dotted(map: &[u8]) -> Vec<u8> {
    map.iter().map(|&c| if c == b'_' { b'.' } else { c }).collect()
}

/// `yp_match()` of the map, and of its dotted name if the server has no
/// such map.
fn match_map(domain: &[u8], map: &[u8], key: &[u8]) -> Result<Vec<u8>, i32> {
    match yp::yp_match(domain, map, key) {
        Err(YPERR_MAP) => yp::yp_match(domain, &dotted(map), key),
        r => r,
    }
}

/// `get_map_order()`: the map's `YP_LAST_MODIFIED`, 0 if there isn't one.
fn get_map_order(domain: &[u8], map: &[u8]) -> u32 {
    match match_map(domain, map, b"YP_LAST_MODIFIED") {
        Ok(order) => cstr::atol(cstr::c(&order)) as u32,
        Err(_) => 0,
    }
}

/// `do_init()`: the new context fields, or `None` on failure.
fn do_init(mapfmt: Option<&[u8]>, argv: &Argv, parse: &mut Option<module::Parse>, reinit: bool) -> Option<Ctxt> {
    if argv.is_empty() {
        logerr!("do_init", "117", "lookup(yp): no map name");
        return None;
    }
    let mapname = cstr::c(argv[0].as_deref().unwrap_or(b"")).to_vec();
    let mut domainname = None;
    if mapfmt.is_some_and(|f| cstr::eq(f, b"amd")) {
        domainname = defaults::conf_amd_get_nis_domain();
    }
    let domainname = match domainname {
        Some(d) => d,
        None => yp::yp_get_default_domain().ok()?,
    };
    let order = get_map_order(&domainname, &mapname);
    let mapfmt = mapfmt.unwrap_or(b"sun");
    let opts: Argv = argv[1..].to_vec();
    if reinit {
        let p = parse.as_ref().expect("parse context");
        if module::reinit_parse(&**p, mapfmt, Some(MODPREFIX), &opts) != 0 {
            logmsg!("lookup(yp): failed to reinit parse context");
            return None;
        }
    } else {
        match module::open_parse(mapfmt, Some(MODPREFIX), &opts) {
            Some(p) => *parse = Some(p),
            None => {
                logmsg!("lookup(yp): failed to open parse context");
                return None;
            }
        }
    }
    Some(Ctxt { domainname, mapname, order, check_defaults: true })
}

/// `lookup_init()`: `None` if it fails.
pub fn lookup_init(mapfmt: Option<&[u8]>, argv: &Argv) -> Option<LookupYp> {
    let mut parse = None;
    let ctxt = do_init(mapfmt, argv, &mut parse, false)?;
    Some(LookupYp { ctxt: Mutex::new(ctxt), parse: Mutex::new(parse) })
}

/// Whether a `yp_all()` key is one to ignore: zero length or a single
/// non-printable character (with the warning), or a `+` inclusion (only
/// valid in file maps).
fn bad_key(logopt: u32, key: &[u8]) -> bool {
    if key.is_empty() || (key.len() == 1 && !(0x20..0x7f).contains(&key[0])) {
        warn!(logopt, "lookup(yp): ignoring invalid map entry, zero length or single character non-printable key");
        return true;
    }
    key[0] == b'+'
}

impl LookupYp {
    fn ctxt(&self) -> Ctxt {
        self.ctxt.lock().unwrap().clone()
    }

    /// The parse context (shared: the lock isn't held while it's used).
    fn parse(&self) -> module::Parse {
        self.parse.lock().unwrap().clone().expect("parse context")
    }

    /// `lookup_one()`: the key's entry from the server into the cache: a
    /// `CHE_` status, or the negated `YPERR_` code.
    fn lookup_one(&self, source: &Arc<MapSource>, key: &[u8]) -> i32 {
        let age = sys::monotonic_time();
        let c = self.ctxt();
        match match_map(&c.domainname, &c.mapname, key) {
            Ok(mapent) => source.mc().lock().update(source.id, key, Some(&mapent), age),
            Err(YPERR_KEY) => CHE_MISSING,
            Err(e) => -e,
        }
    }

    /// `match_key()`: the key, and for amd maps each `prefix/*` of it.
    fn match_key(&self, source: &Arc<MapSource>, key: &[u8]) -> i32 {
        let is_amd_format = source.lock().flags & MAP_FLAG_FORMAT_AMD != 0;
        let ret = self.lookup_one(source, key);
        if ret < 0 {
            return ret;
        }
        if ret == CHE_OK || ret == CHE_UPDATED || !is_amd_format {
            return ret;
        }
        let mut lkp_key = cstr::c(key).to_vec();
        let mut ret = CHE_MISSING;
        // Strip successive directory components, trying map entries ending
        // in a wildcard.
        while let Some(prefix) = cstr::strrchr(&lkp_key, b'/') {
            lkp_key.truncate(prefix);
            let mut m = lkp_key.clone();
            m.extend_from_slice(b"/*");
            ret = self.lookup_one(source, &m);
            if ret < 0 || ret == CHE_OK || ret == CHE_UPDATED {
                break;
            }
        }
        ret
    }

    /// `lookup_wild()`.
    fn lookup_wild(&self, source: &Arc<MapSource>) -> i32 {
        let age = sys::monotonic_time();
        let c = self.ctxt();
        match match_map(&c.domainname, &c.mapname, b"*") {
            Ok(mapent) => source.mc().lock().update(source.id, b"*", Some(&mapent), age),
            Err(YPERR_KEY) => CHE_MISSING,
            Err(e) => -e,
        }
    }

    /// `lookup_amd_defaults()`.
    fn lookup_amd_defaults(&self, source: &Arc<MapSource>) -> i32 {
        let c = self.ctxt();
        match match_map(&c.domainname, &c.mapname, b"/defaults") {
            // No /defaults entry.
            Err(YPERR_KEY) => CHE_OK,
            Err(_) => CHE_FAIL,
            Ok(mapent) => source.mc().lock().update(source.id, b"/defaults", Some(&mapent), sys::monotonic_time()),
        }
    }

    /// `check_map_indirect()`.
    fn check_map_indirect(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>, key: &[u8]) -> i32 {
        let logopt = ap.logopt();
        let mc = source.mc();
        let is_amd = source.lock().flags & MAP_FLAG_FORMAT_AMD != 0;
        {
            // Only read the map if it has been modified.
            let _g = DEFAULTS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
            let c = self.ctxt();
            let map_order = get_map_order(&c.domainname, &c.mapname);
            if map_order > c.order {
                let mut cl = self.ctxt.lock().unwrap();
                cl.order = map_order;
                cl.check_defaults = true;
                drop(cl);
                source.lock().stale = true;
            }
            if is_amd && self.ctxt.lock().unwrap().check_defaults {
                // Check for a /defaults entry to update the map source.
                if self.lookup_amd_defaults(source) == CHE_FAIL {
                    warn!(logopt, "lookup(yp): error getting /defaults from map {}", c.mapname);
                } else {
                    self.ctxt.lock().unwrap().check_defaults = false;
                }
            }
        }
        // Check the map, and if a change is seen reread it.
        let ret = self.match_key(source, key);
        if ret == CHE_FAIL {
            return NSS_STATUS_NOTFOUND;
        }
        if ret < 0 {
            // If the server is down and the entry exists in the cache and
            // belongs to this map, use it.
            {
                let mut c = mc.lock();
                let exists = if is_amd { parse_subs::match_cached_key(ap, source, &mut c, key) } else { c.lookup(key) };
                if exists.is_some_and(|p| c.get(p).source == source.id) {
                    return NSS_STATUS_SUCCESS;
                }
            }
            warn!(logopt, "lookup(yp): lookup for {} failed: {}", key, yperr_string(-ret));
            return NSS_STATUS_UNAVAIL;
        }
        {
            let mut c = mc.lock();
            let exists =
                if is_amd { parse_subs::match_cached_key(ap, source, &mut c, key) } else { c.lookup_distinct(key) };
            // Not found in the map but found in the cache.
            if let Some(p) = exists
                && c.get(p).source == source.id
                && ret & CHE_MISSING != 0
                && c.get(p).mapent.is_some()
            {
                let e = c.get_mut(p);
                e.mapent = None;
                e.status = 0;
                drop(c);
                source.lock().stale = true;
            }
        }
        if ret == CHE_MISSING {
            // QUIRK: a failed wildcard lookup is a negative YPERR_ code, and
            // its bits are tested as CHE_ flags as C does (so -YPERR_RPC
            // reads as both CHE_MISSING and CHE_UPDATED).
            let wild = self.lookup_wild(source);
            // Check for a map change and update for the cache lookup after.
            {
                let mut c = mc.lock();
                match c.lookup_distinct(b"*") {
                    Some(we) => {
                        // A wildcard entry that's now gone.
                        if c.get(we).source == source.id && wild & CHE_MISSING != 0 {
                            c.delete(b"*");
                            drop(c);
                            source.lock().stale = true;
                        }
                    }
                    None => {
                        // A wildcard not in the map before but now is.
                        if wild & (CHE_OK | CHE_UPDATED) != 0 {
                            drop(c);
                            source.lock().stale = true;
                        }
                    }
                }
            }
            if wild & (CHE_OK | CHE_UPDATED) != 0 {
                return NSS_STATUS_SUCCESS;
            }
        }
        if ret == CHE_MISSING {
            return NSS_STATUS_NOTFOUND;
        }
        NSS_STATUS_SUCCESS
    }

    /// `lookup_mount()`.
    fn mount_impl(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        let source = map;
        let mc = source.mc();
        let logopt = ap.logopt();
        debug!(logopt, "lookup_mount", "lookup(yp): looking up {}", name);
        let key = if source.lock().flags & MAP_FLAG_FORMAT_AMD == 0 {
            let key = cstr::c(name).to_vec();
            if key.len() > KEY_MAX_LEN {
                return NSS_STATUS_NOTFOUND;
            }
            key
        } else {
            let key = parse_subs::expandamdent(name, &[]);
            if key.len() > KEY_MAX_LEN {
                return NSS_STATUS_NOTFOUND;
            }
            debug!(logopt, "lookup_mount", "lookup(yp): expanded key: \"{}\"", key);
            key
        };
        // Check if we recorded a mount fail for this key anywhere.
        if let Some((mc2, p)) = lookup::lookup_source_mapent(ap, &key, true)
            && mc2.lock().lookup_negative(p, &key) == CHE_UNAVAIL
        {
            return NSS_STATUS_NOTFOUND;
        }
        let pref = ap.lock().pref.clone();
        let with_pref = |k: &[u8]| match &pref {
            None => k.to_vec(),
            Some(pr) => [pr.as_slice(), k].concat(),
        };
        // The direct map can't be checked: a key not in the cache already
        // never gets a lookup.
        if ap.ty() == master::LKP_INDIRECT && key.first() != Some(&b'/') {
            let lkp_key = {
                let c = mc.lock();
                match c.lookup_distinct(&key) {
                    Some(p) if c.get(p).is_mm() => {
                        let r = c.get(p).mm_root.and_then(|id| c.by_id(id)).expect("multi-mount root");
                        c.get(r).key.clone()
                    }
                    _ => with_pref(&key),
                }
            };
            let status = self.check_map_indirect(ap, source, &lkp_key);
            if status != 0 {
                return status;
            }
        }
        let lkp_key = with_pref(&key);
        let remount = ap.lock().flags & MOUNT_FLAG_REMOUNT != 0;
        let (found, mapent) = {
            let mut c = mc.lock();
            let mut me = parse_subs::match_cached_key(ap, source, &mut c, &lkp_key);
            // A stale mapent: the entry in another source, or the wildcard.
            if let Some(p) = me
                && c.get(p).mapent.is_none()
            {
                let mut n = c.lookup_key_next(p);
                while let Some(q) = n {
                    if c.get(q).source == source.id {
                        break;
                    }
                    n = c.lookup_key_next(q);
                }
                me = n.or_else(|| c.lookup_distinct(b"*"));
            }
            let mut mapent = None;
            if let Some(p) = me
                && c.get(p).mapent.is_some()
            {
                let id = c.get(p).id;
                // A lookup adds the wildcard match, for later validation
                // checks and negative cache lookups.
                if ap.ty() == master::LKP_INDIRECT && c.get(p).key.first() == Some(&b'*') && !remount {
                    let (m, age) = (c.get(p).mapent.clone(), c.get(p).age);
                    let ret = c.update(source.id, &key, m.as_deref(), age);
                    if ret & (CHE_OK | CHE_UPDATED) == 0 {
                        me = None;
                    } else {
                        me = c.by_id(id);
                    }
                }
                if let Some(p) = me {
                    let e = c.get(p);
                    if e.source == source.id || e.key.first() == Some(&b'/') {
                        mapent = e.mapent.clone();
                    }
                }
            }
            (me.is_some(), mapent)
        };
        if !found {
            return NSS_STATUS_NOTFOUND;
        }
        let Some(mapent) = mapent else { return NSS_STATUS_TRYAGAIN };
        debug!(logopt, "lookup_mount", "lookup(yp): {} -> {}", lkp_key, mapent);
        let ret = self.parse().mount(ap, source, &key, Some(&mapent));
        if ret != 0 {
            // Don't update the negative cache when reconnecting.
            if ap.lock().flags & MOUNT_FLAG_REMOUNT != 0 {
                return NSS_STATUS_TRYAGAIN;
            }
            let nt = ap.lock().negative_timeout as i64;
            mc.lock().update_negative(source.id, &key, nt);
            return NSS_STATUS_TRYAGAIN;
        }
        NSS_STATUS_SUCCESS
    }
}

impl LookupMod for LookupYp {
    /// `lookup_reinit()`: a new context (the parse context carried over).
    fn reinit(&self, mapfmt: Option<&[u8]>, argv: &Argv) -> i32 {
        let mut parse = self.parse.lock().unwrap().clone();
        let r = do_init(mapfmt, argv, &mut parse, true);
        match r {
            Some(c) => {
                *self.ctxt.lock().unwrap() = c;
                0
            }
            None => 1,
        }
    }

    /// `lookup_read_master()`.
    fn read_master(&self, master: &Arc<Master>, age: i64) -> i32 {
        let (timeout, logging, logopt) = {
            let m = master.lock();
            (m.default_timeout, m.default_logging, m.logopt)
        };
        let c = self.ctxt();
        let mut foreach = |status: i32, key: Option<&[u8]>, val: Option<&[u8]>| -> i32 {
            if status != YP_TRUE {
                return status;
            }
            let (key, val) = (key.unwrap_or(b""), val.unwrap_or(b""));
            if bad_key(logopt, key) {
                return 0;
            }
            let mut buffer = cstr::c(key).to_vec();
            buffer.push(b' ');
            buffer.extend_from_slice(cstr::c(val));
            master_parse::master_parse_entry(&buffer, timeout, logging, age);
            0
        };
        let mut mapname = c.mapname.clone();
        let mut err = yp::yp_all(&c.domainname, &mapname, &mut foreach);
        if err != YPERR_SUCCESS {
            if err == YPERR_MAP {
                mapname = dotted(&mapname);
                err = yp::yp_all(&c.domainname, &mapname, &mut foreach);
            }
            if err == YPERR_SUCCESS {
                return NSS_STATUS_SUCCESS;
            }
            info!(logopt, "lookup(yp): read of master map {} failed: {}", mapname, yperr_string(err));
            if err == YPERR_YPSERV || err == YPERR_DOMAIN {
                return NSS_STATUS_UNAVAIL;
            }
            return NSS_STATUS_NOTFOUND;
        }
        NSS_STATUS_SUCCESS
    }

    /// `lookup_read_map()`.
    fn read_map(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, age: i64) -> i32 {
        let source = map;
        let logopt = ap.logopt();
        let (flags, ty) = {
            let a = ap.lock();
            (a.flags, a.ty)
        };
        // No use reading the map unless directories are made (or an amd
        // cache:=all map is read); direct mounts always need the whole map
        // for their triggers.
        if ty != LKP_DIRECT && flags & (MOUNT_FLAG_GHOST | MOUNT_FLAG_AMD_CACHE_ALL) == 0 {
            debug!(logopt, "lookup_read_map", "map read not needed, so not done");
            return NSS_STATUS_SUCCESS;
        }
        let is_amd = source.lock().flags & MAP_FLAG_FORMAT_AMD != 0;
        let mc = source.mc();
        let mut foreach = |status: i32, key: Option<&[u8]>, val: Option<&[u8]>| -> i32 {
            if status != YP_TRUE {
                return status;
            }
            let (key, val) = (key.unwrap_or(b""), val.unwrap_or(b""));
            if bad_key(logopt, key) {
                return 0;
            }
            // amd keys may have a "/" in them (type 0).
            let s_key = if is_amd {
                sanitize_path(key, key.len(), 0, logopt)
            } else {
                sanitize_path(key, key.len(), ty, logopt)
            };
            let Some(s_key) = s_key else {
                error!(logopt, "yp_all_callback", "lookup(yp): invalid path {}", cstr::c(key));
                return 0;
            };
            let ret = mc.lock().update(source.id, &s_key, Some(cstr::c(val)), age);
            if ret == CHE_FAIL {
                return -1;
            }
            0
        };
        let c = self.ctxt();
        let mut err = yp::yp_all(&c.domainname, &c.mapname, &mut foreach);
        if err != YPERR_SUCCESS {
            if err == YPERR_MAP {
                err = yp::yp_all(&c.domainname, &dotted(&c.mapname), &mut foreach);
            }
            if err != YPERR_SUCCESS {
                warn!(logopt, "lookup(yp): read of map {} failed: {}", ap.path(), yperr_string(err));
                if err == YPERR_PMAP || err == YPERR_YPSERV {
                    return NSS_STATUS_UNAVAIL;
                }
                return NSS_STATUS_NOTFOUND;
            }
        }
        source.lock().age = age;
        let _g = DEFAULTS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        self.ctxt.lock().unwrap().check_defaults = false;
        NSS_STATUS_SUCCESS
    }

    fn mount(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        self.mount_impl(ap, map, name)
    }

    /// `lookup_done()`.
    fn done(&self) -> i32 {
        self.parse.lock().unwrap().take().map_or(0, module::close_parse)
    }
}
