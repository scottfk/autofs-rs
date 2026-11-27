//! `modules/lookup_file.c`: flat file maps, master and indirect/direct: the
//! reading (`read_one()`'s scanner, `+` includes, the master map and map
//! reads) and key lookups (`lookup_mount()`: the negative cache, the map file
//! read for the key and the wildcard when it changed, the cache match, and
//! the parse module).
//!
//! The scanner works on the file one `getc()` at a time, as C does, with
//! `ungetc()` and the end-of-file flag kept the same way.

use std::sync::Arc;

use crate::daemon::lookup;
use crate::daemon::master::{self, AutofsPoint, MAP_FLAG_FORMAT_AMD, MapSource, Master};
use crate::daemon::master_parse;
use crate::daemon::module::{self, LookupMod, ParseMod};
use crate::libautofs::args::{self, Argv};
use crate::libautofs::cache::{CHE_COMPLETED, CHE_FAIL, CHE_MISSING, CHE_OK, CHE_UNAVAIL, CHE_UPDATED};
use crate::libautofs::cstr;
use crate::libautofs::log::LOGOPT_NONE;
use crate::libautofs::nsswitch::{
    NSS_STATUS_NOTFOUND, NSS_STATUS_SUCCESS, NSS_STATUS_TRYAGAIN, NSS_STATUS_UNAVAIL, NSS_STATUS_UNKNOWN,
};
use crate::libautofs::parse_subs::{self, sanitize_path};
use crate::sys;

const MODPREFIX: &[u8] = b"lookup(file): ";
const MAX_INCLUDE_DEPTH: u32 = 16;
const KEY_MAX_LEN: usize = 255;
const MAPENT_MAX_LEN: usize = 16384;
const EOF: i32 = -1;

#[derive(Debug)]
pub struct LookupFile {
    pub mapname: Vec<u8>,
    pub opts_argv: Argv,
    pub last_read: i64,
    pub parse: Option<Box<dyn ParseMod>>,
}

/// `do_init()`.
fn do_init(
    mapfmt: Option<&[u8]>,
    argv: &Argv,
    parse: &mut Option<Box<dyn ParseMod>>,
    reinit: bool,
) -> Option<(Vec<u8>, Argv)> {
    if argv.is_empty() {
        logerr!("do_init", "61", "lookup(file): No map name");
        return None;
    }
    let m = args::arg(argv, 0).unwrap_or(b"").to_vec();
    if m.first() != Some(&b'/') {
        logmsg!("lookup(file): file map {} is not an absolute pathname", m);
        return None;
    }
    if sys::access(&m, libc::R_OK) != 0 {
        warn!(LOGOPT_NONE, "lookup(file): file map {} missing or not readable", m);
        return None;
    }
    let mapfmt = mapfmt.unwrap_or(b"sun");
    let opts: Argv = argv[1..].to_vec();
    if reinit {
        let p = parse.as_mut().expect("parse context");
        if module::reinit_parse(p.as_mut(), mapfmt, Some(MODPREFIX), &opts) != 0 {
            logmsg!("lookup(file): failed to reinit parse context");
            return None;
        }
    } else {
        match module::open_parse(mapfmt, Some(MODPREFIX), &opts) {
            Some(p) => *parse = Some(p),
            None => {
                logmsg!("lookup(file): failed to open parse context");
                return None;
            }
        }
    }
    Some((m, opts))
}

/// `lookup_init()`.
pub fn lookup_init(mapfmt: Option<&[u8]>, argv: &Argv) -> Option<LookupFile> {
    let mut parse = None;
    let (mapname, opts_argv) = do_init(mapfmt, argv, &mut parse, false)?;
    Some(LookupFile { mapname, opts_argv, last_read: 0, parse })
}

/// A stdio stream over a file's contents: `getc()`, `ungetc()` and `feof()`.
struct Stream {
    data: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl Stream {
    fn getc(&mut self) -> i32 {
        if self.pos < self.data.len() {
            self.pos += 1;
            self.data[self.pos - 1] as i32
        } else {
            self.eof = true;
            EOF
        }
    }

    fn ungetc(&mut self, c: i32) {
        if c == EOF {
            return;
        }
        self.pos -= 1;
        self.eof = false;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum St {
    Begin,
    Compare,
    Star,
    Badent,
    Entspc,
    Getent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd)]
enum Found {
    Nothing,
    Star,
    Real,
    Plus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Esc {
    None,
    Char,
    Val,
    All,
}

/// `read_one()`: the next entry's key and map entry, or `None` at the end.
fn read_one(logopt: u32, f: &mut Stream) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut key: Vec<u8> = Vec::new();
    let mut mapent: Vec<u8> = Vec::new();
    let mut p: Option<()> = None;
    let mut state = St::Begin;
    let mut getting = Found::Nothing;
    let mut gotten = Found::Nothing;
    let mut escape = Esc::None;
    let isspace = |c: i32| (0..256).contains(&c) && cstr::isspace(c as u8);
    let isblank = |c: i32| c == b' ' as i32 || c == b'\t' as i32;
    let show = |v: &[u8]| cstr::c(v).to_vec();
    loop {
        let ch = f.getc();
        if ch == EOF {
            return None;
        }
        match escape {
            Esc::None => {
                if ch == b'\\' as i32 {
                    // Handle continuation lines.
                    let nch = f.getc();
                    if nch == b'\n' as i32 {
                        continue;
                    }
                    f.ungetc(nch);
                    escape = Esc::Char;
                }
                if ch == b'"' as i32 {
                    escape = Esc::All;
                }
            }
            Esc::Char => escape = Esc::Val,
            Esc::Val => escape = Esc::None,
            Esc::All => {
                if ch == b'"' as i32 {
                    escape = Esc::None;
                }
            }
        }
        let c = ch as u8;
        let mut got_it = false;
        let mut next = false;
        match state {
            St::Begin => {
                if escape == Esc::None {
                    if isspace(ch) {
                    } else if c == b'#' {
                        state = St::Badent;
                    } else if c == b'*' {
                        state = St::Star;
                        key.push(c);
                    } else {
                        if c == b'+' {
                            gotten = Found::Plus;
                        }
                        state = St::Compare;
                        key.push(c);
                    }
                } else if escape == Esc::All {
                    state = St::Compare;
                    key.push(c);
                } else if escape == Esc::Char {
                } else {
                    state = St::Badent;
                }
            }
            St::Compare => {
                if c == b'\n' {
                    state = St::Begin;
                    if gotten == Found::Plus {
                        got_it = true;
                    } else if escape == Esc::All {
                        warn!(logopt, "lookup(file): unmatched \" in map key {}", show(&key));
                        next = true;
                    } else if escape != Esc::Val {
                        got_it = true;
                    }
                } else if isspace(ch) && escape == Esc::None {
                    getting = Found::Real;
                    state = St::Entspc;
                    if gotten == Found::Plus {
                        got_it = true;
                    }
                } else if escape == Esc::Char {
                } else if key.len() == KEY_MAX_LEN {
                    state = St::Badent;
                    gotten = Found::Nothing;
                    warn!(
                        logopt,
                        "lookup(file): map key \"{}...\" is too long.  The maximum key length is {}",
                        show(&key),
                        KEY_MAX_LEN as i32
                    );
                } else {
                    if escape == Esc::Val {
                        key.push(b'\\');
                    }
                    key.push(c);
                }
            }
            St::Star => {
                if c == b'\n' {
                    state = St::Begin;
                } else if isspace(ch) && gotten < Found::Star && escape == Esc::None {
                    getting = Found::Star;
                    state = St::Entspc;
                } else if escape != Esc::Char {
                    state = St::Badent;
                }
            }
            St::Badent => {
                if c == b'\n' {
                    let nch = f.getc();
                    if nch != EOF && isblank(nch) {
                        f.ungetc(nch);
                    } else {
                        f.ungetc(nch);
                        state = St::Begin;
                        if gotten == Found::Real || gotten == getting {
                            got_it = true;
                        } else {
                            warn!(
                                logopt,
                                "lookup(file): bad map entry \"{}...\" for key \"{}\"",
                                show(&mapent),
                                show(&key)
                            );
                            next = true;
                        }
                    }
                } else if !isblank(ch) {
                    gotten = Found::Nothing;
                }
            }
            St::Entspc => {
                if c == b'\n' {
                    state = St::Begin;
                } else if !isspace(ch) || escape != Esc::None {
                    let mut set = true;
                    if escape != Esc::None {
                        if escape == Esc::Char {
                            set = false;
                        } else if ch <= 32 {
                            getting = Found::Nothing;
                            state = St::Badent;
                            set = false;
                        } else {
                            mapent.clear();
                            p = Some(());
                            if escape == Esc::Val {
                                mapent.push(b'\\');
                            }
                            mapent.push(c);
                        }
                    } else {
                        mapent.clear();
                        p = Some(());
                        mapent.push(c);
                    }
                    if set {
                        state = St::Getent;
                        gotten = getting;
                    }
                }
            }
            St::Getent => {
                if c == b'\n' {
                    if escape == Esc::All {
                        state = St::Begin;
                        warn!(logopt, "lookup(file): unmatched \" in {} for key {}", show(&mapent), show(&key));
                        next = true;
                    } else {
                        let nch = f.getc();
                        if nch != EOF && isblank(nch) {
                            f.ungetc(nch);
                            state = St::Badent;
                        } else {
                            f.ungetc(nch);
                            state = St::Begin;
                            if gotten == Found::Real || gotten == getting {
                                got_it = true;
                            }
                        }
                    }
                } else if mapent.len() < MAPENT_MAX_LEN {
                    if p.is_some() {
                        mapent.push(c);
                    }
                    let nch = f.getc();
                    if nch == EOF && (gotten == Found::Real || gotten == getting) {
                        got_it = true;
                    } else {
                        f.ungetc(nch);
                    }
                } else {
                    warn!(
                        logopt,
                        "lookup(file): map entry \"{}...\" for key \"{}\" is too long.  The maximum entry size is {}",
                        show(&mapent),
                        show(&key),
                        MAPENT_MAX_LEN as i32
                    );
                    state = St::Badent;
                }
            }
        }
        if got_it {
            if gotten == Found::Nothing {
                next = true;
            } else {
                return Some((key, mapent));
            }
        }
        if next {
            key.clear();
            mapent.clear();
            p = None;
            getting = Found::Nothing;
            gotten = Found::Nothing;
            escape = Esc::None;
        }
    }
}

/// `open_fopen_r()` on a map file, with its failure message; `Err(errno)`.
fn open_map(path: &[u8]) -> Result<Stream, i32> {
    match sys::read_file(path) {
        Ok(data) => Ok(Stream { data, pos: 0, eof: false }),
        Err(e) => {
            logerr!("open_fopen_r", "211", "failed to open file: {}", sys::strerror(e));
            Err(e)
        }
    }
}

/// `check_master_self_include()`.
fn check_master_self_include(master_name: &[u8], mapname: &[u8]) -> bool {
    if master_name.first() == Some(&b'/') {
        return cstr::eq(master_name, mapname);
    }
    cstr::gnu_basename(mapname) == cstr::gnu_basename(master_name)
}

/// `check_self_include()`.
fn check_self_include(key: &[u8], mapname: &[u8]) -> bool {
    let k = &key[1..];
    if k.first() == Some(&b'/') {
        return cstr::eq(k, mapname);
    }
    cstr::gnu_basename(k) == cstr::gnu_basename(mapname)
}

impl LookupFile {
    /// `prepare_plus_include()`.
    fn prepare_plus_include(
        &self,
        ap: &Arc<AutofsPoint>,
        source: &Arc<MapSource>,
        age: i64,
        key: &[u8],
        inc: bool,
    ) -> Option<Arc<MapSource>> {
        let logopt = ap.logopt();
        let Some(info) = parse_subs::parse_map_type_info(&key[1..]) else {
            error!(logopt, "prepare_plus_include", "lookup(file): failed to parse map info");
            return None;
        };
        let mut argv: Argv = vec![info.map.clone()];
        argv.extend(self.opts_argv.iter().cloned());
        let new = match master::master_find_source_instance(
            source,
            info.ty.as_deref(),
            info.format.as_deref(),
            Some(&argv),
        ) {
            Some(n) => {
                let mut nl = n.lock();
                nl.age = age;
                nl.stale = true;
                drop(nl);
                n
            }
            None => master::master_add_source_instance(source, info.ty.as_deref(), info.format.as_deref(), age, &argv),
        };
        let depth = source.lock().depth;
        let mut nl = new.lock();
        nl.depth = depth + 1;
        if inc {
            nl.recurse = true;
        }
        drop(nl);
        Some(new)
    }
}

impl LookupFile {
    /// `match_key()`: an exact key match (or for amd maps a partial one)
    /// updates the cache.
    fn match_key(&self, source: &Arc<MapSource>, map_key: &[u8], key: &[u8], mapent: &[u8]) -> i32 {
        let age = sys::monotonic_time();
        if cstr::eq(map_key, key) {
            return source.mc().lock().update(source.id, key, Some(mapent), age);
        }
        if source.lock().flags & MAP_FLAG_FORMAT_AMD == 0 {
            return CHE_FAIL;
        }
        // A `prefix/*` map key for one of the key's parent paths.
        // QUIRK: the `/` before the `*` isn't checked, so `ab*` matches `a/x`.
        let map_key = cstr::c(map_key);
        let mut lkp_key = cstr::c(key).to_vec();
        if map_key.len() > lkp_key.len() + 2 {
            return CHE_FAIL;
        }
        while let Some(prefix) = cstr::strrchr(&lkp_key, b'/') {
            lkp_key.truncate(prefix);
            let len = lkp_key.len();
            if cstr::neq(map_key, &lkp_key, len) && map_key.get(len + 1) == Some(&b'*') {
                return source.mc().lock().update(source.id, map_key, Some(mapent), age);
            }
        }
        CHE_FAIL
    }

    /// `lookup_one()`: read the map file for `key`.
    fn lookup_one(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>, key: &[u8]) -> i32 {
        let logopt = ap.logopt();
        let age = sys::monotonic_time();
        let mc = source.mc();
        let mut f = match open_map(&self.mapname) {
            Ok(f) => f,
            Err(_) => {
                error!(logopt, "lookup_one", "lookup(file): could not open map file {}", self.mapname);
                return CHE_FAIL;
            }
        };
        loop {
            if let Some((mkey, mapent)) = read_one(logopt, &mut f) {
                if mkey.first() == Some(&b'+') {
                    let ck = cstr::c(&mkey).to_vec();
                    debug!(logopt, "lookup_one", "lookup(file): lookup included map {}", ck);
                    let inc = check_self_include(&ck, &self.mapname);
                    let Some(inc_source) = self.prepare_plus_include(ap, source, age, &ck, inc) else {
                        debug!(logopt, "lookup_one", "lookup(file): failed to select included map {}", key);
                        continue;
                    };
                    if lookup::lookup_nss_mount(ap, Some(&inc_source), key) {
                        return CHE_COMPLETED;
                    }
                } else {
                    let flags = source.lock().flags;
                    let s_key = if flags & MAP_FLAG_FORMAT_AMD != 0 {
                        if cstr::eq(&mkey, b"/defaults") {
                            mc.lock().update(source.id, &mkey, Some(&mapent), age);
                            continue;
                        }
                        sanitize_path(&mkey, mkey.len(), 0, logopt)
                    } else {
                        let Some(s) = sanitize_path(&mkey, mkey.len(), ap.ty(), logopt) else { continue };
                        if key.len() != cstr::c(&s).len() {
                            continue;
                        }
                        Some(s)
                    };
                    let Some(s_key) = s_key else { continue };
                    let ret = self.match_key(source, &s_key, key, &mapent);
                    if ret == CHE_FAIL {
                        continue;
                    }
                    return ret;
                }
            }
            if f.eof {
                break;
            }
        }
        CHE_MISSING
    }

    /// `lookup_wild()`.
    fn lookup_wild(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>) -> i32 {
        let logopt = ap.logopt();
        let age = sys::monotonic_time();
        let mut f = match open_map(&self.mapname) {
            Ok(f) => f,
            Err(_) => {
                error!(logopt, "lookup_wild", "lookup(file): could not open map file {}", self.mapname);
                return CHE_FAIL;
            }
        };
        loop {
            if let Some((mkey, mapent)) = read_one(logopt, &mut f)
                && mkey == b"*"
            {
                return source.mc().lock().update(source.id, b"*", Some(&mapent), age);
            }
            if f.eof {
                break;
            }
        }
        CHE_MISSING
    }

    /// `check_map_indirect()`.
    fn check_map_indirect(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>, key: &[u8]) -> i32 {
        let ret = self.lookup_one(ap, source, key);
        if ret == CHE_COMPLETED {
            return NSS_STATUS_COMPLETED;
        }
        if ret == CHE_FAIL {
            return NSS_STATUS_NOTFOUND;
        }
        let mc = source.mc();
        {
            let mut c = mc.lock();
            let exists = if source.lock().flags & MAP_FLAG_FORMAT_AMD != 0 {
                parse_subs::match_cached_key(ap, source, &mut c, key)
            } else {
                c.lookup_distinct(key)
            };
            if let Some(p) = exists
                && c.get(p).source == source.id
                && ret & CHE_MISSING != 0
                && c.get(p).mapent.is_some()
            {
                let e = c.get_mut(p);
                e.mapent = None;
                e.status = 0;
            }
        }
        if ret == CHE_MISSING {
            let wild = self.lookup_wild(ap, source);
            {
                let mut c = mc.lock();
                if let Some(w) = c.lookup_distinct(b"*")
                    && c.get(w).source == source.id
                    && wild & CHE_MISSING != 0
                {
                    c.delete(b"*");
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

    /// `map_update_needed()`: 1 to read the map, 0 not to, -1 if it can't be
    /// stat()ed.
    fn map_update_needed(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>) -> i32 {
        let Some(st) = sys::stat(&self.mapname) else {
            error!(ap.logopt(), "map_update_needed", "lookup(file): file map {}, could not stat", self.mapname);
            return -1;
        };
        let mut s = source.lock();
        if st.st_mtime <= self.last_read {
            if s.instances.is_empty() && s.ty.as_deref().is_some_and(|t| !cstr::eq(t, b"multi")) {
                return 0;
            }
        } else {
            s.stale = true;
        }
        1
    }
}

const NSS_STATUS_COMPLETED: i32 = 4;

impl LookupFile {
    /// `lookup_mount()`.
    fn mount_impl(&mut self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        let source = map;
        let mc = source.mc();
        let logopt = ap.logopt();
        let (recurse, depth, flags) = {
            let s = source.lock();
            (s.recurse, s.depth, s.flags)
        };
        if recurse {
            return NSS_STATUS_UNAVAIL;
        }
        if depth > MAX_INCLUDE_DEPTH {
            error!(logopt, "lookup_mount", "lookup(file): maximum include depth exceeded {}", self.mapname);
            return NSS_STATUS_SUCCESS;
        }
        debug!(logopt, "lookup_mount", "lookup(file): looking up {}", name);
        let key = if flags & MAP_FLAG_FORMAT_AMD == 0 {
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
            debug!(logopt, "lookup_mount", "lookup(file): expanded key: \"{}\"", key);
            key
        };
        // Check if we recorded a mount fail for this key anywhere.
        if let Some((mc2, p)) = lookup::lookup_source_mapent(ap, &key, true)
            && mc2.lock().lookup_negative(p, &key) == CHE_UNAVAIL
        {
            return NSS_STATUS_NOTFOUND;
        }
        let pref = ap.lock().pref.clone();
        if ap.ty() == master::LKP_INDIRECT && key.first() != Some(&b'/') {
            let ret = self.map_update_needed(ap, source);
            if ret > 0 {
                let lkp_key = {
                    let c = mc.lock();
                    match c.lookup_distinct(&key) {
                        Some(p) if c.get(p).mm => panic!("multi-mount lookups aren't ported yet (phase 4)"),
                        _ => match &pref {
                            None => key.clone(),
                            Some(pr) => [pr.as_slice(), key.as_slice()].concat(),
                        },
                    }
                };
                let status = self.check_map_indirect(ap, source, &lkp_key);
                if status != 0 {
                    if status == NSS_STATUS_COMPLETED {
                        return NSS_STATUS_SUCCESS;
                    }
                    return NSS_STATUS_NOTFOUND;
                }
            }
        }
        // do_cache_lookup:
        let lkp_key = match &pref {
            None => key.clone(),
            Some(pr) => [pr.as_slice(), key.as_slice()].concat(),
        };
        let (found, mapent) = {
            let mut c = mc.lock();
            let me = parse_subs::match_cached_key(ap, source, &mut c, &lkp_key);
            match me {
                None => (false, None),
                Some(p) => {
                    let e = c.get(p);
                    let m = if e.mapent.is_some() && (e.source == source.id || e.key.first() == Some(&b'/')) {
                        e.mapent.clone()
                    } else {
                        None
                    };
                    (true, m)
                }
            }
        };
        if !found {
            return NSS_STATUS_NOTFOUND;
        }
        let Some(mapent) = mapent else { return NSS_STATUS_TRYAGAIN };
        debug!(logopt, "lookup_mount", "lookup(file): {} -> {}", lkp_key, mapent);
        let mut parse = self.parse.take().expect("parse context");
        let ret = parse.mount(ap, source, &key, Some(&mapent));
        self.parse = Some(parse);
        if ret != 0 {
            if ap.lock().flags & master::MOUNT_FLAG_REMOUNT != 0 {
                return NSS_STATUS_TRYAGAIN;
            }
            let nt = ap.lock().negative_timeout as i64;
            mc.lock().update_negative(source.id, &key, nt);
            return NSS_STATUS_TRYAGAIN;
        }
        NSS_STATUS_SUCCESS
    }
}

impl LookupMod for LookupFile {
    /// `lookup_reinit()`.
    fn reinit(&mut self, mapfmt: Option<&[u8]>, argv: &Argv) -> i32 {
        match do_init(mapfmt, argv, &mut self.parse, true) {
            Some((m, o)) => {
                self.mapname = m;
                self.opts_argv = o;
                self.last_read = 0;
                0
            }
            None => 1,
        }
    }

    /// `lookup_read_master()`.
    fn read_master(&mut self, master: &Arc<Master>, age: i64) -> i32 {
        let (recurse, depth, timeout, logging, logopt) = {
            let m = master.lock();
            (m.recurse, m.depth, m.default_timeout, m.default_logging, m.logopt)
        };
        if recurse {
            return NSS_STATUS_TRYAGAIN;
        }
        if depth > MAX_INCLUDE_DEPTH {
            error!(logopt, "lookup_read_master", "lookup(file): maximum include depth exceeded {}", master.name());
            return NSS_STATUS_UNKNOWN;
        }
        let mut f = match open_map(&self.mapname) {
            Ok(f) => f,
            Err(e) => {
                if e == libc::ENOENT {
                    return NSS_STATUS_NOTFOUND;
                }
                error!(logopt, "lookup_read_master", "lookup(file): could not open master map file {}", self.mapname);
                return NSS_STATUS_UNKNOWN;
            }
        };
        loop {
            let Some((path, ent)) = read_one(logopt, &mut f) else {
                if f.eof {
                    break;
                }
                continue;
            };
            debug!(logopt, "lookup_read_master", "lookup(file): read entry {}", cstr::c(&path));
            if path.first() == Some(&b'+') {
                let save = master.name();
                master.set_name(cstr::c(&path[1..]).to_vec());
                let inc = check_master_self_include(&master.name(), &self.mapname);
                {
                    let mut m = master.lock();
                    if inc {
                        m.recurse = true;
                    }
                    m.depth += 1;
                }
                let status = lookup::lookup_nss_read_master(master, age);
                if status != NSS_STATUS_SUCCESS {
                    warn!(logopt, "lookup(file): failed to read included master map {}", master.name());
                    if status == NSS_STATUS_UNAVAIL {
                        master.lock().read_fail = true;
                    }
                }
                {
                    let mut m = master.lock();
                    m.depth -= 1;
                    m.recurse = false;
                }
                master.set_name(save);
            } else {
                let mut buffer = cstr::c(&path).to_vec();
                buffer.push(b' ');
                buffer.extend_from_slice(cstr::c(&ent));
                master_parse::master_parse_entry(&buffer, timeout, logging, age);
            }
            if f.eof {
                break;
            }
        }
        NSS_STATUS_SUCCESS
    }

    /// `lookup_read_map()`.
    fn read_map(&mut self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, age: i64) -> i32 {
        let source = map;
        let mc = source.mc();
        let logopt = ap.logopt();
        let (recurse, depth, flags) = {
            let s = source.lock();
            (s.recurse, s.depth, s.flags)
        };
        if recurse {
            return NSS_STATUS_TRYAGAIN;
        }
        if depth > MAX_INCLUDE_DEPTH {
            error!(logopt, "lookup_read_map", "maximum include depth exceeded {}", self.mapname);
            return NSS_STATUS_UNKNOWN;
        }
        let mut f = match open_map(&self.mapname) {
            Ok(f) => f,
            Err(e) => {
                if e == libc::ENOENT {
                    return NSS_STATUS_NOTFOUND;
                }
                error!(logopt, "lookup_read_map", "lookup(file): could not open map file {}", self.mapname);
                return NSS_STATUS_UNKNOWN;
            }
        };
        loop {
            let Some((key, mapent)) = read_one(logopt, &mut f) else {
                if f.eof {
                    break;
                }
                continue;
            };
            if key.first() == Some(&b'+') {
                let ck = cstr::c(&key).to_vec();
                debug!(logopt, "lookup_read_map", "read included map {}", ck);
                let inc = check_self_include(&ck, &self.mapname);
                let Some(inc_source) = self.prepare_plus_include(ap, source, age, &ck, inc) else {
                    debug!(logopt, "lookup_read_map", "failed to select included map {}", ck);
                    continue;
                };
                if !lookup::lookup_nss_read_map(ap, Some(&inc_source), age) {
                    warn!(logopt, "failed to read included map {}", ck);
                }
            } else {
                let s_key = if flags & MAP_FLAG_FORMAT_AMD != 0 {
                    if cstr::eq(&key, b"/defaults") {
                        mc.lock().update(source.id, &key, Some(&mapent), age);
                        continue;
                    }
                    sanitize_path(&key, key.len(), 0, logopt)
                } else {
                    sanitize_path(&key, key.len(), ap.ty(), logopt)
                };
                let Some(s_key) = s_key else { continue };
                mc.lock().update(source.id, &s_key, Some(&mapent), age);
            }
            if f.eof {
                break;
            }
        }
        source.lock().age = age;
        self.last_read = sys::time();
        NSS_STATUS_SUCCESS
    }

    fn mount(&mut self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        LookupFile::mount_impl(self, ap, map, name)
    }

    /// `lookup_done()`.
    fn done(self: Box<Self>) -> i32 {
        self.parse.map_or(0, module::close_parse)
    }
}
