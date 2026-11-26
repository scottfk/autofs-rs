//! `modules/lookup_file.c`: flat file maps, master and indirect/direct. This
//! phase has the reading (`read_one()`'s scanner, `+` includes, the master map
//! and `--dumpmaps` map reads); key lookups come with the daemon.
//!
//! The scanner works on the file one `getc()` at a time, as C does, with
//! `ungetc()` and the end-of-file flag kept the same way.

use std::sync::Arc;

use crate::daemon::lookup;
use crate::daemon::master::{self, AutofsPoint, MAP_FLAG_FORMAT_AMD, MapSource, Master};
use crate::daemon::master_parse;
use crate::daemon::module::{self, LookupMod, ParseMod};
use crate::libautofs::args::{self, Argv};
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

    /// `lookup_done()`.
    fn done(self: Box<Self>) -> i32 {
        self.parse.map_or(0, module::close_parse)
    }
}
