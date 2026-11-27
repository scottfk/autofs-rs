//! `modules/lookup_program.c`: executable maps. The program is run with the
//! key as its argument and the standard macros in its environment (with an
//! `AUTOFS_` prefix unless `force_standard_program_map_env`), its stdout read
//! as the map entry and its stderr logged (`>> ...`). An amd program map's
//! program prints the key, then the entry.

use std::sync::{Arc, Mutex};

use crate::daemon::lookup;
use crate::daemon::master::{AutofsPoint, MapSource, Master};
use crate::daemon::master::{MAP_FLAG_FORMAT_AMD, MOUNT_FLAG_REMOUNT};
use crate::daemon::module::{self, LookupMod};
use crate::libautofs::args::{self, Argv};
use crate::libautofs::cache::CHE_UNAVAIL;
use crate::libautofs::cstr;
use crate::libautofs::log;
use crate::libautofs::nsswitch::{
    NSS_STATUS_NOTFOUND, NSS_STATUS_SUCCESS, NSS_STATUS_TRYAGAIN, NSS_STATUS_UNAVAIL, NSS_STATUS_UNKNOWN,
};
use crate::libautofs::{defaults, macros, mounts};
use crate::sys;

const MODPREFIX: &[u8] = b"lookup(program): ";

#[derive(Debug)]
pub struct LookupProgram {
    mapname: Mutex<Vec<u8>>,
    mapfmt: Mutex<Vec<u8>>,
    parse: Mutex<Option<module::Parse>>,
}

impl LookupProgram {
    fn mapname(&self) -> Vec<u8> {
        self.mapname.lock().unwrap().clone()
    }

    fn mapfmt(&self) -> Vec<u8> {
        self.mapfmt.lock().unwrap().clone()
    }

    /// The parse context (shared: the lock isn't held while it's used).
    fn parse(&self) -> module::Parse {
        self.parse.lock().unwrap().clone().expect("parse context")
    }
}

/// `do_init()`.
fn do_init(
    mapfmt: Option<&[u8]>,
    argv: &Argv,
    parse: &mut Option<module::Parse>,
    reinit: bool,
) -> Option<(Vec<u8>, Vec<u8>)> {
    let Some(m) = args::arg(argv, 0) else {
        logmsg!("lookup(program): No map name");
        return None;
    };
    if m.first() != Some(&b'/') {
        logmsg!("lookup(program): program map {} is not an absolute pathname", m);
        return None;
    }
    if sys::access(m, libc::X_OK) != 0 {
        logmsg!("lookup(program): program map {} missing or not executable", m);
        return None;
    }
    let mapfmt = mapfmt.unwrap_or(b"sun").to_vec();
    let rest: Argv = argv[1..].to_vec();
    if reinit {
        let p = parse.as_ref().expect("parse context");
        if module::reinit_parse(&**p, &mapfmt, Some(MODPREFIX), &rest) != 0 {
            logmsg!("lookup(program): failed to reinit parse context");
            return None;
        }
    } else {
        match module::open_parse(&mapfmt, Some(MODPREFIX), &rest) {
            Some(p) => *parse = Some(p),
            None => {
                logmsg!("lookup(program): failed to open parse context");
                return None;
            }
        }
    }
    Some((m.to_vec(), mapfmt))
}

/// `lookup_init()`.
pub fn lookup_init(mapfmt: Option<&[u8]>, argv: &Argv) -> Option<LookupProgram> {
    let mut parse = None;
    let (mapname, mapfmt) = do_init(mapfmt, argv, &mut parse, false)?;
    Some(LookupProgram { mapname: Mutex::new(mapname), mapfmt: Mutex::new(mapfmt), parse: Mutex::new(parse) })
}

impl LookupProgram {
    /// `lookup_one()`: run the program for `name`; its map entry, or `None`.
    fn lookup_one(&self, ap: &Arc<AutofsPoint>, name: &[u8]) -> Option<Vec<u8>> {
        let logopt = ap.logopt();
        let prefix: Option<&[u8]> =
            if defaults::defaults_force_std_prog_map_env() != 0 { None } else { Some(b"AUTOFS_") };
        let (pr, pw) = match sys::pipe_cloexec() {
            Ok(p) => p,
            Err(e) => {
                logerr!("open_pipe", "161", "failed to open pipe: {}", sys::strerror(e));
                return None;
            }
        };
        let (er, ew) = match sys::pipe_cloexec() {
            Ok(p) => p,
            Err(e) => {
                sys::close(pr);
                sys::close(pw);
                logerr!("open_pipe", "161", "failed to open pipe: {}", sys::strerror(e));
                return None;
            }
        };
        // The child's environment: macro_setenv() of the global table and the
        // parser's table with addstdenv() applied (sun maps only).
        let mut sets: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        if self.mapfmt() == b"sun"
            && let Some(mut subst) = self.parse.lock().unwrap().clone().and_then(|p| p.subst())
        {
            mounts::addstdenv(&mut subst, prefix);
            for sv in macros::global_table().iter().chain(subst.iter()) {
                sets.push((sv.def.clone(), sv.val.clone()));
            }
        }
        let env = sys::environ_with(&sets);
        let path = ap.path();
        let chdir_msg = if log::have_log_verbose() || log::have_log_debug() || logopt != 0 {
            bfmt!("lookup(program): failed to set PWD to {} for map {}", path, self.mapname())
        } else {
            Vec::new()
        };
        let f = sys::spawn_program(
            &self.mapname(),
            name,
            &env,
            &path,
            &chdir_msg,
            log::logging_to_syslog(),
            (pr, pw),
            (er, ew),
        );
        sys::close(pw);
        sys::close(ew);
        if f < 0 {
            logerr!("lookup_one", "226", "lookup(program): fork: {}", sys::strerror(sys::errno()));
            sys::close(pr);
            sys::close(er);
            return None;
        }
        #[derive(PartialEq)]
        enum St {
            Space,
            Map,
            Done,
        }
        let mut mapent: Vec<u8> = Vec::new();
        let mut errbuf: Vec<u8> = Vec::new();
        let mut state = St::Space;
        let mut quoted = false;
        let (mut fd0, mut fd1) = (pr, er);
        loop {
            let (r, rev0, rev1) = sys::poll2(fd0, fd1);
            if r < 0 && sys::errno() != libc::EINTR {
                break;
            }
            if fd0 == -1 && fd1 == -1 {
                break;
            }
            let hup = libc::POLLIN | libc::POLLHUP;
            if rev0 & hup == libc::POLLHUP && rev1 & hup == libc::POLLHUP {
                break;
            }
            if rev0 != 0 {
                loop {
                    let mut b = [0u8; 1];
                    let n = sys::read(pr, &mut b);
                    if n == 0 {
                        break;
                    }
                    if n < 0 {
                        fd0 = -1;
                        state = St::Done;
                        break;
                    }
                    let ch = b[0];
                    if !quoted && ch == b'\\' {
                        quoted = true;
                        continue;
                    }
                    match state {
                        St::Space => {
                            if quoted || !cstr::isspace(ch) {
                                mapent.push(ch);
                                state = St::Map;
                            }
                        }
                        St::Map => {
                            if !quoted && ch == b'\n' {
                                state = St::Done;
                            } else if quoted {
                                if ch == b'\n' {
                                    mapent.push(b' ');
                                } else {
                                    mapent.push(b'\\');
                                    mapent.push(ch);
                                }
                            } else {
                                mapent.push(ch);
                            }
                        }
                        St::Done => {}
                    }
                    quoted = false;
                }
            } else {
                quoted = false;
            }
            if rev1 != 0 {
                loop {
                    let mut b = [0u8; 1];
                    let n = sys::read(er, &mut b);
                    if n == 0 {
                        break;
                    }
                    if n < 0 {
                        fd1 = -1;
                        break;
                    }
                    if b[0] == b'\n' {
                        if !errbuf.is_empty() && errbuf[0] != 0 {
                            logmsg!(">> {}", cstr::c(&errbuf));
                        }
                        errbuf.clear();
                    } else {
                        if errbuf.len() >= 1023 {
                            logmsg!(">> {}", cstr::c(&errbuf));
                            errbuf.clear();
                        }
                        errbuf.push(b[0]);
                    }
                }
            }
        }
        remember_answer(&mapent);
        if !errbuf.is_empty() {
            logmsg!(">> {}", cstr::c(&errbuf));
        }
        sys::close(pr);
        sys::close(er);
        let (w, st) = sys::waitpid(f);
        if w != f {
            logerr!("lookup_one", "399", "lookup(program): waitpid: {}", sys::strerror(sys::errno()));
            return None;
        }
        if mapent.is_empty() || !libc::WIFEXITED(st) || libc::WEXITSTATUS(st) != 0 {
            info!(logopt, "lookup(program): lookup for {} failed", name);
            return None;
        }
        Some(cstr::c(&mapent).to_vec())
    }

    /// `lookup_amd_defaults()`: cache the program's `/defaults` entry.
    fn lookup_amd_defaults(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>) -> i32 {
        if let Some(ment) = self.lookup_one(ap, b"/defaults") {
            let start = skip_key(&ment, 9);
            let ret = source.mc().lock().update(source.id, b"/defaults", Some(&start), sys::monotonic_time());
            if ret == crate::libautofs::cache::CHE_FAIL {
                return NSS_STATUS_UNAVAIL;
            }
        }
        NSS_STATUS_SUCCESS
    }

    /// `match_key()`: run the program for the key and cache its answer. For an
    /// amd map the program prints the key before its entry, and the
    /// `/defaults` entry and successively shorter `prefix/*` keys are asked for
    /// too.
    fn match_key(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>, name: &[u8]) -> Result<Vec<u8>, i32> {
        let logopt = ap.logopt();
        let is_amd = source.lock().flags & MAP_FLAG_FORMAT_AMD != 0;
        let update = |key: &[u8], ment: &[u8]| -> Result<Vec<u8>, i32> {
            let ret = source.mc().lock().update(source.id, key, Some(ment), sys::monotonic_time());
            if ret == crate::libautofs::cache::CHE_FAIL {
                return Err(NSS_STATUS_UNAVAIL);
            }
            Ok(ment.to_vec())
        };
        if is_amd && self.lookup_amd_defaults(ap, source) != NSS_STATUS_SUCCESS {
            warn!(logopt, "lookup(program): failed to save /defaults entry");
        }
        let mut lkp_key = cstr::c(name).to_vec();
        if is_amd && let Some(p) = ap.lock().pref.clone() {
            lkp_key = [cstr::c(&p), &lkp_key[..]].concat();
        }
        if let Some(ment) = self.lookup_one(ap, &lkp_key) {
            let start = if is_amd { skip_key(&ment, lkp_key.len()) } else { ment };
            return update(&lkp_key, &start);
        }
        if !is_amd {
            return Err(NSS_STATUS_NOTFOUND);
        }
        while let Some(prefix) = cstr::strrchr(&lkp_key, b'/') {
            lkp_key.truncate(prefix);
            let m = [&lkp_key[..], b"/*"].concat();
            if let Some(ment) = self.lookup_one(ap, &m) {
                let start = skip_key(&ment, m.len());
                return update(&m, &start);
            }
        }
        Err(NSS_STATUS_NOTFOUND)
    }

    /// `lookup_mount()`.
    fn mount_impl(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        let source = map;
        let mc = source.mc();
        let logopt = ap.logopt();
        if let Some((mc2, p)) = lookup::lookup_source_mapent(ap, name, true)
            && mc2.lock().lookup_negative(p, name) == CHE_UNAVAIL
        {
            return NSS_STATUS_NOTFOUND;
        }
        let mut ret: i32;
        let cached = {
            let c = mc.lock();
            c.lookup_distinct(name).map(|p| {
                let e = c.get(p);
                (e.mapent.clone(), e.age, e.mm_nonroot())
            })
        };
        let mut done = false;
        ret = 1;
        match cached {
            None => {
                if cstr::strchr(name, b'/').is_some() {
                    debug!(logopt, "lookup_mount", "lookup(program): offset {} not found", name);
                    return NSS_STATUS_NOTFOUND;
                }
            }
            Some((m, age, mm)) => {
                debug!(
                    logopt,
                    "lookup_mount",
                    "lookup(program): {} -> {}",
                    name,
                    crate::daemon::master::cstr_or_null(&m)
                );
                let nt = ap.lock().negative_timeout as i64;
                if cstr::strchr(name, b'/').is_some() || age + nt > sys::monotonic_time() {
                    ret = self.parse().mount(ap, source, name, m.as_deref());
                    done = true;
                } else {
                    if mm {
                        warn!(
                            logopt,
                            "lookup(program): unexpected lookup for active multi-mount key {}, returning fail", name
                        );
                        return NSS_STATUS_UNAVAIL;
                    }
                    let is_mm = {
                        let c = mc.lock();
                        c.lookup_distinct(name).map(|p| c.get(p).is_mm())
                    };
                    if let Some(is_mm) = is_mm {
                        if is_mm {
                            crate::libautofs::mounts::tree_mapent_delete_offsets(ap, &mc, name);
                        }
                        mc.lock().delete(name);
                    }
                }
            }
        }
        if !done {
            debug!(logopt, "lookup_mount", "lookup(program): looking up {}", name);
            match self.match_key(ap, source, name) {
                Err(r) => ret = r,
                Ok(mapent) => {
                    debug!(logopt, "lookup_mount", "lookup(program): {} -> {}", name, mapent);
                    ret = self.parse().mount(ap, source, name, Some(&mapent));
                }
            }
        }
        if ret != 0 {
            if ap.lock().flags & MOUNT_FLAG_REMOUNT != 0 {
                return NSS_STATUS_TRYAGAIN;
            }
            let nt = ap.lock().negative_timeout as i64;
            mc.lock().update_negative(source.id, name, nt);
            return NSS_STATUS_TRYAGAIN;
        }
        NSS_STATUS_SUCCESS
    }
}

impl LookupMod for LookupProgram {
    fn mount(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        self.mount_impl(ap, map, name)
    }

    fn reinit(&self, mapfmt: Option<&[u8]>, argv: &Argv) -> i32 {
        let mut parse = self.parse.lock().unwrap().clone();
        let r = do_init(mapfmt, argv, &mut parse, true);
        *self.parse.lock().unwrap() = parse;
        match r {
            Some((m, f)) => {
                *self.mapname.lock().unwrap() = m;
                *self.mapfmt.lock().unwrap() = f;
                0
            }
            None => 1,
        }
    }

    fn read_master(&self, _master: &Arc<Master>, _age: i64) -> i32 {
        NSS_STATUS_UNKNOWN
    }

    fn read_map(&self, _ap: &Arc<AutofsPoint>, _map: &Arc<MapSource>, _age: i64) -> i32 {
        NSS_STATUS_UNKNOWN
    }

    fn done(&self) -> i32 {
        self.parse.lock().unwrap().take().map_or(0, module::close_parse)
    }
}

const MAPENT_MAX_LEN: usize = 16384;

/// `lookup_one()`'s answer buffer, `malloc(MAPENT_MAX_LEN + 1)`ed and freed for
/// each run. glibc hands each run the chunk the last one freed, so the bytes
/// past an answer's NUL are what longer answers left there.
static ANSWER_BUF: std::sync::Mutex<Vec<u8>> = std::sync::Mutex::new(Vec::new());

fn remember_answer(mapent: &[u8]) {
    let mut b = ANSWER_BUF.lock().unwrap();
    if b.len() < mapent.len() + 1 {
        b.resize((mapent.len() + 1).max(MAPENT_MAX_LEN + 1), 0);
    }
    b[..mapent.len()].copy_from_slice(mapent);
    b[mapent.len()] = 0;
}

/// An amd program's answer past the key it repeats (`len` bytes) and blanks.
///
/// QUIRK: an answer shorter than the key is read past its end, into what a
/// previous answer (in practice the `/defaults` one) left in the buffer.
fn skip_key(ment: &[u8], len: usize) -> Vec<u8> {
    if len <= ment.len() {
        let mut i = len;
        while i < ment.len() && cstr::isblank(ment[i]) {
            i += 1;
        }
        return ment[i..].to_vec();
    }
    let b = ANSWER_BUF.lock().unwrap();
    let mut i = len.min(b.len());
    while i < b.len() && cstr::isblank(b[i]) {
        i += 1;
    }
    cstr::c(&b[i..]).to_vec()
}
