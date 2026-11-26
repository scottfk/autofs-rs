//! `modules/lookup_program.c`: executable maps. The program is run with the
//! key as its argument and the standard macros in its environment (with an
//! `AUTOFS_` prefix unless `force_standard_program_map_env`), its stdout read
//! as the map entry and its stderr logged (`>> ...`). amd program maps come
//! with the amd parser.

use std::sync::Arc;

use crate::daemon::lookup;
use crate::daemon::master::{AutofsPoint, MapSource, Master};
use crate::daemon::master::{MAP_FLAG_FORMAT_AMD, MOUNT_FLAG_REMOUNT};
use crate::daemon::module::{self, LookupMod, ParseMod};
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
    pub mapname: Vec<u8>,
    pub mapfmt: Vec<u8>,
    pub parse: Option<Box<dyn ParseMod>>,
}

/// `do_init()`.
fn do_init(
    mapfmt: Option<&[u8]>,
    argv: &Argv,
    parse: &mut Option<Box<dyn ParseMod>>,
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
        let p = parse.as_mut().expect("parse context");
        if module::reinit_parse(p.as_mut(), &mapfmt, Some(MODPREFIX), &rest) != 0 {
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
    Some(LookupProgram { mapname, mapfmt, parse })
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
        if self.mapfmt == b"sun"
            && let Some(mut subst) = self.parse.as_ref().and_then(|p| p.subst())
        {
            mounts::addstdenv(&mut subst, prefix);
            for sv in macros::global_table().iter().chain(subst.iter()) {
                sets.push((sv.def.clone(), sv.val.clone()));
            }
        }
        let env = sys::environ_with(&sets);
        let path = ap.path();
        let chdir_msg = if log::have_log_verbose() || log::have_log_debug() || logopt != 0 {
            bfmt!("lookup(program): failed to set PWD to {} for map {}", path, self.mapname)
        } else {
            Vec::new()
        };
        let f = sys::spawn_program(
            &self.mapname,
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
            let hup = (libc::POLLIN | libc::POLLHUP) as i16;
            if rev0 & hup == libc::POLLHUP as i16 && rev1 & hup == libc::POLLHUP as i16 {
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

    /// `match_key()` for sun maps.
    fn match_key(&self, ap: &Arc<AutofsPoint>, source: &Arc<MapSource>, name: &[u8]) -> Result<Vec<u8>, i32> {
        if source.lock().flags & MAP_FLAG_FORMAT_AMD != 0 {
            panic!("amd program maps aren't ported yet (phase 2)");
        }
        match self.lookup_one(ap, name) {
            Some(ment) => {
                let ret = source.mc().lock().update(source.id, name, Some(&ment), sys::monotonic_time());
                if ret == crate::libautofs::cache::CHE_FAIL {
                    return Err(NSS_STATUS_UNAVAIL);
                }
                Ok(ment)
            }
            None => Err(NSS_STATUS_NOTFOUND),
        }
    }

    /// `lookup_mount()`.
    fn mount_impl(&mut self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
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
                (e.mapent.clone(), e.age, e.mm)
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
                    let mut parse = self.parse.take().expect("parse context");
                    ret = parse.mount(ap, source, name, m.as_deref());
                    self.parse = Some(parse);
                    done = true;
                } else {
                    if mm {
                        panic!("multi-mount program map entries aren't ported yet (phase 4)");
                    }
                    let mut c = mc.lock();
                    if c.lookup_distinct(name).is_some() {
                        c.delete(name);
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
                    let mut parse = self.parse.take().expect("parse context");
                    ret = parse.mount(ap, source, name, Some(&mapent));
                    self.parse = Some(parse);
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
    fn mount(&mut self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        self.mount_impl(ap, map, name)
    }

    fn reinit(&mut self, mapfmt: Option<&[u8]>, argv: &Argv) -> i32 {
        match do_init(mapfmt, argv, &mut self.parse, true) {
            Some((m, f)) => {
                self.mapname = m;
                self.mapfmt = f;
                0
            }
            None => 1,
        }
    }

    fn read_master(&mut self, _master: &Arc<Master>, _age: i64) -> i32 {
        NSS_STATUS_UNKNOWN
    }

    fn read_map(&mut self, _ap: &Arc<AutofsPoint>, _map: &Arc<MapSource>, _age: i64) -> i32 {
        NSS_STATUS_UNKNOWN
    }

    fn done(self: Box<Self>) -> i32 {
        self.parse.map_or(0, module::close_parse)
    }
}
