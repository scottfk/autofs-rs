//! `modules/lookup_program.c`. This phase has its setup and its (unsupported)
//! map reads; running the program for a key comes with the daemon.

use std::sync::Arc;

use crate::daemon::master::{AutofsPoint, MapSource, Master};
use crate::daemon::module::{self, LookupMod, ParseMod};
use crate::libautofs::args::{self, Argv};
use crate::libautofs::nsswitch::NSS_STATUS_UNKNOWN;
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

impl LookupMod for LookupProgram {
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
