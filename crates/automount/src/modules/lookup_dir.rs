//! `modules/lookup_dir.c`: a directory of master map files (`dir:` master maps),
//! read in `versionsort()` order; only names ending in `.autofs` count.

use std::sync::Arc;

use crate::daemon::lookup;
use crate::daemon::master::{AutofsPoint, MapSource, Master};
use crate::daemon::module::LookupMod;
use crate::libautofs::args::{self, Argv};
use crate::libautofs::log::LOGOPT_NONE;
use crate::libautofs::nsswitch::{NSS_STATUS_NOTFOUND, NSS_STATUS_SUCCESS, NSS_STATUS_UNAVAIL, NSS_STATUS_UNKNOWN};
use crate::sys;

const MAX_INCLUDE_DEPTH: u32 = 16;
const AUTOFS_DIR_EXT: &[u8] = b".autofs";

#[derive(Debug)]
pub struct LookupDir {
    mapname: Vec<u8>,
}

/// `do_init()`.
fn do_init(argv: &Argv) -> Option<Vec<u8>> {
    let Some(m) = args::arg(argv, 0) else {
        logerr!("do_init", "60", "lookup(dir): No map name");
        return None;
    };
    if m.first() != Some(&b'/') {
        logmsg!("lookup(dir): dir map {} is not an absolute pathname", m);
        return None;
    }
    if sys::access(m, libc::R_OK) != 0 {
        warn!(LOGOPT_NONE, "lookup(dir): dir map {} missing or not readable", m);
        return None;
    }
    let Some(st) = sys::stat(m) else {
        warn!(LOGOPT_NONE, "lookup(dir): dir map {}, could not stat", m);
        return None;
    };
    let fmt = st.st_mode & libc::S_IFMT;
    if fmt != libc::S_IFDIR && fmt != libc::S_IFLNK {
        warn!(LOGOPT_NONE, "lookup(dir): dir map {}, is not a directory", m);
        return None;
    }
    Some(m.to_vec())
}

/// `lookup_init()`.
pub fn lookup_init(_mapfmt: Option<&[u8]>, argv: &Argv) -> Option<LookupDir> {
    do_init(argv).map(|mapname| LookupDir { mapname })
}

/// `acceptable_dirent_p()`.
fn acceptable(name: &[u8]) -> bool {
    if name.is_empty() || name[0] == b'.' {
        return false;
    }
    name.len() > AUTOFS_DIR_EXT.len() && name.ends_with(AUTOFS_DIR_EXT)
}

impl LookupMod for LookupDir {
    fn reinit(&mut self, _mapfmt: Option<&[u8]>, argv: &Argv) -> i32 {
        match do_init(argv) {
            Some(m) => {
                self.mapname = m;
                0
            }
            None => 1,
        }
    }

    /// `lookup_read_master()`.
    fn read_master(&mut self, master: &Arc<Master>, age: i64) -> i32 {
        let logopt = master.logopt();
        if master.lock().depth > MAX_INCLUDE_DEPTH {
            error!(logopt, "lookup_read_master", "lookup(dir): maximum include depth exceeded {}", master.name());
            return NSS_STATUS_UNAVAIL;
        }
        debug!(logopt, "lookup_read_master", "lookup(dir): scandir: {}", self.mapname);
        let mut names = match sys::read_dir_names(&self.mapname) {
            Ok(n) => n,
            Err(e) => {
                error!(
                    logopt,
                    "lookup_read_master",
                    "lookup(dir): could not scan master map dir {}: {}",
                    self.mapname,
                    sys::strerror(e)
                );
                return NSS_STATUS_UNAVAIL;
            }
        };
        names.retain(|n| acceptable(n));
        names.sort_by(|a, b| sys::versioncmp(a, b));
        for name in names {
            // include_file()
            let mut path = self.mapname.clone();
            path.push(b'/');
            path.extend_from_slice(&name);
            if path.len() > libc::PATH_MAX as usize {
                continue;
            }
            let save = master.name();
            master.set_name(path);
            master.lock().depth += 1;
            debug!(logopt, "include_file", "lookup(dir): include: {}", master.name());
            let status = lookup::lookup_nss_read_master(master, age);
            if status != NSS_STATUS_SUCCESS {
                warn!(logopt, "lookup(dir): failed to read included master map {}", master.name());
            }
            master.lock().depth -= 1;
            master.set_name(save);
        }
        let _ = NSS_STATUS_NOTFOUND;
        NSS_STATUS_SUCCESS
    }

    fn read_map(&mut self, _ap: &Arc<AutofsPoint>, _map: &Arc<MapSource>, _age: i64) -> i32 {
        NSS_STATUS_UNKNOWN
    }

    fn done(self: Box<Self>) -> i32 {
        0
    }
}
