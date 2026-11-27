//! `modules/lookup_userhome.c`: a key is a user name, mounted as a symlink to
//! its home directory. Nothing selects this module: the master map's
//! `userdir` type asks for `lookup_userdir.so`, which doesn't exist.

use std::sync::Arc;

use crate::daemon::master::{AutofsPoint, MapSource, Master};
use crate::daemon::module::LookupMod;
use crate::libautofs::args::Argv;
use crate::libautofs::cache::CHE_FAIL;
use crate::libautofs::nsswitch::{NSS_STATUS_NOTFOUND, NSS_STATUS_SUCCESS, NSS_STATUS_UNAVAIL, NSS_STATUS_UNKNOWN};
use crate::sys;

#[derive(Debug)]
pub struct LookupUserhome;

pub fn lookup_init(_mapfmt: Option<&[u8]>, _argv: &Argv) -> Option<LookupUserhome> {
    Some(LookupUserhome)
}

impl LookupMod for LookupUserhome {
    fn reinit(&self, _mapfmt: Option<&[u8]>, _argv: &Argv) -> i32 {
        0
    }

    fn read_master(&self, _master: &Arc<Master>, _age: i64) -> i32 {
        NSS_STATUS_UNKNOWN
    }

    fn read_map(&self, _ap: &Arc<AutofsPoint>, _map: &Arc<MapSource>, _age: i64) -> i32 {
        NSS_STATUS_UNKNOWN
    }

    /// `lookup_mount()`.
    fn mount(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8]) -> i32 {
        let logopt = ap.logopt();
        debug!(logopt, "lookup_mount", "lookup(userhome): looking up {}", name);
        let Some(home) = sys::getpwnam_home(name) else {
            warn!(logopt, "lookup(userhome): not found: {}", name);
            return NSS_STATUS_NOTFOUND;
        };
        if sys::chdir(&ap.path()) != 0 {
            logerr!("lookup_mount", "74", "lookup(userhome): chdir failed: {}", sys::strerror(sys::errno()));
            return NSS_STATUS_UNAVAIL;
        }
        if map.mc().lock().update(map.id, name, None, sys::monotonic_time()) == CHE_FAIL {
            sys::chdir(b"/");
            return NSS_STATUS_UNAVAIL;
        }
        if sys::symlink(&home, name) != 0 && sys::errno() != libc::EEXIST {
            logerr!("lookup_mount", "89", "lookup(userhome): symlink failed: {}", sys::strerror(sys::errno()));
            return NSS_STATUS_UNAVAIL;
        }
        sys::chdir(b"/");
        NSS_STATUS_SUCCESS
    }

    fn done(&self) -> i32 {
        0
    }
}
