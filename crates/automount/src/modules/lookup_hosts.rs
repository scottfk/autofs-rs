//! `modules/lookup_hosts.c`: the `-hosts` map. This phase has its setup and
//! the map read: every host `gethostent()` lists (the hosts database, as
//! nsswitch enumerates it) becomes a key. Export lists (`MOUNTPROC_EXPORT`)
//! and mounts come in phase 2 and later.

use std::sync::Arc;

use crate::daemon::master::{AutofsPoint, LKP_DIRECT, MOUNT_FLAG_GHOST, MapSource, Master};
use crate::daemon::module::{self, LookupMod};
use crate::libautofs::args::Argv;
use crate::libautofs::nsswitch::{NSS_STATUS_SUCCESS, NSS_STATUS_UNKNOWN};
use crate::sys;

const MODPREFIX: &[u8] = b"lookup(hosts): ";

#[derive(Debug)]
pub struct LookupHosts {
    parse: std::sync::Mutex<Option<module::Parse>>,
}

/// `lookup_init()`.
pub fn lookup_init(_mapfmt: Option<&[u8]>, argv: &Argv) -> Option<LookupHosts> {
    match module::open_parse(b"sun", Some(MODPREFIX), argv) {
        Some(p) => Some(LookupHosts { parse: std::sync::Mutex::new(Some(p)) }),
        None => {
            logerr!("lookup_init", "57", "lookup(hosts): failed to open parse context");
            None
        }
    }
}

impl LookupMod for LookupHosts {
    fn reinit(&self, _mapfmt: Option<&[u8]>, argv: &Argv) -> i32 {
        let p = self.parse.lock().unwrap().clone().expect("parse context");
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
        if flags & MOUNT_FLAG_GHOST == 0 && ty != LKP_DIRECT {
            debug!(logopt, "lookup_read_map", "lookup(hosts): map not browsable, update existing host entries only");
            // update_hosts_mounts(): only multi-mount (already expanded)
            // entries are updated; a map read doesn't make any.
            source.lock().age = age;
            return NSS_STATUS_SUCCESS;
        }
        for name in sys::host_names() {
            mc.lock().update(source.id, &name, None, age);
        }
        source.lock().age = age;
        NSS_STATUS_SUCCESS
    }

    fn done(&self) -> i32 {
        self.parse.lock().unwrap().take().map_or(0, module::close_parse)
    }
}
