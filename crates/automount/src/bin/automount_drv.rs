//! `automount-drv`: the test driver (not installed). Reads the master map and
//! the maps as the daemon does, then looks keys up, with recording mount
//! modules; `tests/drv/drv.c` does the same with the reference build.
//!
//! Usage: `automount-drv [-d] [-v] PATH KEY UID GID [PATH KEY UID GID...]`

use std::sync::Arc;

use automount::daemon::master::{self, DAEMON_FLAGS_GHOST, MOUNT_FLAG_GHOST};
use automount::daemon::{lookup, master_parse, module};
use automount::libautofs::cache::Cache;
use automount::libautofs::{defaults, log, macros, mounts};
use automount::sys;

fn main() {
    use std::os::unix::ffi::OsStringExt;
    let argv: Vec<Vec<u8>> = std::env::args_os().map(|a| a.into_vec()).collect();
    sys::block_all_signals();
    module::FAKE_MOUNTS.store(true, std::sync::atomic::Ordering::Relaxed);
    let mut i = 1;
    while i < argv.len() && argv[i].first() == Some(&b'-') {
        match &argv[i][..] {
            b"-d" => log::set_log_debug(0),
            b"-v" => log::set_log_verbose(),
            _ => {}
        }
        i += 1;
    }
    if !defaults::defaults_read_config(false) {
        log::print(b"drv: failed to read configuration\n");
        sys::exit(1);
    }
    let flags = if defaults::defaults_get_browse_mode() != 0 { DAEMON_FLAGS_GHOST } else { 0 };
    macros::macro_init();
    let ml = master::master_new(None, defaults::defaults_get_timeout(), flags);
    *master::MASTER_LIST.lock().unwrap() = Some(ml.clone());
    log::log_to_stderr();
    master_parse::master_init_scan();
    ml.lock().nc = Some(Arc::new(Cache::init_null()));
    let age = sys::monotonic_time();
    lookup::lookup_nss_read_master(&ml, age);
    for entry in ml.mounts() {
        let ap = entry.ap();
        log::print(&format!("drv: entry {}\n", String::from_utf8_lossy(&ap.path())).into_bytes());
        if !lookup::lookup_nss_read_map(&ap, None, age) {
            log::print(&format!("drv: failed to read map for {}\n", String::from_utf8_lossy(&ap.path())).into_bytes());
        }
        lookup::lookup_prune_cache(&ap, age);
        if ap.lock().flags & MOUNT_FLAG_GHOST != 0 {
            let r = lookup::lookup_ghost(&ap);
            log::print(&format!("drv: ghost {} -> {:#x}\n", String::from_utf8_lossy(&ap.path()), r).into_bytes());
        }
    }
    log::flush_stdout();
    while i + 3 < argv.len() {
        let (path, key) = (&argv[i], &argv[i + 1]);
        let atoi = |a: &[u8]| String::from_utf8_lossy(a).parse::<u32>().unwrap_or(0);
        match master::master_find_mapent(&ml, path) {
            None => log::print(&format!("drv: no entry {}\n", String::from_utf8_lossy(path)).into_bytes()),
            Some(entry) => {
                let ap = entry.ap();
                mounts::set_tsd_user_vars(ap.logopt(), atoi(&argv[i + 2]), atoi(&argv[i + 3]));
                let ret = lookup::lookup_nss_mount(&ap, None, key);
                log::print(
                    &format!(
                        "drv: lookup {} {} -> {}\n",
                        String::from_utf8_lossy(path),
                        String::from_utf8_lossy(key),
                        ret as i32
                    )
                    .into_bytes(),
                );
            }
        }
        log::flush_stdout();
        i += 4;
    }
    for entry in ml.mounts() {
        lookup::lookup_close_lookup(&entry.ap());
    }
    log::print(b"drv: done\n");
    sys::exit(0);
}
