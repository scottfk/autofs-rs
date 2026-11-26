//! `modules/mount_bind.c`. This phase has its initialization, which checks
//! that bind mounts work by making one between two new directories in `/tmp`.

use std::sync::atomic::{AtomicBool, Ordering};

use crate::daemon::module::MountMod;
use crate::daemon::spawn;
use crate::libautofs::log::{LOGOPT_ANY, LOGOPT_NONE};
use crate::sys;

/// `bind_works`.
pub static BIND_WORKS: AtomicBool = AtomicBool::new(false);

#[derive(Debug)]
pub struct MountBind;

/// `mount_init()`.
pub fn mount_init() -> Option<MountBind> {
    let t1 = sys::mkdtemp(b"/tmp/autoXXXXXX");
    let t2 = sys::mkdtemp(b"/tmp/autoXXXXXX");
    let (Some(t1), Some(t2)) = (t1.clone(), t2.clone()) else {
        if let Some(t) = t1 {
            sys::rmdir(&t);
        }
        if let Some(t) = t2 {
            sys::rmdir(&t);
        }
        return Some(MountBind);
    };
    if let Some(st1) = sys::lstat(&t1) {
        let err = spawn::spawn_mount(LOGOPT_NONE, &[b"-n", b"--bind", &t1, &t2]);
        if err == 0
            && let Some(st2) = sys::lstat(&t2)
            && st1.st_dev == st2.st_dev
            && st1.st_ino == st2.st_ino
        {
            BIND_WORKS.store(true, Ordering::Relaxed);
        }
        if spawn::spawn_umount(LOGOPT_NONE, &[b"-n", &t2]) != 0 {
            debug!(LOGOPT_ANY, "mount_init", "mount(bind): umount failed for {}", t2);
        }
    }
    sys::rmdir(&t1);
    sys::rmdir(&t2);
    Some(MountBind)
}

impl MountMod for MountBind {
    fn done(self: Box<Self>) -> i32 {
        0
    }
}
