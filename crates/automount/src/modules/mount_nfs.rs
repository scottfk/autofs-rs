//! `modules/mount_nfs.c`. This phase has its initialization: it keeps the bind
//! module open (opened by the first instance, closed by the last) and seeds
//! `random()` for server selection.

use std::sync::Mutex;

use crate::daemon::module::{self, MountMod};
use crate::sys;

/// `mount_bind` and `init_ctr`.
static STATE: Mutex<(Option<Box<dyn MountMod>>, u32)> = Mutex::new((None, 0));

#[derive(Debug)]
pub struct MountNfs;

/// `mount_init()`.
pub fn mount_init() -> Option<MountNfs> {
    let have = STATE.lock().unwrap().0.is_some();
    if !have {
        if let Some(b) = module::open_mount(b"bind", Some(b"mount(nfs): ")) {
            let mut s = STATE.lock().unwrap();
            s.0 = Some(b);
            s.1 += 1;
        }
    } else {
        STATE.lock().unwrap().1 += 1;
    }
    sys::seed_random(sys::monotonic_time());
    if STATE.lock().unwrap().0.is_some() { Some(MountNfs) } else { None }
}

impl MountMod for MountNfs {
    fn done(self: Box<Self>) -> i32 {
        let b = {
            let mut s = STATE.lock().unwrap();
            s.1 = s.1.wrapping_sub(1);
            if s.1 == 0 { s.0.take() } else { None }
        };
        b.map_or(0, module::close_mount)
    }
}
