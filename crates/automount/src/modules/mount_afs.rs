//! `modules/mount_afs.c`: an AFS path, as a symlink to it.

use std::sync::Arc;

use crate::daemon::master::{AutofsPoint, MOUNT_FLAG_REMOUNT};
use crate::daemon::module::MountMod;
use crate::libautofs::cstr;
use crate::sys;

const PATH_MAX: usize = 4096;

#[derive(Debug)]
pub struct MountAfs;

/// `mount_init()`.
pub fn mount_init() -> Option<MountAfs> {
    Some(MountAfs)
}

impl MountMod for MountAfs {
    /// `mount_mount()`: `symlink()`'s result.
    fn mount(
        &mut self,
        ap: &Arc<AutofsPoint>,
        root: &[u8],
        name: &[u8],
        what: Option<&[u8]>,
        _fstype: &[u8],
        _options: Option<&[u8]>,
    ) -> i32 {
        let (flags, logopt) = {
            let a = ap.lock();
            (a.flags, a.logopt)
        };
        if flags & MOUNT_FLAG_REMOUNT != 0 {
            return 0;
        }
        let root = cstr::c(root);
        let name = cstr::c(name);
        if root.len() + name.len() + 2 > PATH_MAX {
            return 1;
        }
        let mut dest = [root, b"/", name].concat();
        // A trailing slash goes (http://bugs.debian.org/141775).
        if dest.last() == Some(&b'/') {
            dest.pop();
        }
        let what = what.unwrap_or(b"");
        let m = bfmt!("mount(afs): mounting AFS {} -> {}", dest, what);
        if crate::libautofs::defaults::defaults_get_mount_verbose() != 0 {
            crate::libautofs::log::log_info(logopt, &m);
        } else {
            crate::libautofs::log::log_debug(logopt, &m);
        }
        sys::symlink(what, &dest)
    }

    fn done(self: Box<Self>) -> i32 {
        0
    }
}
