//! `modules/mount_generic.c`: any file system type `mount -t` knows.

use std::sync::Arc;

use crate::daemon::automount::{MP_MODE, mkdir_path, rmdir_path};
use crate::daemon::master::{AutofsPoint, LKP_INDIRECT, MOUNT_FLAG_GHOST, MOUNT_FLAG_REMOUNT};
use crate::daemon::module::MountMod;
use crate::daemon::spawn;
use crate::sys;

#[derive(Debug)]
pub struct MountGeneric;

/// `mount_init()`.
pub fn mount_init() -> Option<MountGeneric> {
    Some(MountGeneric)
}

impl MountMod for MountGeneric {
    /// `mount_mount()`.
    fn mount(
        &mut self,
        ap: &Arc<AutofsPoint>,
        root: &[u8],
        name: &[u8],
        what: Option<&[u8]>,
        fstype: &[u8],
        options: Option<&[u8]>,
    ) -> i32 {
        let (flags, logopt, ty, dev) = {
            let a = ap.lock();
            (a.flags, a.logopt, a.ty, a.dev)
        };
        if flags & MOUNT_FLAG_REMOUNT != 0 {
            return 0;
        }
        let verbose = crate::libautofs::defaults::defaults_get_mount_verbose() != 0;
        let mountlog = |m: Vec<u8>| {
            if verbose {
                crate::libautofs::log::log_info(logopt, &m)
            } else {
                crate::libautofs::log::log_debug(logopt, &m)
            }
        };
        let Some(fullpath) = crate::libautofs::mounts::mount_fullpath(4096, root, name) else {
            error!(logopt, "mount_mount", "mount(generic): mount point path too long");
            return 1;
        };
        debug!(logopt, "mount_mount", "mount(generic): calling mkdir_path {}", fullpath);
        let status = mkdir_path(&fullpath, MP_MODE);
        if status != 0 && sys::errno() != libc::EEXIST {
            error!(
                logopt,
                "mount_mount",
                "mount(generic): mkdir_path {} failed: {}",
                fullpath,
                sys::strerror(sys::errno())
            );
            return 1;
        }
        let existed = status != 0;
        let what = what.unwrap_or(b"");
        let err = match options {
            Some(o) if !o.is_empty() => {
                mountlog(bfmt!("mount(generic): calling mount -t {} -o {} {} {}", fstype, o, what, fullpath));
                spawn::spawn_mount(logopt, &[b"-t", fstype, b"-o", o, what, &fullpath])
            }
            _ => {
                mountlog(bfmt!("mount(generic): calling mount -t {} {} {}", fstype, what, fullpath));
                spawn::spawn_mount(logopt, &[b"-t", fstype, what, &fullpath])
            }
        };
        if err != 0 {
            info!(logopt, "mount(generic): failed to mount {} (type {}) on {}", what, fstype, fullpath);
            if ty != LKP_INDIRECT {
                return 1;
            }
            if (flags & MOUNT_FLAG_GHOST == 0 && !name.is_empty()) || !existed {
                rmdir_path(ap, &fullpath, dev);
            }
            return 1;
        }
        mountlog(bfmt!("mount(generic): mounted {} type {} on {}", what, fstype, fullpath));
        0
    }

    fn done(self: Box<Self>) -> i32 {
        0
    }
}
