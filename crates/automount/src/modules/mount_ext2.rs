//! `modules/mount_ext2.c`: ext2, ext3 and ext4, checked with the matching
//! `fsck` first (`-n` for a read-only mount, `-p` otherwise).

use std::sync::Arc;

use crate::daemon::automount::{MP_MODE, mkdir_path, rmdir_path};
use crate::daemon::master::{AutofsPoint, LKP_INDIRECT, MOUNT_FLAG_GHOST, MOUNT_FLAG_REMOUNT};
use crate::daemon::module::MountMod;
use crate::daemon::spawn;
use crate::libautofs::cat_path::strncmp_len;
use crate::libautofs::cstr;
use crate::sys;

// hydra's build (config.h).
const PATH_E2FSCK: &[u8] = b"/usr/bin/fsck.ext2";
const PATH_E3FSCK: &[u8] = b"/usr/bin/fsck.ext3";
const PATH_E4FSCK: &[u8] = b"/usr/bin/fsck.ext4";

#[derive(Debug)]
pub struct MountExt2;

/// `mount_init()`.
pub fn mount_init() -> Option<MountExt2> {
    Some(MountExt2)
}

/// Whether the options ask for `ro`, as C's loop finds it.
fn has_ro(options: &[u8]) -> bool {
    let o = cstr::c(options);
    let mut ro = false;
    let mut p = 0usize;
    // for (p = options; (p1 = strchr(p, ',')); p = p1)
    //     if (!_strncmp("ro", p, p1 - p) && ++p1 - p == sizeof("ro"))
    while let Some(k) = cstr::strchr(&o[p..], b',') {
        let mut p1 = p + k;
        if strncmp_len(b"ro", &o[p..], p1 - p) == 0 {
            p1 += 1;
            if p1 - p == 3 {
                ro = true;
            }
        }
        p = p1;
    }
    if &o[p..] == b"ro" {
        ro = true;
    }
    ro
}

impl MountMod for MountExt2 {
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
            error!(logopt, "mount_mount", "mount(ext2): mount point path too long");
            return 1;
        };
        debug!(logopt, "mount_mount", "mount(ext2): calling mkdir_path {}", fullpath);
        let status = mkdir_path(&fullpath, MP_MODE);
        if status != 0 && sys::errno() != libc::EEXIST {
            error!(
                logopt,
                "mount_mount",
                "mount(ext2): mkdir_path {} failed: {}",
                fullpath,
                sys::strerror(sys::errno())
            );
            return 1;
        }
        let existed = status != 0;
        let ro = options.is_some_and(|o| !o.is_empty() && has_ro(o));
        let fsck_prog = match cstr::c(fstype) {
            b"ext3" => PATH_E3FSCK,
            b"ext4" => PATH_E4FSCK,
            _ => PATH_E2FSCK,
        };
        let what = what.unwrap_or(b"");
        let flag: &[u8] = if ro { b"-n" } else { b"-p" };
        debug!(logopt, "mount_mount", "mount(ext2): calling {} {} {}", fsck_prog, flag, what);
        let err = spawn::spawnv(logopt, fsck_prog, &[fsck_prog.to_vec(), flag.to_vec(), what.to_vec()]);
        // spawnl() gives the exit status shifted by 8: 2 is "corrected, reboot",
        // 4 "errors left".
        if (err >> 8) & 6 != 0 {
            error!(logopt, "mount_mount", "mount(ext2): {}: filesystem needs repair, won't mount", what);
            return 1;
        }
        let err = match options {
            Some(o) => {
                mountlog(bfmt!("mount(ext2): calling mount -t {} -o {} {} {}", fstype, o, what, fullpath));
                spawn::spawn_mount(logopt, &[b"-t", fstype, b"-o", o, what, &fullpath])
            }
            None => {
                mountlog(bfmt!("mount(ext2): calling mount -t {} {} {}", fstype, what, fullpath));
                spawn::spawn_mount(logopt, &[b"-t", fstype, what, &fullpath])
            }
        };
        if err != 0 {
            info!(logopt, "mount(ext2): failed to mount {} (type {}) on {}", what, fstype, fullpath);
            if ty != LKP_INDIRECT {
                return 1;
            }
            if (flags & MOUNT_FLAG_GHOST == 0 && !name.is_empty()) || !existed {
                rmdir_path(ap, &fullpath, dev);
            }
            return 1;
        }
        mountlog(bfmt!("mount(ext2): mounted {} type {} on {}", what, fstype, fullpath));
        0
    }

    fn done(self: Box<Self>) -> i32 {
        0
    }
}
