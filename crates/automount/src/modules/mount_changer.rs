//! `modules/mount_changer.c`: an iso9660 CD in a changer slot (the key),
//! loaded with `CDROM_SELECT_DISC` before the mount.

use std::sync::Arc;

use crate::daemon::automount::{MP_MODE, mkdir_path, rmdir_path};
use crate::daemon::master::{AutofsPoint, LKP_INDIRECT, MOUNT_FLAG_GHOST, MOUNT_FLAG_REMOUNT};
use crate::daemon::module::MountMod;
use crate::daemon::spawn;
use crate::sys;

const CDROM_SELECT_DISC: libc::c_ulong = 0x5323;
const CDROM_CHANGER_NSLOTS: libc::c_ulong = 0x5328;

#[derive(Debug)]
pub struct MountChanger;

/// `mount_init()`.
pub fn mount_init() -> Option<MountChanger> {
    Some(MountChanger)
}

/// `atoi()`.
fn atoi(s: &[u8]) -> i32 {
    let s = crate::libautofs::cstr::c(s);
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        i += 1;
    }
    let neg = i < s.len() && s[i] == b'-';
    if i < s.len() && (s[i] == b'-' || s[i] == b'+') {
        i += 1;
    }
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.wrapping_mul(10).wrapping_add((s[i] - b'0') as i64);
        i += 1;
    }
    (if neg { -v } else { v }) as i32
}

/// `swapCD()`: 0 when the slot's disc is loaded.
fn swap_cd(device: &[u8], slot_name: &[u8]) -> i32 {
    let slot = atoi(slot_name).wrapping_sub(1);
    // open_fd() (daemon/spawn.c) logs its own failure first.
    let fd = sys::open_flags(device, libc::O_RDONLY | libc::O_NONBLOCK);
    if fd < 0 {
        let e = sys::errno();
        logerr!("open_fd", "102", "failed to open file: {}", sys::strerror(e));
        sys::set_errno(e);
        logerr!("swapCD", "151", "mount(changer): Opening device {} failed : {}", device, sys::strerror(sys::errno()));
        return 1;
    }
    // SAFETY: plain ioctls on an open descriptor.
    let total = unsafe { libc::ioctl(fd, CDROM_CHANGER_NSLOTS) };
    if total <= 1 {
        logerr!("swapCD", "159", "mount(changer): Device {} is not an ATAPI compliant CD changer.", device);
        sys::close(fd);
        return 1;
    }
    // SAFETY: as above; the slot is passed by value.
    let r = unsafe { libc::ioctl(fd, CDROM_SELECT_DISC, slot as libc::c_long) };
    if r < 0 {
        logerr!("swapCD", "169", "mount(changer): CDROM_SELECT_DISC failed");
        sys::close(fd);
        return 1;
    }
    if sys::close(fd) != 0 {
        logerr!("swapCD", "177", "mount(changer): close failed for `{}': {}", device, sys::strerror(sys::errno()));
        return 1;
    }
    0
}

impl MountMod for MountChanger {
    /// `mount_mount()`.
    fn mount(
        &mut self,
        ap: &Arc<AutofsPoint>,
        root: &[u8],
        name: &[u8],
        what: Option<&[u8]>,
        _fstype: &[u8],
        options: Option<&[u8]>,
    ) -> i32 {
        let (flags, logopt, ty, dev) = {
            let a = ap.lock();
            (a.flags, a.logopt, a.ty, a.dev)
        };
        if flags & MOUNT_FLAG_REMOUNT != 0 {
            return 0;
        }
        let fstype: &[u8] = b"iso9660";
        let Some(fullpath) = crate::libautofs::mounts::mount_fullpath(4096, root, name) else {
            error!(logopt, "mount_mount", "mount(changer): mount point path too long");
            return 1;
        };
        let what = what.unwrap_or(b"");
        debug!(logopt, "mount_mount", "mount(changer): calling umount {}", what);
        if spawn::spawn_umount(logopt, &[what]) != 0 {
            error!(logopt, "mount_mount", "mount(changer): umount of {} failed (all may be unmounted)", what);
        }
        debug!(logopt, "mount_mount", "mount(changer): calling mkdir_path {}", fullpath);
        let status = mkdir_path(&fullpath, MP_MODE);
        if status != 0 && sys::errno() != libc::EEXIST {
            error!(
                logopt,
                "mount_mount",
                "mount(changer): mkdir_path {} failed: {}",
                fullpath,
                sys::strerror(sys::errno())
            );
            return 1;
        }
        let existed = status != 0;
        debug!(logopt, "mount_mount", "mount(changer): Swapping CD to slot {}", name);
        if swap_cd(what, name) != 0 {
            error!(logopt, "mount_mount", "mount(changer): failed to swap CD to slot {}", name);
            return 1;
        }
        let err = match options {
            Some(o) if !o.is_empty() => {
                debug!(
                    logopt,
                    "mount_mount", "mount(changer): calling mount -t {} -o {} {} {}", fstype, o, what, fullpath
                );
                spawn::spawn_mount(logopt, &[b"-t", fstype, b"-o", o, what, &fullpath])
            }
            _ => {
                debug!(logopt, "mount_mount", "mount(changer): calling mount -t {} {} {}", fstype, what, fullpath);
                spawn::spawn_mount(logopt, &[b"-t", fstype, what, &fullpath])
            }
        };
        if err != 0 {
            info!(logopt, "mount(changer): failed to mount {} (type {}) on {}", what, fstype, fullpath);
            if ty != LKP_INDIRECT {
                return 1;
            }
            if (flags & MOUNT_FLAG_GHOST == 0 && !name.is_empty()) || !existed {
                rmdir_path(ap, &fullpath, dev);
            }
            return 1;
        }
        debug!(logopt, "mount_mount", "mount(changer): mounted {} type {} on {}", what, fstype, fullpath);
        0
    }

    fn done(self: Box<Self>) -> i32 {
        0
    }
}
