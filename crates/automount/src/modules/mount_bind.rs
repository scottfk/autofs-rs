//! `modules/mount_bind.c`: local file systems bound (`mount --bind`) at the
//! mount point, or symlinked when binds don't work or the entry asks for it
//! (`symlink`). Its initialization checks that bind mounts work by making one
//! between two new directories in `/tmp`.

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

const PATH_MAX: usize = 4096;

/// Whether the options include `symlink` (as a whole option).
fn has_symlink_opt(options: &[u8]) -> bool {
    let o = crate::libautofs::cstr::c(options);
    let mut i = 0;
    let mut found = false;
    while i < o.len() {
        while i < o.len() && o[i] == b',' {
            i += 1;
        }
        while i < o.len() && (o[i] == b' ' || o[i] == b'\t') {
            i += 1;
        }
        let cp = i;
        while i < o.len() && o[i] != b',' {
            i += 1;
        }
        // C's trailing white space loop tests the separator, so it never runs.
        let o_len = i.saturating_sub(cp);
        if crate::libautofs::cat_path::strncmp_len(b"symlink", &o[cp..], o_len) == 0 {
            found = true;
        }
    }
    found
}

impl MountMod for MountBind {
    /// `mount_mount()`.
    fn mount(
        &mut self,
        ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>,
        root: &[u8],
        name: &[u8],
        what: Option<&[u8]>,
        fstype: &[u8],
        options: Option<&[u8]>,
    ) -> i32 {
        use crate::daemon::automount::{MP_MODE, mkdir_path, rmdir_path};
        use crate::daemon::master::{
            LKP_INDIRECT, MOUNT_FLAG_GHOST, MOUNT_FLAG_PRIVATE, MOUNT_FLAG_REMOUNT, MOUNT_FLAG_SHARED,
            MOUNT_FLAG_SYMLINK,
        };
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
        let abs = name.first() == Some(&b'/');
        let mut symlnk = !abs && flags & MOUNT_FLAG_SYMLINK != 0;
        if !abs
            && !symlnk
            && let Some(o) = options
        {
            symlnk = has_symlink_opt(o);
        }
        let Some(mut fullpath) = crate::libautofs::mounts::mount_fullpath(PATH_MAX, root, name) else {
            error!(logopt, "mount_mount", "mount(bind): mount point path too long");
            return 1;
        };
        while fullpath.len() > 1 && fullpath.last() == Some(&b'/') {
            fullpath.pop();
        }
        let options: &[u8] = match options {
            Some(o) if !o.is_empty() => o,
            _ => b"defaults",
        };
        let what = what.unwrap_or(b"");
        if crate::libautofs::cstr::eq(what, &fullpath) {
            debug!(logopt, "mount_mount", "mount(bind): cannot mount or symlink {} to itself", fullpath);
            return 1;
        }
        if !symlnk && BIND_WORKS.load(Ordering::Relaxed) {
            debug!(logopt, "mount_mount", "mount(bind): calling mkdir_path {}", fullpath);
            let status = mkdir_path(&fullpath, MP_MODE);
            if status != 0 && sys::errno() != libc::EEXIST {
                error!(
                    logopt,
                    "mount_mount",
                    "mount(bind): mkdir_path {} failed: {}",
                    fullpath,
                    sys::strerror(sys::errno())
                );
                return 1;
            }
            let existed = status != 0;
            mountlog(bfmt!("mount(bind): calling mount --bind -o {} {} {}", options, what, fullpath));
            let err = spawn::spawn_bind_mount(logopt, &[b"-o", options, what, &fullpath]);
            if err != 0 {
                if ty != LKP_INDIRECT {
                    return 1;
                }
                if !existed && (flags & MOUNT_FLAG_GHOST == 0 && !name.is_empty()) {
                    rmdir_path(ap, &fullpath, dev);
                }
                return err;
            }
            mountlog(bfmt!("mount(bind): mounted {} type {} on {}", what, fstype, fullpath));
            // Set the propagation (slave unless the master map says otherwise).
            let mut mflags = libc::MS_SLAVE;
            if flags & MOUNT_FLAG_PRIVATE != 0 {
                mflags = libc::MS_PRIVATE;
            } else if flags & MOUNT_FLAG_SHARED != 0 {
                mflags = libc::MS_SHARED;
            }
            if sys::mount_flags_only(&fullpath, mflags) != 0 {
                warn!(logopt, "failed to set propagation for {}", fullpath);
            }
            return 0;
        }
        let mut basepath = fullpath.clone();
        if let Some(cp) = crate::libautofs::cstr::strrchr(&basepath, b'/')
            && cp != 0
        {
            basepath.truncate(cp);
        }
        let st = sys::stat(&fullpath);
        if let Some(st) = &st {
            if st.st_mode & libc::S_IFMT == libc::S_IFDIR {
                sys::rmdir(&fullpath);
            }
        } else {
            debug!(logopt, "mount_mount", "mount(bind): calling mkdir_path {}", basepath);
            if mkdir_path(&basepath, MP_MODE) != 0 && sys::errno() != libc::EEXIST {
                error!(
                    logopt,
                    "mount_mount",
                    "mount(bind): mkdir_path {} failed: {}",
                    basepath,
                    sys::strerror(sys::errno())
                );
                return 1;
            }
        }
        if sys::symlink(what, &fullpath) != 0 && sys::errno() != libc::EEXIST {
            error!(logopt, "mount_mount", "mount(bind): failed to create symlink {} -> {}", fullpath, what);
            if flags & MOUNT_FLAG_GHOST != 0 && st.is_some() {
                if mkdir_path(&fullpath, MP_MODE) != 0 && sys::errno() != libc::EEXIST {
                    error!(
                        logopt,
                        "mount_mount",
                        "mount(bind): mkdir_path {} failed: {}",
                        fullpath,
                        sys::strerror(sys::errno())
                    );
                }
            } else if ty == LKP_INDIRECT {
                rmdir_path(ap, &fullpath, dev);
            }
            return 1;
        }
        mountlog(bfmt!("mount(bind): symlinked {} -> {}", fullpath, what));
        0
    }

    fn done(self: Box<Self>) -> i32 {
        0
    }
}
