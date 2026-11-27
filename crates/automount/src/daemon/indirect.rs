//! `daemon/indirect.c`: indirect autofs mounts: mounting and unmounting the
//! autofs file system, the expire thread, and the handlers for the kernel's
//! mount (`missing_indirect`) and expire (`expire_indirect`) requests, each
//! of which runs in a thread of its own.

use std::sync::Arc;

use crate::daemon::automount::{self, DO_FORCE_UNLINK, MP_MODE, UNLINK_AND_EXIT};
use crate::daemon::lookup;
use crate::daemon::master::{self, AutofsPoint, MOUNT_FLAG_DIR_CREATED, MOUNT_FLAG_GHOST, MOUNT_FLAG_REMOUNT};
use crate::daemon::state::{self, ExpireCleanup, Handshake, ST_EXPIRE, ST_PRUNE, ST_SHUTDOWN_FORCE};
use crate::libautofs::alarm;
use crate::libautofs::cstr;
use crate::libautofs::dev_ioctl::{self, AUTOFS_EXP_IMMEDIATE, AUTOFS_TYPE_INDIRECT};
use crate::libautofs::mounts::{self, MNTS_AUTOFS, MNTS_INDIRECT, MNTS_MOUNTED, MNTS_OFFSET};
use crate::libautofs::parse_subs;
use crate::sys;

const CHECK_RATIO: i64 = 4;
const UMOUNT_RETRIES: u32 = 16;
pub const LKP_FAIL: u32 = 0x0001;
pub const LKP_DIRECT: u32 = 0x0004;
pub const LKP_NOTSUP: u32 = 0x8000;

/// `do_mount_autofs_indirect()`.
fn do_mount_autofs_indirect(ap: &Arc<AutofsPoint>) -> i32 {
    let str_indirect = mounts::mount_type_str(AUTOFS_TYPE_INDIRECT).unwrap();
    let logopt = ap.logopt();
    let path = ap.path();
    let maps = ap.entry().maps();
    let first = maps.first().cloned();
    let timeout = master::get_exp_timeout(ap, first.as_deref());
    // If the map is shared the timeout can't come from the map source, so the
    // run frequency was set already.
    if first.as_ref().is_none_or(|m| m.lock().refcnt <= 1) {
        ap.lock().exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;
    }
    let force = DO_FORCE_UNLINK.load(std::sync::atomic::Ordering::Relaxed);
    let close_fds = |ap: &AutofsPoint| {
        let (p, k) = {
            let a = ap.lock();
            (a.pipefd, a.kpipefd)
        };
        sys::close(p);
        sys::close(k);
    };
    if dev_ioctl::has_version() && force == 0 {
        ap.lock().flags |= MOUNT_FLAG_REMOUNT;
        let ret = mounts::try_remount_indirect(ap);
        ap.lock().flags &= !MOUNT_FLAG_REMOUNT;
        if ret == 1 {
            return 0;
        }
        if ret == 0 {
            return -1;
        }
    } else {
        if !mounts::unlink_mount_tree(logopt, &path) {
            error!(
                logopt,
                "do_mount_autofs_indirect", "already mounted as other than autofs or failed to unlink entry in tree"
            );
            close_fds(ap);
            return -1;
        }
        if force & UNLINK_AND_EXIT != 0 {
            return -1;
        }
    }
    let (kpipefd, flags) = {
        let a = ap.lock();
        (a.kpipefd, a.flags)
    };
    let options = mounts::make_options_string(&path, kpipefd, Some(str_indirect), flags);
    // In case the directory doesn't exist, try to mkdir it.
    if automount::mkdir_path(&path, MP_MODE) < 0 {
        let e = sys::errno();
        if e != libc::EEXIST && e != libc::EROFS {
            crit!(logopt, "do_mount_autofs_indirect", "failed to create autofs directory {}", path);
            close_fds(ap);
            return -1;
        }
        ap.lock().flags &= !MOUNT_FLAG_DIR_CREATED;
    } else {
        ap.lock().flags |= MOUNT_FLAG_DIR_CREATED;
    }
    let map_name = match first.as_ref() {
        Some(m) => {
            let d = m.lock();
            match d.ty.as_deref() {
                Some(t) if cstr::eq(t, b"hosts") => b"-hosts".to_vec(),
                _ => d.argv.first().cloned().flatten().unwrap_or_default(),
            }
        }
        None => b"-hosts".to_vec(),
    };
    let fail_rmdir = |ap: &AutofsPoint| {
        if ap.lock().flags & MOUNT_FLAG_DIR_CREATED != 0 {
            sys::rmdir(&path);
        }
        close_fds(ap);
        -1
    };
    if sys::mount(&map_name, &path, b"autofs", libc::MS_MGC_VAL, Some(&options)) != 0 {
        crit!(logopt, "do_mount_autofs_indirect", "failed to mount autofs at {}", path);
        return fail_rmdir(ap);
    }
    let Some(st) = sys::stat(&path) else {
        crit!(logopt, "do_mount_autofs_indirect", "failed to stat mount for autofs path {}", path);
        sys::umount(&path);
        return fail_rmdir(ap);
    };
    let mode = {
        let mut a = ap.lock();
        a.dev = st.st_dev;
        a.mode
    };
    if mode != 0 && sys::chmod(&path, mode as u32) != 0 {
        warn!(logopt, "failed to change mode of {}", path);
    }
    let fd = mounts::open_ioctlfd(logopt, &path, st.st_dev);
    ap.lock().ioctlfd = fd;
    if fd == -1 {
        crit!(logopt, "do_mount_autofs_indirect", "failed to create ioctl fd for autofs path {}", path);
        sys::umount(&path);
        return fail_rmdir(ap);
    }
    dev_ioctl::timeout(fd, timeout);
    let runfreq = ap.lock().exp_runfreq;
    mounts::notify_mount_result(logopt, runfreq, &path, timeout, str_indirect);
    0
}

/// `mount_autofs_indirect()`.
pub fn mount_autofs_indirect(ap: &Arc<AutofsPoint>) -> i32 {
    let now = sys::monotonic_time();
    if DO_FORCE_UNLINK.load(std::sync::atomic::Ordering::Relaxed) & UNLINK_AND_EXIT == 0 {
        if lookup::lookup_nss_read_map(ap, None, now) {
            lookup::lookup_prune_cache(ap, now);
        } else {
            error!(ap.logopt(), "mount_autofs_indirect", "failed to read map for {}", ap.path());
            return -1;
        }
    }
    if do_mount_autofs_indirect(ap) < 0 {
        return -1;
    }
    let map = lookup::lookup_ghost(ap);
    if map & LKP_FAIL != 0 {
        if map & LKP_DIRECT != 0 {
            error!(ap.logopt(), "mount_autofs_indirect", "bad map format,found direct, expected indirect exiting");
        } else {
            error!(ap.logopt(), "mount_autofs_indirect", "failed to load map, exiting");
        }
        return -1;
    }
    if map & LKP_NOTSUP != 0 {
        ap.lock().flags &= !MOUNT_FLAG_GHOST;
    }
    0
}

/// `close_mount_fds()`.
pub fn close_mount_fds(ap: &Arc<AutofsPoint>) {
    let (submount, p, k) = {
        let a = ap.lock();
        (a.submount, a.pipefd, a.kpipefd)
    };
    if submount {
        panic!("submounts aren't ported yet (phase 4)");
    }
    if p >= 0 {
        sys::close(p);
    }
    if k >= 0 {
        sys::close(k);
    }
}

/// `umount_autofs_indirect()`: 0 when the autofs mount went (or can't be
/// recovered), 1 when it's still there.
pub fn umount_autofs_indirect(ap: &Arc<AutofsPoint>) -> i32 {
    let logopt = ap.logopt();
    let path = ap.path();
    let ioctlfd = ap.lock().ioctlfd;
    match dev_ioctl::askumount(logopt, ioctlfd) {
        Err(_) => {
            logerr!("umount_autofs_indirect", "234", "ioctl failed: {}", sys::strerror(sys::errno()));
            return 1;
        }
        Ok(0) => {
            // ENABLE_IGNORE_BUSY_MOUNTS || ENABLE_FORCED_SHUTDOWN
            if !ap.lock().shutdown {
                return 1;
            }
            error!(logopt, "umount_autofs_indirect", "ask umount returned busy {}", path);
        }
        Ok(_) => {}
    }
    dev_ioctl::close(ioctlfd);
    ap.lock().ioctlfd = -1;
    sys::sched_yield();
    let mut retries = UMOUNT_RETRIES;
    let mut rv;
    loop {
        rv = sys::umount(&path);
        if rv != -1 {
            break;
        }
        if retries == 0 {
            break;
        }
        retries -= 1;
        if sys::errno() != libc::EBUSY {
            break;
        }
        sys::nanosleep_once(50_000_000);
    }
    if rv == -1 {
        match sys::errno() {
            libc::ENOENT | libc::EINVAL => {
                error!(logopt, "umount_autofs_indirect", "mount point {} does not exist", path);
                close_mount_fds(ap);
                return 0;
            }
            libc::EBUSY => {
                debug!(logopt, "umount_autofs_indirect", "mount point {} is in use", path);
                if ap.lock().state == ST_SHUTDOWN_FORCE {
                    close_mount_fds(ap);
                    warn!(logopt, "forcing umount of indirect mount {}", path);
                    return sys::umount2(&path, libc::MNT_DETACH);
                }
                // ENABLE_IGNORE_BUSY_MOUNTS
                if ap.lock().shutdown {
                    close_mount_fds(ap);
                    return 0;
                }
                let dev = ap.lock().dev;
                let fd = mounts::open_ioctlfd(logopt, &path, dev);
                ap.lock().ioctlfd = fd;
                if fd < 0 {
                    warn!(logopt, "could not recover autofs path {}", path);
                    close_mount_fds(ap);
                    return 0;
                }
            }
            libc::ENOTDIR => {
                error!(logopt, "umount_autofs_indirect", "mount point is not a directory");
                close_mount_fds(ap);
                return 0;
            }
            _ => {}
        }
        return 1;
    }
    // The kernel end of the pipe went with the super block.
    close_mount_fds(ap);
    info!(logopt, "umounting indirect mount {} succeeded", path);
    if ap.lock().submount {
        automount::rm_unwanted(ap, &path, true);
    }
    0
}

/// `expire_proc_indirect()`: the expire thread.
pub fn expire_proc_indirect(ap: Arc<AutofsPoint>, how: u32, hs: &Handshake) {
    let mut ec = ExpireCleanup { ap: ap.clone(), status: -1 };
    hs.started();
    let logopt = ap.logopt();
    let mut left = 0;
    // Get the list of real mounts and expire them if possible.
    let mnts = mounts::mnts_get_expire_list(&ap);
    if !mnts.is_empty() {
        for mnt in &mnts {
            if mnt.flags & (MNTS_AUTOFS | MNTS_OFFSET) != 0 {
                if mnt.flags & MNTS_AUTOFS != 0 {
                    let st = ap.lock().state;
                    master::master_notify_submount(&ap, &mnt.mp, st);
                    continue;
                }
                // An offset without a real mount: check for a manual umount.
                if mnt.flags & MNTS_OFFSET != 0 && !mounts::is_mounted(&mnt.mp, mounts::MNTS_REAL) {
                    // Don't touch submounts.
                    if mounts::mnts_is_submount(&mnt.mp) {
                        continue;
                    }
                    let entry = ap.entry();
                    entry.source_writelock();
                    let mut found = None;
                    for map in entry.maps() {
                        let mc = map.mc();
                        let id = {
                            let c = mc.lock();
                            c.lookup_distinct(&mnt.mp).map(|p| c.get(p).id)
                        };
                        if let Some(id) = id {
                            found = Some((mc, id));
                            break;
                        }
                    }
                    if let Some((mc, id)) = found {
                        let mut c = mc.lock();
                        if let Some(p) = c.by_id(id) {
                            let (fd, key) = (c.get(p).ioctlfd, c.get(p).key.clone());
                            if fd != -1 {
                                let gone = match sys::fstat(fd) {
                                    None => true,
                                    Some(st) => {
                                        drop(c);
                                        let n = automount::count_mounts(&ap, &key, st.st_dev);
                                        c = mc.lock();
                                        n == 0
                                    }
                                };
                                if gone && let Some(p) = c.by_id(id) {
                                    dev_ioctl::close(fd);
                                    c.get_mut(p).ioctlfd = -1;
                                }
                            }
                        }
                    }
                    entry.source_unlock();
                    continue;
                }
            }
            let st = ap.lock().state;
            if (st == ST_EXPIRE || st == ST_PRUNE) && state::testcancel() {
                state::expire_cleanup(&ec);
                return;
            }
            // An offset's key is the path; otherwise it's the last component.
            let ind_key = cstr::strrchr(&mnt.mp, b'/').map(|i| mnt.mp[i + 1..].to_vec());
            let entry = ap.entry();
            entry.source_readlock();
            let mut me = lookup::lookup_source_mapent(&ap, &mnt.mp, true);
            if me.is_none()
                && let Some(k) = &ind_key
            {
                me = lookup::lookup_source_mapent(&ap, k, false);
            }
            entry.source_unlock();
            let mut ioctlfd = ap.lock().ioctlfd;
            if let Some((mc, p)) = &me {
                let c = mc.lock();
                if c.get(*p).key.first() == Some(&b'/') {
                    ioctlfd = c.get(*p).ioctlfd;
                }
            }
            debug!(logopt, "expire_proc_indirect", "expire {}", mnt.mp);
            if dev_ioctl::expire(logopt, ioctlfd, &mnt.mp, how) == 1 {
                left += 1;
            }
        }
    }
    // No real mounts left, but there may be offsets with no `/` offset or
    // symlinks to remove. Immediate expires can't use the last used time to
    // stop, so they're limited by the number of mounts.
    let (path, dev, ioctlfd) = {
        let a = ap.lock();
        (a.path.clone(), a.dev, a.ioctlfd)
    };
    let mut retries = if how == AUTOFS_EXP_IMMEDIATE { automount::count_mounts(&ap, &path, dev) } else { -1 };
    while retries != 0 {
        retries -= 1;
        let ret = dev_ioctl::expire(logopt, ioctlfd, &path, how);
        if ret != 0 && sys::errno() == libc::EAGAIN {
            break;
        }
        if ret == 1 {
            left += 1;
        }
    }
    let (mut count, mut submnts) = (0, 0);
    for mnt in mounts::mnts_get_expire_list(&ap) {
        if mnt.flags & MNTS_AUTOFS == 0 {
            count += 1;
        } else if mnt.flags & MNTS_INDIRECT != 0 {
            submnts += 1;
        }
    }
    if submnts != 0 {
        debug!(logopt, "expire_proc_indirect", "{} submounts remaining in {}", submnts, path);
    }
    if count != 0 {
        debug!(logopt, "expire_proc_indirect", "{} remaining in {}", count, path);
    }
    ec.status = left;
    state::expire_cleanup(&ec);
}

/// A `struct pending_args`.
#[derive(Debug, Clone)]
pub struct Pending {
    pub ap: Arc<AutofsPoint>,
    pub name: Vec<u8>,
    pub dev: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub wait_queue_token: u32,
    pub status: i32,
}

/// `do_expire_indirect()`.
fn do_expire_indirect(mt: Pending, hs: Arc<Handshake>) {
    hs.started();
    let ap = &mt.ap;
    let status = automount::do_expire(ap, &mt.name);
    let (logopt, ioctlfd) = (ap.logopt(), ap.lock().ioctlfd);
    if status != 0 {
        dev_ioctl::send_fail(logopt, ioctlfd, mt.wait_queue_token, -status);
    } else {
        dev_ioctl::send_ready(logopt, ioctlfd, mt.wait_queue_token);
    }
}

/// `handle_packet_expire_indirect()`.
pub fn handle_packet_expire_indirect(ap: &Arc<AutofsPoint>, pkt: &sys::AutofsV5Packet) -> i32 {
    let logopt = ap.logopt();
    let name = pkt.name_bytes().to_vec();
    debug!(logopt, "handle_packet_expire_indirect", "token {}, name {}", pkt.wait_queue_token, name);
    let mt = Pending {
        ap: ap.clone(),
        name,
        dev: 0,
        uid: 0,
        gid: 0,
        pid: 0,
        wait_queue_token: pkt.wait_queue_token,
        status: 0,
    };
    let hs = Arc::new(Handshake::new());
    hs.hold();
    let hs2 = hs.clone();
    if state::spawn_detached("expire_ind", move || do_expire_indirect(mt, hs2)).is_none() {
        error!(logopt, "handle_packet_expire_indirect", "expire thread create failed");
        let ioctlfd = ap.lock().ioctlfd;
        dev_ioctl::send_fail(logopt, ioctlfd, pkt.wait_queue_token, -libc::EAGAIN);
        return 1;
    }
    hs.wait_timed();
    0
}

/// `mount_send_status()`: what an early exit of the mount thread reports.
fn mount_send_status(mt: &Pending) {
    let ap = &mt.ap;
    let (logopt, ioctlfd) = (ap.logopt(), ap.lock().ioctlfd);
    if mt.status != 0 {
        dev_ioctl::send_fail(logopt, ioctlfd, mt.wait_queue_token, mt.status);
    } else {
        dev_ioctl::send_ready(logopt, ioctlfd, mt.wait_queue_token);
    }
}

/// `do_mount_indirect()`.
fn do_mount_indirect(mut mt: Pending, hs: Arc<Handshake>) {
    let ap = mt.ap.clone();
    automount::set_thread_mount_request_log_id(mt.wait_queue_token, mt.pid, &mt.name);
    hs.started();
    mt.status = 0;
    let logopt = ap.logopt();
    if crate::libautofs::defaults::defaults_get_mount_verbose() != 0 {
        let ppid = automount::log_pidinfo(&ap, mt.pid, "requestor");
        if ppid > 0 {
            automount::log_pidinfo(&ap, ppid as u32, "parent");
        }
    }
    let Some(buf) = crate::libautofs::cat_path::ncat_path(&ap.path(), &mt.name, mt.name.len()) else {
        crit!(logopt, "do_mount_indirect", "path to be mounted is to long");
        mt.status = -libc::ENAMETOOLONG;
        mount_send_status(&mt);
        return;
    };
    if let Some(st) = sys::lstat(&buf)
        && !(st.st_mode & libc::S_IFMT == libc::S_IFDIR && st.st_dev == mt.dev)
    {
        error!(logopt, "do_mount_indirect", "indirect trigger not valid or already mounted {}", buf);
        mount_send_status(&mt);
        return;
    }
    info!(logopt, "attempting to mount entry {}", buf);
    mounts::set_tsd_user_vars(logopt, mt.uid, mt.gid);
    let status = lookup::lookup_nss_mount(&ap, None, &mt.name);
    let ioctlfd = ap.lock().ioctlfd;
    if status {
        dev_ioctl::send_ready(logopt, ioctlfd, mt.wait_queue_token);
        info!(logopt, "mounted {}", buf);
        mounts::mnts_set_mounted_mount(&ap, &mt.name, MNTS_INDIRECT | MNTS_MOUNTED);
        let rf = ap.lock().exp_runfreq;
        alarm::conditional_alarm_add(&ap, rf);
    } else {
        dev_ioctl::send_fail(logopt, ioctlfd, mt.wait_queue_token, -libc::ENOENT);
        info!(logopt, "failed to mount {}", buf);
    }
}

/// `handle_packet_missing_indirect()`.
pub fn handle_packet_missing_indirect(ap: &Arc<AutofsPoint>, pkt: &sys::AutofsV5Packet) -> i32 {
    master::master_mutex_lock();
    let logopt = ap.logopt();
    let name = pkt.name_bytes().to_vec();
    debug!(
        logopt,
        "handle_packet_missing_indirect", "token {}, name {}, request pid {}", pkt.wait_queue_token, name, pkt.pid
    );
    let (shutdown, st, ioctlfd) = {
        let a = ap.lock();
        (a.shutdown, a.state, a.ioctlfd)
    };
    // Ignore the packet if we're trying to shut down.
    if shutdown || st == ST_SHUTDOWN_FORCE {
        dev_ioctl::send_fail(logopt, ioctlfd, pkt.wait_queue_token, -libc::ENOENT);
        master::master_mutex_unlock();
        return 0;
    }
    if let Some((mc, p)) = lookup::lookup_source_mapent(ap, &name, true) {
        let (status, mapent) = {
            let c = mc.lock();
            (c.get(p).status, c.get(p).mapent.clone())
        };
        // A mount fail recorded for this key, or a nulled entry.
        if status >= sys::monotonic_time() || mapent.as_deref().is_some_and(parse_subs::starts_with_null_opt) {
            dev_ioctl::send_fail(logopt, ioctlfd, pkt.wait_queue_token, -libc::ENOENT);
            master::master_mutex_unlock();
            return 0;
        }
    }
    let mt = Pending {
        ap: ap.clone(),
        name,
        dev: pkt.dev as u64,
        uid: pkt.uid,
        gid: pkt.gid,
        pid: pkt.pid,
        wait_queue_token: pkt.wait_queue_token,
        status: 0,
    };
    let hs = Arc::new(Handshake::new());
    hs.hold();
    let hs2 = hs.clone();
    if state::spawn_detached("mount_ind", move || do_mount_indirect(mt, hs2)).is_none() {
        error!(logopt, "handle_packet_missing_indirect", "expire thread create failed");
        dev_ioctl::send_fail(logopt, ioctlfd, pkt.wait_queue_token, -libc::EAGAIN);
        master::master_mutex_unlock();
        return 1;
    }
    master::master_mutex_unlock();
    hs.wait_timed();
    0
}
