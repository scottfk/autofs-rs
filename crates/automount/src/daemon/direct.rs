//! `daemon/direct.c`: direct mounts and offset triggers. Each direct map key
//! (and each multi-mount offset) is an autofs mount of its own, found again
//! by the device and inode the kernel reports; the mount and expire request
//! handlers run in threads of their own, as for indirect mounts.
//!
//! Cache entries are named by their cache and id (`me` in C).

use std::sync::Arc;

use crate::daemon::automount::{self, DO_FORCE_UNLINK, MP_MODE, UNLINK_AND_EXIT};
use crate::daemon::lookup;
use crate::daemon::master::{self, AutofsPoint, MOUNT_FLAG_DIR_CREATED, MOUNT_FLAG_REMOUNT};
use crate::daemon::state::{self, ExpireCleanup, Handshake, ST_EXPIRE, ST_PRUNE, ST_READMAP, ST_SHUTDOWN_FORCE};
use crate::libautofs::alarm;
use crate::libautofs::cache::{Cache, Mapent};
use crate::libautofs::cstr;
use crate::libautofs::dev_ioctl::{self, AUTOFS_TYPE_DIRECT, AUTOFS_TYPE_OFFSET};
use crate::libautofs::mounts::{self, MNTS_ALL, MNTS_AUTOFS, MNTS_DIRECT, MNTS_MOUNTED, MNTS_OFFSET, MNTS_REAL};
use crate::sys;

pub const MOUNT_OFFSET_OK: i32 = 0;
pub const MOUNT_OFFSET_FAIL: i32 = -1;
pub const MOUNT_OFFSET_IGNORE: i32 = -2;

const CHECK_RATIO: i64 = 4;
const UMOUNT_RETRIES: u32 = 16;
const PATH_MAX: usize = 4096;
const KEY_MAX_LEN: usize = 255;
const AUTOFS_SUPER_MAGIC: i64 = 0x0187;

type Mc = Arc<Cache>;

fn me_get<T>(mc: &Mc, id: u64, f: impl FnOnce(&Mapent) -> T) -> Option<T> {
    let c = mc.lock();
    c.by_id(id).map(|p| f(c.get(p)))
}

fn me_set(mc: &Mc, id: u64, f: impl FnOnce(&mut Mapent)) {
    let mut c = mc.lock();
    if let Some(p) = c.by_id(id) {
        f(c.get_mut(p));
    }
}

/// `me->mc->map->argv[0]`: the map the entry's cache belongs to.
fn map_name_of(ap: &AutofsPoint, mc: &Mc) -> Vec<u8> {
    for m in ap.entry().maps() {
        if m.lock().mc.as_ref().is_some_and(|c| Arc::ptr_eq(c, mc)) {
            return m.argv().first().cloned().flatten().unwrap_or_default();
        }
    }
    Vec::new()
}

/// `get_exp_timeout(ap, me->source)`.
fn entry_timeout(ap: &AutofsPoint, mc: &Mc, id: u64) -> i64 {
    let src = me_get(mc, id, |e| e.source).and_then(|s| master::find_source(ap, s));
    master::get_exp_timeout(ap, src.as_deref())
}

/// `do_umount_autofs_direct()`: unmount a direct trigger (and what's on it);
/// 0, 1 when it's still there, -1 when the entry went meanwhile.
pub fn do_umount_autofs_direct(ap: &Arc<AutofsPoint>, mc: &Mc, id: u64) -> i32 {
    let logopt = ap.logopt();
    let Some(key) = me_get(mc, id, |e| e.key.clone()) else { return -1 };
    if key.len() > PATH_MAX {
        error!(logopt, "do_umount_autofs_direct", "path too long");
        return 1;
    }
    let left = automount::umount_multi(ap, &key, false);
    let still = {
        let c = mc.lock();
        c.lookup_distinct(&key).map(|p| c.get(p).id)
    };
    if still != Some(id) {
        error!(logopt, "do_umount_autofs_direct", "key {} no longer in mapent cache", key);
        return -1;
    }
    if left != 0 {
        warn!(logopt, "could not unmount {} dirs under {}", left, key);
        return 1;
    }
    let (me_fd, dev, flags) = me_get(mc, id, |e| (e.ioctlfd, e.dev, e.flags)).unwrap();
    let st = ap.lock().state;
    let mut opened = false;
    let ioctlfd = if me_fd != -1 {
        if st == ST_READMAP && mounts::is_mounted(&key, MNTS_REAL) {
            error!(logopt, "do_umount_autofs_direct", "attempt to umount busy direct mount {}", key);
            return 1;
        }
        me_fd
    } else {
        let fd = mounts::open_ioctlfd(logopt, &key, dev);
        if fd == -1 {
            return 1;
        }
        opened = true;
        fd
    };
    let mut force = false;
    match dev_ioctl::askumount(logopt, ioctlfd) {
        Err(_) => {
            error!(logopt, "do_umount_autofs_direct", "ioctl failed: {}", sys::strerror(sys::errno()));
            if opened {
                dev_ioctl::close(ioctlfd);
            }
            return 1;
        }
        Ok(0) => {
            if st != ST_SHUTDOWN_FORCE {
                error!(logopt, "do_umount_autofs_direct", "ask umount returned busy for {}", key);
                if opened {
                    dev_ioctl::close(ioctlfd);
                }
                return 1;
            }
            me_set(mc, id, |e| e.ioctlfd = -1);
            dev_ioctl::close(ioctlfd);
            force = true;
        }
        Ok(_) => {
            me_set(mc, id, |e| e.ioctlfd = -1);
            dev_ioctl::close(ioctlfd);
        }
    }
    let mut rv = 0;
    if !force {
        sys::sched_yield();
        let mut retries = UMOUNT_RETRIES;
        loop {
            rv = sys::umount(&key);
            if rv != -1 || retries == 0 {
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
                    warn!(logopt, "mount point {} does not exist", key);
                    return 0;
                }
                libc::EBUSY => {
                    warn!(logopt, "mount point {} is in use", key);
                    if st != ST_SHUTDOWN_FORCE {
                        if st != ST_READMAP {
                            set_direct_mount_tree_catatonic(ap, mc, id);
                        }
                        return 0;
                    }
                }
                libc::ENOTDIR => {
                    error!(logopt, "do_umount_autofs_direct", "mount point is not a directory");
                    return 0;
                }
                _ => return 1,
            }
        }
    }
    // QUIRK: a busy trigger at a forced shutdown gets here with askumount()'s
    // 0, so it's reported unmounted and left mounted.
    if rv != 0 {
        info!(logopt, "forcing umount of direct mount {}", key);
        rv = sys::umount2(&key, libc::MNT_DETACH);
    } else {
        info!(logopt, "umounted direct mount {}", key);
    }
    if rv == 0 && flags & MOUNT_FLAG_DIR_CREATED != 0 && sys::rmdir(&key) == -1 {
        warn!(logopt, "failed to remove dir {}: {}", key, sys::strerror(sys::errno()));
    }
    rv
}

/// The ids of a cache's primary entries, in `cache_enumerate()` order.
fn enumerate_ids(mc: &Mc) -> Vec<u64> {
    let c = mc.lock();
    let mut out = Vec::new();
    let mut p = c.enumerate(None);
    while let Some(q) = p {
        out.push(c.get(q).id);
        p = c.enumerate(Some(q));
    }
    out
}

/// `umount_autofs_direct()`: every trigger, at shutdown.
pub fn umount_autofs_direct(ap: &Arc<AutofsPoint>) -> i32 {
    let nc = master::master_list().lock().nc.clone().expect("null map cache");
    for map in ap.entry().maps() {
        let mc = map.mc();
        let master_line = map.lock().master_line as i64;
        'restart: loop {
            for id in enumerate_ids(&mc) {
                let Some(key) = me_get(&mc, id, |e| e.key.clone()) else { continue };
                let ne_age = {
                    let c = nc.lock();
                    c.lookup_distinct(&key).map(|p| c.get(p).age)
                };
                if ne_age.is_some_and(|a| master_line > a) {
                    continue;
                }
                // Exiting: a failed umount gets its trigger made catatonic.
                let error = do_umount_autofs_direct(ap, &mc, id);
                if error == -1 {
                    continue 'restart;
                }
                if error != 0 && ap.lock().state != ST_READMAP {
                    set_direct_mount_tree_catatonic(ap, &mc, id);
                }
            }
            break;
        }
    }
    let (p, k) = {
        let a = ap.lock();
        (a.pipefd, a.kpipefd)
    };
    if p >= 0 {
        sys::close(p);
    }
    if k >= 0 {
        sys::close(k);
        ap.lock().kpipefd = -1;
    }
    0
}

/// `do_mount_autofs_direct()`: mount the trigger for one direct map entry.
pub fn do_mount_autofs_direct(ap: &Arc<AutofsPoint>, mc: &Mc, id: u64, timeout: i64) -> i32 {
    let str_direct = mounts::mount_type_str(AUTOFS_TYPE_DIRECT).unwrap();
    let logopt = ap.logopt();
    if timeout != 0 {
        let runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;
        let mut a = ap.lock();
        a.exp_runfreq = if a.exp_runfreq != 0 { a.exp_runfreq.min(runfreq) } else { runfreq };
    }
    let force = DO_FORCE_UNLINK.load(std::sync::atomic::Ordering::Relaxed);
    let Some(key) = me_get(mc, id, |e| e.key.clone()) else { return -1 };
    if dev_ioctl::has_version() && force == 0 {
        ap.lock().flags |= MOUNT_FLAG_REMOUNT;
        let ret = mounts::try_remount(ap, Some((mc, id)), AUTOFS_TYPE_DIRECT);
        ap.lock().flags &= !MOUNT_FLAG_REMOUNT;
        if ret == 1 {
            return 0;
        }
        if ret == 0 {
            return -1;
        }
    } else {
        if force & UNLINK_AND_EXIT == 0 && ap.lock().state == ST_READMAP && mounts::is_mounted(&key, MNTS_ALL) {
            let tout = entry_timeout(ap, mc, id);
            let (save, dev) = me_get(mc, id, |e| (e.ioctlfd, e.dev)).unwrap();
            let fd = if save == -1 { mounts::open_ioctlfd(logopt, &key, dev) } else { save };
            if fd < 0 {
                error!(logopt, "do_mount_autofs_direct", "failed to create ioctl fd for {}", key);
                return 0;
            }
            dev_ioctl::timeout(fd, tout);
            if save == -1 {
                dev_ioctl::close(fd);
            }
            return 0;
        }
        if !mounts::unlink_mount_tree(logopt, &key) {
            error!(
                logopt,
                "do_mount_autofs_direct", "already mounted as other than autofs or failed to unlink entry in tree"
            );
            return out_err(mc, id, &key);
        }
        if force & UNLINK_AND_EXIT != 0 {
            return -1;
        }
        if me_get(mc, id, |e| e.ioctlfd).unwrap_or(-1) != -1 {
            error!(logopt, "do_mount_autofs_direct", "active direct mount {}", key);
            return -1;
        }
    }
    let (kpipefd, flags, mode) = {
        let a = ap.lock();
        (a.kpipefd, a.flags, a.mode)
    };
    let options = mounts::make_options_string(&ap.path(), kpipefd, Some(str_direct), flags);
    if automount::mkdir_path(&key, MP_MODE) < 0 {
        let e = sys::errno();
        if e != libc::EEXIST && e != libc::EROFS {
            crit!(logopt, "do_mount_autofs_direct", "failed to create mount directory {}", key);
            return -1;
        }
        me_set(mc, id, |e| e.flags &= !MOUNT_FLAG_DIR_CREATED);
    } else {
        me_set(mc, id, |e| e.flags |= MOUNT_FLAG_DIR_CREATED);
    }
    let map_name = map_name_of(ap, mc);
    if sys::mount(&map_name, &key, b"autofs", libc::MS_MGC_VAL, Some(&options)) != 0 {
        crit!(logopt, "do_mount_autofs_direct", "failed to mount autofs path {}", key);
        return out_err(mc, id, &key);
    }
    let Some(st) = sys::stat(&key) else {
        error!(logopt, "do_mount_autofs_direct", "failed to stat direct mount trigger {}", key);
        sys::umount(&key);
        return out_err(mc, id, &key);
    };
    me_set(mc, id, |e| {
        e.dev = st.st_dev;
        e.ino = st.st_ino;
    });
    if mode != 0 && sys::chmod(&key, mode as u32) != 0 {
        warn!(logopt, "failed to change mode of {}", key);
    }
    let fd = mounts::open_ioctlfd(logopt, &key, st.st_dev);
    if fd < 0 {
        crit!(logopt, "do_mount_autofs_direct", "failed to create ioctl fd for {}", key);
        sys::umount(&key);
        return out_err(mc, id, &key);
    }
    dev_ioctl::timeout(fd, timeout);
    let rf = ap.lock().exp_runfreq;
    mounts::notify_mount_result(logopt, rf, &key, timeout, str_direct);
    {
        let mut c = mc.lock();
        if let Some(p) = c.by_id(id) {
            c.set_ino_index(p);
        }
    }
    dev_ioctl::close(fd);
    debug!(logopt, "do_mount_autofs_direct", "mounted trigger {}", key);
    0
}

/// `out_err:` of `do_mount_autofs_direct()`.
fn out_err(mc: &Mc, id: u64, key: &[u8]) -> i32 {
    if me_get(mc, id, |e| e.flags & MOUNT_FLAG_DIR_CREATED != 0).unwrap_or(false) {
        sys::rmdir(key);
    }
    -1
}

/// `mount_autofs_direct()`: read the map and mount a trigger for each key.
pub fn mount_autofs_direct(ap: &Arc<AutofsPoint>) -> i32 {
    let logopt = ap.logopt();
    let now = sys::monotonic_time();
    if ap.path() != b"/-" {
        error!(logopt, "mount_autofs_direct", "expected direct map, exiting");
        return -1;
    }
    if lookup::lookup_nss_read_map(ap, None, now) {
        lookup::lookup_prune_cache(ap, now);
    } else {
        error!(logopt, "mount_autofs_direct", "failed to read direct map");
        return -1;
    }
    let entry = ap.entry();
    entry.source_readlock();
    let nc = master::master_list().lock().nc.clone().expect("null map cache");
    let eage = entry.lock().age;
    for map in entry.maps() {
        // Only map sources read since the master map entry changed.
        if eage > map.lock().age {
            continue;
        }
        let mc = map.mc();
        let timeout = master::get_exp_timeout(ap, Some(&map));
        let master_line = map.lock().master_line as i64;
        for id in enumerate_ids(&mc) {
            let Some(key) = me_get(&mc, id, |e| e.key.clone()) else { continue };
            let ne_age = {
                let c = nc.lock();
                c.lookup_distinct(&key).map(|p| c.get(p).age)
            };
            if let Some(ne_age) = ne_age {
                if master_line < ne_age {
                    do_mount_autofs_direct(ap, &mc, id, timeout);
                }
                continue;
            }
            let nested = {
                let mut c = nc.lock();
                c.partial_match(&key).map(|p| {
                    let k = c.get(p).key.clone();
                    c.delete(&k);
                    k
                })
            };
            if let Some(k) = nested {
                error!(logopt, "mount_autofs_direct", "removing invalid nested null entry {}", k);
            }
            do_mount_autofs_direct(ap, &mc, id, timeout);
        }
    }
    entry.source_unlock();
    0
}

/// `umount_autofs_offset()`.
pub fn umount_autofs_offset(ap: &Arc<AutofsPoint>, mc: &Mc, id: u64) -> i32 {
    let logopt = ap.logopt();
    let Some((key, me_fd, dev)) = me_get(mc, id, |e| (e.key.clone(), e.ioctlfd, e.dev)) else { return 1 };
    let mut opened = false;
    let ioctlfd = if me_fd != -1 {
        if mounts::is_mounted(&key, MNTS_REAL) {
            error!(logopt, "umount_autofs_offset", "attempt to umount busy offset {}", key);
            return 1;
        }
        me_fd
    } else {
        // Not mounted: success, and try to recover.
        if !mounts::is_mounted(&key, MNTS_AUTOFS) {
            debug!(logopt, "umount_autofs_offset", "offset {} not mounted", key);
            return 0;
        }
        let fd = mounts::open_ioctlfd(logopt, &key, dev);
        if fd == -1 {
            return 1;
        }
        opened = true;
        fd
    };
    let (st, shutdown) = {
        let a = ap.lock();
        (a.state, a.shutdown)
    };
    let mut force = false;
    if ioctlfd >= 0 {
        match dev_ioctl::askumount(logopt, ioctlfd) {
            Err(_) => {
                logerr!("umount_autofs_offset", "558", "ioctl failed: {}", sys::strerror(sys::errno()));
                if opened {
                    dev_ioctl::close(ioctlfd);
                }
                return 1;
            }
            Ok(0) if st != ST_SHUTDOWN_FORCE => {
                if shutdown {
                    error!(logopt, "umount_autofs_offset", "ask umount returned busy for {}", key);
                }
                if opened {
                    dev_ioctl::close(ioctlfd);
                }
                return 1;
            }
            Ok(v) => {
                me_set(mc, id, |e| e.ioctlfd = -1);
                dev_ioctl::catatonic(ioctlfd);
                dev_ioctl::close(ioctlfd);
                force = v == 0;
            }
        }
    }
    // QUIRK: as for direct mounts, the forced path carries askumount()'s 0.
    let mut rv = if force { 0 } else { 1 };
    if !force {
        sys::sched_yield();
        let mut retries = UMOUNT_RETRIES;
        loop {
            rv = sys::umount(&key);
            if rv != -1 || retries == 0 {
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
                libc::ENOENT => {
                    warn!(logopt, "mount point does not exist");
                    return 0;
                }
                libc::EBUSY => {
                    error!(logopt, "umount_autofs_offset", "mount point {} is in use", key);
                    if st != ST_SHUTDOWN_FORCE {
                        return 1;
                    }
                }
                libc::ENOTDIR => {
                    error!(logopt, "umount_autofs_offset", "mount point is not a directory");
                    return 0;
                }
                _ => {}
            }
        }
    }
    if rv != 0 {
        info!(logopt, "forcing umount of offset mount {}", key);
        rv = sys::umount2(&key, libc::MNT_DETACH);
    } else {
        info!(logopt, "umounted offset mount {}", key);
    }
    rv
}

/// `mount_autofs_offset()`: mount the trigger of a multi-mount offset.
pub fn mount_autofs_offset(ap: &Arc<AutofsPoint>, mc: &Mc, id: u64) -> i32 {
    let str_offset = mounts::mount_type_str(AUTOFS_TYPE_OFFSET).unwrap();
    let logopt = ap.logopt();
    let timeout = entry_timeout(ap, mc, id);
    let Some(key) = me_get(mc, id, |e| e.key.clone()) else { return MOUNT_OFFSET_FAIL };
    let (flags, st) = {
        let a = ap.lock();
        (a.flags, a.state)
    };
    if dev_ioctl::has_version() && flags & MOUNT_FLAG_REMOUNT != 0 {
        let ret = mounts::try_remount(ap, Some((mc, id)), AUTOFS_TYPE_OFFSET);
        if ret == 1 {
            return MOUNT_OFFSET_OK;
        }
        // Not found: fall through and mount it.
        if !(ret == -1 && sys::errno() == libc::ENOENT) {
            return MOUNT_OFFSET_FAIL;
        }
    } else {
        if mounts::is_mounted(&key, MNTS_AUTOFS) {
            if st != ST_READMAP {
                warn!(logopt, "trigger {} already mounted", key);
            }
            if mounts::mnts_add_mount(ap, &key, MNTS_OFFSET).is_none() {
                error!(logopt, "mount_autofs_offset", "failed to add offset mount {} to mounted list", key);
            }
            return MOUNT_OFFSET_OK;
        }
        if me_get(mc, id, |e| e.ioctlfd).unwrap_or(-1) != -1 {
            error!(logopt, "mount_autofs_offset", "active offset mount {}", key);
            return MOUNT_OFFSET_FAIL;
        }
    }
    let kpipefd = ap.lock().kpipefd;
    let options = mounts::make_options_string(&ap.path(), kpipefd, Some(str_offset), flags);
    if automount::mkdir_path(&key, MP_MODE) < 0 {
        let e = sys::errno();
        if e == libc::EEXIST {
            // A real mount on a mount point that isn't the root offset was
            // made by the kernel NFS client.
            let is_root = me_get(mc, id, |e| e.is_mm_root()).unwrap_or(false);
            if !is_root && mounts::is_mounted(&key, MNTS_REAL) {
                return MOUNT_OFFSET_IGNORE;
            }
            me_set(mc, id, |e| e.flags &= !MOUNT_FLAG_DIR_CREATED);
        } else if e == libc::EACCES {
            // Inside a host file system the mount point must exist.
            debug!(logopt, "mount_autofs_offset", "can't create mount directory: {}, {}", key, sys::strerror(e));
            return MOUNT_OFFSET_FAIL;
        } else {
            crit!(logopt, "mount_autofs_offset", "failed to create mount directory: {}, {}", key, sys::strerror(e));
            return MOUNT_OFFSET_FAIL;
        }
    } else {
        me_set(mc, id, |e| e.flags |= MOUNT_FLAG_DIR_CREATED);
    }
    debug!(logopt, "mount_autofs_offset", "calling mount -t autofs -s  -o {} automount {}", options, key);
    let map_name = match ap.entry().maps().first().and_then(|m| m.ty()) {
        Some(t) if cstr::eq(&t, b"hosts") => b"-hosts".to_vec(),
        _ => map_name_of(ap, mc),
    };
    let out_err = |umount: bool| {
        if umount {
            sys::umount(&key);
        }
        if let Some(st) = sys::stat(&key)
            && me_get(mc, id, |e| e.flags & MOUNT_FLAG_DIR_CREATED != 0).unwrap_or(false)
        {
            automount::rmdir_path(ap, &key, st.st_dev);
        }
        MOUNT_OFFSET_FAIL
    };
    if sys::mount(&map_name, &key, b"autofs", libc::MS_MGC_VAL, Some(&options)) != 0 {
        crit!(logopt, "mount_autofs_offset", "failed to mount offset trigger {} at {}", key, key);
        return out_err(false);
    }
    let Some(st) = sys::stat(&key) else {
        let e = sys::errno();
        error!(logopt, "mount_autofs_offset", "failed to stat direct mount trigger {}", key);
        return out_err(e != libc::ENOENT);
    };
    me_set(mc, id, |e| {
        e.dev = st.st_dev;
        e.ino = st.st_ino;
    });
    let fd = mounts::open_ioctlfd(logopt, &key, st.st_dev);
    if fd < 0 {
        return out_err(true);
    }
    dev_ioctl::timeout(fd, timeout);
    {
        let mut c = mc.lock();
        if let Some(p) = c.by_id(id) {
            c.set_ino_index(p);
        }
    }
    let rf = ap.lock().exp_runfreq;
    mounts::notify_mount_result(logopt, rf, &key, timeout, str_offset);
    dev_ioctl::close(fd);
    debug!(logopt, "mount_autofs_offset", "mounted trigger {}", key);
    MOUNT_OFFSET_OK
}

/// `set_direct_mount_tree_catatonic()`.
pub fn set_direct_mount_tree_catatonic(ap: &Arc<AutofsPoint>, mc: &Mc, id: u64) {
    let (is_root, fd) = me_get(mc, id, |e| (e.is_mm_root(), e.ioctlfd)).unwrap_or((false, -1));
    if is_root {
        mounts::set_offset_tree_catatonic(ap, mc, id);
    }
    mounts::set_mount_catatonic_me(ap, Some((mc, id)), fd);
}

/// `expire_proc_direct()`: the expire thread of a direct mount point.
pub fn expire_proc_direct(ap: Arc<AutofsPoint>, how: u32, hs: &Handshake) {
    let mut ec = ExpireCleanup { ap: ap.clone(), status: -1 };
    hs.started();
    let logopt = ap.logopt();
    let mut left = 0;
    let mnts = mounts::mnts_get_expire_list(&ap);
    if mnts.is_empty() {
        ec.status = left;
        state::expire_cleanup(&ec);
        return;
    }
    for mnt in &mnts {
        // All direct mounts are in the cache.
        let entry = ap.entry();
        entry.source_readlock();
        let me = lookup::lookup_source_mapent(&ap, &mnt.mp, true);
        entry.source_unlock();
        let Some((mc, p)) = me else { continue };
        let (id, key) = {
            let c = mc.lock();
            (c.get(p).id, c.get(p).key.clone())
        };
        if mnt.flags & (MNTS_AUTOFS | MNTS_OFFSET) != 0 {
            // Pass a state change on to a submount below.
            if mnt.flags & MNTS_AUTOFS != 0 {
                let st = ap.lock().state;
                master::master_notify_submount(&ap, &mnt.mp, st);
                continue;
            }
            let me_fd = me_get(&mc, id, |e| e.ioctlfd).unwrap_or(-1);
            if me_fd == -1 {
                continue;
            }
            // Mounted: just send the expire. Otherwise a manual umount?
            if !mounts::is_mounted(&key, MNTS_REAL) {
                let fd = me_get(&mc, id, |e| e.ioctlfd).unwrap_or(-1);
                if fd != -1
                    && let Some(st) = sys::fstat(fd)
                    && automount::count_mounts(&ap, &mnt.mp, st.st_dev) == 0
                {
                    dev_ioctl::close(fd);
                    me_set(&mc, id, |e| e.ioctlfd = -1);
                    mounts::mnts_remove_mount(&mnt.mp, MNTS_MOUNTED);
                    continue;
                }
            }
            let fd = me_get(&mc, id, |e| e.ioctlfd).unwrap_or(-1);
            if dev_ioctl::expire(logopt, fd, &mnt.mp, how) == 1 {
                left += 1;
            }
            continue;
        }
        // Real mounts have an open ioctl descriptor.
        let fd = me_get(&mc, id, |e| e.ioctlfd).unwrap_or(-1);
        if fd < 0 {
            continue;
        }
        let st = ap.lock().state;
        if (st == ST_EXPIRE || st == ST_PRUNE) && state::testcancel() {
            state::expire_cleanup(&ec);
            return;
        }
        debug!(logopt, "expire_proc_direct", "send expire to trigger {}", mnt.mp);
        if dev_ioctl::expire(logopt, fd, &mnt.mp, how) == 1 {
            left += 1;
        }
    }
    if left != 0 {
        debug!(logopt, "expire_proc_direct", "{} remaining in {}", left, ap.path());
    }
    ec.status = left;
    state::expire_cleanup(&ec);
}

/// A direct `struct pending_args`.
#[derive(Debug, Clone)]
struct DPending {
    ap: Arc<AutofsPoint>,
    ioctlfd: i32,
    mc: Mc,
    name: Vec<u8>,
    dev: u64,
    uid: u32,
    gid: u32,
    pid: u32,
    wait_queue_token: u32,
    status: i32,
}

/// `do_expire_direct()`.
fn do_expire_direct(mt: DPending, hs: Arc<Handshake>) {
    hs.started();
    let ap = &mt.ap;
    let logopt = ap.logopt();
    let len = cstr::c(&mt.name).len().min(KEY_MAX_LEN);
    if len == 0 {
        warn!(logopt, "direct key path too long {}", mt.name);
        dev_ioctl::send_fail(logopt, mt.ioctlfd, mt.wait_queue_token, -libc::ENOENT);
        return;
    }
    let status = automount::do_expire(ap, &mt.name[..len]);
    if status != 0 {
        dev_ioctl::send_fail(logopt, mt.ioctlfd, mt.wait_queue_token, -libc::ENOENT);
    } else {
        {
            let mut c = mt.mc.lock();
            if let Some(p) = c.lookup_distinct(&mt.name) {
                c.get_mut(p).ioctlfd = -1;
            }
        }
        dev_ioctl::send_ready(logopt, mt.ioctlfd, mt.wait_queue_token);
        dev_ioctl::close(mt.ioctlfd);
    }
}

/// The map source caches to search for a packet's entry, with the entry.
fn find_by_ino(ap: &Arc<AutofsPoint>, dev: u64, ino: u64, only_read: bool) -> Option<(Mc, u64)> {
    let entry = ap.entry();
    let eage = entry.lock().age;
    for map in entry.maps() {
        if only_read && eage > map.lock().age {
            continue;
        }
        let mc = map.mc();
        let id = {
            let c = mc.lock();
            c.lookup_ino(dev, ino).map(|p| c.get(p).id)
        };
        if let Some(id) = id {
            return Some((mc, id));
        }
    }
    None
}

/// `handle_packet_expire_direct()`.
pub fn handle_packet_expire_direct(ap: &Arc<AutofsPoint>, pkt: &sys::AutofsV5Packet) -> i32 {
    let logopt = ap.logopt();
    let entry = ap.entry();
    entry.source_writelock();
    let Some((mc, id)) = find_by_ino(ap, pkt.dev as u64, pkt.ino, false) else {
        crit!(logopt, "handle_packet_expire_direct", "can't find map entry for ({},{})", pkt.dev, pkt.ino);
        entry.source_unlock();
        return 1;
    };
    let (key, me_fd, dev) = me_get(&mc, id, |e| (e.key.clone(), e.ioctlfd, e.dev)).unwrap();
    if key.len() >= PATH_MAX {
        crit!(logopt, "handle_packet_expire_direct", "lookup key is too long");
        entry.source_unlock();
        return 1;
    }
    // Can't expire it if it isn't mounted.
    if me_fd == -1 {
        let fd = mounts::open_ioctlfd(logopt, &key, dev);
        if fd == -1 {
            entry.source_unlock();
            return 1;
        }
        dev_ioctl::send_ready(logopt, fd, pkt.wait_queue_token);
        dev_ioctl::close(fd);
        entry.source_unlock();
        return 0;
    }
    let mt = DPending {
        ap: ap.clone(),
        ioctlfd: me_fd,
        mc: mc.clone(),
        name: key.clone(),
        dev,
        uid: 0,
        gid: 0,
        pid: 0,
        wait_queue_token: pkt.wait_queue_token,
        status: 0,
    };
    debug!(logopt, "handle_packet_expire_direct", "token {}, name {}", pkt.wait_queue_token, key);
    let hs = Arc::new(Handshake::new());
    hs.hold();
    let hs2 = hs.clone();
    if state::spawn_detached("expire_dir", move || do_expire_direct(mt, hs2)).is_none() {
        error!(logopt, "handle_packet_expire_direct", "expire thread create failed");
        dev_ioctl::send_fail(logopt, me_fd, pkt.wait_queue_token, -libc::EAGAIN);
        entry.source_unlock();
        return 1;
    }
    entry.source_unlock();
    hs.wait_timed();
    0
}

/// `mount_send_status()`: what an early exit of the mount thread reports.
fn mount_send_status(mt: &DPending) {
    let logopt = mt.ap.logopt();
    if mt.status != 0 {
        dev_ioctl::send_fail(logopt, mt.ioctlfd, mt.wait_queue_token, mt.status);
    } else {
        dev_ioctl::send_ready(logopt, mt.ioctlfd, mt.wait_queue_token);
    }
    dev_ioctl::close(mt.ioctlfd);
}

/// `do_mount_direct()`.
fn do_mount_direct(mut mt: DPending, hs: Arc<Handshake>) {
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
    match sys::fstat(mt.ioctlfd) {
        Some(st) if st.st_mode & libc::S_IFMT == libc::S_IFDIR && st.st_dev == mt.dev => {}
        _ => {
            error!(logopt, "do_mount_direct", "direct trigger not valid or already mounted {}", mt.name);
            mt.status = -libc::EINVAL;
            mount_send_status(&mt);
            return;
        }
    }
    info!(logopt, "attempting to mount entry {}", mt.name);
    mounts::set_tsd_user_vars(logopt, mt.uid, mt.gid);
    let status = lookup::lookup_nss_mount(&ap, None, &mt.name);
    // Direct mounts are always a single mount: a failure leaves nothing to undo.
    if status {
        let mut flags = MNTS_DIRECT | MNTS_MOUNTED;
        let sbmnt = mounts::mnts_is_submount(&mt.name);
        let mut close_fd = match sys::statfs_type(&mt.name) {
            None => true,
            Some(t) => t == AUTOFS_SUPER_MAGIC && !sbmnt,
        };
        {
            let mut c = mt.mc.lock();
            if let Some(p) = c.lookup_distinct(&mt.name) {
                // Keep the descriptor of a multi-mount with no real mount at
                // its base, so it expires.
                if close_fd && c.get(p).is_mm_root() {
                    close_fd = false;
                }
                if !close_fd {
                    c.get_mut(p).ioctlfd = mt.ioctlfd;
                }
                if c.get(p).mm_nonroot() {
                    flags |= MNTS_OFFSET;
                }
            }
            dev_ioctl::send_ready(logopt, mt.ioctlfd, mt.wait_queue_token);
        }
        if close_fd {
            dev_ioctl::close(mt.ioctlfd);
        }
        info!(logopt, "mounted {}", mt.name);
        mounts::mnts_set_mounted_mount(&ap, &mt.name, flags);
        let rf = ap.lock().exp_runfreq;
        alarm::conditional_alarm_add(&ap, rf);
    } else {
        dev_ioctl::send_fail(logopt, mt.ioctlfd, mt.wait_queue_token, -libc::ENOENT);
        dev_ioctl::close(mt.ioctlfd);
        info!(logopt, "failed to mount {}", mt.name);
        // A failed multi-mount subtree keeps the tree expiring.
        let nonroot = {
            let c = mt.mc.lock();
            c.lookup_distinct(&mt.name).is_some_and(|p| c.get(p).mm_nonroot())
        };
        if nonroot {
            let rf = ap.lock().exp_runfreq;
            alarm::conditional_alarm_add(&ap, rf);
        }
    }
}

/// `handle_packet_missing_direct()`.
pub fn handle_packet_missing_direct(ap: &Arc<AutofsPoint>, pkt: &sys::AutofsV5Packet) -> i32 {
    let logopt = ap.logopt();
    let (maj, min) = (mounts::get_kver_major(), mounts::get_kver_minor());
    master::master_mutex_lock();
    let entry = ap.entry();
    // Since the vfs-automount changes, covered mounts block during mount
    // tree construction, so a read lock is enough.
    if maj > 5 || (maj == 5 && min > 1) {
        entry.source_readlock();
    } else {
        entry.source_writelock();
    }
    let unlock = || {
        entry.source_unlock();
        master::master_mutex_unlock();
    };
    let Some((mc, id)) = find_by_ino(ap, pkt.dev as u64, pkt.ino, true) else {
        logerr!("handle_packet_missing_direct", "1352", "can't find map entry for ({},{})", pkt.dev, pkt.ino);
        unlock();
        return 1;
    };
    let (key, me_fd, dev, status) = me_get(&mc, id, |e| (e.key.clone(), e.ioctlfd, e.dev, e.status)).unwrap();
    if me_fd != -1 {
        // A manual umount, maybe: clean up.
        sys::close(me_fd);
        me_set(&mc, id, |e| e.ioctlfd = -1);
    }
    let ioctlfd = mounts::open_ioctlfd(logopt, &key, dev);
    if ioctlfd == -1 {
        unlock();
        crit!(logopt, "handle_packet_missing_direct", "failed to create ioctl fd for {}", key);
        return 1;
    }
    debug!(
        logopt,
        "handle_packet_missing_direct", "token {}, name {}, request pid {}", pkt.wait_queue_token, key, pkt.pid
    );
    let (shutdown, st) = {
        let a = ap.lock();
        (a.shutdown, a.state)
    };
    let fail = |err: i32| {
        dev_ioctl::send_fail(logopt, ioctlfd, pkt.wait_queue_token, err);
        dev_ioctl::close(ioctlfd);
        unlock();
        0
    };
    // Shutting down, or a mount fail recorded for the key.
    if shutdown || st == ST_SHUTDOWN_FORCE || status >= sys::monotonic_time() {
        return fail(-libc::ENOENT);
    }
    if key.len() >= PATH_MAX {
        error!(logopt, "handle_packet_missing_direct", "direct mount path too long {}", key);
        return fail(-libc::ENAMETOOLONG);
    }
    let mt = DPending {
        ap: ap.clone(),
        ioctlfd,
        mc,
        name: key,
        dev,
        uid: pkt.uid,
        gid: pkt.gid,
        pid: pkt.pid,
        wait_queue_token: pkt.wait_queue_token,
        status: 0,
    };
    let hs = Arc::new(Handshake::new());
    hs.hold();
    let hs2 = hs.clone();
    if state::spawn_detached("mount_dir", move || do_mount_direct(mt, hs2)).is_none() {
        error!(logopt, "handle_packet_missing_direct", "missing mount thread create failed");
        dev_ioctl::send_fail(logopt, ioctlfd, pkt.wait_queue_token, -libc::EAGAIN);
        dev_ioctl::close(ioctlfd);
        unlock();
        return 1;
    }
    unlock();
    hs.wait_timed();
    0
}
