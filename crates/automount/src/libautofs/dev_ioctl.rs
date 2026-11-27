//! `lib/dev-ioctl-lib.c`: the autofs control operations, through the
//! `/dev/autofs` misc device when it opens and answers `VERSION`, else through
//! the legacy ioctls on each mount's own descriptor (`ctl.ops`).

use std::sync::Mutex;

use crate::libautofs::cstr;
use crate::sys::{self, AutofsDevIoctl, Fd};

const CONTROL_DEVICE: &[u8] = b"/dev/autofs";
const AUTOFS_SUPER_MAGIC: i64 = 0x0187;
const EXPIRE_RETRIES: u32 = 1;

pub const DEV_IOCTL_IS_MOUNTED: u32 = 0x0001;
pub const DEV_IOCTL_IS_AUTOFS: u32 = 0x0002;
pub const DEV_IOCTL_IS_OTHER: u32 = 0x0004;

pub const AUTOFS_TYPE_ANY: u32 = 0;
pub const AUTOFS_TYPE_INDIRECT: u32 = 1;
pub const AUTOFS_TYPE_DIRECT: u32 = 2;
pub const AUTOFS_TYPE_OFFSET: u32 = 4;

pub const AUTOFS_EXP_NORMAL: u32 = 0x00;
pub const AUTOFS_EXP_IMMEDIATE: u32 = 0x01;
pub const AUTOFS_EXP_LEAVES: u32 = 0x02;
pub const AUTOFS_EXP_FORCE: u32 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Dev,
    Legacy,
}

/// `struct ioctl_ctl`.
#[derive(Debug)]
struct Ctl {
    devfd: Fd,
    ops: Option<Kind>,
}

static CTL: Mutex<Ctl> = Mutex::new(Ctl { devfd: -1, ops: None });

/// A `struct autofs_dev_ioctl` with its path, 8-aligned.
struct Param {
    buf: Vec<u64>,
}

impl Param {
    /// `init_autofs_dev_ioctl()`, then the path (if any) after the struct.
    fn new(path: Option<&[u8]>) -> Param {
        let p = path.map(cstr::c).unwrap_or(b"");
        let size = sys::AUTOFS_DEV_IOCTL_SIZE + if path.is_some() { p.len() + 1 } else { 0 };
        let mut prm = Param { buf: vec![0u64; size.div_ceil(8)] };
        {
            let h = prm.head();
            h.ver_major = 1;
            h.ver_minor = 0;
            h.size = size as u32;
            h.ioctlfd = -1;
        }
        let b = prm.bytes();
        b[sys::AUTOFS_DEV_IOCTL_SIZE..sys::AUTOFS_DEV_IOCTL_SIZE + p.len()].copy_from_slice(p);
        prm
    }

    fn head(&mut self) -> &mut AutofsDevIoctl {
        // SAFETY: buf is 8-aligned and at least the struct's size; the struct
        // is plain integers.
        unsafe { &mut *(self.buf.as_mut_ptr() as *mut AutofsDevIoctl) }
    }

    fn bytes(&mut self) -> &mut [u8] {
        let n = self.buf.len() * 8;
        // SAFETY: the same allocation viewed as bytes.
        unsafe { std::slice::from_raw_parts_mut(self.buf.as_mut_ptr() as *mut u8, n) }
    }

    fn arg64(&mut self) -> &mut u64 {
        // SAFETY: the union starts 16 bytes in, 8-aligned.
        unsafe { &mut *((self.head().arg.as_mut_ptr()) as *mut u64) }
    }
}

fn dev_ioctl(devfd: Fd, req: u64, prm: &mut Param) -> i32 {
    sys::ioctl_dev(devfd, req, prm.bytes())
}

/// `init_ioctl_ctl()`.
pub fn init_ioctl_ctl() {
    let mut c = CTL.lock().unwrap();
    if c.ops.is_some() {
        return;
    }
    let devfd = sys::open_flags(CONTROL_DEVICE, libc::O_RDONLY);
    if devfd == -1 {
        c.ops = Some(Kind::Legacy);
        return;
    }
    let mut prm = Param::new(None);
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_VERSION, &mut prm) == -1 {
        sys::close(devfd);
        c.ops = Some(Kind::Legacy);
    } else {
        c.devfd = devfd;
        c.ops = Some(Kind::Dev);
    }
}

/// `close_ioctl_ctl()`.
pub fn close_ioctl_ctl() {
    let mut c = CTL.lock().unwrap();
    if c.devfd != -1 {
        sys::close(c.devfd);
        c.devfd = -1;
    }
    c.ops = None;
}

fn ops() -> (Kind, Fd) {
    {
        let c = CTL.lock().unwrap();
        if let Some(k) = c.ops {
            return (k, c.devfd);
        }
    }
    init_ioctl_ctl();
    let c = CTL.lock().unwrap();
    (c.ops.unwrap(), c.devfd)
}

/// Whether the misc device is in use (`ops->version` is set).
pub fn has_version() -> bool {
    ops().0 == Kind::Dev
}

/// `ops->version`: the misc device's version (major, minor).
pub fn version(ioctlfd: Fd) -> Option<(u32, u32)> {
    let (k, devfd) = ops();
    if k != Kind::Dev {
        return None;
    }
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_VERSION, &mut prm) == -1 {
        return None;
    }
    let h = prm.head();
    Some((h.ver_major, h.ver_minor))
}

/// `ops->protover`.
pub fn protover(ioctlfd: Fd) -> Result<u32, i32> {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        let mut v = 0u32;
        return if sys::ioctl_int_ptr(ioctlfd, sys::AUTOFS_IOC_PROTOVER, &mut v) == -1 { Err(-1) } else { Ok(v) };
    }
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_PROTOVER, &mut prm) == -1 {
        return Err(-1);
    }
    Ok(prm.head().arg[0])
}

/// `ops->protosubver`.
pub fn protosubver(ioctlfd: Fd) -> Result<u32, i32> {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        let mut v = 0u32;
        return if sys::ioctl_int_ptr(ioctlfd, sys::AUTOFS_IOC_PROTOSUBVER, &mut v) == -1 { Err(-1) } else { Ok(v) };
    }
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_PROTOSUBVER, &mut prm) == -1 {
        return Err(-1);
    }
    Ok(prm.head().arg[0])
}

/// `ops->mount_device`: (the ioctl's result, the device id). The legacy
/// interface can't do it (-1).
pub fn mount_device(path: &[u8], ty: u32) -> (i32, u64) {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        return (-1, 0);
    }
    let mut prm = Param::new(Some(path));
    prm.head().arg[0] = ty;
    let err = dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_ISMOUNTPOINT, &mut prm);
    if err == -1 {
        return (-1, u64::MAX);
    }
    let devid = if err != 0 { prm.head().arg[0] as u64 } else { u64::MAX };
    (err, devid)
}

/// `ops->open`: an ioctl descriptor for the autofs mount at `path`.
pub fn open(devid: u64, path: &[u8]) -> Result<Fd, i32> {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        let fd = sys::open_flags(path, libc::O_RDONLY);
        if fd == -1 {
            return Err(sys::errno());
        }
        match sys::fstatfs_type(fd) {
            None => {
                let e = sys::errno();
                sys::close(fd);
                sys::set_errno(e);
                return Err(e);
            }
            Some(t) if t != AUTOFS_SUPER_MAGIC => {
                sys::close(fd);
                sys::set_errno(libc::ENOENT);
                return Err(libc::ENOENT);
            }
            _ => return Ok(fd),
        }
    }
    let mut prm = Param::new(Some(path));
    prm.head().arg[0] = devid as u32;
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_OPENMOUNT, &mut prm) == -1 {
        return Err(sys::errno());
    }
    Ok(prm.head().ioctlfd)
}

/// `ops->close`.
pub fn close(ioctlfd: Fd) -> i32 {
    sys::close(ioctlfd)
}

/// `ops->send_ready`.
pub fn send_ready(logopt: u32, ioctlfd: Fd, token: u32) -> i32 {
    let (k, devfd) = ops();
    if token == 0 {
        sys::set_errno(libc::EINVAL);
        return -1;
    }
    if k == Kind::Legacy {
        debug!(logopt, "ioctl_send_ready", "token = {}", token);
        if sys::ioctl_val(ioctlfd, sys::AUTOFS_IOC_READY, token as libc::c_ulong) == -1 {
            let e = sys::errno();
            logerr!("ioctl_send_ready", "457", "AUTOFS_IOC_READY: error {}", sys::strerror(e));
            sys::set_errno(e);
            return -1;
        }
        return 0;
    }
    debug!(logopt, "dev_ioctl_send_ready", "token = {}", token);
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    prm.head().arg[0] = token;
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_READY, &mut prm) == -1 {
        let e = sys::errno();
        logerr!("dev_ioctl_send_ready", "436", "AUTOFS_DEV_IOCTL_READY: error {}", sys::strerror(e));
        sys::set_errno(e);
        return -1;
    }
    0
}

/// `ops->send_fail`.
pub fn send_fail(logopt: u32, ioctlfd: Fd, token: u32, status: i32) -> i32 {
    let (k, devfd) = ops();
    if token == 0 {
        sys::set_errno(libc::EINVAL);
        return -1;
    }
    if k == Kind::Legacy {
        debug!(logopt, "ioctl_send_fail", "token = {}", token);
        if sys::ioctl_val(ioctlfd, sys::AUTOFS_IOC_FAIL, token as libc::c_ulong) == -1 {
            let e = sys::errno();
            logerr!("ioctl_send_fail", "512", "AUTOFS_IOC_FAIL: error {}", sys::strerror(e));
            sys::set_errno(e);
            return -1;
        }
        return 0;
    }
    debug!(logopt, "dev_ioctl_send_fail", "token = {}", token);
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    prm.head().arg = [token, status as u32];
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_FAIL, &mut prm) == -1 {
        let e = sys::errno();
        logerr!("dev_ioctl_send_fail", "491", "AUTOFS_DEV_IOCTL_FAIL: error {}", sys::strerror(e));
        sys::set_errno(e);
        return -1;
    }
    0
}

/// `ops->setpipefd` (`None` for the legacy interface, which has none).
pub fn setpipefd(ioctlfd: Fd, pipefd: Fd) -> Option<i32> {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        return None;
    }
    if pipefd == -1 {
        sys::set_errno(libc::EBADF);
        return Some(-1);
    }
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    prm.head().arg[0] = pipefd as u32;
    Some(if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_SETPIPEFD, &mut prm) == -1 { -1 } else { 0 })
}

/// `ops->catatonic`.
pub fn catatonic(ioctlfd: Fd) -> i32 {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        return sys::ioctl_val(ioctlfd, sys::AUTOFS_IOC_CATATONIC, 0);
    }
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_CATATONIC, &mut prm) == -1 { -1 } else { 0 }
}

/// `ops->timeout`.
pub fn timeout(ioctlfd: Fd, timeout: i64) -> i32 {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        let mut t = timeout;
        return sys::ioctl_long_ptr(ioctlfd, sys::AUTOFS_IOC_SETTIMEOUT, &mut t);
    }
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    *prm.arg64() = timeout as u64;
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_TIMEOUT, &mut prm) == -1 { -1 } else { 0 }
}

/// `ops->requester`: (uid, gid) of the last request at `path`.
pub fn requester(ioctlfd: Fd, path: &[u8]) -> Option<Result<(u32, u32), i32>> {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        return None;
    }
    let mut prm = Param::new(Some(path));
    prm.head().ioctlfd = ioctlfd;
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_REQUESTER, &mut prm) == -1 {
        return Some(Err(sys::errno()));
    }
    let a = prm.head().arg;
    Some(Ok((a[0], a[1])))
}

/// `expire()`: ask for expires until the kernel says `EAGAIN` (or the mount
/// goes), `EXPIRE_RETRIES` (1) tries; 1 when the mount is still busy afterwards.
fn expire_loop(logopt: u32, mut call: impl FnMut() -> i32, ioctlfd: Fd) -> i32 {
    let mut retries = EXPIRE_RETRIES;
    let mut ret = 0;
    let mut save_errno = 0;
    while retries > 0 {
        retries -= 1;
        ret = call();
        if ret == -1 {
            save_errno = sys::errno();
            if save_errno == libc::EBADF || save_errno == libc::EINVAL {
                break;
            }
            if save_errno == libc::EAGAIN {
                break;
            }
        }
        sys::nanosleep_once(100_000_000);
    }
    if (ret == 0 || save_errno == libc::EAGAIN)
        && let Ok(may_umount) = askumount(logopt, ioctlfd)
        && may_umount == 0
    {
        ret = 1;
    }
    sys::set_errno(save_errno);
    ret
}

/// `ops->expire`.
pub fn expire(logopt: u32, ioctlfd: Fd, _path: &[u8], how: u32) -> i32 {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        let mut w = how;
        return expire_loop(logopt, || sys::ioctl_int_ptr(ioctlfd, sys::AUTOFS_IOC_EXPIRE_MULTI, &mut w), ioctlfd);
    }
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    prm.head().arg[0] = how;
    expire_loop(logopt, || dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_EXPIRE, &mut prm), ioctlfd)
}

/// `ops->askumount`: whether the mount may be unmounted (1) or is busy (0).
pub fn askumount(_logopt: u32, ioctlfd: Fd) -> Result<u32, i32> {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        let mut v = 0u32;
        return if sys::ioctl_int_ptr(ioctlfd, sys::AUTOFS_IOC_ASKUMOUNT, &mut v) == -1 { Err(-1) } else { Ok(v) };
    }
    let mut prm = Param::new(None);
    prm.head().ioctlfd = ioctlfd;
    if dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_ASKUMOUNT, &mut prm) == -1 {
        return Err(-1);
    }
    Ok(prm.head().arg[0])
}

/// `ops->ismountpoint`: `DEV_IOCTL_IS_*` flags (0 when `path` doesn't exist);
/// `None` for the legacy interface.
pub fn ismountpoint(ioctlfd: Fd, path: &[u8]) -> Option<Result<u32, i32>> {
    let (k, devfd) = ops();
    if k == Kind::Legacy {
        return None;
    }
    let mut prm = Param::new(Some(path));
    prm.head().ioctlfd = ioctlfd;
    prm.head().arg[0] = AUTOFS_TYPE_ANY;
    let err = dev_ioctl(devfd, sys::AUTOFS_DEV_IOCTL_ISMOUNTPOINT, &mut prm);
    if err == -1 {
        let e = sys::errno();
        if e == libc::ENOENT {
            return Some(Ok(0));
        }
        return Some(Err(e));
    }
    let mut mp = 0;
    if err != 0 {
        mp = DEV_IOCTL_IS_MOUNTED;
        mp |= if prm.head().arg[1] as i64 == AUTOFS_SUPER_MAGIC { DEV_IOCTL_IS_AUTOFS } else { DEV_IOCTL_IS_OTHER };
    }
    Some(Ok(mp))
}
