//! `daemon/spawn.c`: running `mount` and `umount`, their output read through a
//! pipe and logged line by line at debug level (`>> ...`).

use crate::libautofs::defaults;
use crate::libautofs::mounts::{self, MNTS_AUTOFS};
use crate::sys::{self, ChildPrep};

pub const PATH_MOUNT: &[u8] = b"/usr/bin/mount";
pub const PATH_UMOUNT: &[u8] = b"/usr/bin/umount";
const PATH_MOUNTED: &[u8] = b"/etc/mtab";
const PROC_MOUNTS: &[u8] = b"/proc/mounts";
const PROC_SELF_MOUNTS: &[u8] = b"/proc/self/mounts";
const MTAB_NOTUPDATED: i32 = 0x1000;
const MNT_FORCE_FAIL: i32 = -1;
const MTAB_LOCK_RETRIES: u32 = 3;
const ERRBUFSIZ: usize = 2047;

const SPAWN_OPT_NONE: u32 = 0;
const SPAWN_OPT_OPEN: u32 = 2;

/// `open_pipe()`.
fn open_pipe() -> Option<(sys::Fd, sys::Fd)> {
    match sys::pipe_cloexec() {
        Ok(p) => Some(p),
        Err(e) => {
            logerr!("open_pipe", "161", "failed to open pipe: {}", sys::strerror(e));
            None
        }
    }
}

/// `timed_read()`: the bytes read, 0 at the end, `-ETIMEDOUT` or -1.
fn timed_read(fd: sys::Fd, buf: &mut [u8], time: i32) -> isize {
    let timeout = if time != -1 { if time >= (i32::MAX - 1) / 1000 { i32::MAX - 1 } else { time * 1000 } } else { -1 };
    let (r, revents) = sys::poll_in(fd, timeout);
    if r <= 0 {
        return if r == 0 { -(libc::ETIMEDOUT as isize) } else { r as isize };
    }
    if revents & (libc::POLLIN | libc::POLLHUP) == libc::POLLHUP {
        return 0;
    }
    loop {
        let n = sys::read(fd, buf);
        if n == -1 && sys::errno() == libc::EINTR {
            continue;
        }
        return n;
    }
}

/// `do_spawn()`: the child's wait status, or -1.
fn do_spawn(logopt: u32, wait: u32, options: u32, prog: &[u8], argv: &[Vec<u8>]) -> i32 {
    let Some((pr, pw)) = open_pipe() else { return -1 };
    let old = sys::block_all_signals();
    // What to mount must always be second last.
    let loc = argv.len();
    let prep = if loc > 3 && options & SPAWN_OPT_OPEN != 0 && argv[loc - 2].first() == Some(&b'/') {
        let l = argv[loc - 2].clone();
        let is_bind = argv.iter().any(|a| a == b"--bind");
        ChildPrep::OpenLocation { is_bind_to_autofs: is_bind && mounts::is_mounted(&l, MNTS_AUTOFS), loc: l }
    } else {
        ChildPrep::None
    };
    let f = sys::spawn(prog, argv, pr, pw, &prep);
    sys::mask_with_sigchld(&old);
    sys::close(pw);
    if f < 0 {
        sys::close(pr);
        sys::set_sigmask(&old);
        return -1;
    }
    let mut errbuf = vec![0u8; ERRBUFSIZ + 1];
    let mut errp = 0usize;
    let mut errn;
    loop {
        errn = timed_read(pr, &mut errbuf[errp..ERRBUFSIZ], wait as i32);
        if errn > 0 {
            errp += errn as usize;
            let mut sp = 0usize;
            while errp > 0 {
                let Some(nl) = errbuf[sp..sp + errp].iter().position(|&b| b == b'\n') else { break };
                let line = errbuf[sp..sp + nl].to_vec();
                if !line.is_empty() && line[0] != 0 {
                    debug!(logopt, "do_spawn", ">> {}", crate::libautofs::cstr::c(&line));
                }
                errp -= nl + 1;
                sp += nl + 1;
            }
            if errp > 0 && sp != 0 {
                errbuf.copy_within(sp..sp + errp, 0);
            }
            if errp >= ERRBUFSIZ {
                let line = errbuf[..errp].to_vec();
                debug!(logopt, "do_spawn", ">> {}", crate::libautofs::cstr::c(&line));
                errp = 0;
            }
        }
        if errn <= 0 {
            break;
        }
    }
    if errn == -(libc::ETIMEDOUT as isize) {
        sys::kill(f, libc::SIGTERM);
    }
    sys::close(pr);
    if errp > 0 {
        let line = errbuf[..errp].to_vec();
        debug!(logopt, "do_spawn", ">> {}", crate::libautofs::cstr::c(&line));
    }
    let (r, st) = sys::waitpid(f);
    let ret = if r != f { -1 } else { st };
    sys::set_sigmask(&old);
    ret
}

/// Whether `/etc/mtab` is a link to the kernel's table (then `-n` is passed).
fn mtab_is_proc() -> bool {
    sys::readlink(PATH_MOUNTED).is_some_and(|l| l == PROC_MOUNTS || l == PROC_SELF_MOUNTS)
}

/// `spawn_mount(logopt, args...)`.
pub fn spawn_mount(logopt: u32, args: &[&[u8]]) -> i32 {
    let wait = defaults::defaults_get_mount_wait();
    let verbose = defaults::defaults_get_mount_verbose();
    let mut options = SPAWN_OPT_OPEN;
    let mut argc = args.len() + 1;
    let no_mtab = mtab_is_proc();
    if no_mtab {
        debug!(logopt, "spawn_mount", "mtab link detected, passing -n to mount");
        argc += 1;
    }
    let mut argv: Vec<Vec<u8>> = vec![PATH_MOUNT.to_vec()];
    if no_mtab {
        argv.push(b"-n".to_vec());
    }
    if verbose != 0 {
        argv.push(b"-v".to_vec());
    }
    let mut i = 0;
    while i < args.len() {
        argv.push(args[i].to_vec());
        if options == SPAWN_OPT_OPEN && args[i] == b"-t" {
            i += 1;
            if i >= args.len() {
                break;
            }
            argv.push(args[i].to_vec());
            if crate::libautofs::cstr::strstr(args[i], b"cifs").is_some() {
                options = SPAWN_OPT_NONE;
            }
        }
        i += 1;
    }
    let mut ret = 0;
    let mut printed = false;
    for _ in 0..MTAB_LOCK_RETRIES {
        ret = do_spawn(logopt, wait, options, PATH_MOUNT, &argv);
        if ret == MTAB_NOTUPDATED {
            if !printed {
                debug!(logopt, "spawn_mount", "mount failed with error code 16, retrying with the -f option");
                printed = true;
            }
            if argv.len() <= argc {
                let n = argv.len();
                let last = argv[n - 1].clone();
                let before = argv[n - 2].clone();
                argv[n - 2] = b"-f".to_vec();
                argv[n - 1] = before;
                argv.push(last);
            }
            sys::sleep_secs(3);
            continue;
        }
        break;
    }
    if ret == MTAB_NOTUPDATED {
        warn!(logopt, "Unable to update the mtab file, forcing mount fail!");
        if let Some(a) = argv.get(argc) {
            sys::umount(a);
        }
        ret = MNT_FORCE_FAIL;
    }
    ret
}

/// `spawn_umount(logopt, args...)`.
pub fn spawn_umount(logopt: u32, args: &[&[u8]]) -> i32 {
    let wait = defaults::defaults_get_umount_wait();
    let no_mtab = mtab_is_proc();
    if no_mtab {
        debug!(logopt, "spawn_umount", "mtab link detected, passing -n to mount");
    }
    let mut argv: Vec<Vec<u8>> = vec![PATH_UMOUNT.to_vec(), b"-c".to_vec()];
    if no_mtab {
        argv.push(b"-n".to_vec());
    }
    argv.extend(args.iter().map(|a| a.to_vec()));
    let mut ret = 0;
    let mut printed = false;
    let mut retries = MTAB_LOCK_RETRIES;
    while retries > 0 {
        retries -= 1;
        ret = do_spawn(logopt, wait, SPAWN_OPT_NONE, PATH_UMOUNT, &argv);
        if ret == MTAB_NOTUPDATED {
            if !printed {
                debug!(logopt, "spawn_umount", "umount failed with error code 16, retrying with the -f option");
                printed = true;
            }
        } else {
            if retries < MTAB_LOCK_RETRIES - 1 {
                ret = 0;
            }
            break;
        }
    }
    if ret == MTAB_NOTUPDATED {
        warn!(logopt, "Unable to update the mtab file, /proc/mounts and /etc/mtab will differ");
        ret = 0;
    }
    ret
}
