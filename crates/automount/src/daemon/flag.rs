//! `daemon/flag.c`: the "already running" flag file, `/run/autofs-running`,
//! holding the daemon's pid. It's made by linking a per-pid file to the name,
//! so only one daemon can succeed; a flag file whose process has gone (or isn't
//! this program) is stale and replaced.

use std::sync::Mutex;

use crate::libautofs::defaults::AUTOFS_FLAG_DIR;
use crate::sys;

const MAX_PIDSIZE: usize = 20;

#[derive(Debug)]
struct Flag {
    we_created_flagfile: bool,
    fd: i32,
}

static FLAG: Mutex<Flag> = Mutex::new(Flag { we_created_flagfile: false, fd: -1 });

fn flag_file() -> Vec<u8> {
    [AUTOFS_FLAG_DIR, b"/autofs-running"].concat()
}

/// `check_pid_exe_name()`: whether `pid` runs the same executable as we do.
fn check_pid_exe_name(pid: i32) -> bool {
    let Some(self_name) = sys::readlink(b"/proc/self/exe") else { return false };
    if self_name.len() >= 4096 {
        return false;
    }
    let exe_pid = format!("/proc/{}/exe", pid as u32);
    if exe_pid.len() >= MAX_PIDSIZE {
        return false;
    }
    let Some(pid_name) = sys::readlink(exe_pid.as_bytes()) else { return false };
    if pid_name.len() >= 4096 {
        return false;
    }
    self_name == pid_name
}

/// `flag_is_owned()`.
fn flag_is_owned(fd: i32) -> bool {
    let mut pid = 0;
    let mut tries: i32 = 3;
    while tries > 0 {
        tries -= 1;
        sys::rewind(fd);
        let mut buf = [0u8; MAX_PIDSIZE + 1];
        let got = sys::read(fd, &mut buf[..MAX_PIDSIZE]);
        // A terminating newline shows the write completed; a file not finished
        // in 300 milliseconds is probably stale.
        if got > 0 && buf[got as usize - 1] == b'\n' {
            pid = crate::libautofs::cstr::atoi(&buf[..got as usize]);
            break;
        }
        sys::sleep_ns(100_000_000);
    }
    // Stale flag file.
    if tries == 0 {
        return false;
    }
    if pid == 0 {
        return false;
    }
    if sys::kill0(pid) == -1 && sys::errno() == libc::ESRCH {
        return false;
    }
    check_pid_exe_name(pid)
}

/// `release_flag_file()`.
pub fn release_flag_file() {
    let mut f = FLAG.lock().unwrap();
    if f.fd > 0 {
        sys::close(f.fd);
        f.fd = -1;
    }
    if f.we_created_flagfile {
        sys::unlink(&flag_file());
        f.we_created_flagfile = false;
    }
}

/// `aquire_flag_file()`: whether this process now holds the flag.
pub fn aquire_flag_file() -> bool {
    let linkf = format!("{}.{}", String::from_utf8_lossy(&flag_file()), sys::getpid()).into_bytes();
    if linkf.len() >= 4096 {
        return false;
    }
    let ff = flag_file();
    loop {
        if FLAG.lock().unwrap().we_created_flagfile {
            break;
        }
        let i = sys::open_mode(&linkf, libc::O_WRONLY | libc::O_CREAT, 0o644);
        if i < 0 {
            release_flag_file();
            return false;
        }
        sys::close(i);
        let j = sys::link(&linkf, &ff);
        let errsv = sys::errno();
        sys::unlink(&linkf);
        if j < 0 && errsv != libc::EEXIST {
            release_flag_file();
            return false;
        }
        let fd = sys::open_flags(&ff, libc::O_RDWR);
        if fd < 0 {
            // Maybe the file was just removed.
            if sys::errno() == libc::ENOENT {
                continue;
            }
            release_flag_file();
            return false;
        }
        FLAG.lock().unwrap().fd = fd;
        if j == 0 {
            let pidbuf = format!("{}\n", sys::getpid()).into_bytes();
            if sys::write_all(fd, &pidbuf) != pidbuf.len() as isize {
                release_flag_file();
                return false;
            }
            FLAG.lock().unwrap().we_created_flagfile = true;
        } else {
            // Someone else made the link: clean up a stale one and try again.
            if !flag_is_owned(fd) {
                sys::close(fd);
                FLAG.lock().unwrap().fd = -1;
                sys::unlink(&ff);
                continue;
            }
            release_flag_file();
            return false;
        }
        sys::close(fd);
        FLAG.lock().unwrap().fd = -1;
    }
    true
}
