//! Thin wrappers over libc.
//!
//! This is the only module of the crate with `unsafe` code. Where autofs'
//! behavior depends on the C library (syslog, `strerror()`, `scandir()` with
//! `versionsort()`, `getopt_long()`'s argument order, the environment
//! programs inherit), the C library is called rather than imitated, so both
//! programs get the same answers.

use std::ffi::{CStr, CString, c_char, c_int};

/// A file descriptor.
pub type Fd = c_int;

/// `s` as a C string, cut at the first NUL (as C sees it).
pub fn cstring(s: &[u8]) -> CString {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    CString::new(&s[..end]).unwrap()
}

/// `errno`.
pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Set `errno`.
pub fn set_errno(e: i32) {
    // SAFETY: __errno_location returns this thread's errno.
    unsafe { *libc::__errno_location() = e };
}

/// `strerror(e)`.
pub fn strerror(e: i32) -> Vec<u8> {
    let mut buf = [0 as c_char; 128];
    // SAFETY: buf has room for 128 bytes; the GNU strerror_r returns a C string
    // (buf or a static one).
    let p = unsafe { libc::strerror_r(e, buf.as_mut_ptr(), buf.len()) };
    let _ = p;
    // SAFETY: the XSI variant (what the libc crate binds) filled buf.
    unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes().to_vec()
}

/// `openlog(ident, LOG_PID, LOG_DAEMON)`. The identity must outlive the log.
pub fn openlog(ident: &'static CStr) {
    // SAFETY: ident is a static C string.
    unsafe { libc::openlog(ident.as_ptr(), libc::LOG_PID, libc::LOG_DAEMON) };
}

/// `closelog()`.
pub fn closelog() {
    // SAFETY: no preconditions.
    unsafe { libc::closelog() };
}

/// `syslog(pri, "%s", msg)`.
pub fn syslog(pri: c_int, msg: &[u8]) {
    let m = cstring(msg);
    // SAFETY: both are valid C strings.
    unsafe { libc::syslog(pri, c"%s".as_ptr(), m.as_ptr()) };
}

/// `write(fd, buf, buf.len())`.
pub fn write(fd: Fd, buf: &[u8]) -> isize {
    // SAFETY: buf is valid for buf.len() bytes.
    unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) }
}

/// Write all of `buf` to stderr (unbuffered, as C's `stderr`).
pub fn write_stderr(buf: &[u8]) {
    let mut off = 0;
    while off < buf.len() {
        let n = write(2, &buf[off..]);
        if n <= 0 {
            if n < 0 && errno() == libc::EINTR {
                continue;
            }
            return;
        }
        off += n as usize;
    }
}

/// `getenv(name)`.
pub fn getenv(name: &[u8]) -> Option<Vec<u8>> {
    let n = cstring(name);
    // SAFETY: n is a valid C string; the result is copied at once.
    let p = unsafe { libc::getenv(n.as_ptr()) };
    if p.is_null() {
        None
    } else {
        // SAFETY: getenv returned a valid C string.
        Some(unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
    }
}

/// `setenv(name, value, overwrite)`.
pub fn setenv(name: &[u8], value: &[u8], overwrite: bool) -> i32 {
    let (n, v) = (cstring(name), cstring(value));
    // SAFETY: valid C strings; autofs is single-threaded where it does this.
    unsafe { libc::setenv(n.as_ptr(), v.as_ptr(), overwrite as c_int) }
}

/// `access(path, mode)`.
pub fn access(path: &[u8], mode: c_int) -> i32 {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::access(p.as_ptr(), mode) }
}

/// `stat(path)`.
pub fn stat(path: &[u8]) -> Option<libc::stat> {
    let p = cstring(path);
    // SAFETY: zeroed stat is a valid out buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: p is a valid C string and st a valid out pointer.
    if unsafe { libc::stat(p.as_ptr(), &mut st) } == 0 { Some(st) } else { None }
}

/// `lstat(path)`.
pub fn lstat(path: &[u8]) -> Option<libc::stat> {
    let p = cstring(path);
    // SAFETY: zeroed stat is a valid out buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: p is a valid C string and st a valid out pointer.
    if unsafe { libc::lstat(p.as_ptr(), &mut st) } == 0 { Some(st) } else { None }
}

/// `fstat(fd)`.
pub fn fstat(fd: Fd) -> Option<libc::stat> {
    // SAFETY: zeroed stat is a valid out buffer.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: st is a valid out pointer.
    if unsafe { libc::fstat(fd, &mut st) } == 0 { Some(st) } else { None }
}

/// The fields of `uname()`.
#[derive(Debug, Clone, Default)]
pub struct Uname {
    pub sysname: Vec<u8>,
    pub nodename: Vec<u8>,
    pub release: Vec<u8>,
    pub version: Vec<u8>,
    pub machine: Vec<u8>,
}

/// `uname()`: its return value and the fields.
pub fn uname() -> (i32, Uname) {
    // SAFETY: zeroed utsname is a valid out buffer.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: u is a valid out pointer.
    let r = unsafe { libc::uname(&mut u) };
    let f = |a: &[c_char]| -> Vec<u8> {
        let b: Vec<u8> = a.iter().map(|&c| c as u8).collect();
        super::libautofs::cstr::c(&b).to_vec()
    };
    (
        r,
        Uname {
            sysname: f(&u.sysname),
            nodename: f(&u.nodename),
            release: f(&u.release),
            version: f(&u.version),
            machine: f(&u.machine),
        },
    )
}

/// `gethostname(buf, len)`: the result and what it wrote (up to `len` bytes,
/// not NUL-terminated if truncated).
pub fn gethostname(len: usize) -> (i32, Vec<u8>) {
    let mut buf = vec![0u8; len + 1];
    // SAFETY: buf has room for len bytes.
    let r = unsafe { libc::gethostname(buf.as_mut_ptr().cast(), len) };
    (r, buf[..len].to_vec())
}

/// `geteuid()`.
pub fn geteuid() -> u32 {
    // SAFETY: no preconditions.
    unsafe { libc::geteuid() }
}

/// `getrlimit(RLIMIT_NOFILE)` / `setrlimit()`.
pub fn get_nofile() -> Option<(u64, u64)> {
    let mut r = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: r is a valid out pointer.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut r) } == 0 { Some((r.rlim_cur, r.rlim_max)) } else { None }
}

pub fn set_nofile(cur: u64, max: u64) -> i32 {
    let r = libc::rlimit { rlim_cur: cur, rlim_max: max };
    // SAFETY: r is a valid pointer.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &r) }
}

/// `setrlimit(RLIMIT_CORE, {RLIM_INFINITY, RLIM_INFINITY})`.
pub fn set_core_unlimited() -> i32 {
    let r = libc::rlimit { rlim_cur: libc::RLIM_INFINITY, rlim_max: libc::RLIM_INFINITY };
    // SAFETY: r is a valid pointer.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &r) }
}

/// Block every signal but the ones that drop cores (`main()`'s first step).
pub fn block_all_but_core_signals() {
    // SAFETY: the sigset is initialized by sigfillset before use.
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut s);
        for sig in [libc::SIGABRT, libc::SIGBUS, libc::SIGSEGV, libc::SIGILL, libc::SIGFPE, libc::SIGTRAP] {
            libc::sigdelset(&mut s, sig);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &s, std::ptr::null_mut());
    }
}

/// glibc's `__chk_fail()`: a `_FORTIFY_SOURCE` check found an overflow (the
/// reference is built with it, as Gentoo builds everything). The message, then
/// `abort()`; buffered stdout is lost.
pub fn chk_fail() -> ! {
    super::libautofs::log::flush_stdout_lost();
    write_stderr(b"*** buffer overflow detected ***: terminated\n");
    die_by_signal(libc::SIGABRT)
}

/// `abort()`.
pub fn abort() -> ! {
    std::process::abort()
}

/// `raise(sig)` with `sig` unblocked first, then `_exit` in case it returns.
pub fn die_by_signal(sig: c_int) -> ! {
    // SAFETY: plain signal calls on a valid sigset.
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        libc::sigaddset(&mut s, sig);
        libc::pthread_sigmask(libc::SIG_UNBLOCK, &s, std::ptr::null_mut());
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
        libc::_exit(128 + sig)
    }
}

/// `exit(status)` after flushing stdout, as C's `exit()` flushes stdio.
pub fn exit(status: i32) -> ! {
    super::libautofs::log::flush_stdout();
    std::process::exit(status)
}

/// A whole file's contents read through `fopen(path, "re")`; `Err(errno)`.
pub fn read_file(path: &[u8]) -> Result<Vec<u8>, i32> {
    use std::os::unix::ffi::OsStrExt;
    let p = std::ffi::OsStr::from_bytes(super::libautofs::cstr::c(path));
    std::fs::read(p).map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))
}

unsafe extern "C" {
    fn strverscmp(a: *const c_char, b: *const c_char) -> c_int;
    fn srandom(seed: libc::c_uint);
}

/// glibc's `strverscmp()`.
pub fn versioncmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    let (x, y) = (cstring(a), cstring(b));
    // SAFETY: both are valid C strings.
    let r = unsafe { strverscmp(x.as_ptr(), y.as_ptr()) };
    r.cmp(&0)
}

/// The names in `dir`, as `scandir()` reads them (`Err(errno)` if it can't).
pub fn read_dir_names(dir: &[u8]) -> Result<Vec<Vec<u8>>, i32> {
    let d = cstring(dir);
    // SAFETY: d is a valid C string.
    let dp = unsafe { libc::opendir(d.as_ptr()) };
    if dp.is_null() {
        return Err(errno());
    }
    let mut names = Vec::new();
    loop {
        // SAFETY: dp is an open DIR.
        let e = unsafe { libc::readdir(dp) };
        if e.is_null() {
            break;
        }
        // SAFETY: e points to a valid dirent with a NUL-terminated name.
        let name = unsafe { CStr::from_ptr((*e).d_name.as_ptr()) }.to_bytes().to_vec();
        names.push(name);
    }
    // SAFETY: dp is an open DIR.
    unsafe { libc::closedir(dp) };
    Ok(names)
}

/// `mkdtemp(template)`: the directory made, or `None`.
pub fn mkdtemp(template: &[u8]) -> Option<Vec<u8>> {
    let mut t = template.to_vec();
    t.push(0);
    // SAFETY: t is a writable NUL-terminated buffer.
    let p = unsafe { libc::mkdtemp(t.as_mut_ptr().cast()) };
    if p.is_null() {
        None
    } else {
        t.pop();
        Some(t)
    }
}

/// `rmdir(path)`.
pub fn rmdir(path: &[u8]) -> i32 {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::rmdir(p.as_ptr()) }
}

/// `readlink(path)`.
pub fn readlink(path: &[u8]) -> Option<Vec<u8>> {
    let p = cstring(path);
    let mut buf = vec![0u8; libc::PATH_MAX as usize + 1];
    // SAFETY: buf has room for PATH_MAX bytes.
    let n = unsafe { libc::readlink(p.as_ptr(), buf.as_mut_ptr().cast(), libc::PATH_MAX as usize) };
    if n < 0 {
        None
    } else {
        buf.truncate(n as usize);
        Some(buf)
    }
}

/// `pipe2(O_CLOEXEC)`.
pub fn pipe_cloexec() -> Result<(Fd, Fd), i32> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for two ints.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } == 0 { Ok((fds[0], fds[1])) } else { Err(errno()) }
}

/// `close(fd)`.
pub fn close(fd: Fd) -> i32 {
    // SAFETY: no memory-safety preconditions.
    unsafe { libc::close(fd) }
}

/// `read(fd, buf)`.
pub fn read(fd: Fd, buf: &mut [u8]) -> isize {
    // SAFETY: buf is valid for buf.len() bytes.
    unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
}

/// `poll()` on one descriptor for `POLLIN`: the result and the `revents`.
pub fn poll_in(fd: Fd, timeout_ms: c_int) -> (i32, i16) {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: p is a valid pollfd.
    let r = unsafe { libc::poll(&mut p, 1, timeout_ms) };
    (r, p.revents)
}

/// `kill(pid, sig)`.
pub fn kill(pid: i32, sig: c_int) -> i32 {
    // SAFETY: no memory-safety preconditions.
    unsafe { libc::kill(pid, sig) }
}

/// `waitpid(pid, &status, 0)`: the pid returned and the status.
pub fn waitpid(pid: i32) -> (i32, i32) {
    let mut st: c_int = 0;
    loop {
        // SAFETY: st is a valid out pointer.
        let r = unsafe { libc::waitpid(pid, &mut st, 0) };
        if r < 0 && errno() == libc::EINTR {
            continue;
        }
        return (r, st);
    }
}

/// What the child of [`spawn`] does before `execv()`.
#[derive(Debug, Clone)]
pub enum ChildPrep {
    /// Nothing.
    None,
    /// `do_spawn()`'s `SPAWN_OPT_OPEN` handling for a local-path location: open
    /// the location (to trigger a dependent mount), and refuse a bind onto an
    /// autofs mount.
    OpenLocation { loc: Vec<u8>, is_bind_to_autofs: bool },
}

/// `fork()` a child with its stdout and stderr on the write end of `pipe_w`,
/// its signals reset (`reset_signals()`), and `execv(prog, argv)`; `_exit(255)`
/// if that fails. Returns the child's pid (or -1).
pub fn spawn(prog: &[u8], argv: &[Vec<u8>], pipe_r: Fd, pipe_w: Fd, prep: &ChildPrep) -> i32 {
    let prog_c = cstring(prog);
    let argv_c: Vec<CString> = argv.iter().map(|a| cstring(a)).collect();
    let mut argv_p: Vec<*const c_char> = argv_c.iter().map(|a| a.as_ptr()).collect();
    argv_p.push(std::ptr::null());
    let (loc_c, bind_autofs) = match prep {
        ChildPrep::None => (None, false),
        ChildPrep::OpenLocation { loc, is_bind_to_autofs } => (Some(cstring(loc)), *is_bind_to_autofs),
    };
    let msg = b"error: can't bind to an autofs mount\n";
    // SAFETY: between fork and exec the child makes only async-signal-safe calls
    // on memory prepared above.
    unsafe {
        let pid = libc::fork();
        if pid != 0 {
            return pid;
        }
        reset_signals_raw();
        libc::close(pipe_r);
        libc::dup2(pipe_w, 1);
        libc::dup2(pipe_w, 2);
        libc::close(pipe_w);
        if let Some(loc) = &loc_c {
            let pgrp = libc::getpgrp();
            libc::setpgid(0, 0);
            let fd = libc::open(loc.as_ptr(), libc::O_DIRECTORY);
            if fd != -1 {
                libc::close(fd);
            }
            // The "warning: seteuid/setegid" messages can't happen as root.
            libc::seteuid(0);
            libc::setegid(0);
            if pgrp >= 0 {
                libc::setpgid(0, pgrp);
            }
            if bind_autofs {
                libc::write(2, msg.as_ptr().cast(), msg.len());
                libc::close(1);
                libc::close(2);
                libc::_exit(libc::EINVAL);
            }
        }
        libc::execv(prog_c.as_ptr(), argv_p.as_ptr());
        libc::_exit(255);
    }
}

/// `reset_signals()`, in a forked child.
///
/// # Safety
///
/// Only for a child between `fork()` and `exec()`.
unsafe fn reset_signals_raw() {
    // SAFETY: plain signal calls on initialized structures.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::sigprocmask(libc::SIG_BLOCK, &all, std::ptr::null_mut());
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = libc::SIG_IGN;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        for i in 1..libc::SIGRTMAX() + 1 {
            if i != libc::SIGKILL && i != libc::SIGSTOP {
                libc::sigaction(i, &sa, std::ptr::null_mut());
            }
        }
        sa.sa_sigaction = libc::SIG_DFL;
        for i in 1..libc::SIGRTMAX() + 1 {
            if i != libc::SIGKILL && i != libc::SIGSTOP {
                libc::sigaction(i, &sa, std::ptr::null_mut());
            }
        }
        sa.sa_sigaction = libc::SIG_IGN;
        sa.sa_flags = libc::SA_RESTART;
        libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGUSR2, &sa, std::ptr::null_mut());
        libc::sigprocmask(libc::SIG_UNBLOCK, &all, std::ptr::null_mut());
    }
}

/// Block every signal (around a fork, as `do_spawn()` does); returns the old mask.
pub fn block_all_signals() -> libc::sigset_t {
    // SAFETY: plain signal calls on initialized structures.
    unsafe {
        let mut all: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut all);
        libc::pthread_sigmask(libc::SIG_BLOCK, &all, &mut old);
        old
    }
}

/// Set the signal mask to `old` plus `SIGCHLD` (the parent side of `do_spawn()`).
pub fn mask_with_sigchld(old: &libc::sigset_t) {
    // SAFETY: plain signal calls on initialized structures.
    unsafe {
        let mut m = *old;
        libc::sigaddset(&mut m, libc::SIGCHLD);
        libc::pthread_sigmask(libc::SIG_SETMASK, &m, std::ptr::null_mut());
    }
}

/// Restore a signal mask.
pub fn set_sigmask(m: &libc::sigset_t) {
    // SAFETY: m is an initialized sigset.
    unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, m, std::ptr::null_mut()) };
}

/// `umount(path)`.
pub fn umount(path: &[u8]) -> i32 {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::umount(p.as_ptr()) }
}

/// `monotonic_time(NULL)`: `CLOCK_MONOTONIC` seconds.
pub fn monotonic_time() -> i64 {
    // SAFETY: zeroed timespec is a valid out buffer.
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    // SAFETY: ts is a valid out pointer.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec
}

/// `time(NULL)`.
pub fn time() -> i64 {
    // SAFETY: a null argument is allowed.
    unsafe { libc::time(std::ptr::null_mut()) }
}

/// `nanosleep()` for `secs` seconds; -1 if interrupted.
pub fn sleep_secs(secs: i64) -> i32 {
    let t = libc::timespec { tv_sec: secs, tv_nsec: 0 };
    // SAFETY: t is valid; the remainder isn't wanted.
    unsafe { libc::nanosleep(&t, std::ptr::null_mut()) }
}

/// `open(path, O_RDONLY|O_CLOEXEC)` and read 4 bytes (`seed_random()`), then
/// `srandom()` with them, or with `fallback`.
pub fn seed_random(fallback: i64) {
    let mut seed = [0u8; 4];
    let p = c"/dev/urandom";
    // SAFETY: p is a valid C string; seed has room for 4 bytes.
    unsafe {
        let fd = libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
        if fd < 0 {
            srandom(fallback as u32);
            return;
        }
        if libc::read(fd, seed.as_mut_ptr().cast(), 4) != -1 {
            srandom(u32::from_ne_bytes(seed));
        } else {
            srandom(fallback as u32);
        }
        libc::close(fd);
    }
}

/// `open(path, O_RDONLY|O_CLOEXEC)`.
pub fn open_rdonly(path: &[u8]) -> Fd {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) }
}

/// `open(path, flags|O_CLOEXEC)`.
pub fn open_flags(path: &[u8], flags: c_int) -> Fd {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::open(p.as_ptr(), flags | libc::O_CLOEXEC) }
}

/// What [`getopt_long`] returns: the options with their arguments, and the operands.
pub type Getopt = (Vec<(c_int, Option<Vec<u8>>)>, Vec<Vec<u8>>);

/// `getopt_long()` over `argv` with `optstring` and `long`, as glibc does it,
/// with `opterr = 0`. Returns the options (`(opt, optarg)`) in order and the
/// operands (what's left from `optind`, after glibc's permutation).
pub fn getopt_long(argv: &[Vec<u8>], optstring: &CStr, long: &[(&'static CStr, c_int, u8)]) -> Getopt {
    let argv_c: Vec<CString> = argv.iter().map(|a| cstring(a)).collect();
    let mut argv_p: Vec<*mut c_char> = argv_c.iter().map(|a| a.as_ptr() as *mut c_char).collect();
    argv_p.push(std::ptr::null_mut());
    let mut longs: Vec<libc::option> = long
        .iter()
        .map(|(n, has, v)| libc::option {
            name: n.as_ptr(),
            has_arg: *has,
            flag: std::ptr::null_mut(),
            val: *v as c_int,
        })
        .collect();
    longs.push(libc::option { name: std::ptr::null(), has_arg: 0, flag: std::ptr::null_mut(), val: 0 });
    let mut out = Vec::new();
    unsafe extern "C" {
        static mut optarg: *mut c_char;
        static mut optind: c_int;
        static mut opterr: c_int;
    }
    // SAFETY: getopt_long runs over valid argv/longopts arrays that outlive the
    // calls; its globals are only touched here, from the main thread.
    unsafe {
        opterr = 0;
        optind = 1;
        loop {
            let o = libc::getopt_long(
                argv_p.len() as c_int - 1,
                argv_p.as_ptr(),
                optstring.as_ptr(),
                longs.as_ptr(),
                std::ptr::null_mut(),
            );
            if o == -1 {
                break;
            }
            let arg = if optarg.is_null() { None } else { Some(CStr::from_ptr(optarg).to_bytes().to_vec()) };
            out.push((o, arg));
        }
        let mut rest = Vec::new();
        for p in &argv_p[optind as usize..argv_p.len() - 1] {
            rest.push(CStr::from_ptr(*p).to_bytes().to_vec());
        }
        (out, rest)
    }
}

/// `query_kproto_ver()`'s test mount: mount autofs on `dir` with a pipe as its
/// kernel end; (the read end of the pipe, the mount's device) if it worked.
/// On failure nothing is left mounted or open.
pub fn autofs_test_mount_keep(dir: &[u8]) -> Option<(Fd, u64)> {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for two ints.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } == -1 {
        return None;
    }
    let pgrp = getpgrp();
    let opts = format!("fd={},pgrp={},minproto=3,maxproto=5", fds[1], pgrp as u32);
    if mount(b"automount", dir, b"autofs", libc::MS_MGC_VAL, Some(opts.as_bytes())) != 0 {
        close(fds[0]);
        close(fds[1]);
        return None;
    }
    close(fds[1]);
    match stat(dir) {
        Some(st) => Some((fds[0], st.st_dev)),
        None => {
            umount(dir);
            close(fds[0]);
            None
        }
    }
}

/// `getpgrp()`.
pub fn getpgrp() -> i32 {
    // SAFETY: plain call.
    unsafe { libc::getpgrp() }
}

/// `getdomainname()`.
pub fn getdomainname() -> Option<Vec<u8>> {
    let mut buf = [0u8; 1025];
    // SAFETY: buf has room for 1024 bytes and a NUL.
    if unsafe { libc::getdomainname(buf.as_mut_ptr().cast(), 1024) } != 0 {
        return None;
    }
    Some(super::libautofs::cstr::c(&buf).to_vec())
}

#[repr(C)]
struct Hostent {
    h_name: *mut c_char,
    h_aliases: *mut *mut c_char,
    h_addrtype: c_int,
    h_length: c_int,
    h_addr_list: *mut *mut c_char,
}

unsafe extern "C" {
    fn sethostent(stayopen: c_int);
    fn gethostent() -> *mut Hostent;
    fn endhostent();
}

/// `sethostent(0)`, the `h_name` of each `gethostent()`, `endhostent()`.
pub fn host_names() -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    // SAFETY: the glibc host enumeration, single-threaded here; each name is
    // copied before the next call.
    unsafe {
        sethostent(0);
        loop {
            let h = gethostent();
            if h.is_null() {
                break;
            }
            out.push(CStr::from_ptr((*h).h_name).to_bytes().to_vec());
        }
        endhostent();
    }
    out
}

/// `getpwuid_r()`: (name, home), or `None`.
pub fn getpwuid(uid: u32) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut buf = vec![0 as c_char; 16384];
    // SAFETY: zeroed passwd is a valid out buffer.
    let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: valid buffers; the strings are copied before buf goes away.
    unsafe {
        let r = libc::getpwuid_r(uid, &mut pw, buf.as_mut_ptr(), buf.len(), &mut res);
        if r != 0 || res.is_null() {
            return None;
        }
        Some((CStr::from_ptr(pw.pw_name).to_bytes().to_vec(), CStr::from_ptr(pw.pw_dir).to_bytes().to_vec()))
    }
}

/// `getgrgid_r()`: the group name, or `None`.
pub fn getgrgid(gid: u32) -> Option<Vec<u8>> {
    let mut buf = vec![0 as c_char; 65536];
    // SAFETY: zeroed group is a valid out buffer.
    let mut gr: libc::group = unsafe { std::mem::zeroed() };
    let mut res: *mut libc::group = std::ptr::null_mut();
    // SAFETY: valid buffers; the string is copied before buf goes away.
    unsafe {
        let r = libc::getgrgid_r(gid, &mut gr, buf.as_mut_ptr(), buf.len(), &mut res);
        if r != 0 || res.is_null() {
            return None;
        }
        Some(CStr::from_ptr(gr.gr_name).to_bytes().to_vec())
    }
}

/// `mkdir(path, mode)`.
pub fn mkdir(path: &[u8], mode: u32) -> i32 {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::mkdir(p.as_ptr(), mode) }
}

/// The environment (`environ`) with `sets` applied as `setenv(name, val, 1)`
/// calls would apply them, in order: a name already there keeps its place.
pub fn environ_with(sets: &[(Vec<u8>, Vec<u8>)]) -> Vec<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let mut env: Vec<Vec<u8>> = Vec::new();
    for (k, v) in std::env::vars_os() {
        let mut e = k.as_bytes().to_vec();
        e.push(b'=');
        e.extend_from_slice(v.as_bytes());
        env.push(e);
    }
    for (name, val) in sets {
        let mut e = name.clone();
        e.push(b'=');
        e.extend_from_slice(val);
        match env.iter().position(|x| x.starts_with(name) && x.get(name.len()) == Some(&b'=')) {
            Some(i) => env[i] = e,
            None => env.push(e),
        }
    }
    env
}

/// What `lookup_program`'s child does: stdout and stderr on two pipes,
/// signals reset, `chdir(dir)` (writing `chdir_msg` to stderr, or to syslog,
/// if it fails and the message isn't empty), then `execve(prog, [prog, arg],
/// env)`; `_exit(255)` if that fails. Returns the pid.
#[allow(clippy::too_many_arguments)]
pub fn spawn_program(
    prog: &[u8],
    arg: &[u8],
    env: &[Vec<u8>],
    dir: &[u8],
    chdir_msg: &[u8],
    msg_to_syslog: bool,
    out: (Fd, Fd),
    err: (Fd, Fd),
) -> i32 {
    let prog_c = cstring(prog);
    let argv_c = [cstring(prog), cstring(arg)];
    let argv_p: [*const c_char; 3] = [argv_c[0].as_ptr(), argv_c[1].as_ptr(), std::ptr::null()];
    let env_c: Vec<CString> = env.iter().map(|e| cstring(e)).collect();
    let mut env_p: Vec<*const c_char> = env_c.iter().map(|e| e.as_ptr()).collect();
    env_p.push(std::ptr::null());
    let dir_c = cstring(dir);
    let msg_c = cstring(chdir_msg);
    // SAFETY: between fork and exec the child makes only async-signal-safe
    // calls (and syslog() as C does) on memory prepared above.
    unsafe {
        let pid = libc::fork();
        if pid != 0 {
            return pid;
        }
        reset_signals_raw();
        libc::close(out.0);
        libc::close(err.0);
        libc::dup2(out.1, 1);
        libc::dup2(err.1, 2);
        libc::close(out.1);
        libc::close(err.1);
        if libc::chdir(dir_c.as_ptr()) != 0 && !chdir_msg.is_empty() {
            if msg_to_syslog {
                libc::syslog(libc::LOG_INFO, c"%s".as_ptr(), msg_c.as_ptr());
            } else {
                libc::write(2, chdir_msg.as_ptr().cast(), chdir_msg.len());
                libc::write(2, b"\n".as_ptr().cast(), 1);
            }
        }
        libc::execve(prog_c.as_ptr(), argv_p.as_ptr(), env_p.as_ptr());
        libc::_exit(255);
    }
}

/// `poll()` on two descriptors for `POLLIN`: the result and the `revents`.
/// A descriptor of -1 is ignored, as poll() does.
pub fn poll2(a: Fd, b: Fd) -> (i32, i16, i16) {
    let mut p = [
        libc::pollfd { fd: a, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: b, events: libc::POLLIN, revents: 0 },
    ];
    // SAFETY: p is a valid array of two pollfds.
    let r = unsafe { libc::poll(p.as_mut_ptr(), 2, -1) };
    (r, p[0].revents, p[1].revents)
}

/// `getpwnam(name)->pw_dir`.
pub fn getpwnam_home(name: &[u8]) -> Option<Vec<u8>> {
    let n = cstring(name);
    // SAFETY: n is a valid C string; the result is copied at once.
    unsafe {
        let pw = libc::getpwnam(n.as_ptr());
        if pw.is_null() {
            return None;
        }
        Some(CStr::from_ptr((*pw).pw_dir).to_bytes().to_vec())
    }
}

/// `chdir(path)`.
pub fn chdir(path: &[u8]) -> i32 {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::chdir(p.as_ptr()) }
}

/// `symlink(target, link)`.
pub fn symlink(target: &[u8], link: &[u8]) -> i32 {
    let (t, l) = (cstring(target), cstring(link));
    // SAFETY: valid C strings.
    unsafe { libc::symlink(t.as_ptr(), l.as_ptr()) }
}

/// A socket address as `getaddrinfo()` and `getifaddrs()` give it: the family
/// and the raw address bytes (4 for IPv4, 16 for IPv6; empty for others).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SockAddr {
    pub family: c_int,
    pub addr: Vec<u8>,
    raw: Vec<u8>,
}

/// # Safety
/// `sa` must be null or point to a socket address of its family's size.
unsafe fn sockaddr_from(sa: *const libc::sockaddr) -> Option<SockAddr> {
    if sa.is_null() {
        return None;
    }
    // SAFETY: the caller's guarantee.
    unsafe {
        let family = (*sa).sa_family as c_int;
        let (addr, len) = match family {
            libc::AF_INET => {
                let s = &*(sa as *const libc::sockaddr_in);
                (s.sin_addr.s_addr.to_ne_bytes().to_vec(), std::mem::size_of::<libc::sockaddr_in>())
            }
            libc::AF_INET6 => {
                let s = &*(sa as *const libc::sockaddr_in6);
                (s.sin6_addr.s6_addr.to_vec(), std::mem::size_of::<libc::sockaddr_in6>())
            }
            _ => (Vec::new(), std::mem::size_of::<libc::sockaddr>()),
        };
        let raw = std::slice::from_raw_parts(sa as *const u8, len).to_vec();
        Some(SockAddr { family, addr, raw })
    }
}

/// One `getaddrinfo()` result.
#[derive(Debug, Clone)]
pub struct AddrInfo {
    pub addr: SockAddr,
    pub canonname: Option<Vec<u8>>,
}

/// `getaddrinfo(name, NULL, hints)`: the results, or the error code.
pub fn getaddrinfo(name: &[u8], family: c_int, socktype: c_int, flags: c_int) -> Result<Vec<AddrInfo>, c_int> {
    let n = cstring(name);
    // SAFETY: zeroed addrinfo is valid hints.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_flags = flags;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: valid arguments; the list is copied, then freed.
    unsafe {
        let r = libc::getaddrinfo(n.as_ptr(), std::ptr::null(), &hints, &mut res);
        if r != 0 {
            return Err(r);
        }
        let mut out = Vec::new();
        let mut p = res;
        while !p.is_null() {
            let canon = if (*p).ai_canonname.is_null() {
                None
            } else {
                Some(CStr::from_ptr((*p).ai_canonname).to_bytes().to_vec())
            };
            if let Some(addr) = sockaddr_from((*p).ai_addr) {
                out.push(AddrInfo { addr, canonname: canon });
            }
            p = (*p).ai_next;
        }
        libc::freeaddrinfo(res);
        Ok(out)
    }
}

/// `gai_strerror(code)`.
pub fn gai_strerror(code: c_int) -> Vec<u8> {
    // SAFETY: gai_strerror returns a static string.
    unsafe { CStr::from_ptr(libc::gai_strerror(code)).to_bytes().to_vec() }
}

/// `getnameinfo(addr, host, NI_MAXHOST, NULL, 0, flags)`: the host, or the error code.
pub fn getnameinfo(addr: &SockAddr, hostlen: usize, flags: c_int) -> Result<Vec<u8>, c_int> {
    let mut host = vec![0 as c_char; hostlen];
    // SAFETY: raw holds a complete socket address; host is hostlen bytes.
    unsafe {
        let r = libc::getnameinfo(
            addr.raw.as_ptr() as *const libc::sockaddr,
            addr.raw.len() as libc::socklen_t,
            host.as_mut_ptr(),
            hostlen as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            flags,
        );
        if r != 0 {
            return Err(r);
        }
        Ok(CStr::from_ptr(host.as_ptr()).to_bytes().to_vec())
    }
}

/// One `getifaddrs()` entry.
#[derive(Debug, Clone)]
pub struct IfAddr {
    pub flags: u32,
    pub addr: Option<SockAddr>,
    pub netmask: Option<SockAddr>,
}

/// `getifaddrs()`: the entries, or `errno`.
pub fn getifaddrs() -> Result<Vec<IfAddr>, i32> {
    let mut ifa: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: the list is copied, then freed.
    unsafe {
        if libc::getifaddrs(&mut ifa) != 0 {
            return Err(errno());
        }
        let mut out = Vec::new();
        let mut p = ifa;
        while !p.is_null() {
            out.push(IfAddr {
                flags: (*p).ifa_flags,
                addr: sockaddr_from((*p).ifa_addr),
                netmask: sockaddr_from((*p).ifa_netmask),
            });
            p = (*p).ifa_next;
        }
        libc::freeifaddrs(ifa);
        Ok(out)
    }
}

#[repr(C)]
struct Netent {
    n_name: *mut c_char,
    n_aliases: *mut *mut c_char,
    n_addrtype: c_int,
    n_net: u32,
}

unsafe extern "C" {
    fn getnetbyname(name: *const c_char) -> *mut Netent;
    fn innetgr(netgroup: *const c_char, host: *const c_char, user: *const c_char, domain: *const c_char) -> c_int;
}

/// `getnetbyname(name)->n_net`, or `None`.
pub fn getnetbyname_net(name: &[u8]) -> Option<u32> {
    let n = cstring(name);
    // SAFETY: n is a valid C string; the result is read before the next call.
    unsafe {
        let e = getnetbyname(n.as_ptr());
        if e.is_null() { None } else { Some((*e).n_net) }
    }
}

/// `innetgr(netgroup, host, NULL, NULL)`.
pub fn innetgr_host(netgroup: &[u8], host: &[u8]) -> bool {
    let (g, h) = (cstring(netgroup), cstring(host));
    // SAFETY: valid C strings.
    unsafe { innetgr(g.as_ptr(), h.as_ptr(), std::ptr::null(), std::ptr::null()) != 0 }
}

/// `statfs(path).f_type`, or `None`.
pub fn statfs_type(path: &[u8]) -> Option<i64> {
    let p = cstring(path);
    // SAFETY: zeroed statfs is a valid out buffer.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid arguments.
    if unsafe { libc::statfs(p.as_ptr(), &mut fs) } != 0 {
        return None;
    }
    Some(fs.f_type as i64)
}

/// `unlink(path)`.
pub fn unlink(path: &[u8]) -> i32 {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::unlink(p.as_ptr()) }
}

/// POSIX `dirname()` (libgen.h's), on a copy of `s`.
pub fn xpg_dirname(s: &[u8]) -> Vec<u8> {
    let mut c = cstring(s).into_bytes_with_nul();
    // SAFETY: c is a NUL-terminated buffer dirname() may write into; the result
    // points into it or to a static string, and is copied before c goes away.
    unsafe {
        let r = libc::dirname(c.as_mut_ptr() as *mut c_char);
        CStr::from_ptr(r).to_bytes().to_vec()
    }
}

// ---------------------------------------------------------------------------
// The daemon: the autofs ioctls, mounts, signals and processes.

/// `struct autofs_dev_ioctl` (linux/auto_dev-ioctl.h), with room for a path.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AutofsDevIoctl {
    pub ver_major: u32,
    pub ver_minor: u32,
    pub size: u32,
    pub ioctlfd: i32,
    /// The parameter union: 8 bytes, 8-aligned (`args_timeout` is a `__u64`).
    pub arg: [u32; 2],
}

pub const AUTOFS_DEV_IOCTL_SIZE: usize = std::mem::size_of::<AutofsDevIoctl>();

const fn iowr(nr: u64, size: u64) -> u64 {
    (3 << 30) | (size << 16) | (0x93 << 8) | nr
}
const fn io(nr: u64) -> u64 {
    (0x93 << 8) | nr
}
const fn ior(nr: u64, size: u64) -> u64 {
    (2 << 30) | (size << 16) | (0x93 << 8) | nr
}
const fn iow(nr: u64, size: u64) -> u64 {
    (1 << 30) | (size << 16) | (0x93 << 8) | nr
}

pub const AUTOFS_DEV_IOCTL_VERSION: u64 = iowr(0x71, 24);
pub const AUTOFS_DEV_IOCTL_PROTOVER: u64 = iowr(0x72, 24);
pub const AUTOFS_DEV_IOCTL_PROTOSUBVER: u64 = iowr(0x73, 24);
pub const AUTOFS_DEV_IOCTL_OPENMOUNT: u64 = iowr(0x74, 24);
pub const AUTOFS_DEV_IOCTL_READY: u64 = iowr(0x76, 24);
pub const AUTOFS_DEV_IOCTL_FAIL: u64 = iowr(0x77, 24);
pub const AUTOFS_DEV_IOCTL_SETPIPEFD: u64 = iowr(0x78, 24);
pub const AUTOFS_DEV_IOCTL_CATATONIC: u64 = iowr(0x79, 24);
pub const AUTOFS_DEV_IOCTL_TIMEOUT: u64 = iowr(0x7a, 24);
pub const AUTOFS_DEV_IOCTL_REQUESTER: u64 = iowr(0x7b, 24);
pub const AUTOFS_DEV_IOCTL_EXPIRE: u64 = iowr(0x7c, 24);
pub const AUTOFS_DEV_IOCTL_ASKUMOUNT: u64 = iowr(0x7d, 24);
pub const AUTOFS_DEV_IOCTL_ISMOUNTPOINT: u64 = iowr(0x7e, 24);

pub const AUTOFS_IOC_READY: u64 = io(0x60);
pub const AUTOFS_IOC_FAIL: u64 = io(0x61);
pub const AUTOFS_IOC_CATATONIC: u64 = io(0x62);
pub const AUTOFS_IOC_PROTOVER: u64 = ior(0x63, 4);
pub const AUTOFS_IOC_SETTIMEOUT: u64 = iowr(0x64, 8);
pub const AUTOFS_IOC_EXPIRE_MULTI: u64 = iow(0x66, 4);
pub const AUTOFS_IOC_PROTOSUBVER: u64 = ior(0x67, 4);
pub const AUTOFS_IOC_ASKUMOUNT: u64 = ior(0x70, 4);

/// `ioctl(fd, req, buf)` with a `struct autofs_dev_ioctl` and its path
/// (`buf` holds the struct, then the path's bytes and a NUL).
pub fn ioctl_dev(fd: Fd, req: u64, buf: &mut [u8]) -> i32 {
    // SAFETY: buf is at least AUTOFS_DEV_IOCTL_SIZE bytes, 8-aligned by the
    // caller's allocation (a Vec<u64> viewed as bytes), and as long as the
    // struct's size field says.
    unsafe { libc::ioctl(fd, req as libc::c_ulong, buf.as_mut_ptr()) }
}

/// `ioctl(fd, req, &int)`.
pub fn ioctl_int_ptr(fd: Fd, req: u64, v: &mut u32) -> i32 {
    // SAFETY: v is a valid int out pointer.
    unsafe { libc::ioctl(fd, req as libc::c_ulong, v as *mut u32) }
}

/// `ioctl(fd, req, &long)`.
pub fn ioctl_long_ptr(fd: Fd, req: u64, v: &mut i64) -> i32 {
    // SAFETY: v is a valid long pointer.
    unsafe { libc::ioctl(fd, req as libc::c_ulong, v as *mut i64) }
}

/// `ioctl(fd, req, val)` with an integer argument.
pub fn ioctl_val(fd: Fd, req: u64, val: libc::c_ulong) -> i32 {
    // SAFETY: the argument is passed by value.
    unsafe { libc::ioctl(fd, req as libc::c_ulong, val) }
}

/// `mount(source, target, fstype, flags, data)`.
pub fn mount(source: &[u8], target: &[u8], fstype: &[u8], flags: libc::c_ulong, data: Option<&[u8]>) -> i32 {
    let (s, t, f) = (cstring(source), cstring(target), cstring(fstype));
    let d = data.map(cstring);
    // SAFETY: valid C strings; data may be null.
    unsafe {
        libc::mount(
            s.as_ptr(),
            t.as_ptr(),
            f.as_ptr(),
            flags,
            d.as_ref().map_or(std::ptr::null(), |d| d.as_ptr().cast()),
        )
    }
}

/// `umount2(path, flags)`.
pub fn umount2(path: &[u8], flags: c_int) -> i32 {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::umount2(p.as_ptr(), flags) }
}

/// `chmod(path, mode)`.
pub fn chmod(path: &[u8], mode: u32) -> i32 {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::chmod(p.as_ptr(), mode) }
}

/// `umask(mask)`: the old mask.
pub fn umask(mask: u32) -> u32 {
    // SAFETY: umask can't fail.
    unsafe { libc::umask(mask) }
}

/// `mkfifo(path, mode)`.
pub fn mkfifo(path: &[u8], mode: u32) -> i32 {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::mkfifo(p.as_ptr(), mode) }
}

/// `link(old, new)`.
pub fn link(old: &[u8], new: &[u8]) -> i32 {
    let (o, n) = (cstring(old), cstring(new));
    // SAFETY: valid C strings.
    unsafe { libc::link(o.as_ptr(), n.as_ptr()) }
}

/// `open(path, flags | O_CLOEXEC, mode)` (`open_fd_mode()`).
pub fn open_mode(path: &[u8], flags: c_int, mode: u32) -> Fd {
    let p = cstring(path);
    // SAFETY: p is a valid C string.
    unsafe { libc::open(p.as_ptr(), flags | libc::O_CLOEXEC, mode) }
}

/// `lseek(fd, 0, SEEK_SET)`.
pub fn rewind(fd: Fd) -> i64 {
    // SAFETY: plain call.
    unsafe { libc::lseek(fd, 0, libc::SEEK_SET) }
}

/// `getpid()`.
pub fn getpid() -> i32 {
    // SAFETY: plain call.
    unsafe { libc::getpid() }
}

/// `fork()`.
pub fn fork() -> i32 {
    // SAFETY: called while the process has one thread (become_daemon()).
    unsafe { libc::fork() }
}

/// `setsid()`.
pub fn setsid() -> i32 {
    // SAFETY: plain call.
    unsafe { libc::setsid() }
}

/// `dup2(old, new)`.
pub fn dup2(old: Fd, new: Fd) -> i32 {
    // SAFETY: plain call.
    unsafe { libc::dup2(old, new) }
}

/// `sched_yield()`.
pub fn sched_yield() {
    // SAFETY: plain call.
    unsafe { libc::sched_yield() };
}

/// `nanosleep()` of `ns` nanoseconds, resumed after signals as autofs does.
pub fn sleep_ns(ns: i64) {
    let mut t = libc::timespec { tv_sec: ns / 1_000_000_000, tv_nsec: ns % 1_000_000_000 };
    loop {
        let mut r = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: valid timespecs.
        if unsafe { libc::nanosleep(&t, &mut r) } == -1 && errno() == libc::EINTR {
            t = r;
            continue;
        }
        break;
    }
}

/// One `nanosleep()` of `ns` nanoseconds: -1 if a signal interrupted it.
pub fn nanosleep_once(ns: i64) -> i32 {
    let t = libc::timespec { tv_sec: ns / 1_000_000_000, tv_nsec: ns % 1_000_000_000 };
    // SAFETY: valid timespec; the remainder isn't wanted.
    unsafe { libc::nanosleep(&t, std::ptr::null_mut()) }
}

/// `fstatfs(fd).f_type`.
pub fn fstatfs_type(fd: Fd) -> Option<i64> {
    // SAFETY: zeroed statfs is a valid out buffer.
    let mut fs: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid arguments.
    if unsafe { libc::fstatfs(fd, &mut fs) } != 0 {
        return None;
    }
    Some(fs.f_type as i64)
}

/// A signal set.
pub fn sigset(sigs: &[c_int]) -> libc::sigset_t {
    // SAFETY: plain signal set calls.
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut s);
        for &g in sigs {
            libc::sigaddset(&mut s, g);
        }
        s
    }
}

/// Every signal but `except`.
pub fn sigset_all_but(except: &[c_int]) -> libc::sigset_t {
    // SAFETY: plain signal set calls.
    unsafe {
        let mut s: libc::sigset_t = std::mem::zeroed();
        libc::sigfillset(&mut s);
        for &g in except {
            libc::sigdelset(&mut s, g);
        }
        s
    }
}

/// `pthread_sigmask(how, set, &old)`: the old mask.
pub fn sigmask(how: c_int, set: &libc::sigset_t) -> libc::sigset_t {
    // SAFETY: valid sigsets.
    unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(how, set, &mut old);
        old
    }
}

/// The calling thread's signal mask.
pub fn current_sigmask() -> libc::sigset_t {
    // SAFETY: a null set queries the mask.
    unsafe {
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut old);
        old
    }
}

extern "C" fn dummy_handler(_sig: c_int) {}

/// `sigaction(sig, {dummy handler, empty mask, no flags})`.
pub fn set_dummy_handler(sig: c_int) -> i32 {
    // SAFETY: an initialized sigaction with a handler that does nothing.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = dummy_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(sig, &sa, std::ptr::null_mut())
    }
}

/// `sigwait(set)`: the signal.
pub fn sigwait(set: &libc::sigset_t) -> c_int {
    let mut sig: c_int = 0;
    // SAFETY: valid set and out pointer.
    unsafe { libc::sigwait(set, &mut sig) };
    sig
}

/// `ppoll(&{fd, POLLIN}, 1, NULL, mask)`: the result, the events, errno.
pub fn ppoll_in(fd: Fd, mask: &libc::sigset_t) -> (i32, i16, i32) {
    let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    set_errno(0);
    // SAFETY: one valid pollfd, a valid mask.
    let r = unsafe { libc::ppoll(&mut p, 1, std::ptr::null(), mask) };
    (r, p.revents, errno())
}

/// `pthread_self()`.
pub fn pthread_self() -> u64 {
    // SAFETY: plain call.
    unsafe { libc::pthread_self() as u64 }
}

/// `pthread_kill(thread, sig)`.
pub fn pthread_kill(thread: u64, sig: c_int) -> i32 {
    // SAFETY: the thread id comes from pthread_self() of a live thread.
    unsafe { libc::pthread_kill(thread as libc::pthread_t, sig) }
}

/// `read()` until `buf` is full or an error (`fullread()`): what's left.
pub fn fullread(fd: Fd, buf: &mut [u8]) -> usize {
    let mut off = 0;
    while off < buf.len() {
        // SAFETY: the slice is valid for the length given.
        let r = unsafe { libc::read(fd, buf[off..].as_mut_ptr().cast(), buf.len() - off) };
        if r == -1 {
            if errno() == libc::EINTR {
                continue;
            }
            break;
        }
        off += r as usize;
    }
    buf.len() - off
}

/// `scandir(dir, ..., alphasort)` names (C locale), including `.` and `..`.
pub fn scandir_alpha(dir: &[u8]) -> Option<Vec<Vec<u8>>> {
    let d = cstring(dir);
    // SAFETY: opendir/readdir/closedir on a valid C string; names are copied.
    unsafe {
        let dp = libc::opendir(d.as_ptr());
        if dp.is_null() {
            return None;
        }
        let mut out = Vec::new();
        loop {
            let e = libc::readdir(dp);
            if e.is_null() {
                break;
            }
            out.push(CStr::from_ptr((*e).d_name.as_ptr()).to_bytes().to_vec());
        }
        libc::closedir(dp);
        out.sort();
        Some(out)
    }
}

/// `uname().release`.
pub fn uname_release() -> Vec<u8> {
    // SAFETY: zeroed utsname is a valid out buffer.
    let mut u: libc::utsname = unsafe { std::mem::zeroed() };
    // SAFETY: valid out pointer.
    unsafe { libc::uname(&mut u) };
    // SAFETY: uname NUL-terminates.
    unsafe { CStr::from_ptr(u.release.as_ptr()).to_bytes().to_vec() }
}

/// `write(fd, buf)`, all of it or -1.
pub fn write_all(fd: Fd, buf: &[u8]) -> isize {
    // SAFETY: the slice is valid for its length.
    unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) }
}

/// `kill(pid, 0)`: 0, or -1 with errno.
pub fn kill0(pid: i32) -> i32 {
    // SAFETY: signal 0 only checks.
    unsafe { libc::kill(pid, 0) }
}

/// `struct autofs_v5_packet` (linux/auto_fs4.h): 304 bytes on x86_64.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AutofsV5Packet {
    pub proto_version: i32,
    pub ty: i32,
    pub wait_queue_token: u32,
    pub dev: u32,
    pub ino: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub tgid: u32,
    pub len: u32,
    pub name: [u8; 256],
}

impl std::fmt::Debug for AutofsV5Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "packet type {} token {}", self.ty, self.wait_queue_token)
    }
}

impl AutofsV5Packet {
    pub fn zeroed() -> AutofsV5Packet {
        // SAFETY: plain integers and bytes.
        unsafe { std::mem::zeroed() }
    }

    /// The name, `len` bytes (as `strncpy(name, pkt->name, pkt->len)` reads it).
    pub fn name_bytes(&self) -> &[u8] {
        let l = (self.len as usize).min(self.name.len());
        crate::libautofs::cstr::c(&self.name[..l])
    }

    /// The packet as bytes, to read into.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: a repr(C) struct of plain fields.
        unsafe { std::slice::from_raw_parts_mut(self as *mut Self as *mut u8, std::mem::size_of::<Self>()) }
    }
}

/// `mount(NULL, target, NULL, flags, NULL)` (a propagation change).
pub fn mount_flags_only(target: &[u8], flags: libc::c_ulong) -> i32 {
    let t = cstring(target);
    // SAFETY: a valid target; the rest may be null for a propagation change.
    unsafe { libc::mount(std::ptr::null(), t.as_ptr(), std::ptr::null(), flags, std::ptr::null()) }
}
