//! `daemon/automount.c`: `main()` (the configuration, `mount.nfs`'s version,
//! the options, the root check, the kernel protocol probe, the open file
//! limit, the macros, `-m`/`--dumpmaps`) and the daemon: daemonizing, the
//! signal handler, the command FIFO, the mount handler threads, unmounting
//! and expiring.

use std::sync::atomic::{AtomicU32, Ordering};

use crate::daemon::master::{self, DAEMON_FLAGS_CHECK_DAEMON, DAEMON_FLAGS_DUMP_MAPS, DAEMON_FLAGS_FOREGROUND};
use crate::daemon::master::{DAEMON_FLAGS_GHOST, DAEMON_FLAGS_HAVE_GLOBAL_OPTIONS, DAEMON_FLAGS_SYSTEMD_SERVICE};
use crate::daemon::{lookup, master_parse};
use crate::libautofs::cache::Cache;
use crate::libautofs::cstr;
use crate::libautofs::defaults::{self, AUTOFS_CONF_DIR, AUTOFS_LIB_DIR, AUTOFS_MAP_DIR};
use crate::libautofs::log::{self, LOGOPT_DEBUG, LOGOPT_VERBOSE};
use crate::libautofs::macros;
use crate::libautofs::mounts;
use crate::sys;

const VERSION: &[u8] = b"5.1.9";
const PATH_MOUNT_NFS: &[u8] = b"/usr/bin/mount.nfs";

/// `nfs_mount_uses_string_options`.
pub static NFS_MOUNT_USES_STRING_OPTIONS: AtomicU32 = AtomicU32::new(0);

fn print(s: &[u8]) {
    log::print(s);
}

/// `usage()`.
fn usage(program: &[u8]) {
    log::eprint(&bfmt!(
        "Usage: {} [options] [master_map_name]\n\
\t-h --help\tthis text\n\
\t-p --pid-file f write process id to file f\n\
\t-t --timeout n\tauto-unmount in n seconds (0-disable)\n\
\t-M --master-wait n\n\
\t\t\tmaximum wait time (seconds) for master\n\
\t\t\tmap to become available\n\
\t-v --verbose\tbe verbose\n\
\t-d[level]\n\
\t--debug[=level]\n\
\t\t\tlog debugging info\n\
\t-Dvariable=value, --define variable=value\n\
\t\t\tdefine global macro variable\n\
\t-S --systemd-service\n\
\t\t\trun automounter as a systemd service\n\
\t-f --foreground do not fork into background\n\
\t-r --random-multimount-selection\n\
\t\t\tuse random replicated server selection\n\
\t-m --dumpmaps [<map type> <map name>]\n\
\t\t\tdump automounter maps and exit\n\
\t-n --negative-timeout n\n\
\t\t\tset the timeout for failed key lookups.\n\
\t-P --positive-timeout n\n\
\t\t\tset the positive timeout for key lookups.\n\
\t-O --global-options\n\
\t\t\tspecify global mount options\n\
\t-l --set-log-priority priority path [path,...]\n\
\t\t\tset daemon log verbosity\n\
\t-C --dont-check-daemon\n\
\t\t\tdon't check if daemon is already running\n\
\t-F --force\tforceably clean up known automounts at start\n\
\t-U --force-exit\tforceably clean up known automounts and exit\n\
\t-V --version\tprint version, build config and exit\n",
        program
    ));
}

/// `show_build_info()`, for this build's options.
fn show_build_info() {
    print(&bfmt!("\nLinux automount version {}\n", VERSION));
    print(b"\nDirectories:\n");
    print(&bfmt!("\tconfig dir:\t{}\n", AUTOFS_CONF_DIR));
    print(&bfmt!("\tmaps dir:\t{}\n", AUTOFS_MAP_DIR));
    print(&bfmt!("\tmodules dir:\t{}\n", AUTOFS_LIB_DIR));
    print(b"\nCompile options:\n  ");
    // DISABLE_MOUNT_LOCKING (22), ENABLE_FORCED_SHUTDOWN (+23),
    // ENABLE_IGNORE_BUSY_MOUNTS (+26: over 60, so a new line),
    // LIBXML2_WORKAROUND (config.h defines it even without LDAP),
    // WITH_LIBTIRPC.
    print(b"DISABLE_MOUNT_LOCKING ");
    print(b"ENABLE_FORCED_SHUTDOWN ");
    print(b"ENABLE_IGNORE_BUSY_MOUNTS ");
    print(b"\n  ");
    print(b"LIBXML2_WORKAROUND ");
    print(b"WITH_LIBTIRPC ");
    print(b"\n\n");
}

/// `convert_log_priority()`.
fn convert_log_priority(name: &[u8]) -> i32 {
    const NAMES: [(&[u8], i32); 11] = [
        (b"alert", libc::LOG_ALERT),
        (b"crit", libc::LOG_CRIT),
        (b"debug", libc::LOG_DEBUG),
        (b"emerg", libc::LOG_EMERG),
        (b"err", libc::LOG_ERR),
        (b"error", libc::LOG_ERR),
        (b"info", libc::LOG_INFO),
        (b"notice", libc::LOG_NOTICE),
        (b"panic", libc::LOG_EMERG),
        (b"warn", libc::LOG_WARNING),
        (b"warning", libc::LOG_WARNING),
    ];
    NAMES.iter().find(|(n, _)| cstr::caseeq(name, n)).map_or(-1, |(_, v)| *v)
}

/// `remove_empty_args()`.
fn remove_empty_args(argv: &mut Vec<Vec<u8>>) {
    let argc = argv.len();
    if argc == 0 {
        return;
    }
    let next_to_last = argc as isize - 1;
    let mut j = 1usize;
    let mut i = 1usize;
    while i < argc {
        if !argv[i].is_empty() {
            j += 1;
            i += 1;
            continue;
        }
        while i < argc && argv[i].is_empty() {
            i += 1;
        }
        if i == argc {
            break;
        }
        if i as isize == next_to_last {
            if !argv[i].is_empty() {
                argv[j] = argv[i].clone();
                j += 1;
            }
            break;
        } else {
            argv[j] = argv[i].clone();
            j += 1;
            argv[i] = Vec::new();
            // i-- then the loop's i++
        }
    }
    argv.truncate(j);
}

/// `getnumopt()`.
fn getnumopt(program: &[u8], s: &[u8], opt: u8) -> u64 {
    let (v, used) = cstr::strtoul(s, 0);
    if s.is_empty() || used != s.len() {
        let o = [opt];
        log::eprint(&bfmt!("{}: option -{} requires a numeric argument, got {}\n", program, &o[..], s));
        sys::exit(1);
    }
    v
}

/// `getsnumopt()`.
fn getsnumopt(program: &[u8], s: &[u8], opt: u8) -> i64 {
    let (v, used) = cstr::strtol(s, 0);
    if s.is_empty() || used != s.len() {
        let o = [opt];
        log::eprint(&bfmt!("{}: option -{} requires a numeric argument, got {}\n", program, &o[..], s));
        sys::exit(1);
    }
    v
}

/// `extract_version()`: `nfs-utils` then a space and `major.minor.fix`.
fn extract_version(start: &[u8]) -> Option<(u32, u32, u32)> {
    let sp = cstr::strchr(start, b' ')?;
    let mut s = &start[sp..];
    // C's loop runs once: it steps past the space, gives up at the end.
    if !s.is_empty() && !cstr::isdigit(s[0]) {
        s = &s[1..];
        if s.is_empty() {
            return None;
        }
    }
    let mut toks = s.split(|&b| b == b'.').filter(|t| !t.is_empty());
    let mut next = || toks.next().map_or(0, cstr::atoi);
    Some((next() as u32, next() as u32, next() as u32))
}

/// `check_nfs_mount_version()` against 1.1.1.
///
/// QUIRK: output lines that end in a newline are dropped unread; the version
/// is only looked for in a line that fills the buffer or ends the output
/// without a newline, so with `mount.nfs` as it is this returns 0.
fn check_nfs_mount_version() -> u32 {
    let Ok((pr, pw)) = sys::pipe_cloexec() else {
        logerr!("open_pipe", "161", "failed to open pipe: {}", sys::strerror(sys::errno()));
        return u32::MAX;
    };
    let old = sys::block_all_signals();
    let argv = vec![PATH_MOUNT_NFS.to_vec(), b"-V".to_vec()];
    let f = sys::spawn(PATH_MOUNT_NFS, &argv, pr, pw, &sys::ChildPrep::None);
    sys::mask_with_sigchld(&old);
    sys::close(pw);
    if f < 0 {
        sys::close(pr);
        sys::set_sigmask(&old);
        return u32::MAX;
    }
    const EBUFSIZ: usize = 1024;
    // The buffer as C cuts it: lines end at a NUL where their newline was,
    // and the version is looked for in it (a C string from the start) after
    // every read, so a line just cut counts too.
    let mut errbuf = vec![0u8; EBUFSIZ + 1];
    let mut errp = 0usize;
    let mut found: Option<(u32, u32, u32)> = None;
    let look = |buf: &[u8], found: &mut Option<(u32, u32, u32)>| {
        let line = cstr::c(buf);
        if let Some(at) = cstr::strstr(line, b"nfs-utils")
            && let Some(v) = extract_version(&line[at..])
        {
            *found = Some(v);
        }
    };
    loop {
        let n = loop {
            let n = sys::read(pr, &mut errbuf[errp..EBUFSIZ]);
            if n == -1 && sys::errno() == libc::EINTR {
                continue;
            }
            break n;
        };
        if n > 0 {
            errp += n as usize;
            let mut sp = 0;
            while errp > 0 {
                let Some(nl) = errbuf[sp..sp + errp].iter().position(|&b| b == b'\n') else { break };
                errbuf[sp + nl] = 0;
                errp -= nl + 1;
                sp += nl + 1;
            }
            if errp > 0 && sp != 0 {
                errbuf.copy_within(sp..sp + errp, 0);
            }
            if errp >= EBUFSIZ {
                // A line too long: split it.
                errbuf[errp] = 0;
                look(&errbuf, &mut found);
                errp = 0;
            }
            look(&errbuf, &mut found);
        }
        if n <= 0 {
            break;
        }
    }
    sys::close(pr);
    if errp > 0 {
        // End of file without a newline.
        errbuf[errp] = 0;
        look(&errbuf, &mut found);
    }
    let mut ret = found.is_some() as u32;
    if let Some((maj, min, fix)) = found
        && (maj < 1 || (maj == 1 && min < 1) || (maj == 1 && min == 1 && fix < 1))
    {
        ret = 0;
    }
    if sys::waitpid(f).0 != f {
        debug!(log::LOGOPT_NONE, "check_nfs_mount_version", "no process found to wait for");
    }
    sys::set_sigmask(&old);
    ret
}

pub fn main() {
    // The master map's age is the second the program started.
    let start_age = sys::monotonic_time();
    sys::block_all_but_core_signals();
    let mut argv: Vec<Vec<u8>> = {
        use std::os::unix::ffi::OsStringExt;
        std::env::args_os().map(|a| a.into_vec()).collect()
    };
    let program = argv.first().cloned().unwrap_or_default();

    if !defaults::defaults_read_config(false) {
        print(&bfmt!("{}: failed to read configuration, exiting", program));
        sys::exit(1);
    }
    NFS_MOUNT_USES_STRING_OPTIONS.store(check_nfs_mount_version(), Ordering::Relaxed);
    init_kpkt_len();

    let mut flags = if defaults::defaults_get_browse_mode() != 0 { DAEMON_FLAGS_GHOST } else { 0 };
    flags |= DAEMON_FLAGS_CHECK_DAEMON;
    let mut _master_wait = defaults::defaults_get_master_wait();
    let mut timeout = defaults::defaults_get_timeout() as u64;
    let mut logging = defaults::defaults_get_logging();
    let mut debug_level: i64 = 0;
    let mut logpri: i32 = -1;
    {
        let mut g = master::GLOBALS.lock().unwrap();
        g.selection_options = 0;
        g.global_options = None;
    }

    remove_empty_args(&mut argv);

    let longs: [(&'static std::ffi::CStr, i32, u8); 19] = [
        (c"help", 0, b'h'),
        (c"pid-file", 1, b'p'),
        (c"timeout", 1, b't'),
        (c"verbose", 0, b'v'),
        (c"debug", 2, b'd'),
        (c"define", 1, b'D'),
        (c"systemd-service", 0, b'S'),
        (c"foreground", 0, b'f'),
        (c"random-multimount-selection", 0, b'r'),
        (c"negative-timeout", 1, b'n'),
        (c"positive-timeout", 1, b'P'),
        (c"dumpmaps", 0, b'm'),
        (c"global-options", 1, b'O'),
        (c"version", 0, b'V'),
        (c"set-log-priority", 1, b'l'),
        (c"dont-check-daemon", 0, b'C'),
        (c"force", 0, b'F'),
        (c"force-exit", 0, b'U'),
        (c"master-wait", 1, b'M'),
    ];
    let (opts, operands) = sys::getopt_long(&argv, c"+hp:t:vmd::D:SfVrO:l:n:P:CFUM:", &longs);
    for (opt, optarg) in opts {
        let arg = optarg.clone().unwrap_or_default();
        match opt as u8 {
            b'h' => {
                usage(&program);
                sys::exit(0);
            }
            b'p' => set_pid_file(arg),
            b't' => timeout = getnumopt(&program, &arg, b't'),
            b'v' => logging |= LOGOPT_VERBOSE,
            b'd' => {
                logging |= LOGOPT_DEBUG;
                if optarg.is_some() {
                    debug_level = getsnumopt(&program, &arg, b'd');
                }
            }
            b'D' => {
                macros::macro_parse_globalvar(&arg);
            }
            b'S' => flags |= DAEMON_FLAGS_SYSTEMD_SERVICE,
            b'f' => flags |= DAEMON_FLAGS_FOREGROUND,
            b'V' => {
                show_build_info();
                sys::exit(0);
            }
            b'r' => master::GLOBALS.lock().unwrap().selection_options |= master::MOUNT_FLAG_RANDOM_SELECT,
            b'n' => master::GLOBALS.lock().unwrap().negative_timeout = getnumopt(&program, &arg, b'n') as i64,
            b'P' => master::GLOBALS.lock().unwrap().positive_timeout = getnumopt(&program, &arg, b'P') as i64,
            b'm' => flags |= DAEMON_FLAGS_DUMP_MAPS,
            b'M' => _master_wait = getnumopt(&program, &arg, b'M') as i32,
            b'O' => {
                if flags & DAEMON_FLAGS_HAVE_GLOBAL_OPTIONS == 0 {
                    master::GLOBALS.lock().unwrap().global_options = Some(arg);
                    flags |= DAEMON_FLAGS_HAVE_GLOBAL_OPTIONS;
                } else {
                    print(&bfmt!("{}: global options already specified.\n", program));
                }
            }
            b'l' => {
                if cstr::isalpha(arg.first().copied().unwrap_or(0)) {
                    logpri = convert_log_priority(&arg);
                    if logpri < 0 {
                        log::eprint(&bfmt!("Invalid log priority: {}\n", arg));
                        sys::exit(1);
                    }
                } else if cstr::isdigit(arg.first().copied().unwrap_or(0)) {
                    logpri = getnumopt(&program, &arg, b'l') as i32;
                } else {
                    log::eprint(b"non-alphanumeric character found in log priority.  Aborting.\n");
                    sys::exit(1);
                }
            }
            b'C' => flags &= !DAEMON_FLAGS_CHECK_DAEMON,
            b'F' => DO_FORCE_UNLINK.store(UNLINK_AND_CONT, Ordering::Relaxed),
            b'U' => {
                flags |= DAEMON_FLAGS_FOREGROUND;
                DO_FORCE_UNLINK.store(UNLINK_AND_EXIT, Ordering::Relaxed);
            }
            _ => {
                log::eprint(&bfmt!("{}: Ambiguous or unknown options\n", program));
                log::eprint(&bfmt!("Try `{} --help` for more information\n", program));
                sys::exit(1);
            }
        }
    }

    if logging & LOGOPT_VERBOSE != 0 {
        log::set_log_verbose();
    }
    if logging & LOGOPT_DEBUG != 0 {
        log::set_log_debug(debug_level as u32);
    }

    if sys::geteuid() != 0 {
        log::eprint(&bfmt!("{}: this program must be run by root.\n", program));
        sys::exit(1);
    }

    if logpri >= 0 {
        let code = set_log_priorities(&operands, logpri);
        log::flush_stdout();
        sys::exit(code);
    }

    // Don't need the kernel module just to look at the configured maps.
    if flags & DAEMON_FLAGS_DUMP_MAPS == 0 && (!mounts::query_kproto_ver() || mounts::get_kver_major() < 5) {
        log::eprint(&bfmt!(
            "{}: test mount forbidden or incorrect kernel protocol version, kernel protocol version 5.00 or above required.\n",
            program
        ));
        sys::exit(1);
    }

    let max_open_files = defaults::defaults_get_open_file_limit();
    let (mut cur, mut max) = sys::get_nofile().unwrap_or((0, 0));
    if cur <= max_open_files {
        cur = max_open_files;
        if max < max_open_files {
            max = max_open_files;
        }
    }
    if sys::set_nofile(cur, max) != 0 {
        print(&bfmt!("{}: can't increase open file limit - continuing", program));
    }
    // ENABLE_CORES (automount.h defines it).
    if sys::set_core_unlimited() != 0 {
        print(&bfmt!("{}: can't increase core file limit - continuing", program));
    }

    macros::macro_init();

    if flags & DAEMON_FLAGS_DUMP_MAPS != 0 {
        let (ty, name, master_name) = match operands.len() {
            0 | 1 => (None, None, None),
            2 => (Some(operands[0].clone()), Some(operands[1].clone()), None),
            _ => (
                Some(operands[0].clone()),
                Some(operands[1].clone()),
                if operands.len() == 3 { Some(operands[2].clone()) } else { None },
            ),
        };
        // QUIRK: a master map name given as the third operand is ignored (both
        // branches pass NULL).
        let _ = &master_name;
        let ml = master::master_new(None, timeout as u32, flags);
        *master::MASTER_LIST.lock().unwrap() = Some(ml.clone());
        log::log_to_stderr();
        master_parse::master_init_scan();
        ml.lock().nc = Some(std::sync::Arc::new(Cache::init_null()));
        lookup::lookup_nss_read_master(&ml, 0);
        match (ty, name) {
            (Some(t), Some(n)) => {
                let map = cstr::gnu_basename(&n).to_vec();
                master::dump_map(&ml, &t, &map);
            }
            _ => {
                master::master_show_mounts(&ml);
            }
        }
        for entry in ml.mounts() {
            master::master_free_mapent_sources(&entry);
        }
        macros::macro_free_global_table();
        sys::exit(0);
    }

    let master_name = operands.first().cloned();
    run_daemon(&program, master_name.as_deref(), timeout as u32, flags, logging, _master_wait, start_age);
}

const AUTOFS_SUPER_MAGIC: i64 = 0x0187;
const PATH_MAX: usize = 4096;

/// `rmdir_path()`: remove as much of `path` as lies in the autofs file system
/// on `dev`.
///
/// QUIRK: when the last component is a symbolic link it's unlinked, but the
/// call still fails.
pub fn rmdir_path(ap: &std::sync::Arc<master::AutofsPoint>, path: &[u8], dev: u64) -> i32 {
    let logopt = ap.logopt();
    let path = cstr::c(path);
    if path.len() > PATH_MAX {
        error!(logopt, "rmdir_path", "path longer than maximum length");
        return -1;
    }
    let mut buf = path.to_vec();
    let mut first = true;
    loop {
        let Some(st) = sys::lstat(&buf) else {
            crit!(logopt, "rmdir_path", "lstat of {} failed", buf);
            return -1;
        };
        if st.st_dev != dev {
            return 0;
        }
        let Some(f_type) = sys::statfs_type(&buf) else {
            error!(logopt, "rmdir_path", "could not stat fs of {}", buf);
            return -1;
        };
        if f_type != AUTOFS_SUPER_MAGIC {
            crit!(logopt, "rmdir_path", "attempt to remove directory from a non-autofs filesystem!");
            crit!(logopt, "rmdir_path", "requester dev == {}, \"{}\" owner dev == {}", dev, buf, st.st_dev);
            return -1;
        }
        if sys::rmdir(&buf) == -1 {
            if first && sys::errno() == libc::ENOTDIR {
                if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
                    if sys::unlink(&buf) == -1 {
                        return -1;
                    }
                } else {
                    crit!(
                        logopt,
                        "rmdir_path",
                        "file \"{}\" is neither a directory nor a symbolic link. mode {}",
                        buf,
                        st.st_mode
                    );
                    return -1;
                }
            }
            return -1;
        }
        first = false;
        match cstr::strrchr(&buf, b'/') {
            Some(cp) if cp != 0 => buf.truncate(cp),
            _ => break,
        }
    }
    0
}

// ---------------------------------------------------------------------------
// The daemon.

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicU64};

use crate::daemon::indirect;
use crate::daemon::master::{AutofsPoint, LKP_INDIRECT, MOUNT_FLAG_DIR_CREATED, MOUNT_FLAG_GHOST, MOUNT_FLAG_NOBIND};
use crate::daemon::state::{self, ST_INIT, ST_READMAP, ST_READY, ST_SHUTDOWN, ST_SHUTDOWN_FORCE, ST_SHUTDOWN_PENDING};
use crate::libautofs::alarm;
use crate::libautofs::dev_ioctl;
use crate::libautofs::log::LOGOPT_ANY;

pub const UNLINK_AND_CONT: i32 = 0x01;
pub const UNLINK_AND_EXIT: i32 = 0x02;
/// `mp_mode`.
pub const MP_MODE: u32 = 0o755;
/// `do_force_unlink`.
pub static DO_FORCE_UNLINK: AtomicI32 = AtomicI32::new(0);
static PID_FILE: std::sync::Mutex<Option<Vec<u8>>> = std::sync::Mutex::new(None);
static START_PIPE_W: AtomicI32 = AtomicI32::new(-1);
static SIGNAL_HANDLER_THID: AtomicU64 = AtomicU64::new(0);
/// `struct autofs_v5_packet`'s size on this kernel (`get_kpkt_len()`).
static KPKT_LEN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

const NFS_SUPER_MAGIC: i64 = 0x6969;
const SMB_SUPER_MAGIC: i64 = 0x517B;
const CIFS_MAGIC_NUMBER: i64 = 0xFF534D42;
const NCP_SUPER_MAGIC: i64 = 0x564c;

/// The mutex of `struct master_readmap_cond mrc`, and its handshake state.
static MRC: crate::libautofs::csync::CMutex = crate::libautofs::csync::CMutex::new();
static MRC_COND: crate::libautofs::csync::CCond = crate::libautofs::csync::CCond::new();
static MRC_SIGNALED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// `sdbm_hash()`.
fn sdbm_hash(s: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for &c in cstr::c(s) {
        // C's `char` is signed.
        let c = c as i8 as i64 as u64;
        hash = c.wrapping_add(hash << 6).wrapping_add(hash << 16).wrapping_sub(hash);
    }
    hash
}

/// `set_thread_mount_request_log_id()`.
pub fn set_thread_mount_request_log_id(token: u32, pid: u32, name: &[u8]) {
    if defaults::defaults_get_use_mount_request_log_id() == 0 || log::has_attempt_id() {
        return;
    }
    let mut id = sdbm_hash(format!("{}", token as i64).as_bytes(), 0);
    id = sdbm_hash(format!("{pid}").as_bytes(), id);
    id = sdbm_hash(name, id);
    log::set_attempt_id(id);
}

/// `log_pidinfo()` (lib/log.c): log a process from `/proc/PID/status` (with
/// `mount_verbose`); its parent's pid, or -1.
pub fn log_pidinfo(ap: &Arc<AutofsPoint>, pid: u32, label: &str) -> i32 {
    let logopt = ap.logopt();
    let path = format!("/proc/{}/status", pid as i32);
    let Ok(data) = sys::read_file(path.as_bytes()) else {
        info!(logopt, "pidinfo {}: failed to open {}", label, path);
        return -1;
    };
    let (mut comm, mut tgid, mut ppid, mut uid, mut euid, mut gid, mut egid) = (Vec::new(), 0, 0, 0, 0, 0, 0);
    // sscanf("%d") of each field after its tab.
    let nums = |rest: &[u8]| -> Vec<i32> {
        rest.split(|&c| c == b'\t' || c == b' ' || c == b'\n').filter(|f| !f.is_empty()).map(cstr::atoi).collect()
    };
    for line in data.split(|&c| c == b'\n') {
        if let Some(r) = line.strip_prefix(b"Name:") {
            comm = r.split(|&c| c == b'\t' || c == b' ').find(|f| !f.is_empty()).unwrap_or(b"").to_vec();
        } else if let Some(r) = line.strip_prefix(b"Tgid:") {
            tgid = nums(r).first().copied().unwrap_or(tgid);
        } else if let Some(r) = line.strip_prefix(b"PPid:") {
            ppid = nums(r).first().copied().unwrap_or(ppid);
        } else if let Some(r) = line.strip_prefix(b"Uid:") {
            let n = nums(r);
            uid = n.first().copied().unwrap_or(uid);
            euid = n.get(1).copied().unwrap_or(euid);
        } else if let Some(r) = line.strip_prefix(b"Gid:") {
            let n = nums(r);
            gid = n.first().copied().unwrap_or(gid);
            egid = n.get(1).copied().unwrap_or(egid);
        }
    }
    info!(
        logopt,
        "pidinfo {}: pid:{} comm:{} tgid:{} uid:{} euid:{} gid:{} egid:{}",
        label,
        pid as i32,
        comm,
        tgid,
        uid,
        euid,
        gid,
        egid
    );
    ppid
}

fn is_remote_fstype(t: i64) -> bool {
    matches!(t, SMB_SUPER_MAGIC | CIFS_MAGIC_NUMBER | NCP_SUPER_MAGIC | NFS_SUPER_MAGIC)
}

/// `do_mkdir()`: 1 if it made `path`; 0 with `errno` set if it exists or
/// couldn't be made (`EACCES`).
fn do_mkdir(parent: &[u8], path: &[u8], mode: u32) -> bool {
    if let Some(st) = sys::stat(path) {
        sys::set_errno(if st.st_mode & libc::S_IFMT != libc::S_IFDIR { libc::ENOTDIR } else { libc::EEXIST });
        return false;
    }
    let fail = || {
        sys::set_errno(libc::EACCES);
        false
    };
    // Not on a remote file system unless it's the root file system.
    if !parent.is_empty() {
        let Some(t) = sys::statfs_type(parent) else { return fail() };
        if is_remote_fstype(t) {
            let Some(st) = sys::stat(parent) else { return fail() };
            let Some(root) = sys::stat(b"/") else { return fail() };
            if st.st_dev != root.st_dev {
                return fail();
            }
        }
    }
    let mask = sys::umask(0o022);
    let status = sys::mkdir(path, mode);
    sys::umask(mask);
    if status == -1 {
        return fail();
    }
    true
}

/// `mkdir_path()`: each missing component of `path`; 0, or -1 with `errno`.
pub fn mkdir_path(path: &[u8], mode: u32) -> i32 {
    let path = cstr::c(path);
    let mut parent: Vec<u8> = Vec::new();
    let mut lcp = 0usize;
    let mut i = 0usize;
    loop {
        let at_end = i == path.len();
        if i != 0 && (at_end || path[i] == b'/') {
            let buf = &path[..i];
            if !do_mkdir(&parent, buf, mode) {
                if !at_end {
                    parent.extend_from_slice(&path[lcp..i]);
                    lcp = i;
                    i += 1;
                    continue;
                }
                return -1;
            }
            parent.extend_from_slice(&path[lcp..i]);
            lcp = i;
        }
        if at_end {
            break;
        }
        i += 1;
    }
    0
}

/// `walk_tree()`: `f(file, stat, when)` before (0) and after (1) a directory's
/// entries; a directory is entered when the first call returns true. A mount
/// point is passed without a `stat`.
/// `walk_tree()`'s callback: (file, its stat unless a mount point, before 0 / after 1).
type WalkFn<'a> = dyn FnMut(&[u8], Option<&libc::stat>, i32) -> bool + 'a;

fn walk_tree(base: &[u8], f: &mut WalkFn<'_>, incl: bool) -> i32 {
    let st = if !mounts::is_mounted(base, mounts::MNTS_REAL) {
        match sys::lstat(base) {
            Some(st) => Some(st),
            None => return 0,
        }
    } else {
        None
    };
    if f(base, st.as_ref(), 0) {
        // C reads st.st_mode even for a mount point, where st is left as it was.
        if st.is_some_and(|s| s.st_mode & libc::S_IFMT == libc::S_IFDIR) {
            let Some(names) = sys::scandir_alpha(base) else { return -1 };
            for name in names.iter().rev() {
                if name == b"." || name == b".." {
                    continue;
                }
                let Some(buf) = crate::libautofs::cat_path::cat_path(4096 + 1, base, name) else { return -1 };
                walk_tree(&buf, f, true);
            }
        }
        if incl {
            f(base, st.as_ref(), 1);
        }
    }
    0
}

/// `rm_unwanted()`: remove the directories and symlinks of the autofs file
/// system under `path`.
pub fn rm_unwanted(ap: &Arc<AutofsPoint>, path: &[u8], incl: bool) {
    let logopt = ap.logopt();
    let dev = ap.lock().dev;
    let mut f = |file: &[u8], st: Option<&libc::stat>, when: i32| -> bool {
        let Some(st) = st else { return false };
        if when == 0 {
            return st.st_dev == dev;
        }
        let Some(newst) = sys::lstat(file) else {
            crit!(logopt, "rm_unwanted_fn", "unable to stat file, possible race condition");
            return false;
        };
        if newst.st_dev != dev {
            crit!(logopt, "rm_unwanted_fn", "file {} has the wrong device, possible race condition", file);
            return false;
        }
        match newst.st_mode & libc::S_IFMT {
            libc::S_IFDIR => {
                debug!(logopt, "rm_unwanted_fn", "removing directory {}", file);
                if sys::rmdir(file) != 0 {
                    warn!(logopt, "unable to remove directory {}: {}", file, sys::strerror(sys::errno()));
                    return false;
                }
            }
            libc::S_IFREG => {
                crit!(logopt, "rm_unwanted_fn", "attempting to remove files from a mounted directory. file {}", file);
                return false;
            }
            libc::S_IFLNK => {
                debug!(logopt, "rm_unwanted_fn", "removing symlink {}", file);
                sys::unlink(file);
            }
            _ => {}
        }
        true
    };
    walk_tree(path, &mut f, incl);
}

/// `count_mounts()`: mounted file systems and symlinks under `path`.
pub fn count_mounts(_ap: &Arc<AutofsPoint>, path: &[u8], dev: u64) -> i32 {
    let mut count = 0;
    let mut f = |_file: &[u8], st: Option<&libc::stat>, _when: i32| -> bool {
        match st {
            Some(st)
                if !(st.st_mode & libc::S_IFMT == libc::S_IFLNK
                    || (st.st_mode & libc::S_IFMT == libc::S_IFDIR && st.st_dev != dev)) =>
            {
                true
            }
            _ => {
                count += 1;
                false
            }
        }
    };
    if walk_tree(path, &mut f, true) == -1 {
        return -1;
    }
    count
}

/// `check_rm_dirs()`.
fn check_rm_dirs(ap: &Arc<AutofsPoint>, path: &[u8], incl: bool) {
    let (submount, flags, st, ty) = {
        let a = ap.lock();
        (a.submount, a.flags, a.state, a.ty)
    };
    // A submount shutting down leaves its mount point directories in place.
    if !incl && submount {
        return;
    }
    if flags & MOUNT_FLAG_GHOST == 0 || matches!(st, ST_SHUTDOWN_PENDING | ST_SHUTDOWN_FORCE | ST_SHUTDOWN) {
        rm_unwanted(ap, path, incl);
    } else if flags & MOUNT_FLAG_GHOST != 0 && ty == LKP_INDIRECT {
        rm_unwanted(ap, path, false);
    }
}

/// `update_map_cache()`: purge entries kept for mounts in maps that are gone.
fn update_map_cache(ap: &Arc<AutofsPoint>, path: &[u8]) {
    let key: Vec<u8> = if ap.ty() == LKP_INDIRECT {
        cstr::strrchr(path, b'/').map(|i| path[i + 1..].to_vec()).unwrap_or_default()
    } else {
        path.to_vec()
    };
    let entry = ap.entry();
    let age = entry.lock().age;
    for map in entry.maps() {
        if age <= map.lock().age {
            continue;
        }
        let mc = map.mc();
        let mut c = mc.lock();
        if let Some(p) = c.lookup_distinct(&key)
            && c.get(p).ioctlfd == -1
        {
            c.delete(&key);
        }
    }
}

/// `umount_subtree_mounts()`.
fn umount_subtree_mounts(ap: &Arc<AutofsPoint>, path: &[u8], is_autofs_fs: bool) -> i32 {
    let logopt = ap.logopt();
    let mut me = lookup::lookup_source_mapent(ap, path, true);
    if me.is_none() {
        let ind_key = cstr::strrchr(path, b'/').map(|i| path[i + 1..].to_vec()).unwrap_or_else(|| path.to_vec());
        me = lookup::lookup_source_mapent(ap, &ind_key, false);
    }
    let mut is_mm_root = false;
    let mut left = 0;
    if let Some((mc, p)) = &me {
        let (id, is_mm, key) = {
            let c = mc.lock();
            let e = c.get(*p);
            is_mm_root = e.is_mm_root();
            (e.id, e.is_mm(), e.key.clone())
        };
        if is_mm {
            if mounts::tree_mapent_umount_offsets(ap, mc, id) == 0 {
                warn!(logopt, "some offset mounts still present under {}", path);
                left += 1;
            }
            if key.len() > 4096 {
                crit!(logopt, "umount_subtree_mounts", "me->key too long for buffer");
                return 1;
            }
            let still = {
                let c = mc.lock();
                c.lookup_distinct(&key).map(|q| c.get(q).id)
            };
            // The entry went while we waited?
            if still != Some(id) {
                return 0;
            }
            let root_now = {
                let c = mc.lock();
                c.by_id(id).is_some_and(|q| c.get(q).is_mm_root())
            };
            if left == 0 && root_now && !mounts::tree_mapent_delete_offsets(ap, mc, &key) {
                warn!(logopt, "couldn't delete offset list");
                left += 1;
            }
            let amd = ap.entry().maps().first().is_some_and(|m| m.lock().flags & master::MAP_FLAG_FORMAT_AMD != 0);
            if amd {
                let mut c = mc.lock();
                if let Some(q) = c.by_id(id) {
                    c.pop_mapent(q);
                }
            }
        }
    }
    if left != 0 || is_autofs_fs {
        return left;
    }
    if !is_mm_root && mounts::is_mounted(path, mounts::MNTS_REAL) {
        debug!(logopt, "umount_subtree_mounts", "unmounting dir = {}", path);
        let st = ap.lock().state;
        if mounts::umount_ent_state(logopt, path, st) != 0 {
            warn!(logopt, "could not umount dir {}", path);
            left += 1;
            return left;
        }
        // An external mount to umount too?
        if let Some(mnt) = mounts::mnts_find_amdmount(path) {
            mounts::umount_amd_ext_mount(ap, &mnt.ext_mp.clone().unwrap_or_default());
            mounts::mnts_remove_amdmount(path);
        }
    }
    left
}

/// `umount_multi()`: unmount everything under `path` (and `path` itself with
/// `incl`); the number left mounted.
pub fn umount_multi(ap: &Arc<AutofsPoint>, path: &[u8], incl: bool) -> i32 {
    let logopt = ap.logopt();
    debug!(logopt, "umount_multi", "path {} incl {}", path, incl as i32);
    let Some(st) = sys::lstat(path) else {
        warn!(logopt, "failed to stat directory or symlink {}", path);
        return 1;
    };
    if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
        let (dev, flags) = {
            let a = ap.lock();
            (a.dev, a.flags)
        };
        if st.st_dev != dev {
            crit!(logopt, "umount_multi", "symlink {} has the wrong device, possible race condition", path);
            return 1;
        }
        debug!(logopt, "umount_multi", "removing symlink {}", path);
        if sys::unlink(path) != 0 {
            error!(logopt, "umount_multi", "failed to remove symlink {}", path);
            return 1;
        }
        // With browsing, the directory comes back.
        if flags & MOUNT_FLAG_GHOST != 0 && mkdir_path(path, MP_MODE) != 0 {
            let e = sys::errno();
            if e != libc::EEXIST {
                warn!(logopt, "mkdir_path {} failed: {}", path, sys::strerror(e));
            }
        }
        if let Some(mnt) = mounts::mnts_find_amdmount(path) {
            mounts::umount_amd_ext_mount(ap, &mnt.ext_mp.clone().unwrap_or_default());
            mounts::mnts_remove_amdmount(path);
        }
        mounts::mnts_remove_mount(path, mounts::MNTS_MOUNTED);
        return 0;
    }
    let is_autofs_fs = mounts::mnts_is_submount(path);
    let left = umount_subtree_mounts(ap, path, is_autofs_fs);
    // Delete detritus like unwanted mount points and symlinks.
    let (dev, state) = {
        let a = ap.lock();
        (a.dev, a.state)
    };
    if left == 0 && state != ST_READMAP && count_mounts(ap, path, dev) == 0 {
        update_map_cache(ap, path);
        check_rm_dirs(ap, path, incl);
    }
    left
}

/// `umount_all()`.
fn umount_all(ap: &Arc<AutofsPoint>) {
    let path = ap.path();
    let left = umount_multi(ap, &path, false);
    if left != 0 {
        warn!(ap.logopt(), "could not unmount {} dirs under {}", left, path);
    }
}

/// `umount_autofs()`.
fn umount_autofs(ap: &Arc<AutofsPoint>) -> i32 {
    if ap.lock().state == ST_INIT {
        return -1;
    }
    if ap.ty() == LKP_INDIRECT {
        umount_all(ap);
        indirect::umount_autofs_indirect(ap)
    } else {
        crate::daemon::direct::umount_autofs_direct(ap)
    }
}

/// `get_kpkt_len()`.
fn get_kpkt_len() -> usize {
    let pkt_len = std::mem::size_of::<sys::AutofsV5Packet>();
    if mounts::linux_version_code() >= (3 << 16) + (3 << 8) {
        return pkt_len;
    }
    let mut len = pkt_len;
    if !pkt_len.is_multiple_of(8) {
        let m = sys::uname().1.machine;
        if [&b"alpha"[..], b"ia64", b"x86_64", b"parisc64", b"ppc64"].iter().any(|a| m == *a) {
            len += 4;
        }
    }
    len
}

/// `get_pkt()`: wait for the next kernel packet (or `SIGCONT` at shutdown).
fn get_pkt(ap: &Arc<AutofsPoint>, pkt: &mut sys::AutofsV5Packet) -> i32 {
    if sys::set_dummy_handler(libc::SIGCONT) == -1 {
        error!(LOGOPT_ANY, "get_pkt", "failed to set signal handler {}", sys::errno());
    }
    let mask = sys::sigset_all_but(&[libc::SIGCONT]);
    let pipefd = ap.lock().pipefd;
    loop {
        let (r, revents, e) = sys::ppoll_in(pipefd, &mask);
        if r == -1 {
            if e == libc::EINTR {
                state::st_mutex_lock();
                if ap.lock().state == ST_SHUTDOWN {
                    state::st_mutex_unlock();
                    return -1;
                }
                state::st_mutex_unlock();
                continue;
            }
            logerr!("get_pkt", "845", "poll failed: {}", sys::strerror(e));
            return -1;
        }
        if revents & libc::POLLIN != 0 {
            let kpkt_len = KPKT_LEN.load(Ordering::Relaxed);
            let buf = pkt.as_bytes_mut();
            let n = kpkt_len.min(buf.len());
            let left = sys::fullread(pipefd, &mut buf[..n]);
            if left != 0 {
                error!(
                    ap.logopt(),
                    "get_pkt",
                    "read error on request pipe, read {}, expected {} error {}",
                    left,
                    kpkt_len,
                    sys::strerror(sys::errno())
                );
            }
            return left as i32;
        }
    }
}

/// `do_expire()`: unmount what's at `name` for an expire request.
pub fn do_expire(ap: &Arc<AutofsPoint>, name: &[u8]) -> i32 {
    let logopt = ap.logopt();
    let ap_path = ap.path();
    let (buf, parent) = if name.first() != Some(&b'/') {
        (crate::libautofs::cat_path::ncat_path_len(4096, &ap_path, name, name.len()), ap_path.clone())
    } else {
        let n = cstr::c(name).to_vec();
        (if n.len() >= 4096 { None } else { Some(n.clone()) }, n)
    };
    let Some(buf) = buf else {
        crit!(logopt, "do_expire", "path too long for buffer");
        return 1;
    };
    info!(logopt, "expiring path {} on {}", buf, parent);
    let entry = ap.entry();
    entry.source_readlock();
    let ret = umount_multi(ap, &buf, true);
    if ret == 0 {
        info!(logopt, "umounting {} succeeded", buf);
    } else {
        warn!(logopt, "couldn't complete expire of {}", buf);
    }
    entry.source_unlock();
    ret
}

/// `autofs_init_ap()`: the kernel pipe.
fn autofs_init_ap(ap: &Arc<AutofsPoint>) -> i32 {
    let st = ap.lock().state;
    if st != ST_INIT {
        error!(ap.logopt(), "autofs_init_ap", "bad state {}", st);
        return -1;
    }
    {
        let mut a = ap.lock();
        a.pipefd = -1;
        a.kpipefd = -1;
        a.ioctlfd = -1;
    }
    match sys::pipe_cloexec() {
        Ok((r, w)) => {
            let mut a = ap.lock();
            a.pipefd = r;
            a.kpipefd = w;
            0
        }
        Err(e) => {
            logerr!("open_pipe", "161", "failed to open pipe: {}", sys::strerror(e));
            crit!(ap.logopt(), "autofs_init_ap", "failed to create commumication pipe for autofs path {}", ap.path());
            -1
        }
    }
}

/// `mount_autofs()`.
fn mount_autofs(ap: &Arc<AutofsPoint>) -> i32 {
    if DO_FORCE_UNLINK.load(Ordering::Relaxed) & UNLINK_AND_EXIT == 0 && autofs_init_ap(ap) != 0 {
        return -1;
    }
    let status = if ap.ty() == master::LKP_DIRECT {
        crate::daemon::direct::mount_autofs_direct(ap)
    } else {
        indirect::mount_autofs_indirect(ap)
    };
    state::st_add_task(ap, ST_READY);
    status
}

/// `handle_packet()`.
fn handle_packet(ap: &Arc<AutofsPoint>) -> i32 {
    let mut pkt = sys::AutofsV5Packet::zeroed();
    if get_pkt(ap, &mut pkt) != 0 {
        return -1;
    }
    let logopt = ap.logopt();
    debug!(logopt, "handle_packet", "type = {}", pkt.ty);
    match pkt.ty {
        3 => indirect::handle_packet_missing_indirect(ap, &pkt),
        5 => crate::daemon::direct::handle_packet_missing_direct(ap, &pkt),
        4 => indirect::handle_packet_expire_indirect(ap, &pkt),
        6 => crate::daemon::direct::handle_packet_expire_direct(ap, &pkt),
        t => {
            error!(logopt, "handle_packet", "unknown packet type {}", t);
            -1
        }
    }
}

/// `become_daemon()`.
fn become_daemon(program: &[u8], flags: u32) {
    if sys::chdir(b"/") != 0 {
        log::eprint(&bfmt!("{}: failed change working directory.\n", program));
        sys::exit(0);
    }
    let check = flags & DAEMON_FLAGS_CHECK_DAEMON != 0;
    if flags & DAEMON_FLAGS_FOREGROUND != 0 && flags & DAEMON_FLAGS_SYSTEMD_SERVICE == 0 {
        if check && !crate::daemon::flag::aquire_flag_file() {
            log::eprint(&bfmt!("{}: program is already running.\n", program));
            sys::exit(1);
        }
        log::log_to_stderr();
    } else if flags & DAEMON_FLAGS_SYSTEMD_SERVICE != 0 {
        if check && !crate::daemon::flag::aquire_flag_file() {
            log::eprint(&bfmt!("{}: program is already running.\n", program));
            sys::exit(1);
        }
        log::open_log();
    } else {
        let Ok((r, w)) = sys::pipe_cloexec() else {
            logerr!("open_pipe", "161", "failed to open pipe: {}", sys::strerror(sys::errno()));
            log::eprint(&bfmt!("{}: failed to create start_pipefd.\n", program));
            sys::exit(0);
        };
        log::flush_stdout();
        let pid = sys::fork();
        if pid > 0 {
            sys::close(w);
            let mut b = [0u8; 4];
            let res = sys::read(r, &mut b);
            if res < 0 {
                sys::exit(1);
            }
            // A short read leaves st_stat as it was (1).
            let st = if res == 4 { i32::from_ne_bytes(b) } else { 1 };
            sys::exit(st);
        } else if pid < 0 {
            log::eprint(&bfmt!("{}: Could not detach process\n", program));
            sys::exit(1);
        }
        sys::close(r);
        START_PIPE_W.store(w, Ordering::Relaxed);
        if check && !crate::daemon::flag::aquire_flag_file() {
            log::eprint(&bfmt!("{}: program is already running.\n", program));
            // Already running is a success.
            write_start_status(0);
            sys::exit(0);
        }
        if sys::setsid() == -1 {
            log::eprint(&bfmt!("setsid: {}", sys::strerror(sys::errno())));
            write_start_status(1);
            sys::exit(1);
        }
        let nullfd = sys::open_flags(b"/dev/null", libc::O_RDWR);
        if nullfd < 0 {
            log::eprint(&bfmt!("cannot open /dev/null: {}", sys::strerror(sys::errno())));
            write_start_status(1);
            sys::exit(1);
        }
        if sys::dup2(nullfd, 0) < 0 || sys::dup2(nullfd, 1) < 0 || sys::dup2(nullfd, 2) < 0 {
            log::eprint(&bfmt!("redirecting file descriptors failed: {}", sys::strerror(sys::errno())));
            write_start_status(1);
            sys::exit(1);
        }
        log::open_log();
        sys::close(nullfd);
    }
    let pid_file = PID_FILE.lock().unwrap().clone();
    if let Some(pf) = pid_file {
        match std::fs::write(std::ffi::OsStr::from_bytes(&pf), format!("{}\n", sys::getpid())) {
            Ok(()) => {}
            Err(e) => {
                logerr!(
                    "become_daemon",
                    "1081",
                    "failed to write pid file {}: {}",
                    pf,
                    sys::strerror(e.raw_os_error().unwrap_or(0))
                );
                *PID_FILE.lock().unwrap() = None;
            }
        }
    }
}

use std::os::unix::ffi::OsStrExt;

/// Write `st_stat` to the start pipe (the parent exits with it) and close it.
fn write_start_status(st: i32) {
    let w = START_PIPE_W.swap(-1, Ordering::Relaxed);
    if w != -1 {
        sys::write_all(w, &st.to_ne_bytes());
        sys::close(w);
    }
}

/// `do_notify_state()` and `do_signals()`: a thread passes the signal to the
/// mount points.
fn do_signals(master: &Arc<master::Master>, sig: i32) {
    MRC.lock();
    let m = master.clone();
    let r = state::spawn_detached("notify", move || {
        MRC.lock();
        debug!(m.logopt(), "do_notify_state", "signal {}", sig);
        MRC_SIGNALED.store(true, Ordering::SeqCst);
        MRC_COND.signal();
        MRC.unlock();
        master::master_notify_state_change(&m, sig);
    });
    if r.is_none() {
        error!(master.logopt(), "do_signals", "mount state notify thread create failed");
        MRC.unlock();
        return;
    }
    MRC_SIGNALED.store(false, Ordering::SeqCst);
    while !MRC_SIGNALED.load(Ordering::SeqCst) {
        MRC_COND.wait(&MRC);
    }
    MRC.unlock();
}

/// `do_read_master()` and `do_hup_signal()`: reread the configuration and the
/// master map in a thread.
fn do_hup_signal(master: &Arc<master::Master>) -> bool {
    let logopt = master.logopt();
    let age = sys::monotonic_time();
    MRC.lock();
    NFS_MOUNT_USES_STRING_OPTIONS.store(check_nfs_mount_version(), Ordering::Relaxed);
    master::master_mutex_lock();
    if master.lock().reading {
        MRC.unlock();
        master::master_mutex_unlock();
        return true;
    }
    master.lock().reading = true;
    master::master_mutex_unlock();
    let m = master.clone();
    let r = state::spawn_detached("read_master", move || {
        MRC.lock();
        let logopt = m.logopt();
        MRC_SIGNALED.store(true, Ordering::SeqCst);
        MRC_COND.signal();
        MRC.unlock();
        if !defaults::defaults_read_config(true) {
            error!(logopt, "do_read_master", "failed to read configuration, exiting");
            m.lock().reading = false;
            return;
        }
        info!(logopt, "re-reading master map {}", m.name());
        m.lock().readall = true;
        master::master_read_master(&m, age);
        let mut d = m.lock();
        d.readall = false;
        d.reading = false;
    });
    if r.is_none() {
        error!(logopt, "do_hup_signal", "master read map thread create failed");
        master.lock().reading = false;
        MRC.unlock();
        return false;
    }
    MRC_SIGNALED.store(false, Ordering::SeqCst);
    while !MRC_SIGNALED.load(Ordering::SeqCst) {
        MRC_COND.wait(&MRC);
    }
    MRC.unlock();
    true
}

/// `signal_handler()`: the main thread's signal loop.
fn signal_handler(master: &Arc<master::Master>) {
    let set = sys::sigset_all_but(&[
        libc::SIGABRT,
        libc::SIGBUS,
        libc::SIGSEGV,
        libc::SIGILL,
        libc::SIGFPE,
        libc::SIGTRAP,
        libc::SIGCHLD,
        libc::SIGCONT,
    ]);
    loop {
        let sig = sys::sigwait(&set);
        match sig {
            libc::SIGTERM | libc::SIGINT | libc::SIGUSR2 => {
                master::master_mutex_lock();
                if master.lock().completed.is_empty() {
                    if master.lock().mounts.is_empty() {
                        master::master_mutex_unlock();
                        return;
                    }
                } else {
                    if master::master_done(master) {
                        master::master_mutex_unlock();
                        return;
                    }
                    master::master_mutex_unlock();
                    continue;
                }
                master::master_mutex_unlock();
                do_signals(master, sig);
            }
            libc::SIGUSR1 => do_signals(master, sig),
            libc::SIGHUP => {
                do_hup_signal(master);
            }
            s => {
                logerr!("signal_handler", "1347", "got unexpected signal {}!", s);
            }
        }
    }
}

static CMD_PIPE_FIFO: AtomicI32 = AtomicI32::new(-1);
static CMD_PIPE_MUTEX: crate::libautofs::csync::CMutex = crate::libautofs::csync::CMutex::new();
static CMD_PIPE_DONE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static CMD_PIPE_THID: AtomicU64 = AtomicU64::new(u64::MAX);

/// `create_cmd_pipe_fifo()`.
fn create_cmd_pipe_fifo(program: &[u8]) -> i32 {
    if CMD_PIPE_FIFO.load(Ordering::Relaxed) != -1 {
        return 0;
    }
    let name = cmd_pipe_name();
    if sys::unlink(&name) != 0 && sys::errno() != libc::ENOENT {
        log::eprint(&bfmt!("{}: failed to unlink command pipe. Is the automount daemon already running?", program));
        return -1;
    }
    if sys::mkfifo(&name, 0o600) != 0 && sys::errno() != libc::EEXIST {
        log::eprint(&bfmt!("{}: mkfifo for {} failed: {}", program, name, sys::strerror(sys::errno())));
        return -1;
    }
    let fd = sys::open_flags(&name, libc::O_RDWR | libc::O_NONBLOCK);
    if fd < 0 {
        let e = sys::errno();
        sys::unlink(&name);
        log::eprint(&bfmt!("{}: failed to open command pipe {}: {}", program, name, sys::strerror(e)));
        return -1;
    }
    CMD_PIPE_FIFO.store(fd, Ordering::Relaxed);
    0
}

/// `cmd_pipe_name`: `AUTOFS_FIFO_DIR "/" FIFO_NAME`.
fn cmd_pipe_name() -> Vec<u8> {
    [defaults::AUTOFS_FIFO_DIR, b"/autofs.cmd.fifo"].concat()
}

/// `destroy_cmd_pipe_fifo()`.
fn destroy_cmd_pipe_fifo() {
    let fd = CMD_PIPE_FIFO.swap(-1, Ordering::Relaxed);
    if fd == -1 {
        return;
    }
    let name = cmd_pipe_name();
    if sys::close(fd) != 0 {
        warn!(LOGOPT_ANY, "close for command pipe {}: {}", name, sys::strerror(sys::errno()));
    }
    if sys::unlink(&name) != 0 {
        warn!(LOGOPT_ANY, "failed to unlink FIFO. Was the fifo created OK?");
    }
}

/// `handle_cmd_pipe_fifo_message()`: `"devid priority"` sets a mount's logging.
fn handle_cmd_pipe_fifo_message(fd: i32) {
    let mut buffer = [0u8; 4096];
    let ret = sys::read(fd, &mut buffer);
    if ret < 0 {
        warn!(LOGOPT_ANY, "read on command pipe returned error: {}", sys::strerror(sys::errno()));
        return;
    }
    if ret as usize >= buffer.len() {
        error!(LOGOPT_ANY, "handle_cmd_pipe_fifo_message", "read overrun on command pipe message");
        return;
    }
    let msg = cstr::c(&buffer[..ret as usize]).to_vec();
    let Some(sep) = cstr::strrchr(&msg, b' ') else {
        error!(LOGOPT_ANY, "handle_cmd_pipe_fifo_message", "incorrect command pipe message format {}.", msg);
        return;
    };
    let sep = &msg[sep + 1..];
    let (devid, end) = cstr::strtol(&msg, 10);
    if devid == i64::MIN || devid == i64::MAX {
        debug!(LOGOPT_ANY, "handle_cmd_pipe_fifo_message", "strtol reported a range error.");
        error!(LOGOPT_ANY, "handle_cmd_pipe_fifo_message", "invalid command pipe message format {}.", msg);
        return;
    }
    if end == 0 {
        debug!(LOGOPT_ANY, "handle_cmd_pipe_fifo_message", "devid id is expected to be a integer.");
        return;
    }
    let Some(ap) = master::master_find_mapent_by_devid(&master::master_list(), devid as u64) else {
        error!(LOGOPT_ANY, "handle_cmd_pipe_fifo_message", "can't locate autofs_point for device id {}.", devid);
        return;
    };
    let (pri, end) = cstr::strtol(sep, 10);
    let logopt = ap.logopt();
    if pri == i64::MIN || pri == i64::MAX {
        error!(logopt, "handle_cmd_pipe_fifo_message", "failed to set log priority.");
        let w = if pri == i64::MIN { "underflow" } else { "overflow" };
        error!(logopt, "handle_cmd_pipe_fifo_message", "strtol reported an {}.", w);
        return;
    }
    if end == 0 {
        debug!(
            logopt,
            "handle_cmd_pipe_fifo_message", "priority is expected to be an integer in the range 0-7 inclusive."
        );
        return;
    }
    if !(libc::LOG_EMERG as i64..=libc::LOG_DEBUG as i64).contains(&pri) {
        debug!(logopt, "handle_cmd_pipe_fifo_message", "invalid log priority ({}) received on fifo", pri);
        return;
    }
    let path = ap.path();
    if pri >= libc::LOG_WARNING as i64 {
        if pri == libc::LOG_DEBUG as i64 {
            ap.lock().logopt = LOGOPT_DEBUG;
            info!(LOGOPT_DEBUG, "debug logging set for {}", path);
        } else {
            ap.lock().logopt = LOGOPT_VERBOSE;
            info!(LOGOPT_VERBOSE, "verbose logging set for {}", path);
        }
    } else {
        if logopt & LOGOPT_ANY != 0 {
            info!(logopt, "basic logging set for {}", path);
        }
        ap.lock().logopt = log::LOGOPT_NONE;
    }
}

/// `set_log_priority()`: ask the running daemon, through its FIFO, to log for
/// the mount at `path` at `priority`.
fn set_log_priority(path: &[u8], priority: i32) -> i32 {
    let (ret, devid) = dev_ioctl::mount_device(path, 0);
    if ret == -1 || ret == 0 {
        log::eprint(&bfmt!("Could not find device id for mount {}\n", path));
        return -1;
    }
    if !(libc::LOG_EMERG..=libc::LOG_DEBUG).contains(&priority) {
        log::eprint(&bfmt!("Log priority {} is invalid.\n", priority));
        log::eprint(b"Please specify a number in the range 0-7.\n");
        return -1;
    }
    let mut buf = format!("{} {}", devid as i64, priority).into_bytes();
    if buf.len() >= 25 {
        log::eprint(b"Invalid device id or log priotity\n");
        return -1;
    }
    // FIFO_BUF_SIZE bytes are written, the rest NULs.
    buf.resize(25, 0);
    let name = cmd_pipe_name();
    let fd = sys::open_flags(&name, libc::O_WRONLY | libc::O_NONBLOCK);
    if fd < 0 {
        let e = sys::strerror(sys::errno());
        log::eprint(&bfmt!("set_log_priority: open of {} failed with {}\n", name, e));
        log::eprint(b"set_log_priority: perhaps the fifo wasn't setup, please check your log for more information\n");
        return -1;
    }
    if sys::write_all(fd, &buf) != buf.len() as isize {
        log::eprint(b"Failed to change logging priority.  ");
        log::eprint(&bfmt!("write to fifo failed: {}.\n", sys::strerror(sys::errno())));
        sys::close(fd);
        return -1;
    }
    sys::close(fd);
    log::print(&bfmt!("Successfully set log priority for {}.\n", path));
    0
}

/// `cmd_pipe_handler()`.
fn cmd_pipe_handler(program: Vec<u8>) {
    if create_cmd_pipe_fifo(&program) != 0 {
        return;
    }
    let fd = CMD_PIPE_FIFO.load(Ordering::Relaxed);
    if sys::set_dummy_handler(libc::SIGPIPE) == -1 {
        error!(LOGOPT_ANY, "cmd_pipe_handler", "failed to set signal handler {}", sys::errno());
        return;
    }
    let mask = sys::sigset_all_but(&[libc::SIGPIPE]);
    loop {
        CMD_PIPE_MUTEX.lock();
        if CMD_PIPE_DONE.load(Ordering::SeqCst) {
            break;
        }
        CMD_PIPE_MUTEX.unlock();
        let (r, revents, e) = sys::ppoll_in(fd, &mask);
        if r == -1 {
            if e == libc::EINTR {
                continue;
            }
            CMD_PIPE_MUTEX.lock();
            logerr!("cmd_pipe_handler", "1635", "poll failed: {}", sys::strerror(e));
            break;
        }
        if revents & libc::POLLIN != 0 {
            debug!(LOGOPT_ANY, "cmd_pipe_handler", "message pending on control fifo.");
            handle_cmd_pipe_fifo_message(fd);
        }
    }
    destroy_cmd_pipe_fifo();
    CMD_PIPE_MUTEX.unlock();
}

/// `start_cmd_pipe_handler()`.
fn start_cmd_pipe_handler(program: &[u8]) -> bool {
    let p = program.to_vec();
    match state::spawn_detached("cmd_pipe", move || cmd_pipe_handler(p)) {
        Some(t) => {
            CMD_PIPE_THID.store(t, Ordering::Relaxed);
            true
        }
        None => false,
    }
}

/// `finish_cmd_pipe_handler()`.
fn finish_cmd_pipe_handler() {
    CMD_PIPE_MUTEX.lock();
    let thid = CMD_PIPE_THID.load(Ordering::Relaxed);
    if thid != u64::MAX && !CMD_PIPE_DONE.load(Ordering::SeqCst) {
        CMD_PIPE_DONE.store(true, Ordering::SeqCst);
        sys::pthread_kill(thid, libc::SIGPIPE);
    }
    CMD_PIPE_MUTEX.unlock();
}

/// `handle_mounts_cleanup()` (the master mutex held, released here).
fn handle_mounts_cleanup(ap: &Arc<AutofsPoint>) {
    let master = master::master_list();
    let (logopt, submount, path, flags) = {
        let a = ap.lock();
        (a.logopt, a.submount, a.path.clone(), a.flags)
    };
    let clean = !submount && path != b"/-" && flags & MOUNT_FLAG_DIR_CREATED != 0;
    if submount {
        // The submount is on its parent's submount and mounted lists.
        mounts::mnts_remove_submount(&path);
        mounts::mnts_remove_mount(&path, mounts::MNTS_MOUNTED);
        if mounts::mnts_find_amdmount(&path).is_some() {
            mounts::mnts_remove_amdmount(&path);
        }
    }
    // Don't signal the handler if that was done already.
    let pending = !master.lock().completed.is_empty();
    info!(logopt, "shut down path {}", path);
    if clean && sys::rmdir(&path) == -1 {
        warn!(logopt, "failed to remove dir {}: {}", path, sys::strerror(sys::errno()));
    }
    let entry = ap.entry();
    master::master_remove_mapent(&master, &entry);
    entry.source_unlock();
    if !pending {
        sys::pthread_kill(SIGNAL_HANDLER_THID.load(Ordering::Relaxed), libc::SIGTERM);
    }
    master::master_mutex_unlock();
}

/// `handle_mounts_exit()`: finish a shutdown (1), or go back to ready (0).
fn handle_mounts_exit(ap: &Arc<AutofsPoint>) -> bool {
    master::master_mutex_lock();
    let entry = ap.entry();
    entry.source_writelock();
    let back_to_ready = |ap: &Arc<AutofsPoint>| {
        let rf = ap.lock().exp_runfreq;
        alarm::conditional_alarm_add(ap, rf);
        state::st_add_task(ap, ST_READY);
        ap.entry().source_unlock();
        master::master_mutex_unlock();
        false
    };
    if ap.lock().state != ST_SHUTDOWN {
        return back_to_ready(ap);
    }
    alarm::alarm_delete(ap);
    state::st_remove_tasks(ap);
    state::st_wait_task(ap, state::ST_ANY, 0);
    // Direct mounts have all gone by now, and are only unmounted at
    // shutdown: nothing to recover.
    if ap.ty() == master::LKP_DIRECT {
        umount_autofs(ap);
        handle_mounts_cleanup(ap);
        return true;
    }
    // A non-zero umount_autofs() left the mount intact (a lookup came in).
    if umount_autofs(ap) == 0 {
        mounts::set_indirect_mount_tree_catatonic(ap);
        handle_mounts_cleanup(ap);
        return true;
    }
    warn!(ap.logopt(), "can't shutdown: filesystem {} still busy", ap.path());
    back_to_ready(ap)
}

/// `handle_mounts()`: the mount handler thread of one autofs point.
pub fn handle_mounts(ap: Arc<AutofsPoint>, suc: Arc<master::StartupCond>) {
    suc.mutex.lock();
    let force = DO_FORCE_UNLINK.load(Ordering::Relaxed);
    if mount_autofs(&ap) < 0 {
        if force & UNLINK_AND_EXIT == 0 {
            crit!(ap.logopt(), "handle_mounts", "mount of {} failed!", ap.path());
        }
        suc.status.store(1, Ordering::SeqCst);
        umount_autofs(&ap);
        suc.return_start_status();
        return;
    }
    let (flags, ty, logopt) = {
        let a = ap.lock();
        (a.flags, a.ty, a.logopt)
    };
    if flags & MOUNT_FLAG_NOBIND != 0 {
        info!(logopt, "bind mounts disabled");
    }
    if flags & MOUNT_FLAG_GHOST != 0 && ty != master::LKP_DIRECT {
        info!(logopt, "ghosting enabled");
    }
    suc.status.store(0, Ordering::SeqCst);
    suc.return_start_status();
    loop {
        if handle_packet(&ap) != 0 && handle_mounts_exit(&ap) {
            break;
        }
        // A packet was handled and the mount is still there, but a shutdown
        // may have been asked for meanwhile.
        if ap.lock().state == ST_SHUTDOWN && handle_mounts_exit(&ap) {
            break;
        }
    }
}

/// `do_master_list_reset()`.
fn do_master_list_reset(master: &Arc<master::Master>) {
    master::master_mutex_lock();
    let entries = std::mem::take(&mut master.lock().mounts);
    for e in entries {
        master::master_free_mapent_sources(&e);
    }
    master::master_mutex_unlock();
}

/// `do_master_read_master()`: retry reading the master map every 2 seconds,
/// for at most `wait` seconds (forever if it's 0 or less).
fn do_master_read_master(master: &Arc<master::Master>, age: &mut i64, wait: i32) -> bool {
    let set = sys::sigset(&[libc::SIGTERM, libc::SIGINT, libc::SIGHUP]);
    let save = sys::sigmask(libc::SIG_UNBLOCK, &set);
    let retry_wait = 2;
    let mut elapsed = 0;
    let mut ret = false;
    loop {
        do_master_list_reset(master);
        *age = sys::monotonic_time();
        if master::master_read_master(master, *age) {
            ret = true;
            break;
        }
        if sys::nanosleep_once(retry_wait as i64 * 1_000_000_000) == -1 {
            break;
        }
        if wait > 0 {
            elapsed += retry_wait;
            if elapsed >= wait {
                log::logmsg(b"problem reading master map, maximum wait exceeded");
                break;
            }
        }
    }
    sys::set_sigmask(&save);
    ret
}

/// The daemon itself, after the options and checks of `main()`.
pub fn run_daemon(
    program: &[u8],
    master_name: Option<&[u8]>,
    timeout: u32,
    flags: u32,
    logging: u32,
    master_wait: i32,
    start_age: i64,
) -> ! {
    let ml = master::master_new(master_name, timeout, flags);
    *master::MASTER_LIST.lock().unwrap() = Some(ml.clone());
    become_daemon(program, flags);
    info!(logging, "Starting automounter version {}, master map {}", VERSION, ml.name());
    info!(
        logging,
        "using kernel protocol version {}.{}",
        mounts::get_kver_major(),
        format!("{:02}", mounts::get_kver_minor())
    );
    dev_ioctl::init_ioctl_ctl();
    if !start_cmd_pipe_handler(program) {
        logerr!("main", "2651", "{}: failed to create command pipe handler thread!", program);
        write_start_status(1);
        crate::daemon::flag::release_flag_file();
        sys::exit(1);
    }
    if !alarm::alarm_start_handler() {
        logerr!("main", "2663", "{}: failed to create alarm handler thread!", program);
        write_start_status(1);
        crate::daemon::flag::release_flag_file();
        sys::exit(1);
    }
    if !state::st_start_handler() {
        logerr!("main", "2675", "{}: failed to create FSM handler thread!", program);
        write_start_status(1);
        crate::daemon::flag::release_flag_file();
        sys::exit(1);
    }
    let mut age = start_age;
    if !master::master_read_master(&ml, age) && !do_master_read_master(&ml, &mut age, master_wait) {
        log::logmsg(&bfmt!(
            "{}: warning: could not read at least one map source after waiting, continuing ...",
            program
        ));
        master::master_mutex_lock();
        ml.lock().readall = true;
        master::master_mount_mounts(&ml, age);
        ml.lock().readall = false;
        if ml.lock().mounts.is_empty() {
            warn!(ml.logopt(), "no mounts in table");
        }
        master::master_mutex_unlock();
    }
    if DO_FORCE_UNLINK.load(Ordering::Relaxed) & UNLINK_AND_EXIT == 0 {
        // Reset the forced unlink so a SIGHUP doesn't do it again.
        DO_FORCE_UNLINK.store(0, Ordering::Relaxed);
        write_start_status(0);
        SIGNAL_HANDLER_THID.store(sys::pthread_self(), Ordering::Relaxed);
        signal_handler(&ml);
    }
    master::master_kill(&ml);
    finish_cmd_pipe_handler();
    if let Some(pf) = PID_FILE.lock().unwrap().take() {
        sys::unlink(&pf);
    }
    sys::closelog();
    crate::daemon::flag::release_flag_file();
    macros::macro_free_global_table();
    dev_ioctl::close_ioctl_ctl();
    info!(logging, "autofs stopped");
    sys::exit(0);
}

/// Set from `-p`.
pub fn set_pid_file(p: Vec<u8>) {
    *PID_FILE.lock().unwrap() = Some(p);
}

/// Called by `main()` before anything else of the daemon.
pub fn init_kpkt_len() {
    KPKT_LEN.store(get_kpkt_len(), Ordering::Relaxed);
}

/// `--set-log-priority` for each path; the exit status.
pub fn set_log_priorities(paths: &[Vec<u8>], logpri: i32) -> i32 {
    let mut code = 0;
    for p in paths {
        if set_log_priority(p, logpri) < 0 {
            code = 1;
        }
    }
    if paths.is_empty() {
        log::eprint(b"--set-log-priority requires a path.\n");
        code = 1;
    }
    code
}
