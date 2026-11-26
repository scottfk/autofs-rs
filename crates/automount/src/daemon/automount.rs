//! `daemon/automount.c`: `main()`. This phase has the startup up to the point
//! where the daemon detaches: the configuration, `mount.nfs`'s version, the
//! options, the root check, the kernel protocol probe, the open file limit,
//! the macros, and `-m`/`--dumpmaps`. The daemon itself comes in phase 3.

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
    let mut errbuf = vec![0u8; EBUFSIZ + 1];
    let mut errp = 0usize;
    let mut found: Option<(u32, u32, u32)> = None;
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
                errp -= nl + 1;
                sp += nl + 1;
            }
            if errp > 0 && sp != 0 {
                errbuf.copy_within(sp..sp + errp, 0);
            }
            if errp >= EBUFSIZ {
                let line = cstr::c(&errbuf[..errp]).to_vec();
                if let Some(at) = cstr::strstr(&line, b"nfs-utils")
                    && let Some(v) = extract_version(&line[at..])
                {
                    found = Some(v);
                }
                errp = 0;
            }
        }
        if n <= 0 {
            break;
        }
    }
    sys::close(pr);
    if errp > 0 {
        let line = cstr::c(&errbuf[..errp]).to_vec();
        if let Some(at) = cstr::strstr(&line, b"nfs-utils")
            && let Some(v) = extract_version(&line[at..])
        {
            found = Some(v);
        }
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
    let mut _pid_file: Option<Vec<u8>> = None;
    for (opt, optarg) in opts {
        let arg = optarg.clone().unwrap_or_default();
        match opt as u8 {
            b'h' => {
                usage(&program);
                sys::exit(0);
            }
            b'p' => _pid_file = Some(arg),
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
            b'F' | b'U' => {
                if opt as u8 == b'U' {
                    flags |= DAEMON_FLAGS_FOREGROUND;
                }
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
        // set_log_priority() for each path, through the daemon's command FIFO;
        // it comes with the daemon (phase 3).
        if operands.is_empty() {
            log::eprint(b"--set-log-priority requires a path.\n");
            sys::exit(1);
        }
        panic!("--set-log-priority isn't ported yet (phase 3)");
    }

    // Don't need the kernel module just to look at the configured maps.
    if flags & DAEMON_FLAGS_DUMP_MAPS == 0 && !mounts::query_kproto_ver() {
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

    let _ = (timeout, flags & DAEMON_FLAGS_FOREGROUND);
    panic!("the daemon isn't ported yet (phase 3)");
}
