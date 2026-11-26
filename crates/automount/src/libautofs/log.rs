//! `lib/log.c`: the daemon's logging, to stderr until `open_log()` and to syslog
//! (`automount[pid]`, `LOG_DAEMON`) after.
//!
//! QUIRK: every function logs at `LOG_INFO` unless the message carries a mount
//! attempt id prefix (`use_mount_request_log_id`): only then does it use its own
//! priority. Messages are printf formats in C; here they arrive formatted.

use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::sys;

pub const LOGOPT_NONE: u32 = 0x0000;
pub const LOGOPT_ERROR: u32 = 0x0000;
pub const LOGOPT_DEBUG: u32 = 0x0001;
pub const LOGOPT_VERBOSE: u32 = 0x0002;
pub const LOGOPT_ANY: u32 = LOGOPT_DEBUG | LOGOPT_VERBOSE;

static SYSLOG_OPEN: AtomicBool = AtomicBool::new(false);
static LOGGING_TO_SYSLOG: AtomicBool = AtomicBool::new(false);
static DO_VERBOSE: AtomicBool = AtomicBool::new(false);
static DO_DEBUG: AtomicBool = AtomicBool::new(false);
static DEBUG_LEVEL: AtomicU32 = AtomicU32::new(0);

/// C's `stdout`: fully buffered when it isn't a terminal, flushed at `exit()`.
static STDOUT: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// `printf()`.
pub fn print(s: &[u8]) {
    let mut o = STDOUT.lock().unwrap();
    o.extend_from_slice(s);
    if o.len() >= 4096 {
        let _ = std::io::stdout().write_all(&o);
        let _ = std::io::stdout().flush();
        o.clear();
    }
}

/// Drop what `print()` buffered, as a crash loses C's unflushed `stdout`.
pub fn flush_stdout_lost() {
    STDOUT.lock().unwrap().clear();
}

/// Flush what `print()` buffered.
pub fn flush_stdout() {
    let mut o = STDOUT.lock().unwrap();
    if !o.is_empty() {
        let _ = std::io::stdout().write_all(&o);
        o.clear();
    }
    let _ = std::io::stdout().flush();
}

/// `fprintf(stderr, ...)`.
pub fn eprint(s: &[u8]) {
    sys::write_stderr(s);
}

pub fn have_log_verbose() -> bool {
    DO_VERBOSE.load(Ordering::Relaxed)
}

pub fn have_log_debug() -> bool {
    DO_DEBUG.load(Ordering::Relaxed)
}

pub fn get_log_debug_level() -> u32 {
    DEBUG_LEVEL.load(Ordering::Relaxed)
}

pub fn set_log_norm() {
    DO_VERBOSE.store(false, Ordering::Relaxed);
    DO_DEBUG.store(false, Ordering::Relaxed);
}

pub fn set_log_verbose() {
    DO_VERBOSE.store(true, Ordering::Relaxed);
}

pub fn set_log_debug(level: u32) {
    DO_DEBUG.store(true, Ordering::Relaxed);
    DEBUG_LEVEL.store(level, Ordering::Relaxed);
}

/// The common tail of every `log_*()`: syslog at `LOG_INFO` (see the module
/// docs), or the message and a newline on stderr.
fn emit(msg: &[u8]) {
    if LOGGING_TO_SYSLOG.load(Ordering::Relaxed) {
        sys::syslog(libc::LOG_INFO, msg);
    } else {
        let mut m = msg.to_vec();
        m.push(b'\n');
        sys::write_stderr(&m);
    }
}

/// `log_info()`.
pub fn log_info(logopt: u32, msg: &[u8]) {
    let opt_log = logopt & (LOGOPT_DEBUG | LOGOPT_VERBOSE);
    if !have_log_debug() && !have_log_verbose() && opt_log == 0 {
        return;
    }
    emit(msg);
}

/// `log_notice()`.
pub fn log_notice(logopt: u32, msg: &[u8]) {
    log_info(logopt, msg);
}

/// `log_warn()`.
pub fn log_warn(logopt: u32, msg: &[u8]) {
    log_info(logopt, msg);
}

/// `log_error()`.
pub fn log_error(_logopt: u32, msg: &[u8]) {
    emit(msg);
}

/// `log_crit()`.
pub fn log_crit(_logopt: u32, msg: &[u8]) {
    emit(msg);
}

/// `log_debug()`.
pub fn log_debug(logopt: u32, msg: &[u8]) {
    let opt_log = logopt & LOGOPT_DEBUG;
    if !have_log_debug() && opt_log == 0 {
        return;
    }
    emit(msg);
}

/// `logmsg()`.
pub fn logmsg(msg: &[u8]) {
    emit(msg);
}

/// `open_log()`.
pub fn open_log() {
    if !SYSLOG_OPEN.swap(true, Ordering::Relaxed) {
        sys::openlog(c"automount");
    }
    LOGGING_TO_SYSLOG.store(true, Ordering::Relaxed);
}

/// `log_to_stderr()`.
pub fn log_to_stderr() {
    if SYSLOG_OPEN.swap(false, Ordering::Relaxed) {
        sys::closelog();
    }
    LOGGING_TO_SYSLOG.store(false, Ordering::Relaxed);
}

/// Whether messages go to syslog.
pub fn logging_to_syslog() -> bool {
    LOGGING_TO_SYSLOG.load(Ordering::Relaxed)
}
