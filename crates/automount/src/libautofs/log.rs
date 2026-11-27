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

thread_local! {
    /// `key_thread_attempt_id`: the mount request this thread works on.
    static ATTEMPT_ID: std::cell::Cell<Option<u64>> = const { std::cell::Cell::new(None) };
}

/// Set this thread's mount request id (`set_thread_mount_request_log_id()`).
pub fn set_attempt_id(id: u64) {
    ATTEMPT_ID.with(|a| a.set(Some(id)));
}

/// Whether this thread has a mount request id.
pub fn has_attempt_id() -> bool {
    ATTEMPT_ID.with(|a| a.get().is_some())
}

/// The common tail of every `log_*()`: syslog, or the message and a newline
/// on stderr. With a mount request id (`prepare_attempt_prefix()`) the message
/// gets `id|` in front and syslog gets `pri`; without, `LOG_INFO` (see the
/// module docs).
fn emit_pri(pri: libc::c_int, msg: &[u8]) {
    let prefixed = ATTEMPT_ID.with(|a| a.get()).map(|id| {
        let mut p = format!("{id:02x}").into_bytes();
        p.truncate(23);
        p.push(b'|');
        p.extend_from_slice(msg);
        p
    });
    if LOGGING_TO_SYSLOG.load(Ordering::Relaxed) {
        match &prefixed {
            Some(p) => sys::syslog(pri, p),
            None => sys::syslog(libc::LOG_INFO, msg),
        }
    } else {
        let mut m = prefixed.unwrap_or_else(|| msg.to_vec());
        m.push(b'\n');
        sys::write_stderr(&m);
    }
}

fn emit(msg: &[u8]) {
    emit_pri(libc::LOG_INFO, msg);
}

/// `log_info()`.
pub fn log_info(logopt: u32, msg: &[u8]) {
    let opt_log = logopt & (LOGOPT_DEBUG | LOGOPT_VERBOSE);
    if !have_log_debug() && !have_log_verbose() && opt_log == 0 {
        return;
    }
    emit_pri(libc::LOG_INFO, msg);
}

fn verbose_or_debug(logopt: u32) -> bool {
    let opt_log = logopt & (LOGOPT_DEBUG | LOGOPT_VERBOSE);
    have_log_debug() || have_log_verbose() || opt_log != 0
}

/// `log_notice()`.
pub fn log_notice(logopt: u32, msg: &[u8]) {
    if verbose_or_debug(logopt) {
        emit_pri(libc::LOG_NOTICE, msg);
    }
}

/// `log_warn()`.
pub fn log_warn(logopt: u32, msg: &[u8]) {
    if verbose_or_debug(logopt) {
        emit_pri(libc::LOG_WARNING, msg);
    }
}

/// `log_error()`.
pub fn log_error(_logopt: u32, msg: &[u8]) {
    emit_pri(libc::LOG_ERR, msg);
}

/// `log_crit()`.
pub fn log_crit(_logopt: u32, msg: &[u8]) {
    emit_pri(libc::LOG_CRIT, msg);
}

/// `log_debug()` (syslog's priority for it is `LOG_WARNING`, as C has it).
pub fn log_debug(logopt: u32, msg: &[u8]) {
    let opt_log = logopt & LOGOPT_DEBUG;
    if !have_log_debug() && opt_log == 0 {
        return;
    }
    emit_pri(libc::LOG_WARNING, msg);
}

/// `logmsg()`.
pub fn logmsg(msg: &[u8]) {
    emit_pri(libc::LOG_CRIT, msg);
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
