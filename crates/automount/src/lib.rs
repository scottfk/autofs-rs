//! autofs-rs: a drop-in port of the Linux automounter, autofs 5.1.9. The
//! `automount` binary is `daemon::automount::main()`; the test driver
//! (`automount-drv`) uses the same code.
//!
//! The layout follows upstream's: `libautofs/` is upstream's `lib/`, `libautofs.so` holds, `daemon/`
//! is `automount` itself, and `modules/` are the lookup, parse and mount modules,
//! built in rather than `dlopen()`ed. `tables/` has the flex and bison tables of the
//! three grammars, extracted from the reference build by `tools/gen-tables.py`.
//! Each module names the upstream file it ports.

// Parts of the ported files are only used by later phases.
#![allow(dead_code)]

/// Format bytes like C's `printf("%s ...")`: `bfmt!("a {} b {}", x, y)` with each
/// argument a [`libautofs::Piece`] (byte strings, strings, integers). Each `{}` takes
/// the next argument.
macro_rules! bfmt {
    ($fmt:expr $(, $arg:expr)* $(,)?) => {{
        let pieces: &[&dyn $crate::libautofs::Piece] = &[$(&$arg),*];
        $crate::libautofs::format_pieces($fmt, pieces)
    }};
}

/// `debug(opt, msg, ...)`: `log_debug()` with the function name in front.
macro_rules! debug {
    ($opt:expr, $func:literal, $fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::libautofs::log::log_debug($opt, &bfmt!(concat!($func, ": ", $fmt) $(, $arg)*))
    };
}

/// `info(opt, msg, ...)`.
macro_rules! info {
    ($opt:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::libautofs::log::log_info($opt, &bfmt!($fmt $(, $arg)*))
    };
}

/// `warn(opt, msg, ...)`.
macro_rules! warn {
    ($opt:expr, $fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::libautofs::log::log_warn($opt, &bfmt!($fmt $(, $arg)*))
    };
}

/// `error(opt, msg, ...)`: `log_error()` with the function name in front.
macro_rules! error {
    ($opt:expr, $func:literal, $fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::libautofs::log::log_error($opt, &bfmt!(concat!($func, ": ", $fmt) $(, $arg)*))
    };
}

/// `crit(opt, msg, ...)`: `log_crit()` with the function name in front.
macro_rules! crit {
    ($opt:expr, $func:literal, $fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::libautofs::log::log_crit($opt, &bfmt!(concat!($func, ": ", $fmt) $(, $arg)*))
    };
}

/// `logerr(msg, ...)`: `logmsg()` with the function name and the C source line.
macro_rules! logerr {
    ($func:literal, $line:literal, $fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::libautofs::log::logmsg(&bfmt!(concat!($func, ":", $line, ": ", $fmt) $(, $arg)*))
    };
}

/// autofs's own `assert(x)` (include/log.h): log `FILE:LINE: assertion
/// failed: x` and carry on.
macro_rules! c_assert {
    ($cond:expr, $file:literal, $line:literal, $text:literal) => {
        if !$cond {
            $crate::libautofs::log::logmsg(concat!($file, ":", $line, ": assertion failed: ", $text).as_bytes())
        }
    };
}

/// `logmsg(msg, ...)`.
macro_rules! logmsg {
    ($fmt:literal $(, $arg:expr)* $(,)?) => {
        $crate::libautofs::log::logmsg(&bfmt!($fmt $(, $arg)*))
    };
}

pub mod daemon;
pub mod libautofs;
pub mod modules;
pub mod sys;
#[allow(dead_code)]
mod tables;
