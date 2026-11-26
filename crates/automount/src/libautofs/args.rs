//! `lib/args.c`: argument vectors. A vector is a list of optional strings (C's
//! `char **` with possible NULL entries); its `argc` is the list's length.

use crate::libautofs::cstr;

/// An argument vector.
pub type Argv = Vec<Option<Vec<u8>>>;

/// `add_argv(argc, argv, str)`: `argv` with `str` appended (as its new last
/// entry `argc - 1`).
pub fn add_argv(argv: &Argv, s: &[u8]) -> Argv {
    let mut v = argv.clone();
    v.push(Some(cstr::c(s).to_vec()));
    v
}

/// `append_argv()`.
pub fn append_argv(argv1: &Argv, argv2: &Argv) -> Argv {
    let mut v = argv1.clone();
    v.extend(argv2.iter().cloned());
    v
}

/// `copy_argv()`.
pub fn copy_argv(argv: &Argv) -> Argv {
    argv.clone()
}

/// `compare_argv()`.
pub fn compare_argv(a: &Argv, b: &Argv) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).all(|(x, y)| match (x, y) {
        (Some(x), Some(y)) => cstr::eq(x, y),
        (None, None) => true,
        _ => false,
    })
}

/// `argv[i]`, NULL past the end (C vectors are NULL-terminated).
pub fn arg(argv: &Argv, i: usize) -> Option<&[u8]> {
    argv.get(i).and_then(|a| a.as_deref())
}
