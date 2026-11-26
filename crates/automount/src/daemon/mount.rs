//! `daemon/mount.c`: `do_mount()`, the generic dispatcher to a mount module.

use std::sync::Arc;

use crate::daemon::master::AutofsPoint;
use crate::daemon::module;
use crate::libautofs::cstr;

/// File systems known not to work with the `generic` module.
const NOT_GENERIC: [&[u8]; 6] = [b"nfs", b"userfs", b"afs", b"autofs", b"changer", b"bind"];

/// `do_mount()`.
pub fn do_mount(
    ap: &Arc<AutofsPoint>,
    root: &[u8],
    name: &[u8],
    what: Option<&[u8]>,
    fstype: &[u8],
    options: Option<&[u8]>,
) -> i32 {
    let logopt = ap.logopt();
    let mut modstr: &[u8] = fstype;
    let mut m = module::open_mount(fstype, None);
    if m.is_none() {
        if !NOT_GENERIC.iter().any(|g| cstr::eq(fstype, g)) {
            modstr = b"generic";
            m = module::open_mount(b"generic", Some(b"(mount):"));
        } else {
            m = module::open_mount(fstype, Some(b"(mount):"));
        }
        if m.is_none() {
            error!(logopt, "do_mount", "cannot find mount method for filesystem {}", fstype);
            return -1;
        }
    }
    let mut m = m.unwrap();
    let w = crate::daemon::master::cstr_or_null(&what.map(|w| w.to_vec()));
    let o = crate::daemon::master::cstr_or_null(&options.map(|o| o.to_vec()));
    if name.first() == Some(&b'/') {
        debug!(logopt, "do_mount", "{} {} type {} options {} using module {}", w, name, fstype, o, modstr);
    } else if root.len() > 1 && root.last() == Some(&b'/') {
        debug!(logopt, "do_mount", "{} {} type {} options {} using module {}", w, root, fstype, o, modstr);
    } else {
        debug!(logopt, "do_mount", "{} {}/{} type {} options {} using module {}", w, root, name, fstype, o, modstr);
    }
    let rv = m.mount(ap, root, name, what, fstype, options);
    module::close_mount(m);
    rv
}
