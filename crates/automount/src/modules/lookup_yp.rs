//! `modules/lookup_yp.c` (also `nis`). This phase has the start of its setup:
//! without a NIS domain (`yp_get_default_domain()` failing, as it does when the
//! domain is unset or `(none)`) it fails quietly. The YP client comes in phase 2.

use crate::libautofs::args::Argv;
use crate::sys;

#[derive(Debug)]
pub struct LookupYp;

/// libnsl's `yp_get_default_domain()`: the domain, or `None` for `YPERR_NODOM`.
fn yp_get_default_domain() -> Option<Vec<u8>> {
    let d = sys::getdomainname()?;
    if d == b"(none)" {
        return None;
    }
    Some(d)
}

/// `lookup_init()`: `None` if it fails.
pub fn lookup_init(_mapfmt: Option<&[u8]>, argv: &Argv) -> Option<LookupYp> {
    if argv.is_empty() {
        logerr!("do_init", "117", "lookup(yp): no map name");
        return None;
    }
    yp_get_default_domain()?;
    panic!("lookup module yp isn't ported yet (phase 5)");
}
