//! `modules/parse_amd.c`. This phase has the module's setup: unlike the sun
//! parser it takes no options, and `parse_reinit()` does nothing. It keeps its
//! own reference to the NFS mount module (a separate count from the sun
//! parser's, as each `.so` has its own statics).

use std::sync::Mutex;

use crate::daemon::module::{self, MountMod, ParseMod};
use crate::libautofs::args::Argv;

const MODPREFIX: &[u8] = b"parse(amd): ";

/// `mount_nfs` and `init_ctr`.
static NFS: Mutex<(Option<Box<dyn MountMod>>, u32)> = Mutex::new((None, 0));

/// A `struct parse_context`.
#[derive(Debug, Default)]
pub struct ParseAmd {
    pub optstr: Option<Vec<u8>>,
    pub macros: Option<Vec<u8>>,
}

/// `parse_init()`.
pub fn parse_init(_argv: &Argv) -> Option<ParseAmd> {
    let mut g = NFS.lock().unwrap();
    if g.0.is_some() {
        g.1 += 1;
    } else {
        drop(g);
        let m = module::open_mount(b"nfs", Some(MODPREFIX))?;
        let mut g = NFS.lock().unwrap();
        g.0 = Some(m);
        g.1 += 1;
    }
    Some(ParseAmd::default())
}

impl ParseMod for ParseAmd {
    fn reinit(&mut self, _argv: &Argv) -> i32 {
        0
    }

    fn done(self: Box<Self>) -> i32 {
        let m = {
            let mut g = NFS.lock().unwrap();
            g.1 = g.1.wrapping_sub(1);
            if g.1 == 0 { g.0.take() } else { None }
        };
        m.map_or(0, module::close_mount)
    }
}
