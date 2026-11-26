//! `modules/parse_sun.c`. This phase has the module's setup: the map options
//! (`-D` macros, `--[no-]slashify-colons`, the mount options), the global
//! options merge, and the shared NFS mount module, opened by the first parse
//! context and closed by the last.

use std::sync::Mutex;

use crate::daemon::master::GLOBALS;
use crate::daemon::module::{self, MountMod, ParseMod};
use crate::libautofs::args::Argv;
use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::libautofs::log::{LOGOPT_ANY, LOGOPT_NONE};
use crate::libautofs::macros::{self, Table};
use crate::libautofs::parse_subs::strmcmp;

const MODPREFIX: &[u8] = b"parse(sun): ";

/// `mount_nfs` and `init_ctr`.
static NFS: Mutex<(Option<Box<dyn MountMod>>, u32)> = Mutex::new((None, 0));

/// A `struct parse_context`.
#[derive(Debug)]
pub struct ParseSun {
    pub optstr: Option<Vec<u8>>,
    pub macros: Option<Vec<u8>>,
    pub subst: Table,
    pub slashify_colons: bool,
}

fn default_context() -> ParseSun {
    ParseSun { optstr: None, macros: None, subst: Vec::new(), slashify_colons: true }
}

/// `concat_options()`.
fn concat_options(left: Option<Vec<u8>>, right: Option<Vec<u8>>) -> Option<Vec<u8>> {
    let empty = |s: &Option<Vec<u8>>| s.as_deref().is_none_or(|v| v.is_empty());
    if empty(&left) {
        if empty(&right) {
            return None;
        }
        return right;
    }
    if empty(&right) {
        return left;
    }
    let mut r = left.unwrap();
    r.push(b',');
    r.extend_from_slice(&right.unwrap());
    Some(r)
}

/// `do_init()`.
fn do_init(argv: &Argv, ctxt: &mut ParseSun) -> i32 {
    let argc = argv.len();
    let mut i = 0;
    while i < argc {
        let a = argv[i].clone().unwrap_or_default();
        if a.first() == Some(&b'-') && (a.get(1) == Some(&b'D') || a.get(1) == Some(&b'-')) {
            if a[1] == b'D' {
                let def = if a.len() > 2 {
                    a[2..].to_vec()
                } else {
                    i += 1;
                    if i < argc {
                        argv[i].clone().unwrap_or_default()
                    } else {
                        i += 1;
                        continue;
                    }
                };
                let (name, val) = match cstr::strchr(&def, b'=') {
                    Some(e) => (def[..e].to_vec(), def[e + 1..].to_vec()),
                    None => (def.clone(), Vec::new()),
                };
                {
                    let _l = macros::macro_lock();
                    macros::macro_addvar(&mut ctxt.subst, &name, name.len(), Some(&val));
                }
                let m = ctxt.macros.get_or_insert_with(Vec::new);
                if !m.is_empty() {
                    m.push(b',');
                }
                m.extend_from_slice(b"-D");
                m.extend_from_slice(&name);
                m.push(b'=');
                m.extend_from_slice(&val);
            } else {
                let (xopt, bval) = if cstr::neq(&a[2..], b"no-", 3) { (&a[5..], false) } else { (&a[2..], true) };
                if strmcmp(xopt, b"slashify-colons", 1) == 0 {
                    ctxt.slashify_colons = bval;
                } else {
                    error!(LOGOPT_ANY, "do_init", "parse(sun): unknown option: {}", a);
                }
            }
        } else {
            let offset = if a.first() == Some(&b'-') { 1 } else { 0 };
            let opt = &a[offset.min(a.len())..];
            match &mut ctxt.optstr {
                Some(o) => {
                    o.push(b',');
                    o.extend_from_slice(cstr::c(opt));
                }
                None => ctxt.optstr = Some(cstr::c(opt).to_vec()),
            }
        }
        i += 1;
    }
    let global_options = GLOBALS.lock().unwrap().global_options.clone();
    let mut done = false;
    let mut gbl_options = None;
    if let Some(g) = &global_options {
        if ctxt.optstr.as_deref().is_some_and(|o| cstr::strstr(o, g).is_some()) {
            done = true;
        } else {
            gbl_options = Some(g.clone());
        }
    }
    if !done && let Some(g) = gbl_options {
        if defaults::defaults_get_append_options() != 0 {
            ctxt.optstr = concat_options(Some(g), ctxt.optstr.take());
        } else if ctxt.optstr.is_none() {
            ctxt.optstr = Some(g);
        }
    }
    debug!(
        LOGOPT_NONE,
        "do_init",
        "parse(sun): init gathered global options: {}",
        crate::daemon::master::cstr_or_null(&ctxt.optstr)
    );
    0
}

/// `parse_init()`.
pub fn parse_init(argv: &Argv) -> Option<ParseSun> {
    let mut ctxt = default_context();
    if do_init(argv, &mut ctxt) != 0 {
        return None;
    }
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
    Some(ctxt)
}

impl ParseMod for ParseSun {
    /// `parse_reinit()`.
    fn reinit(&mut self, argv: &Argv) -> i32 {
        let mut new = default_context();
        if do_init(argv, &mut new) != 0 {
            return 1;
        }
        *self = new;
        0
    }

    /// `parse_done()`.
    fn done(self: Box<Self>) -> i32 {
        let m = {
            let mut g = NFS.lock().unwrap();
            g.1 = g.1.wrapping_sub(1);
            if g.1 == 0 { g.0.take() } else { None }
        };
        m.map_or(0, module::close_mount)
    }
}
