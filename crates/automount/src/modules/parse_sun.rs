//! `modules/parse_sun.c`: the module's setup (the map options: `-D` macros,
//! `--[no-]slashify-colons`, the mount options; the global options merge; the
//! shared NFS mount module, opened by the first parse context and closed by the
//! last), and `parse_mount()` for plain entries: `$`/`&` expansion, the
//! entry's options, the locations (replicated ones joined with spaces), and
//! `sun_mount()`'s pseudo options (`fstype=`, `[no]strict`, `[no-]use-weight-only`)
//! on the way to the mount module. Multi-mount entries come in phase 4.

use std::sync::Mutex;

use crate::daemon::master::GLOBALS;
use std::sync::Arc;

use crate::daemon::master::{AutofsPoint, MOUNT_FLAG_USE_WEIGHT_ONLY, MapSource};
use crate::daemon::module::{self, MountMod, ParseMod};
use crate::libautofs::args::Argv;
use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::libautofs::log::{LOGOPT_ANY, LOGOPT_NONE};
use crate::libautofs::macros::{self, Table};
use crate::libautofs::mounts;
use crate::libautofs::parse_subs::{check_colon, chunklen, dequote, skipspace, strmcmp};

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

/// `expandsunent()`: `&` is the key (white space in it escaped), `$NAME` and
/// `${NAME}` are macros; colons after the first `:/` become slashes if
/// `slashify_colons`.
pub fn expandsunent(src: &[u8], key: &[u8], svc: &[macros::SubstVar], slashify_colons: bool) -> Vec<u8> {
    let src = cstr::c(src);
    let at = |i: usize| src.get(i).copied().unwrap_or(0);
    let mut dst = Vec::new();
    let mut seen_colons = false;
    let mut i = 0;
    while i < src.len() {
        let ch = src[i];
        i += 1;
        match ch {
            b'&' => {
                for &k in cstr::c(key) {
                    if cstr::isspace(k) {
                        dst.push(b'\\');
                    }
                    dst.push(k);
                }
            }
            b'$' => {
                if at(i) == b'{' {
                    i += 1;
                    let Some(close) = cstr::strchr(&src[i..], b'}') else {
                        // Ignore the rest of the string.
                        return dst;
                    };
                    if let Some(sv) = macros::macro_findvar(svc, &src[i..], close) {
                        dst.extend_from_slice(&sv.val);
                    }
                    i += close + 1;
                } else {
                    if cstr::isblank(at(i)) || at(i) == 0 {
                        dst.push(ch);
                        continue;
                    }
                    let mut p = i;
                    while at(p).is_ascii_alphanumeric() || at(p) == b'_' {
                        p += 1;
                    }
                    if let Some(sv) = macros::macro_findvar(svc, &src[i..], p - i) {
                        dst.extend_from_slice(&sv.val);
                    }
                    i = p;
                }
            }
            b'\\' => {
                dst.push(ch);
                if at(i) != 0 {
                    dst.push(at(i));
                    i += 1;
                }
            }
            b'"' => {
                dst.push(ch);
                while at(i) != 0 && at(i) != b'"' {
                    dst.push(at(i));
                    i += 1;
                }
                if at(i) != 0 {
                    dst.push(at(i));
                    i += 1;
                }
            }
            b':' => {
                dst.push(if seen_colons && slashify_colons { b'/' } else { b':' });
                if at(i) == b'/' {
                    seen_colons = true;
                }
            }
            _ => {
                if cstr::isspace(ch) {
                    seen_colons = false;
                }
                dst.push(ch);
            }
        }
    }
    dst
}

/// `parse_options()`: if `s` starts with `-`, the option chunk after it
/// (dequoted) and where it ends.
fn parse_options(s: &[u8], ret: &mut Option<Vec<u8>>, logopt: u32) -> usize {
    if s.first() != Some(&b'-') {
        return 0;
    }
    let cp = &s[1..];
    let len = chunklen(cp, false);
    *ret = dequote(cp, len, logopt);
    1 + len
}

/// `check_is_multi()`: whether the entry has several `path location` pairs.
fn check_is_multi(mapent: &[u8]) -> bool {
    let s = cstr::c(mapent);
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut p = 0;
    if at(p) == b'"' {
        p += 1;
    }
    if at(p) == b'/' {
        return true;
    }
    let mut not_first_chunk = false;
    while at(p) != 0 {
        p += skipspace(&s[p.min(s.len())..]);
        if not_first_chunk {
            if at(p) == b'"' {
                p += 1;
            }
            if at(p) == b'-' {
                p += 1;
            }
            if at(p) == b'/' {
                return true;
            }
        }
        while at(p) == b'-' {
            p += chunklen(&s[p..], false);
            p += skipspace(&s[p.min(s.len())..]);
        }
        let rest = &s[p.min(s.len())..];
        p += chunklen(rest, check_colon(rest));
        not_first_chunk = true;
    }
    false
}

/// `validate_location()`.
fn validate_location(logopt: u32, loc: &[u8]) -> bool {
    let loc = cstr::c(loc);
    let at = |i: usize| loc.get(i).copied().unwrap_or(0);
    if at(0) == b':' {
        return true;
    }
    if at(0) == b',' {
        error!(logopt, "validate_location", "missing first host name in location {}", loc);
        return false;
    }
    let mut p = 0;
    if !check_colon(loc) {
        let esc_colon = cstr::strchr(loc, b'\\').is_some_and(|e| at(e + 1) == b':');
        let pre = |x: &[u8]| loc.starts_with(x);
        if cstr::strchr(loc, b':').is_none()
            || esc_colon
            || pre(b"file:")
            || pre(b"yp:")
            || pre(b"nis:")
            || pre(b"nisplus:")
            || pre(b"ldap:")
            || pre(b"ldaps:")
            || pre(b"sss:")
            || pre(b"dir:")
        {
            return true;
        }
        error!(logopt, "validate_location", "expected colon delimeter not found in location {}", loc);
        return false;
    }
    while at(p) != 0 && !(at(p) == b':' && at(p + 1) == b'/') {
        let c = at(p);
        if !(c.is_ascii_alphanumeric() || b"-._,()#@:[]%".contains(&c)) {
            let ch = [c];
            error!(logopt, "validate_location", "invalid character \"{}\" found in location {}", &ch[..], loc);
            return false;
        }
        if c == b',' {
            let next = at(p + 1);
            if next == b',' || next == b':' {
                error!(logopt, "validate_location", "missing host name in location {}", loc);
                return false;
            }
        }
        p += 1;
    }
    if at(p) != 0 && at(p) == b':' && at(p + 1) == b'/' {
        p += 1;
    }
    if at(p) == 0 {
        error!(logopt, "validate_location", "invalid location {}", loc);
        return false;
    }
    true
}

/// `_strncmp(s1, s2, n)` with `s2` the rest of the options from `cp`.
fn opt_is(pat: &[u8], cp: &[u8], n: usize) -> bool {
    crate::libautofs::cat_path::strncmp_len(pat, cp, n) == 0
}

impl ParseSun {
    /// `sun_mount()`.
    fn sun_mount(
        &self,
        ap: &Arc<AutofsPoint>,
        root: &[u8],
        name: &[u8],
        loc: Option<&[u8]>,
        options: Option<&[u8]>,
    ) -> i32 {
        let logopt = ap.logopt();
        let mut fstype: Vec<u8> = b"nfs".to_vec();
        let mut nonstrict = true;
        let mut use_weight_only: i32 = (ap.lock().flags & MOUNT_FLAG_USE_WEIGHT_ONLY) as i32;
        let mut options: Option<Vec<u8>> = options.filter(|o| !o.is_empty()).map(|o| cstr::c(o).to_vec());
        if let Some(opts) = options.clone() {
            let len = opts.len() + 1;
            let mut np: Vec<u8> = Vec::new();
            let at = |i: usize| opts.get(i).copied().unwrap_or(0);
            let mut comma = 0;
            while at(comma) != 0 {
                while at(comma) == b',' {
                    comma += 1;
                }
                let cp = comma;
                while at(comma) != 0 && at(comma) != b',' {
                    comma += 1;
                }
                let chunk = &opts[cp..comma];
                // The C copies the chunk and the delimiter after it (',' or NUL).
                let with_delim = |np: &mut Vec<u8>| {
                    np.extend_from_slice(chunk);
                    np.push(at(comma));
                };
                let rest = &opts[cp..];
                if opt_is(b"fstype=", rest, 7) {
                    fstype = chunk[7.min(chunk.len())..].to_vec();
                } else if opt_is(b"nonstrict", rest, 9) {
                    nonstrict = true;
                } else if opt_is(b"strict", rest, 6) && comma - cp == 6 {
                    nonstrict = false;
                } else if opt_is(b"nobrowse", rest, 8) || opt_is(b"browse", rest, 6) || opt_is(b"timeout=", rest, 8) {
                    if fstype == b"autofs" || cstr::strstr(rest, b"fstype=autofs").is_some() {
                        with_delim(&mut np);
                    }
                } else if opt_is(b"no-use-weight-only", rest, 18) {
                    use_weight_only = -1;
                } else if opt_is(b"use-weight-only", rest, 15) {
                    use_weight_only = MOUNT_FLAG_USE_WEIGHT_ONLY as i32;
                } else if opt_is(b"bg", rest, 2) || opt_is(b"nofg", rest, 4) {
                    continue;
                } else {
                    with_delim(&mut np);
                }
            }
            if np.len() > len {
                warn!(logopt, "parse(sun): options string truncated");
                np.truncate(len);
            } else if !np.is_empty() {
                np.pop();
            }
            options = Some(cstr::c(&np).to_vec());
        }
        if fstype == b"autofs"
            && let Some(m) = &self.macros
        {
            let mut n = match &options {
                Some(o) if !o.is_empty() => {
                    let mut n = o.clone();
                    n.push(b',');
                    n
                }
                _ => Vec::new(),
            };
            if !n.is_empty() {
                n.extend_from_slice(m);
                options = Some(n);
            } else {
                error!(logopt, "sun_mount", "parse(sun): alloca failed for options");
            }
        }
        let entry = ap.entry();
        let maps_type = entry.maps().first().and_then(|m| m.ty());
        if maps_type.as_deref().is_some_and(|t| cstr::eq(t, b"hosts")) {
            match &options {
                Some(o) if !o.is_empty() => {
                    let suid = cstr::strstr(o, b"suid").is_none();
                    let dev = cstr::strstr(o, b"dev").is_none();
                    if suid || dev {
                        let mut t = o.clone();
                        if suid {
                            t.extend_from_slice(b",nosuid");
                        }
                        if dev {
                            t.extend_from_slice(b",nodev");
                        }
                        options = Some(t);
                    }
                }
                _ => options = Some(b"nosuid,nodev".to_vec()),
            }
        }
        let loc = loc.unwrap_or(b"");
        let o_str = crate::daemon::master::cstr_or_null(&options);
        let rv = if fstype == b"nfs" || fstype == b"nfs4" {
            let what = loc.to_vec();
            if use_weight_only != 0 {
                let w: &[u8] = if use_weight_only == MOUNT_FLAG_USE_WEIGHT_ONLY as i32 {
                    b"use-weight-only"
                } else {
                    b"no-use-weight-only"
                };
                options = Some(match &options {
                    Some(o) if !o.is_empty() => {
                        let mut t = o.clone();
                        t.push(b',');
                        t.extend_from_slice(w);
                        t
                    }
                    _ => w.to_vec(),
                });
            }
            debug!(
                logopt,
                "sun_mount",
                "parse(sun): mounting root {}, mountpoint {}, what {}, fstype {}, options {}",
                root,
                name,
                what,
                fstype,
                crate::daemon::master::cstr_or_null(&options)
            );
            let _ = o_str;
            let mut g = NFS.lock().unwrap();
            let m = g.0.as_mut().expect("the NFS mount module");
            m.mount(ap, root, name, Some(&what), &fstype, options.as_deref())
        } else {
            let what: Option<Vec<u8>> = if loc.is_empty() {
                None
            } else if loc[0] == b':' {
                Some(loc[1..].to_vec())
            } else {
                Some(loc.to_vec())
            };
            debug!(
                logopt,
                "sun_mount",
                "parse(sun): mounting root {}, mountpoint {}, what {}, fstype {}, options {}",
                root,
                name,
                crate::daemon::master::cstr_or_null(&what),
                fstype,
                crate::daemon::master::cstr_or_null(&options)
            );
            crate::daemon::mount::do_mount(ap, root, name, what.as_deref(), &fstype, options.as_deref())
        };
        if nonstrict && rv != 0 {
            return -rv;
        }
        rv
    }
}

impl ParseMod for ParseSun {
    /// `parse_mount()`.
    fn mount(&mut self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8], mapent: Option<&[u8]>) -> i32 {
        let logopt = ap.logopt();
        let Some(mapent) = mapent else {
            warn!(logopt, "parse(sun): error: empty map entry");
            return 1;
        };
        let _ = map;
        let pmapent = {
            let _l = macros::macro_lock();
            mounts::addstdenv(&mut self.subst, None);
            let e = expandsunent(mapent, name, &self.subst, self.slashify_colons);
            if e.is_empty() {
                error!(logopt, "parse_mount", "parse(sun): failed to expand map entry");
                mounts::removestdenv(&mut self.subst, None);
                return 1;
            }
            mounts::removestdenv(&mut self.subst, None);
            e
        };
        debug!(logopt, "parse_mount", "parse(sun): expanded entry: {}", pmapent);
        let append_options = defaults::defaults_get_append_options() != 0;
        let mut options: Option<Vec<u8>> = Some(self.optstr.clone().unwrap_or_default());
        let mut p = skipspace(&pmapent);
        let at = |i: usize| pmapent.get(i).copied().unwrap_or(0);
        if at(p) == b'-' {
            let mut mnt_options: Option<Vec<u8>> = None;
            loop {
                let mut noptions = None;
                p += parse_options(&pmapent[p..], &mut noptions, logopt);
                if let (Some(m), Some(n)) = (&mnt_options, &noptions)
                    && cstr::strstr(n, m).is_some()
                {
                    mnt_options = noptions;
                } else if noptions.is_some() {
                    mnt_options = concat_options(mnt_options.take(), noptions);
                }
                p += skipspace(&pmapent[p.min(pmapent.len())..]);
                if at(p) != b'-' {
                    break;
                }
            }
            if options.is_some() && !append_options {
                options = None;
            }
            if append_options {
                if let (Some(o), Some(m)) = (&options, &mnt_options)
                    && cstr::strstr(m, o).is_some()
                {
                    options = mnt_options;
                } else if mnt_options.is_some() {
                    options = concat_options(options.take(), mnt_options);
                }
            } else {
                options = mnt_options;
            }
        }
        debug!(
            logopt,
            "parse_mount",
            "parse(sun): gathered options: {}",
            crate::daemon::master::cstr_or_null(&options)
        );
        let rest = &pmapent[p.min(pmapent.len())..];
        if check_is_multi(rest) {
            panic!("multi-mount entries aren't ported yet (phase 4)");
        }
        let l = chunklen(rest, check_colon(rest));
        let Some(mut loc) = dequote(rest, l, logopt) else {
            warn!(logopt, "parse(sun): null location or out of memory");
            return 1;
        };
        if rest.first() == Some(&b'/') {
            warn!(logopt, "parse(sun): error location begins with \"/\"");
            return 1;
        }
        if !validate_location(logopt, &loc) {
            return 1;
        }
        debug!(logopt, "parse_mount", "parse(sun): dequote(\"{}\") -> {}", &rest[..l.min(rest.len())], loc);
        p += l;
        p += skipspace(&pmapent[p.min(pmapent.len())..]);
        while at(p) != 0 {
            let r = &pmapent[p..];
            let l = chunklen(r, check_colon(r));
            let Some(ent) = dequote(r, l, logopt) else {
                warn!(logopt, "parse(sun): null location or out of memory");
                return 1;
            };
            if !validate_location(logopt, &ent) {
                return 1;
            }
            debug!(logopt, "parse_mount", "parse(sun): dequote(\"{}\") -> {}", &r[..l.min(r.len())], ent);
            loc.push(b' ');
            loc.extend_from_slice(&ent);
            p += l;
            p += skipspace(&pmapent[p.min(pmapent.len())..]);
        }
        let opts = options.clone().unwrap_or_default();
        let loc: Option<Vec<u8>> =
            if cstr::strstr(&opts, b"fstype=autofs").is_some() && cstr::strstr(&opts, b"hosts").is_some() {
                None
            } else {
                if loc.is_empty() {
                    error!(logopt, "parse_mount", "parse(sun): entry {} is empty!", name);
                    return 1;
                }
                Some(loc)
            };
        debug!(
            logopt,
            "parse_mount",
            "parse(sun): core of entry: options={}, loc={}",
            crate::daemon::master::cstr_or_null(&options),
            loc.clone().unwrap_or_default()
        );
        let path = ap.path();
        if path == b"/-" {
            self.sun_mount(ap, name, name, loc.as_deref(), options.as_deref())
        } else {
            self.sun_mount(ap, &path, name, loc.as_deref(), options.as_deref())
        }
    }

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
