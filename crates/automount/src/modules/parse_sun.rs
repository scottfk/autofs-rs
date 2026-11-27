//! `modules/parse_sun.c`: the module's setup (the map options: `-D` macros,
//! `--[no-]slashify-colons`, the mount options; the global options merge; the
//! shared NFS mount module, opened by the first parse context and closed by the
//! last), and `parse_mount()` for plain entries: `$`/`&` expansion, the
//! entry's options, the locations (replicated ones joined with spaces), and
//! `sun_mount()`'s pseudo options (`fstype=`, `[no]strict`, `[no-]use-weight-only`)
//! on the way to the mount module, and multi-mount entries, whose offsets go
//! into the cache as a tree under the entry and get triggers of their own.

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
use crate::libautofs::parse_subs::{self, check_colon, chunklen, dequote, skipspace, strmcmp};

const MODPREFIX: &[u8] = b"parse(sun): ";

/// `mount_nfs` and `init_ctr`.
static NFS: Mutex<(Option<Box<dyn MountMod>>, u32)> = Mutex::new((None, 0));

/// A `struct parse_context`.
#[derive(Debug)]
pub struct SunCtx {
    pub optstr: Option<Vec<u8>>,
    pub macros: Option<Vec<u8>>,
    pub subst: Table,
    pub slashify_colons: bool,
}

/// The parser's context (`struct parse_context`), shared by every caller:
/// held only briefly, never across a mount.
#[derive(Debug)]
pub struct ParseSun {
    ctx: Mutex<SunCtx>,
}

impl ParseSun {
    fn optstr(&self) -> Option<Vec<u8>> {
        self.ctx.lock().unwrap().optstr.clone()
    }

    fn macros(&self) -> Option<Vec<u8>> {
        self.ctx.lock().unwrap().macros.clone()
    }
}

fn default_context() -> SunCtx {
    SunCtx { optstr: None, macros: None, subst: Vec::new(), slashify_colons: true }
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
fn do_init(argv: &Argv, ctxt: &mut SunCtx) -> i32 {
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
    Some(ParseSun { ctx: Mutex::new(ctxt) })
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
            && let Some(m) = &self.macros()
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
    fn subst(&self) -> Option<Table> {
        Some(self.ctx.lock().unwrap().subst.clone())
    }

    /// `parse_mount()`.
    fn mount(&self, ap: &Arc<AutofsPoint>, map: &Arc<MapSource>, name: &[u8], mapent: Option<&[u8]>) -> i32 {
        let logopt = ap.logopt();
        let Some(mapent) = mapent else {
            warn!(logopt, "parse(sun): error: empty map entry");
            return 1;
        };
        let mc = map.mc();
        // Offsets were expanded with their multi-mount: not again, so quoting
        // stays the same.
        let is_offset = name.first() == Some(&b'/') && {
            let c = mc.lock();
            c.lookup_distinct(name).is_some_and(|p| c.get(p).mm_nonroot())
        };
        let pmapent = if is_offset {
            cstr::c(mapent).to_vec()
        } else {
            let _l = macros::macro_lock();
            let mut c = self.ctx.lock().unwrap();
            mounts::addstdenv(&mut c.subst, None);
            let e = expandsunent(mapent, name, &c.subst, c.slashify_colons);
            mounts::removestdenv(&mut c.subst, None);
            drop(c);
            if e.is_empty() {
                error!(logopt, "parse_mount", "parse(sun): failed to expand map entry");
                return 1;
            }
            e
        };
        debug!(logopt, "parse_mount", "parse(sun): expanded entry: {}", pmapent);
        let append_options = defaults::defaults_get_append_options() != 0;
        let mut options: Option<Vec<u8>> = Some(self.optstr().unwrap_or_default());
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
            let o = options.clone().unwrap_or_default();
            return self.parse_multi(ap, map, name, &pmapent, p, &o);
        }
        // An offset of a multi-mount was parsed with it, options and all:
        // the rest is the location.
        let is_mm = name.first() == Some(&b'/') && {
            let c = mc.lock();
            c.lookup_distinct(name).is_some_and(|q| c.get(q).is_mm())
        };
        if is_mm {
            let o = options.clone().unwrap_or_default();
            return self.mount_subtree(ap, &mc, name, Some(rest), &o);
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
    fn reinit(&self, argv: &Argv) -> i32 {
        let mut new = default_context();
        if do_init(argv, &mut new) != 0 {
            return 1;
        }
        *self.ctx.lock().unwrap() = new;
        0
    }

    /// `parse_done()`.
    fn done(&self) -> i32 {
        let m = {
            let mut g = NFS.lock().unwrap();
            g.1 = g.1.wrapping_sub(1);
            if g.1 == 0 { g.0.take() } else { None }
        };
        m.map_or(0, module::close_mount)
    }
}

// ---------------------------------------------------------------------------
// Multi-mount entries.

const LKP_MULTI: u32 = 0x0008;
const MAPENT_MAX_LEN: usize = 16384;
const PATH_MAX: usize = 4096;

/// `span_space()`: the length of a path that may be quoted.
fn span_space(s: &[u8], maxlen: usize) -> usize {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let (mut p, mut len) = (0usize, 0usize);
    while at(p) != 0 && !cstr::isblank(at(p)) && len < maxlen {
        if at(p) == b'"' {
            // while (*p++ && len++ < maxlen) if (*p == '"') break;
            loop {
                let c = at(p);
                p += 1;
                if c == 0 {
                    break;
                }
                let ok = len < maxlen;
                len += 1;
                if !ok {
                    break;
                }
                if at(p) == b'"' {
                    break;
                }
            }
        } else if at(p) == b'\\' {
            p += 2;
            len += 2;
            continue;
        }
        p += 1;
        len += 1;
    }
    len
}

/// Whether `p` starts a location rather than an offset path.
fn starts_location(s: &[u8], p: usize) -> bool {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    (at(p) == b'"' && at(p + 1) != b'/') || (at(p) != b'"' && at(p) != b'/')
}

/// `parse_mapent()`: an offset's options (added to `g_options`) and its
/// locations; how much was used, or `None` (C's 0).
fn parse_mapent(ent: &[u8], g_options: &[u8], logopt: u32) -> Option<(usize, Vec<u8>, Option<Vec<u8>>)> {
    let at = |i: usize| ent.get(i).copied().unwrap_or(0);
    let mut p = 0usize;
    let mut myoptions: Vec<u8> = cstr::c(g_options).to_vec();
    // Local options are appended to the per-map ones.
    if at(p) == b'-' {
        loop {
            let mut newopt = None;
            p += parse_options(&ent[p..], &mut newopt, logopt);
            match newopt {
                Some(n) if cstr::strstr(&n, &myoptions).is_some() => myoptions = n,
                Some(n) => match concat_options(Some(myoptions.clone()), Some(n)) {
                    Some(t) => myoptions = t,
                    None => myoptions = Vec::new(),
                },
                None => {}
            }
            p += skipspace(&ent[p.min(ent.len())..]);
            if at(p) != b'-' {
                break;
            }
        }
    }
    debug!(logopt, "parse_mapent", "parse(sun): gathered options: {}", myoptions);
    let autofs_hosts = |o: &[u8]| cstr::strstr(o, b"fstype=autofs").is_some() && cstr::strstr(o, b"hosts").is_some();
    let rest = &ent[p.min(ent.len())..];
    let l = chunklen(rest, check_colon(rest));
    let Some(mut loc) = dequote(rest, l, logopt) else {
        if autofs_hosts(&myoptions) {
            warn!(logopt, "parse(sun): possible missing location");
            return None;
        }
        return Some((p, myoptions, None));
    };
    if rest.first() == Some(&b'/') {
        warn!(logopt, "parse(sun): error location begins with \"/\"");
        return None;
    }
    if !validate_location(logopt, &loc) {
        return None;
    }
    debug!(logopt, "parse_mapent", "parse(sun): dequote(\"{}\") -> {}", &rest[..l.min(rest.len())], loc);
    p += l;
    p += skipspace(&ent[p.min(ent.len())..]);
    while at(p) != 0 && starts_location(ent, p) {
        let r = &ent[p..];
        let l = chunklen(r, check_colon(r));
        match dequote(r, l, logopt) {
            None => {
                if autofs_hosts(&myoptions) {
                    warn!(logopt, "parse(sun): null location or out of memory");
                    return None;
                }
            }
            Some(chunk) => {
                if r.first() == Some(&b'/') {
                    warn!(logopt, "parse(sun): error location begins with \"/\"");
                    return None;
                }
                if !validate_location(logopt, &chunk) {
                    return None;
                }
                debug!(logopt, "parse_mapent", "parse(sun): dequote(\"{}\") -> {}", &r[..l.min(r.len())], chunk);
                loc.push(b' ');
                loc.extend_from_slice(&chunk);
            }
        }
        p += l;
        p += skipspace(&ent[p.min(ent.len())..]);
    }
    Some((p, myoptions, Some(loc)))
}

/// `update_offset_entry()`: cache an offset of the multi-mount `name`, and
/// list it (shortest path first, near enough) for the tree.
#[allow(clippy::too_many_arguments)]
fn update_offset_entry(
    ap: &Arc<AutofsPoint>,
    mc: &Arc<crate::libautofs::cache::Cache>,
    offsets: &mut Vec<u64>,
    name: &[u8],
    m_root: &[u8],
    m_offset: &[u8],
    myoptions: &[u8],
    loc: Option<&[u8]>,
    age: i64,
) -> i32 {
    use crate::libautofs::cache::{CHE_DUPLICATE, CHE_FAIL, CHE_OK};
    let logopt = ap.logopt();
    let m_offset = cstr::c(m_offset);
    if loc.is_none_or(|l| l.is_empty()) {
        // Only the internal hosts map may have no location.
        let ty = ap.entry().maps().first().and_then(|m| m.ty());
        if ty.as_deref().is_none_or(|t| !cstr::eq(t, b"hosts")) {
            error!(
                logopt,
                "update_offset_entry",
                "parse(sun): syntax error in offset {} -> {}",
                m_offset,
                loc.unwrap_or(b"(null)")
            );
            return CHE_FAIL;
        }
    }
    if m_offset.is_empty() {
        error!(
            logopt,
            "update_offset_entry",
            "parse(sun): syntax error in offset {} -> {}",
            m_offset,
            loc.unwrap_or(b"(null)")
        );
        return CHE_FAIL;
    }
    // A trailing '/' causes pain.
    let mut o_len = m_offset.len();
    while o_len > 1 && m_offset[o_len - 1] == b'/' {
        o_len -= 1;
    }
    let m_key_len = m_root.len() + o_len;
    if m_key_len > PATH_MAX {
        error!(logopt, "update_offset_entry", "parse(sun): multi mount key too long");
        return CHE_FAIL;
    }
    let m_key = [m_root, &m_offset[..o_len]].concat();
    let myoptions = cstr::c(myoptions);
    let m_options_len = if myoptions.is_empty() { 0 } else { myoptions.len() + 2 };
    let m_mapent_len = loc.map_or(0, |l| l.len());
    if m_mapent_len + m_options_len > MAPENT_MAX_LEN {
        error!(logopt, "update_offset_entry", "parse(sun): multi mount mapent too long");
        return CHE_FAIL;
    }
    let mut m_mapent = Vec::new();
    if !myoptions.is_empty() {
        m_mapent.push(b'-');
        m_mapent.extend_from_slice(myoptions);
        if let Some(l) = loc {
            m_mapent.push(b' ');
            m_mapent.extend_from_slice(l);
        }
    } else if let Some(l) = loc {
        m_mapent.extend_from_slice(l);
    }
    let ret = {
        let mut c = mc.lock();
        let ret = c.update_offset(logopt, name, &m_key, &m_mapent, age);
        if let Some(p) = c.lookup_distinct(&m_key) {
            let (id, len) = (c.get(p).id, c.get(p).key.len());
            if !offsets.contains(&id) {
                // list_for_each_prev(): before the first (from the end) that
                // isn't longer, or at the end when that's the last.
                let lens: Vec<usize> =
                    offsets.iter().map(|o| c.by_id(*o).map(|q| c.get(q).key.len()).unwrap_or(0)).collect();
                let mut placed = false;
                for i in (0..offsets.len()).rev() {
                    if len >= lens[i] {
                        if i == offsets.len() - 1 {
                            offsets.push(id);
                        } else {
                            offsets.insert(i, id);
                        }
                        placed = true;
                        break;
                    }
                }
                if !placed {
                    offsets.insert(0, id);
                }
            }
        }
        ret
    };
    if ret == CHE_DUPLICATE {
        warn!(logopt, "parse(sun): syntax error or duplicate offset {} -> {}", m_offset, loc.unwrap_or(b"(null)"));
        CHE_OK
    } else if ret == CHE_FAIL {
        debug!(
            logopt,
            "update_offset_entry", "parse(sun): failed to update multi-mount offset {} -> {}", m_offset, m_mapent
        );
        ret
    } else {
        debug!(logopt, "update_offset_entry", "parse(sun): updated multi-mount offset {} -> {}", m_offset, m_mapent);
        CHE_OK
    }
}

/// `cleanup_offset_entries()`.
fn cleanup_offset_entries(ap: &Arc<AutofsPoint>, mc: &Arc<crate::libautofs::cache::Cache>, offsets: &[u64]) {
    let mut c = mc.lock();
    for id in offsets {
        let Some(p) = c.by_id(*id) else { continue };
        let key = c.get(p).key.clone();
        if c.delete(&key) != crate::libautofs::cache::CHE_OK {
            crit!(ap.logopt(), "cleanup_offset_entries", "failed to delete offset {}", key);
        }
    }
}

impl ParseSun {
    /// `mount_subtree()`: mount a multi-mount's root offset (or a nesting
    /// point) and the offset triggers directly in it.
    fn mount_subtree(
        &self,
        ap: &Arc<AutofsPoint>,
        mc: &Arc<crate::libautofs::cache::Cache>,
        name: &[u8],
        loc: Option<&[u8]>,
        options: &[u8],
    ) -> i32 {
        let logopt = ap.logopt();
        let me = {
            let c = mc.lock();
            c.lookup_distinct(name).map(|p| (c.get(p).id, c.get(p).is_mm_root(), c.get(p).key.clone(), c.get(p).age))
        };
        let Some((id, is_root, key, age)) = me else { return 0 };
        let mut rv = 0;
        let mut ret = 0;
        if is_root {
            let Some(mut rkey) = mounts::mount_fullpath(PATH_MAX, &ap.path(), &key) else {
                warn!(logopt, "path loo long");
                mounts::tree_mapent_delete_offsets(ap, mc, name);
                return 1;
            };
            rkey.push(b'/');
            // Mount the root offset if there is one.
            let ro = {
                let c = mc.lock();
                c.lookup_distinct(&rkey).map(|p| (c.get(p).age, c.get(p).mapent.clone()))
            };
            if let Some((ro_age, ro_mapent)) = ro
                && ro_age == age
            {
                let Some((_, myoptions, ro_loc)) = parse_mapent(&ro_mapent.unwrap_or_default(), options, logopt) else {
                    warn!(logopt, "parse(sun): failed to parse root offset");
                    mounts::tree_mapent_delete_offsets(ap, mc, name);
                    return 1;
                };
                rv = self.sun_mount(ap, &rkey, name, ro_loc.as_deref(), Some(&myoptions));
            }
            if rv <= 0 {
                ret = mounts::tree_mapent_mount_offsets(ap, mc, id, true);
                if ret == 0 {
                    mounts::tree_mapent_cleanup_offsets(ap, mc, id);
                    error!(logopt, "mount_subtree", "parse(sun): failed to mount offset triggers");
                    mounts::tree_mapent_delete_offsets(ap, mc, name);
                    return 1;
                }
            }
        } else {
            // Mounts at nesting points must work for their offsets to be mounted.
            rv = self.sun_mount(ap, name, name, loc, Some(options));
            if rv <= 0 {
                ret = mounts::tree_mapent_mount_offsets(ap, mc, id, true);
                if ret == 0 {
                    mounts::tree_mapent_cleanup_offsets(ap, mc, id);
                    error!(logopt, "mount_subtree", "parse(sun): failed to mount offset triggers");
                    return 1;
                }
            }
        }
        // A strict mount failed.
        if rv > 0 {
            return rv;
        }
        // A nonstrict fail with a non-empty multi-mount is a success.
        if rv < 0 && ret > 0 {
            rv = 0;
        }
        rv
    }

    /// The multi-mount branch of `parse_mount()`: cache the entry's offsets,
    /// build its tree and mount the top of it.
    fn parse_multi(
        &self,
        ap: &Arc<AutofsPoint>,
        source: &Arc<MapSource>,
        name: &[u8],
        pmapent: &[u8],
        mut p: usize,
        options: &[u8],
    ) -> i32 {
        use crate::libautofs::cache::CHE_OK;
        let logopt = ap.logopt();
        let mc = source.mc();
        let mapent_len = pmapent.len() + 1;
        let at = |i: usize| pmapent.get(i).copied().unwrap_or(0);
        let Some(m_root) = mounts::mount_fullpath(PATH_MAX, &ap.path(), name) else {
            error!(logopt, "parse_mount", "parse(sun): multi-mount root path too long");
            return 1;
        };
        let age = {
            let mut c = mc.lock();
            let Some(mp) = c.lookup_distinct(name) else {
                drop(c);
                error!(logopt, "parse_mount", "parse(sun): can't find multi root {}", name);
                return 1;
            };
            if !c.get(mp).is_mm() {
                // So we know we're the multi-mount root.
                mounts::tree_mapent_root(&mut c, mp);
            } else if source.lock().flags & crate::daemon::master::MAP_FLAG_FORMAT_AMD != 0 {
                // No multi-mount updates for amd mounts.
                return 0;
            }
            c.get(mp).age
        };
        let mut offsets: Vec<u64> = Vec::new();
        loop {
            let (l, m_offset) = if starts_location(pmapent, p) {
                let m = dequote(b"/", 1, logopt);
                debug!(logopt, "parse_mount", "parse(sun): dequote(\"/\") -> {}", m.clone().unwrap_or_default());
                (0, m)
            } else {
                let l = span_space(&pmapent[p..], mapent_len - p);
                let m = parse_subs::sanitize_path(&pmapent[p..], l, LKP_MULTI, logopt);
                debug!(
                    logopt,
                    "parse_mount",
                    "parse(sun): dequote(\"{}\") -> {}",
                    &pmapent[p..(p + l).min(pmapent.len())],
                    crate::daemon::master::cstr_or_null(&m)
                );
                (l, m)
            };
            let Some(m_offset) = m_offset else {
                warn!(logopt, "parse(sun): null path or out of memory");
                cleanup_offset_entries(ap, &mc, &offsets);
                return 1;
            };
            p += l;
            p += skipspace(&pmapent[p.min(pmapent.len())..]);
            let Some((l, myoptions, loc)) = parse_mapent(&pmapent[p.min(pmapent.len())..], options, logopt) else {
                cleanup_offset_entries(ap, &mc, &offsets);
                return 1;
            };
            if l == 0 {
                cleanup_offset_entries(ap, &mc, &offsets);
                return 1;
            }
            p += l;
            p += skipspace(&pmapent[p.min(pmapent.len())..]);
            let status =
                update_offset_entry(ap, &mc, &mut offsets, name, &m_root, &m_offset, &myoptions, loc.as_deref(), age);
            if status != CHE_OK {
                warn!(logopt, "parse(sun): error adding multi-mount");
                cleanup_offset_entries(ap, &mc, &offsets);
                return 1;
            }
            if !(at(p) == b'/' || (at(p) == b'"' && at(p + 1) == b'/')) {
                break;
            }
        }
        {
            let mut c = mc.lock();
            let Some(mp) = c.lookup_distinct(name) else {
                drop(c);
                cleanup_offset_entries(ap, &mc, &offsets);
                return 1;
            };
            let root = c.get(mp).mm_root.expect("multi-mount root");
            for oe in &offsets {
                if !mounts::tree_mapent_add_node(&mut c, root, *oe) {
                    let k = c.by_id(*oe).map(|q| c.get(q).key.clone()).unwrap_or_default();
                    error!(logopt, "parse_mount", "failed to add offset {} to tree", k);
                }
            }
        }
        self.mount_subtree(ap, &mc, name, None, options)
    }
}
