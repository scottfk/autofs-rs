//! `modules/amd_tok.l` and `modules/amd_parse.y`: one amd map entry, parsed into
//! its locations (`amd_parse_list()`), plus the `struct amd_entry` helpers of
//! `lib/mounts.c` (`new_amd_entry()`...).
//!
//! The scanner and its `amd_lval` persist between parses as in C, but each
//! parse flushes the buffer and starts in the `START` state.
//!
//! QUIRKs kept:
//! - `add_selector()` links a new selector in front of the list's *last* one,
//!   so a location keeps only its first and its latest selector (latest first).
//! - `match_map_option_cache_option()` tests `strncmp()`'s result the wrong way
//!   round: anything but `inc...` is "inc", `inc...` is "all".
//! - `sel!=` without a value is a `==` test.
//! - An `opts` list longer than 1023 bytes trips `_FORTIFY_SOURCE`.

use std::sync::Mutex;

use crate::daemon::master::AutofsPoint;
use crate::libautofs::bison::{self, Flow, Grammar, Rhs};
use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::libautofs::flex::{self, Act, Scanner};
use crate::libautofs::log;
use crate::libautofs::macros::{self, SubstVar};
use crate::libautofs::parse_subs::{self, SEL_COMP_EQUAL, SEL_COMP_NONE, SEL_COMP_NOT, SEL_COMP_NOTEQUAL, Selector};
use crate::sys;
use crate::tables::{amd_parse as ap_, amd_tok as at};

pub const AMD_MOUNT_TYPE_NONE: u64 = 0x0000_0000;
pub const AMD_MOUNT_TYPE_AUTO: u64 = 0x0000_0001;
pub const AMD_MOUNT_TYPE_NFS: u64 = 0x0000_0002;
pub const AMD_MOUNT_TYPE_LINK: u64 = 0x0000_0004;
pub const AMD_MOUNT_TYPE_HOST: u64 = 0x0000_0008;
pub const AMD_MOUNT_TYPE_NFSL: u64 = 0x0000_0010;
pub const AMD_MOUNT_TYPE_NFSX: u64 = 0x0000_0020;
pub const AMD_MOUNT_TYPE_LINKX: u64 = 0x0000_0040;
pub const AMD_MOUNT_TYPE_LOFS: u64 = 0x0000_0080;
pub const AMD_MOUNT_TYPE_EXT: u64 = 0x0000_0100;
pub const AMD_MOUNT_TYPE_UFS: u64 = 0x0000_0200;
pub const AMD_MOUNT_TYPE_XFS: u64 = 0x0000_0400;
pub const AMD_MOUNT_TYPE_JFS: u64 = 0x0000_0800;
pub const AMD_MOUNT_TYPE_CACHEFS: u64 = 0x0000_1000;
pub const AMD_MOUNT_TYPE_CDFS: u64 = 0x0000_2000;
pub const AMD_MOUNT_TYPE_PROGRAM: u64 = 0x0000_4000;
pub const AMD_MOUNT_TYPE_MASK: u64 = 0x0000_ffff;
pub const AMD_ENTRY_CUT: u64 = 0x0001_0000;
pub const AMD_DEFAULTS_MERGE: u64 = 0x0100_0000;
pub const AMD_DEFAULTS_RESET: u64 = 0x0200_0000;

pub const AMD_CACHE_OPTION_NONE: u32 = 0x0000;
pub const AMD_CACHE_OPTION_INC: u32 = 0x0001;
pub const AMD_CACHE_OPTION_ALL: u32 = 0x0002;
pub const AMD_CACHE_OPTION_REGEXP: u32 = 0x0004;
pub const AMD_CACHE_OPTION_SYNC: u32 = 0x8000;

const STRTYPE_LEN: usize = 2048;
const MAX_OPTS_LEN: usize = 1024;

/// A `struct amd_entry`. `selector` is the selector list, head first.
#[derive(Debug, Clone, Default)]
pub struct AmdEntry {
    pub path: Option<Vec<u8>>,
    pub flags: u64,
    pub cache_opts: u32,
    pub ty: Option<Vec<u8>>,
    pub map_type: Option<Vec<u8>>,
    pub pref: Option<Vec<u8>>,
    pub fs: Option<Vec<u8>>,
    pub rhost: Option<Vec<u8>>,
    pub rfs: Option<Vec<u8>>,
    pub dev: Option<Vec<u8>>,
    pub opts: Option<Vec<u8>>,
    pub addopts: Option<Vec<u8>>,
    pub remopts: Option<Vec<u8>>,
    pub sublink: Option<Vec<u8>>,
    pub mount: Option<Vec<u8>>,
    pub umount: Option<Vec<u8>>,
    pub selector: Vec<Selector>,
}

/// `new_amd_entry()`: an entry for `${path}`.
pub fn new_amd_entry(sv: &[SubstVar]) -> Option<AmdEntry> {
    let v = macros::macro_findvar(sv, b"path", 4)?;
    Some(AmdEntry { path: Some(v.val), ..AmdEntry::default() })
}

/// The `%union { char strtype[2048]; int inttype; long longtype; }`.
#[derive(Clone)]
pub struct Val(Box<[u8; STRTYPE_LEN]>);

impl std::fmt::Debug for Val {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self.s()))
    }
}

impl Val {
    fn new() -> Val {
        Val(Box::new([0; STRTYPE_LEN]))
    }

    fn s(&self) -> &[u8] {
        cstr::c(&self.0[..])
    }
}

/// The scanner's input: `amd_set_scan_buffer()`'s string and its extra NUL.
struct LineInput {
    line: Vec<u8>,
    pos: usize,
    lim: usize,
}

impl flex::Input for LineInput {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.lim.saturating_sub(self.pos));
        for (i, b) in buf.iter_mut().take(n).enumerate() {
            *b = self.line.get(self.pos + i).copied().unwrap_or(0);
        }
        self.pos += n;
        n
    }
}

struct State {
    scanner: Scanner,
    lval: Val,
    input: LineInput,
    reset_start_state: bool,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

impl State {
    /// `amd_copy_buffer()`.
    fn copy_buffer(&mut self) {
        let text = self.scanner.yytext();
        let n = text.len();
        if n < STRTYPE_LEN {
            self.lval.0[..n].copy_from_slice(text);
            self.lval.0[n] = 0;
        } else {
            self.lval.0[..STRTYPE_LEN - 1].copy_from_slice(&text[..STRTYPE_LEN - 1]);
            self.lval.0[STRTYPE_LEN - 1] = 0;
            let near = cstr::c(&self.lval.0[2030..]).to_vec();
            log::logmsg(&bfmt!("warning: truncated option near {}\n", near));
        }
    }

    /// `amd_lex()`.
    fn lex(&mut self) -> i32 {
        if self.reset_start_state {
            self.scanner.begin(at::START);
            self.reset_start_state = false;
        }
        loop {
            let act = self.scanner.scan(&mut self.input);
            macro_rules! tok {
                ($t:expr) => {{
                    self.copy_buffer();
                    return $t;
                }};
            }
            macro_rules! to_start {
                ($t:expr) => {{
                    self.scanner.begin(at::START);
                    return $t;
                }};
            }
            match act {
                Act::Rule(1) | Act::Rule(2) => {}
                Act::Rule(3) => {
                    self.scanner.begin(at::MAPOPTVAL);
                    tok!(ap_::MAP_OPTION)
                }
                Act::Rule(4) => {
                    self.scanner.begin(at::FSOPTVAL);
                    tok!(ap_::FS_OPTION)
                }
                Act::Rule(5) => {
                    self.scanner.begin(at::MNTOPTVAL);
                    tok!(ap_::MNT_OPTION)
                }
                Act::Rule(6) => {
                    self.scanner.begin(at::SELOPTVAL);
                    tok!(ap_::SELECTOR)
                }
                Act::Rule(7) | Act::Rule(8) => return ap_::NOT,
                Act::Rule(9) | Act::Rule(10) => {
                    self.scanner.begin(at::SELARGVAL);
                    tok!(ap_::SELECTOR)
                }
                Act::Rule(11) => return ap_::CUT,
                Act::Rule(12) => return ap_::HYPHEN,
                Act::Rule(13) => return ap_::SPACE,
                Act::Rule(14) => return ap_::COMMENT,
                Act::Rule(15) => tok!(ap_::OTHER),
                // {NL} in a value state: back to START, keep the \r of a \r\n.
                Act::Rule(16) | Act::Rule(25) | Act::Rule(31) | Act::Rule(39) | Act::Rule(46) => {
                    self.scanner.begin(at::START);
                    self.scanner.yyless(1);
                }
                Act::Rule(17) | Act::Rule(18) | Act::Rule(26) | Act::Rule(27) | Act::Rule(32) | Act::Rule(33) => {
                    to_start!(ap_::SEPERATOR)
                }
                Act::Rule(40) | Act::Rule(41) | Act::Rule(47) | Act::Rule(48) => to_start!(ap_::SEPERATOR),
                Act::Rule(19) | Act::Rule(28) | Act::Rule(34) | Act::Rule(42) => to_start!(ap_::SPACE),
                Act::Rule(20) | Act::Rule(29) | Act::Rule(35) => return ap_::OPTION_ASSIGN,
                Act::Rule(21) => tok!(ap_::FS_TYPE),
                Act::Rule(22) => tok!(ap_::MAP_TYPE),
                Act::Rule(23) => tok!(ap_::CACHE_OPTION),
                Act::Rule(24) | Act::Rule(30) => tok!(ap_::FS_OPT_VALUE),
                Act::Rule(36) | Act::Rule(52) => return ap_::COMMA,
                Act::Rule(37) => return ap_::QUOTE,
                Act::Rule(38) => tok!(ap_::OPTION),
                Act::Rule(43) => return ap_::IS_EQUAL,
                Act::Rule(44) => return ap_::NOT_EQUAL,
                Act::Rule(45) => tok!(ap_::SELECTOR_VALUE),
                Act::Rule(49) => return ap_::LBRACKET,
                Act::Rule(50) | Act::Rule(51) | Act::Rule(53) | Act::Rule(54) => tok!(ap_::SEL_ARG_VALUE),
                Act::Rule(55) => return ap_::RBRACKET,
                Act::Rule(56) => {
                    // ECHO: amd_echo().
                    let t = self.scanner.yytext().to_vec();
                    log::logmsg(&bfmt!("{}\n", t));
                }
                Act::Rule(r) => unreachable!("amd scanner rule {r}"),
                Act::Eof(_) => return 0,
            }
        }
    }
}

/// The parser's file-scope variables.
struct Parse<'a> {
    st: &'a mut State,
    entry: AmdEntry,
    entries: &'a mut Vec<AmdEntry>,
    logopt: u32,
    psv: &'a [SubstVar],
    opts: [u8; MAX_OPTS_LEN],
}

fn amd_notify(s: &[u8]) {
    log::logmsg(&bfmt!("syntax error in location near [ {} ]\n", s));
}

fn amd_msg(s: &[u8]) {
    log::logmsg(&bfmt!("{}\n", s));
}

impl Parse<'_> {
    fn amd_info(&self, s: &[u8]) {
        info!(self.logopt, "{}\n", s);
    }

    /// `amd_strdup()`: strip a pair of double quotes, checking that quotes match.
    fn amd_strdup(&self, s: &[u8]) -> Option<Vec<u8>> {
        let s = cstr::c(s);
        let quoted = s.first() == Some(&b'"');
        let mut tmp = if quoted { s[1..].to_vec() } else { s.to_vec() };
        if quoted {
            // len = strlen(str) - 2 (unsigned): tmp[len] is the closing quote.
            let len = s.len().wrapping_sub(2);
            if tmp.get(len) != Some(&b'"') {
                self.amd_info(&bfmt!("unmatched double quote near: {}", s));
                return None;
            }
            tmp.truncate(len);
        }
        if tmp.contains(&b'\'') && tmp.iter().filter(|&&c| c == b'\'').count() % 2 == 1 {
            self.amd_info(&bfmt!("unmatched single quote near: {}", s));
            return None;
        }
        Some(tmp)
    }

    /// `prepend_opt()`: `opt,` in front of the options so far, fortified.
    fn prepend_opt(&mut self, opt: &[u8]) {
        let opt = cstr::c(opt);
        let mut new = opt.to_vec();
        if new.len() >= MAX_OPTS_LEN {
            sys::chk_fail();
        }
        let dest = cstr::c(&self.opts).to_vec();
        if !dest.is_empty() {
            new.push(b',');
            new.extend_from_slice(&dest);
            if new.len() >= MAX_OPTS_LEN {
                sys::chk_fail();
            }
        }
        // memmove(dest, new, strlen(new)): no terminating NUL is copied.
        self.opts[..new.len()].copy_from_slice(&new);
    }

    fn opts_str(&self) -> Vec<u8> {
        cstr::c(&self.opts).to_vec()
    }

    /// `match_map_option_fs_type()`.
    fn match_fs_type(&mut self, map_option: &[u8], ty: &[u8]) -> bool {
        let Some(fs_type) = self.amd_strdup(ty) else {
            amd_notify(ty);
            return false;
        };
        let e = &mut self.entry;
        let is = |s: &[u8]| cstr::eq(&fs_type, s);
        let mut keep = true;
        if is(b"auto") {
            e.flags |= AMD_MOUNT_TYPE_AUTO;
        } else if is(b"nfs") || is(b"nfs4") {
            e.flags |= AMD_MOUNT_TYPE_NFS;
        } else if is(b"nfsl") {
            e.flags |= AMD_MOUNT_TYPE_NFSL;
        } else if is(b"link") {
            e.flags |= AMD_MOUNT_TYPE_LINK;
        } else if is(b"linkx") {
            e.flags |= AMD_MOUNT_TYPE_LINKX;
        } else if is(b"host") {
            e.flags |= AMD_MOUNT_TYPE_HOST;
        } else if is(b"lofs") {
            e.flags |= AMD_MOUNT_TYPE_LOFS;
        } else if is(b"xfs") {
            e.flags |= AMD_MOUNT_TYPE_XFS;
        } else if is(b"ext2") || is(b"ext3") || is(b"ext4") {
            e.flags |= AMD_MOUNT_TYPE_EXT;
        } else if is(b"program") {
            e.flags |= AMD_MOUNT_TYPE_PROGRAM;
        } else if is(b"ufs") {
            e.flags |= AMD_MOUNT_TYPE_UFS;
            e.ty = defaults::conf_amd_get_linux_ufs_mount_type();
            if e.ty.is_none() {
                amd_msg(b"memory allocation error");
                amd_notify(ty);
                return false;
            }
            keep = false;
        } else if is(b"cdfs") {
            e.flags |= AMD_MOUNT_TYPE_CDFS;
            e.ty = Some(b"iso9660".to_vec());
            keep = false;
        } else if is(b"jfs") || is(b"nfsx") || is(b"lustre") || is(b"direct") {
            amd_msg(&bfmt!("file system type {} is not yet implemented", fs_type));
            return false;
        } else if is(b"cachefs") {
            amd_msg(&bfmt!("file system {} is not supported by autofs, ignored", fs_type));
            keep = false;
        } else {
            amd_notify(&fs_type);
            return false;
        }
        let _ = map_option;
        if keep {
            self.entry.ty = Some(fs_type);
        }
        true
    }

    /// `match_map_option_map_type()` (built without hesiod).
    fn match_map_type(&mut self, ty: &[u8]) -> bool {
        let Some(map_type) = self.amd_strdup(ty) else {
            amd_notify(ty);
            return false;
        };
        let is = |s: &[u8]| cstr::eq(&map_type, s);
        if is(b"file") || is(b"nis") || is(b"nisplus") || is(b"ldap") || is(b"hesiod") {
            if is(b"hesiod") {
                amd_msg(b"hesiod support not built in");
                return false;
            }
            self.entry.map_type = Some(map_type);
        } else if is(b"exec") {
            self.entry.map_type = Some(b"program".to_vec());
        } else if is(b"passwd") {
            amd_msg(&bfmt!("map type {} is not yet implemented", map_type));
            return false;
        } else if is(b"ndbm") || is(b"union") {
            amd_msg(&bfmt!("map type {} is not supported by autofs", map_type));
            return false;
        } else {
            amd_notify(ty);
            return false;
        }
        true
    }

    /// `match_map_option_cache_option()`.
    fn match_cache_option(&mut self, ty: &[u8]) -> bool {
        let Some(c) = self.amd_strdup(ty) else {
            amd_notify(ty);
            return false;
        };
        // QUIRK: the strncmp() results are tested the wrong way round.
        if !cstr::neq(&c, b"inc", 3) {
            self.entry.cache_opts = AMD_CACHE_OPTION_INC;
        } else if !cstr::neq(&c, b"all", 3) {
            self.entry.cache_opts = AMD_CACHE_OPTION_ALL;
        } else if !cstr::neq(&c, b"re", 2) {
            self.entry.cache_opts = AMD_CACHE_OPTION_REGEXP;
        }
        if cstr::strstr(&c, b"sync").is_some() {
            self.entry.cache_opts |= AMD_CACHE_OPTION_SYNC;
        }
        true
    }

    /// `match_mnt_option_options()`.
    fn match_mnt_options(&mut self, mnt_option: &[u8], options: &[u8]) -> bool {
        let which = if cstr::eq(mnt_option, b"opts") {
            0
        } else if cstr::eq(mnt_option, b"addopts") {
            1
        } else if cstr::eq(mnt_option, b"remopts") {
            2
        } else {
            return false;
        };
        let Some(t) = self.amd_strdup(options) else { return false };
        match which {
            0 => self.entry.opts = Some(t),
            1 => self.entry.addopts = Some(t),
            _ => self.entry.remopts = Some(t),
        }
        true
    }

    /// `add_selector()`. QUIRK: the new selector is linked in front of the
    /// list's last selector, dropping any in between.
    fn add_selector(&mut self, s: Selector) {
        let list = &mut self.entry.selector;
        match list.last().cloned() {
            None => list.push(s),
            Some(last) => *list = vec![s, last],
        }
    }

    /// `make_selector()`.
    fn make_selector(&mut self, name: &[u8], value1: Option<&[u8]>, value2: Option<&[u8]>, compare: u32) -> bool {
        let Some(sel) = parse_subs::sel_lookup(name) else { return false };
        let mut s = Selector { sel, compare: 0, arg1: None, arg2: None };
        if sel.flags & parse_subs::SEL_FLAG_MACRO != 0 {
            let Some(t) = self.amd_strdup(value1.unwrap_or(b"")) else { return false };
            s.arg1 = Some(t);
        } else if sel.flags & parse_subs::SEL_FLAG_FUNC1 != 0 {
            match value1 {
                None => s.arg1 = None,
                Some(v) => {
                    let Some(t) = self.amd_strdup(v) else { return false };
                    s.arg1 = Some(t);
                }
            }
        } else if sel.flags & parse_subs::SEL_FLAG_FUNC2 != 0 {
            let Some(t) = self.amd_strdup(value1.unwrap_or(b"")) else { return false };
            s.arg1 = Some(t);
            if let Some(v) = value2
                && let Some(t) = self.amd_strdup(v)
            {
                s.arg2 = Some(t);
            }
        }
        s.compare = compare;
        self.add_selector(s);
        true
    }

    /// `add_location()`.
    fn add_location(&mut self) -> bool {
        let Some(mut new) = new_amd_entry(self.psv) else { return false };
        let e = std::mem::take(&mut self.entry);
        if e.path.is_some() {
            new.path = e.path;
        }
        new.flags = e.flags;
        new.ty = e.ty;
        new.map_type = e.map_type;
        new.pref = e.pref;
        new.fs = e.fs;
        new.rhost = e.rhost;
        new.rfs = e.rfs;
        new.dev = e.dev;
        new.opts = e.opts;
        new.addopts = e.addopts;
        new.remopts = e.remopts;
        new.sublink = e.sublink;
        new.mount = e.mount;
        new.umount = e.umount;
        new.selector = e.selector;
        // The memset() also clears cache_opts, which isn't copied.
        self.entries.push(new);
        true
    }

    fn location(&mut self) -> Flow {
        if !self.add_location() {
            amd_msg(b"failed to allocate new location");
            return Flow::Abort;
        }
        Flow::Continue
    }

    /// The rule `option_assignment: MAP_OPTION OPTION_ASSIGN FS_OPT_VALUE`.
    fn map_option_value(&mut self, opt: &[u8], val: &[u8]) -> Flow {
        let abort = |ok: bool| if ok { Flow::Continue } else { Flow::Abort };
        if cstr::eq(opt, b"type") {
            return abort(self.match_fs_type(opt, val));
        }
        if cstr::eq(opt, b"maptype") {
            return abort(self.match_map_type(val));
        }
        if cstr::eq(opt, b"cache") {
            return abort(self.match_cache_option(val));
        }
        let Some(v) = self.amd_strdup(val) else {
            amd_notify(val);
            return Flow::Abort;
        };
        if cstr::eq(opt, b"fs") {
            self.entry.fs = Some(v);
        } else if cstr::eq(opt, b"sublink") {
            self.entry.sublink = Some(v);
        } else if cstr::eq(opt, b"pref") {
            self.entry.pref = Some(if cstr::eq(&v, b"null") { Vec::new() } else { v });
        } else {
            amd_notify(opt);
            return Flow::Abort;
        }
        Flow::Continue
    }

    /// `option_assignment: FS_OPTION OPTION_ASSIGN FS_OPT_VALUE`.
    fn fs_option_value(&mut self, opt: &[u8], val: &[u8]) -> Flow {
        let Some(v) = self.amd_strdup(val) else {
            amd_notify(opt);
            return Flow::Abort;
        };
        let is = |s: &[u8]| cstr::eq(opt, s);
        if is(b"rhost") {
            self.entry.rhost = Some(v);
        } else if is(b"rfs") {
            self.entry.rfs = Some(v);
        } else if is(b"dev") {
            self.entry.dev = Some(v);
        } else if is(b"mount") {
            self.entry.mount = Some(v);
        } else if is(b"unmount") || is(b"umount") {
            if self.entry.umount.is_some() {
                self.amd_info(b"unmount or umount may only be used once");
                return Flow::Abort;
            }
            self.entry.umount = Some(v);
        } else if is(b"delay") || is(b"cachedir") {
            self.amd_info(&bfmt!("option {} is not used by autofs", opt));
        } else {
            amd_notify(opt);
            return Flow::Abort;
        }
        Flow::Continue
    }

    /// `option_assignment: FS_OPTION OPTION_ASSIGN`.
    fn fs_option_empty(&mut self, opt: &[u8]) -> Flow {
        let is = |s: &[u8]| cstr::eq(opt, s);
        if is(b"rhost") {
            self.entry.rhost = Some(Vec::new());
        } else if is(b"rfs") {
            self.entry.rfs = Some(Vec::new());
        } else if is(b"dev") {
            self.entry.dev = Some(Vec::new());
        } else if is(b"mount") {
            self.entry.mount = None;
        } else if is(b"umount") || is(b"unmount") {
            self.entry.umount = None;
        } else {
            amd_notify(opt);
            return Flow::Abort;
        }
        Flow::Continue
    }

    /// `options: OPTION`.
    fn last_option(&mut self, o: &[u8]) {
        if cstr::eq(o, b"fullybrowsable") || cstr::eq(o, b"nounmount") {
            self.amd_info(&bfmt!("option {} is not currently implemented, ignored", o));
        } else if cstr::neq(o, b"ping=", 5)
            || cstr::neq(o, b"retry=", 6)
            || cstr::eq(o, b"public")
            || cstr::eq(o, b"softlookup")
            || cstr::eq(o, b"xlatecookie")
        {
            self.amd_info(&bfmt!("option {} is not used by autofs, ignored", o));
        } else if cstr::neq(o, b"utimeout=", 9) {
            if self.entry.flags & AMD_MOUNT_TYPE_AUTO != 0 {
                self.prepend_opt(&o[1..]);
            } else {
                self.amd_info(b"umount timeout can't be used for other than type \"auto\" with autofs, ignored");
            }
        } else {
            self.prepend_opt(o);
        }
    }
}

impl Grammar for Parse<'_> {
    type Value = Val;

    fn lex(&mut self) -> i32 {
        self.st.lex()
    }

    fn yylval(&self) -> &Val {
        &self.st.lval
    }

    fn action(&mut self, rule: i32, rhs: &mut Rhs<'_, Val>) -> Flow {
        let s = |k: usize| rhs.arg(k).s().to_vec();
        let abort_unless = |ok: bool, name: &[u8]| {
            if ok {
                Flow::Continue
            } else {
                amd_notify(name);
                Flow::Abort
            }
        };
        match rule {
            2 => self.opts = [0; MAX_OPTS_LEN],
            6 | 7 => return self.location(),
            8 => {
                self.entry.flags |= AMD_ENTRY_CUT;
                return self.location();
            }
            10 => self.entry.flags |= AMD_DEFAULTS_MERGE,
            11 => self.entry.flags |= AMD_DEFAULTS_RESET,
            17 => {
                amd_notify(&s(1));
                return Flow::Abort;
            }
            18 => {
                let ok = self.make_selector(&s(1), Some(&s(3)), None, SEL_COMP_EQUAL);
                return abort_unless(ok, &s(1));
            }
            // QUIRK: `sel!=` without a value is an equality test.
            19 | 21 => {
                let ok = self.make_selector(&s(1), Some(b""), None, SEL_COMP_EQUAL);
                return abort_unless(ok, &s(1));
            }
            20 => {
                let ok = self.make_selector(&s(1), Some(&s(3)), None, SEL_COMP_NOTEQUAL);
                return abort_unless(ok, &s(1));
            }
            22 => {
                let ok = self.make_selector(&s(1), Some(&s(3)), None, SEL_COMP_NONE);
                return abort_unless(ok, &s(1));
            }
            23 => {
                let ok = self.make_selector(&s(1), Some(&s(3)), Some(&s(5)), SEL_COMP_NONE);
                return abort_unless(ok, &s(1));
            }
            24 => {
                let ok = self.make_selector(&s(2), Some(&s(4)), None, SEL_COMP_NOT);
                return abort_unless(ok, &s(2));
            }
            25 => {
                let ok = self.make_selector(&s(2), Some(&s(4)), Some(&s(6)), SEL_COMP_NOT);
                return abort_unless(ok, &s(2));
            }
            26 => {
                if !self.match_fs_type(&s(1), &s(3)) {
                    return Flow::Abort;
                }
            }
            27 => {
                if !self.match_map_type(&s(3)) {
                    return Flow::Abort;
                }
            }
            28 => return self.map_option_value(&s(1), &s(3)),
            29 => {
                if cstr::eq(&s(1), b"fs") {
                    self.entry.fs = Some(Vec::new());
                } else {
                    amd_notify(&s(1));
                    return Flow::Abort;
                }
            }
            30 => return self.fs_option_value(&s(1), &s(3)),
            31 => return self.fs_option_empty(&s(1)),
            32 | 33 => {
                let o = self.opts_str();
                if !self.match_mnt_options(&s(1), &o) {
                    amd_notify(&s(1));
                    return Flow::Abort;
                }
                self.opts = [0; MAX_OPTS_LEN];
            }
            34 => {
                self.opts = [0; MAX_OPTS_LEN];
                if !self.match_mnt_options(&s(1), b"") {
                    amd_notify(&s(1));
                    return Flow::Abort;
                }
            }
            35 => {
                if cstr::eq(&s(1), b"cache") {
                    if !self.match_cache_option(&s(3)) {
                        return Flow::Abort;
                    }
                } else {
                    amd_notify(&s(1));
                    return Flow::Abort;
                }
            }
            36 => self.last_option(&s(1)),
            37 | 38 => self.prepend_opt(&s(1)),
            _ => {}
        }
        Flow::Continue
    }

    /// `amd_error()`.
    fn error(&mut self, msg: &str) {
        if msg != "syntax" {
            let t = cstr::c(self.st.scanner.yytext_c()).to_vec();
            log::logmsg(&bfmt!("syntax error in location near [ {} ]\n", t));
        } else {
            log::logmsg(&bfmt!("{} while parsing location.\n", msg));
        }
    }
}

/// `amd_parse_list()`: parse `buffer` into `list`; 0 if it was accepted.
pub fn amd_parse_list(ap: &AutofsPoint, buffer: &[u8], list: &mut Vec<AmdEntry>, sv: &[SubstVar]) -> i32 {
    let mut g = STATE.lock().unwrap();
    let st = g.get_or_insert_with(|| State {
        scanner: Scanner::new(&at::TABLES),
        lval: Val::new(),
        input: LineInput { line: Vec::new(), pos: 0, lim: 0 },
        reset_start_state: false,
    });
    // amd_set_scan_buffer()
    st.scanner.flush_buffer();
    st.reset_start_state = true;
    let line = cstr::c(buffer).to_vec();
    let lim = line.len() + 1;
    st.input = LineInput { line, pos: 0, lim };
    let mut p = Parse {
        st,
        entry: AmdEntry { cache_opts: AMD_CACHE_OPTION_NONE, ..AmdEntry::default() },
        entries: list,
        logopt: ap.logopt(),
        psv: sv,
        opts: [0; MAX_OPTS_LEN],
    };
    bison::parse(&ap_::TABLES, &mut p)
}
