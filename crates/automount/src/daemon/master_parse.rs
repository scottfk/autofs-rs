//! `daemon/master_tok.l` and `daemon/master_parse.y`: one master map entry
//! (`master_parse_entry()`).
//!
//! The scanner's and parser's globals persist between entries as in C: the
//! start state (an entry the parser aborts in the middle of leaves the scanner
//! in whatever state it was in for the next one), `buff`/`bptr`/`optr`, and
//! `master_lval`, whose stale contents are what tokens that don't set a value
//! carry (and what some error messages print).
//!
//! QUIRKs kept: a `multi` entry whose format is `hesiod` frees the parsed path
//! twice (the action frees it, then `master_parse_entry()` does) and glibc
//! aborts; a `multi` map list with `-hosts` or `-null` in it dereferences a NULL
//! vector and segfaults.

use std::sync::{Arc, Mutex};

use crate::daemon::master::{self, MOUNT_FLAG_PRIVATE, MOUNT_FLAG_SHARED, MOUNT_FLAG_SLAVE};
use crate::libautofs::args::{self, Argv};
use crate::libautofs::bison::{self, Flow, Grammar, Rhs};
use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::libautofs::flex::{self, Act, Scanner};
use crate::libautofs::log;
use crate::sys;
use crate::tables::{master_parse as mp, master_tok as mt};

const STRTYPE_LEN: usize = 2048;
const BUFF_LEN: usize = 1024;
const PROPAGATION_MASK: u32 = MOUNT_FLAG_SHARED | MOUNT_FLAG_SLAVE | MOUNT_FLAG_PRIVATE;

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

    /// `strtype` as a C string.
    fn s(&self) -> &[u8] {
        cstr::c(&self.0[..])
    }

    /// `strcpy(strtype, s)`, fortified.
    fn set(&mut self, s: &[u8]) {
        let s = cstr::c(s);
        if s.len() >= STRTYPE_LEN {
            sys::chk_fail();
        }
        self.0[..s.len()].copy_from_slice(s);
        self.0[s.len()] = 0;
    }

    /// `strcat(strtype, s)`.
    fn cat(&mut self, s: &[u8]) {
        let mut v = self.s().to_vec();
        v.extend_from_slice(cstr::c(s));
        self.set(&v);
    }

    fn long(&self) -> i64 {
        i64::from_ne_bytes(self.0[..8].try_into().unwrap())
    }

    fn set_long(&mut self, v: i64) {
        self.0[..8].copy_from_slice(&v.to_ne_bytes());
    }
}

/// The scanner's input: `master_set_scan_buffer()`'s line and its extra NUL.
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

/// The parser's file-scope variables.
#[derive(Debug, Default)]
struct Vars {
    path: Option<Vec<u8>>,
    ty: Option<Vec<u8>>,
    format: Option<Vec<u8>>,
    timeout: i64,
    negative_timeout: i64,
    symlnk: bool,
    strictexpire: bool,
    nobind: bool,
    ghost: bool,
    random_selection: bool,
    use_weight: bool,
    mode: u64,
    tmp_argv: Option<Argv>,
    local_argv: Option<Argv>,
    propagation: u32,
    verbose: bool,
    debug: bool,
    /// Set when an action freed the variables (`local_free_vars()`) without
    /// clearing `path`, `type` and `format`.
    freed: bool,
}

struct State {
    scanner: Scanner,
    lval: Val,
    buff: Vec<u8>,
    bptr: usize,
    optr: usize,
    input: LineInput,
    lineno: u32,
    v: Vars,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn master_error(s: &[u8]) {
    log::logmsg(&bfmt!("{} while parsing map.", s));
}

fn master_notify(s: &[u8]) {
    log::logmsg(&bfmt!("syntax error in map near [ {} ]", s));
}

fn master_msg(s: &[u8]) {
    log::logmsg(s);
}

/// The scanner's own `master_error()`: `logmsg("%s")` without an argument,
/// which prints whatever a register held. Not reproducible; it's only reached
/// for tokens of 2048 bytes and more.
fn tok_error(_s: &str) {
    log::logmsg(b"");
}

impl State {
    fn put_b(&mut self, c: u8) {
        if self.bptr >= self.buff.len() {
            self.buff.resize(self.bptr + 1, 0);
        }
        self.buff[self.bptr] = c;
        self.bptr += 1;
    }

    fn put_o(&mut self, c: u8) {
        if self.optr >= self.buff.len() {
            self.buff.resize(self.optr + 1, 0);
        }
        self.buff[self.optr] = c;
        self.optr += 1;
    }

    fn term_b(&mut self) {
        let p = self.bptr;
        if p >= self.buff.len() {
            self.buff.resize(p + 1, 0);
        }
        self.buff[p] = 0;
    }

    fn buff_str(&self) -> Vec<u8> {
        cstr::c(&self.buff).to_vec()
    }

    /// `free_argv()` everything and NULL the vectors (`local_free_vars()`).
    fn local_free_vars(&mut self) {
        if self.v.freed && (self.v.path.is_some() || self.v.ty.is_some() || self.v.format.is_some()) {
            // QUIRK: the second free of the same pointer; glibc catches it.
            log::flush_stdout_lost();
            sys::write_stderr(b"free(): double free detected in tcache 2\n");
            sys::die_by_signal(libc::SIGABRT);
        }
        self.v.freed = true;
        self.v.local_argv = None;
        self.v.tmp_argv = None;
    }

    /// `master_lex()`.
    fn lex(&mut self) -> i32 {
        loop {
            let act = self.scanner.scan(&mut self.input);
            let text = self.scanner.yytext().to_vec();
            let leng = self.scanner.yyleng();
            let t0 = text.first().copied().unwrap_or(0);
            match act {
                Act::Rule(1) | Act::Rule(2) => {
                    if self.optr != 0 {
                        let o = self.optr;
                        self.put_o(0);
                        self.optr = o;
                        let b = cstr::c(&self.buff[..]).to_vec();
                        self.lval.set(&b);
                        return mp::NILL;
                    }
                }
                Act::Rule(3) => return mp::COMMENT,
                Act::Rule(4) => {
                    if self.optr != 0 {
                        let o = self.optr;
                        self.put_o(0);
                        self.optr = o;
                        let b = cstr::c(&self.buff[..]).to_vec();
                        self.lval.set(&b);
                        return mp::NILL;
                    }
                    self.scanner.begin(mt::PATHSTR);
                    self.bptr = 0;
                    self.scanner.yyless(0);
                }
                Act::Rule(5) => self.put_o(t0),
                Act::Rule(6) => {
                    self.scanner.begin(mt::INITIAL);
                    self.put_b(t0);
                    let b = self.buff_str();
                    self.lval.set(&b);
                    return mp::NILL;
                }
                Act::Rule(7) | Act::Rule(26) => self.put_b(text.get(1).copied().unwrap_or(0)),
                Act::Rule(8) => {
                    self.scanner.begin(mt::INITIAL);
                    self.put_b(t0);
                    self.term_b();
                    let b = self.buff_str();
                    self.lval.set(&b);
                    return mp::QUOTE;
                }
                Act::Rule(9) => {
                    self.scanner.begin(mt::MAPSTR);
                    self.term_b();
                    let b = self.buff_str();
                    self.lval.set(&b);
                    self.bptr = 0;
                    self.buff.iter_mut().take(BUFF_LEN).for_each(|b| *b = 0);
                    return mp::PATH;
                }
                Act::Eof(s) if s == mt::PATHSTR => {
                    self.scanner.begin(mt::INITIAL);
                    self.term_b();
                    let b = self.buff_str();
                    self.lval.set(&b);
                    return mp::PATH;
                }
                Act::Rule(10) => {
                    self.scanner.begin(mt::INITIAL);
                    self.term_b();
                    let b = self.buff_str();
                    self.lval.set(&b);
                    return mp::PATH;
                }
                Act::Rule(11) | Act::Rule(30) => self.put_b(t0),
                Act::Rule(12) | Act::Rule(31) | Act::Rule(43) | Act::Rule(62) | Act::Rule(67) => {}
                Act::Rule(n @ (13..=16)) => {
                    let mut tlen = leng - 1;
                    if self.bptr != 0 && cstr::isblank(text[tlen]) {
                        while cstr::isblank(text[tlen - 1]) {
                            tlen -= 1;
                        }
                        // strncat(buff, master_text, tlen): appended at strlen(buff),
                        // fortified against buff's 1024 bytes.
                        let mut at = cstr::c(&self.buff).len();
                        if at + tlen.min(cstr::c(&text).len()) >= BUFF_LEN {
                            sys::chk_fail();
                        }
                        for &c in &text[..tlen] {
                            if at >= self.buff.len() {
                                self.buff.resize(at + 1, 0);
                            }
                            self.buff[at] = c;
                            at += 1;
                        }
                        if at >= self.buff.len() {
                            self.buff.resize(at + 1, 0);
                        }
                        self.buff[at] = 0;
                        self.bptr += tlen;
                        self.scanner.yyless(tlen);
                    } else {
                        if tlen <= STRTYPE_LEN {
                            self.lval.set(&text);
                        } else {
                            tok_error(if n == 13 { "MULTITYPE" } else { "MAPTYPE" });
                            self.lval.set(&text[..STRTYPE_LEN - 2]);
                        }
                        return if n == 13 { mp::MULTITYPE } else { mp::MAPTYPE };
                    }
                }
                Act::Rule(17) => return mp::DDASH,
                Act::Rule(18) => return mp::COLON,
                Act::Rule(19) => {
                    self.scanner.begin(mt::OPTSTR);
                    self.lval.set(&text);
                    return mp::MAPHOSTS;
                }
                Act::Rule(20) => {
                    self.scanner.begin(mt::OPTSTR);
                    self.lval.set(&text);
                    return mp::MAPNULL;
                }
                Act::Rule(21) => {
                    self.scanner.begin(mt::INITIAL);
                    self.lval.set(&text);
                    return mp::MAPXFN;
                }
                Act::Rule(22) | Act::Rule(23) | Act::Rule(24) => {
                    self.scanner.begin(mt::DNSTR);
                    self.scanner.yyless(0);
                }
                Act::Rule(25) => {
                    self.scanner.begin(mt::INITIAL);
                    self.term_b();
                    let b = self.buff_str();
                    self.lval.set(&b);
                    self.bptr = 0;
                    return mp::MAPNAME;
                }
                Act::Rule(27) => {
                    self.scanner.begin(mt::OPTSTR);
                    self.term_b();
                    let b = self.buff_str();
                    self.lval.set(&b);
                    self.bptr = 0;
                    return mp::MAPNAME;
                }
                Act::Rule(28) | Act::Rule(29) => {
                    self.scanner.begin(mt::INITIAL);
                    self.term_b();
                    let b = self.buff_str();
                    self.lval.set(&b);
                    return mp::MAPNAME;
                }
                Act::Eof(s) if s == mt::MAPSTR => {
                    self.scanner.begin(mt::INITIAL);
                    self.term_b();
                    let b = self.buff_str();
                    self.lval.set(&b);
                    return mp::MAPNAME;
                }
                Act::Rule(n @ (32 | 33 | 35 | 36)) => {
                    if leng < STRTYPE_LEN {
                        self.lval.set(&text);
                    } else {
                        tok_error("DN");
                        self.lval.set(&text[..STRTYPE_LEN - 2]);
                    }
                    return match n {
                        32 => mp::DNSERVER,
                        33 => mp::DNATTR,
                        _ => mp::DNNAME,
                    };
                }
                Act::Rule(34) => return mp::EQUAL,
                Act::Rule(37) | Act::Rule(61) => return mp::COMMA,
                Act::Rule(38) | Act::Rule(39) => {
                    self.scanner.begin(mt::INITIAL);
                    if leng < STRTYPE_LEN {
                        self.lval.set(&text);
                    } else {
                        tok_error("SPACE");
                        self.lval.set(&text[..STRTYPE_LEN - 2]);
                    }
                    return mp::SPACE;
                }
                Act::Rule(40) => self.scanner.begin(mt::OPTSTR),
                Act::Rule(41) | Act::Rule(42) | Act::Rule(68) | Act::Rule(69) => self.scanner.begin(mt::INITIAL),
                Act::Eof(s) if s == mt::DNSTR || s == mt::OPTSTR => self.scanner.begin(mt::INITIAL),
                Act::Rule(44) => {
                    self.scanner.begin(mt::MAPSTR);
                    return mp::DDASH;
                }
                Act::Rule(45) => return mp::OPT_TIMEOUT,
                Act::Rule(46) => return mp::OPT_NTIMEOUT,
                Act::Rule(47) => {
                    self.lval.set_long(cstr::atol(&text));
                    return mp::NUMBER;
                }
                Act::Rule(48) => return mp::OPT_SYMLINK,
                Act::Rule(49) => return mp::OPT_NOBIND,
                Act::Rule(50) => return mp::OPT_NOGHOST,
                Act::Rule(51) => return mp::OPT_SHARED,
                Act::Rule(52) => return mp::OPT_SLAVE,
                Act::Rule(53) => return mp::OPT_PRIVATE,
                Act::Rule(54) => return mp::OPT_STRICTEXPIRE,
                Act::Rule(55) => return mp::OPT_GHOST,
                Act::Rule(56) => return mp::OPT_VERBOSE,
                Act::Rule(57) => return mp::OPT_DEBUG,
                Act::Rule(58) => return mp::OPT_USE_WEIGHT,
                Act::Rule(59) => return mp::OPT_RANDOM,
                Act::Rule(60) => {
                    self.scanner.begin(mt::OCTAL);
                    return mp::OPT_MODE;
                }
                Act::Rule(63) | Act::Rule(64) => {
                    self.lval.set(&text);
                    return mp::OPTION;
                }
                Act::Rule(65) => {
                    if leng < STRTYPE_LEN {
                        self.lval.set(&text);
                    } else {
                        tok_error("OPTION");
                        self.lval.set(&text[..STRTYPE_LEN - 2]);
                    }
                    return mp::OPTION;
                }
                Act::Rule(66) => {
                    self.lval.set(&text);
                    return mp::EQUAL;
                }
                Act::Rule(70) => {
                    self.lval.set_long(cstr::strtoul(&text, 8).0 as i64);
                    return mp::OCTALNUMBER;
                }
                Act::Rule(71) => {
                    self.scanner.begin(mt::OPTSTR);
                    self.scanner.yyless(0);
                }
                Act::Rule(72) => {
                    // ECHO: master_echo() logs the text.
                    log::logmsg(cstr::c(&text));
                }
                Act::Rule(n) => panic!("master scanner: no rule {n}"),
                Act::Eof(_) => return 0,
            }
        }
    }
}

/// `trim_maptype()` on a value in the parser's stack.
fn trim_maptype(t: &[u8]) -> Vec<u8> {
    let mut t = cstr::c(t).to_vec();
    if let Some(c) = cstr::strchr(&t, b':') {
        t.truncate(c);
    } else {
        while let Some(&l) = t.last() {
            if !cstr::isblank(l) {
                break;
            }
            t.pop();
        }
    }
    t
}

/// Split `type[,format]` at the comma.
fn split_comma(t: &[u8]) -> (Vec<u8>, Option<Vec<u8>>) {
    match cstr::strchr(t, b',') {
        Some(c) => (t[..c].to_vec(), Some(cstr::c(&t[c + 1..]).to_vec())),
        None => (t.to_vec(), None),
    }
}

struct Parse<'a> {
    st: &'a mut State,
}

impl Parse<'_> {
    fn tmp_add(&mut self, s: &[u8]) {
        let v = self.st.v.tmp_argv.take().unwrap_or_default();
        self.st.v.tmp_argv = Some(args::add_argv(&v, s));
    }

    /// `add_multi_mapstr()`.
    fn add_multi_mapstr(&mut self) {
        let v = &mut self.st.v;
        if let Some(mut ty) = v.ty.take() {
            if let Some(f) = v.format.take() {
                ty.push(b',');
                ty.extend_from_slice(&f);
            }
            let l = v.local_argv.take().unwrap_or_default();
            v.local_argv = Some(args::add_argv(&l, &ty));
        }
        match v.tmp_argv.take() {
            Some(t) => {
                let l = v.local_argv.take().unwrap_or_default();
                v.local_argv = Some(args::append_argv(&l, &t));
            }
            None => {
                // QUIRK: append_argv() reads argv2[0] through a NULL vector.
                log::flush_stdout_lost();
                sys::die_by_signal(libc::SIGSEGV);
            }
        }
    }

    /// The `MAPTYPE PATH|MAPNAME|dn` actions (rules 41-43).
    fn maptype(&mut self, rhs: &Rhs<'_, Val>, hesiod_check: bool) -> Flow {
        let t = trim_maptype(rhs.arg(1).s());
        let (t, fmt) = split_comma(&t);
        if hesiod_check && (cstr::eq(&t, b"hesiod") || fmt.as_deref().is_some_and(|f| cstr::eq(f, b"hesiod"))) {
            master_error(b"hesiod support not built in");
            self.st.local_free_vars();
            return Flow::Abort;
        }
        self.st.v.ty = Some(if cstr::eq(&t, b"exec") { b"program".to_vec() } else { t });
        if let Some(f) = fmt {
            self.st.v.format = Some(f);
        }
        let a2 = rhs.arg(2).s().to_vec();
        self.tmp_add(&a2);
        Flow::Continue
    }
}

fn dn_attr_ok(a: &[u8]) -> bool {
    cstr::caseeq(a, b"cn")
        || cstr::caseeq(a, b"ou")
        || cstr::caseeq(a, b"automountMapName")
        || cstr::caseeq(a, b"nisMapName")
}

fn notify_attr(a: &[u8], b: &[u8]) {
    const MAX_ERR_LEN: usize = 512;
    let e = bfmt!("{}={}", a, b);
    if e.len() < MAX_ERR_LEN {
        master_notify(&e);
    } else {
        master_notify(b"error string too long");
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
        fn sv(rhs: &Rhs<'_, Val>, k: usize) -> Vec<u8> {
            rhs.arg(k).s().to_vec()
        }
        macro_rules! s {
            ($k:expr) => {
                sv(rhs, $k)
            };
        }
        match rule {
            5 => self.st.v.path = Some(s!(1)),
            6 => {
                let t = trim_maptype(&s!(2));
                self.st.v.path = Some(s!(1));
                let (t, fmt) = split_comma(&t);
                if cstr::eq(&t, b"hesiod") || fmt.as_deref().is_some_and(|f| cstr::eq(f, b"hesiod")) {
                    master_error(b"hesiod support not built in");
                    self.st.local_free_vars();
                    return Flow::Abort;
                }
                self.st.v.ty = Some(t);
                if let Some(f) = fmt {
                    self.st.v.format = Some(f);
                }
            }
            7 | 10..=24 | 25 | 26 | 27 => {
                master_notify(&s!(1));
                return Flow::Abort;
            }
            8 | 9 => {
                master_notify(&s!(2));
                return Flow::Abort;
            }
            28 => return Flow::Abort,
            29 | 30 => {
                self.st.v.local_argv = self.st.v.tmp_argv.take();
            }
            31 | 32 => self.add_multi_mapstr(),
            33 | 34 => {
                let l = self.st.v.local_argv.take().unwrap_or_default();
                self.st.v.local_argv = Some(args::add_argv(&l, b"--"));
                self.add_multi_mapstr();
            }
            35 | 36 => self.tmp_add(&s!(1)),
            37 | 39 => {
                let a = s!(1);
                self.st.v.ty = Some(a[1.min(a.len())..].to_vec());
            }
            38 => {
                master_notify(&s!(1));
                master_msg(b"X/Open Federated Naming service not supported");
                return Flow::Abort;
            }
            40 => {
                self.st.v.ty = Some(b"ldap".to_vec());
                self.tmp_add(&s!(1));
            }
            41 => return self.maptype(rhs, true),
            42 => return self.maptype(rhs, false),
            43 => {
                let f = self.maptype(rhs, false);
                if f != Flow::Continue {
                    return f;
                }
                // Add back the type for lookup_ldap.c to handle ldaps.
                let ty = self.st.v.ty.clone().unwrap_or_default();
                if let Some(t) = self.st.v.tmp_argv.as_mut()
                    && let Some(Some(a0)) = t.first_mut()
                    && !a0.is_empty()
                {
                    let mut n = ty.clone();
                    n.push(b':');
                    n.extend_from_slice(a0);
                    *a0 = n;
                }
            }
            44 => {
                let (a, b) = (s!(1), s!(2));
                rhs.val.set(&a);
                rhs.val.cat(&b);
            }
            45 => {
                let a = s!(1);
                rhs.val.set(&a);
            }
            46 => {
                master_notify(b"syntax error in dn");
                return Flow::Abort;
            }
            47 | 48 => {
                let (a, c) = (s!(1), s!(3));
                if !dn_attr_ok(&a) {
                    notify_attr(&a, &c);
                    return Flow::Abort;
                }
                rhs.val.set(&a);
                rhs.val.cat(b"=");
                rhs.val.cat(&c);
                if rule == 48 {
                    let e = s!(5);
                    rhs.val.cat(b",");
                    rhs.val.cat(&e);
                }
            }
            49 => {
                let a = s!(1);
                rhs.val.set(&a);
            }
            50 | 53 | 54 => {
                master_notify(&s!(1));
                return Flow::Abort;
            }
            51 | 52 => {
                let (a, c) = (s!(1), s!(3));
                if cstr::caseeq(&a, b"automountMapName") || cstr::caseeq(&a, b"nisMapName") {
                    notify_attr(&a, &c);
                    return Flow::Abort;
                }
                rhs.val.set(&a);
                rhs.val.cat(b"=");
                rhs.val.cat(&c);
                if rule == 52 {
                    let e = s!(5);
                    rhs.val.cat(b",");
                    rhs.val.cat(&e);
                }
            }
            58 | 59 => {
                master_notify(&s!(1));
                return Flow::Abort;
            }
            62 => {
                master_notify(b"bogus option");
                return Flow::Abort;
            }
            63 => self.st.v.timeout = rhs.arg(2).long(),
            64 => self.st.v.negative_timeout = rhs.arg(2).long(),
            65 => {}
            66 => self.st.v.symlnk = true,
            67 => self.st.v.strictexpire = true,
            68 => self.st.v.propagation = MOUNT_FLAG_SHARED,
            69 => self.st.v.propagation = MOUNT_FLAG_SLAVE,
            70 => self.st.v.propagation = MOUNT_FLAG_PRIVATE,
            71 => self.st.v.nobind = true,
            72 => self.st.v.ghost = false,
            73 => self.st.v.ghost = true,
            74 => self.st.v.verbose = true,
            75 => self.st.v.debug = true,
            76 => self.st.v.random_selection = true,
            77 => self.st.v.use_weight = true,
            78 => self.st.v.mode = rhs.arg(2).long() as u64,
            79 => self.tmp_add(&s!(1)),
            _ => {}
        }
        Flow::Continue
    }

    fn error(&mut self, msg: &str) {
        master_error(msg.as_bytes());
    }
}

/// `master_init_scan()`.
pub fn master_init_scan() {
    let mut g = STATE.lock().unwrap();
    if let Some(st) = g.as_mut() {
        st.lineno = 0;
    }
}

/// `master_parse_entry()`: parse one master map line and add (or update) its
/// entry; false (C's 0) if it was rejected.
pub fn master_parse_entry(buffer: &[u8], _default_timeout: u32, logging: u32, age: i64) -> bool {
    let master = master::master_list();
    let mut g = STATE.lock().unwrap();
    let st = g.get_or_insert_with(|| State {
        scanner: Scanner::new(&mt::TABLES),
        lval: Val::new(),
        buff: vec![0; BUFF_LEN],
        bptr: 0,
        optr: 0,
        input: LineInput { line: Vec::new(), pos: 0, lim: 0 },
        lineno: 0,
        v: Vars::default(),
    });
    let m_logopt = master.logopt();
    let mut logopt = logging;
    // local_init_vars()
    st.v = Vars {
        timeout: -1,
        propagation: MOUNT_FLAG_SLAVE,
        ghost: defaults::defaults_get_browse_mode() != 0,
        random_selection: master::GLOBALS.lock().unwrap().selection_options & master::MOUNT_FLAG_RANDOM_SELECT != 0,
        ..Vars::default()
    };
    st.lineno += 1;
    // master_set_scan_buffer()
    st.buff.iter_mut().for_each(|b| *b = 0);
    st.optr = 0;
    st.scanner.flush_buffer();
    let line = cstr::c(buffer).to_vec();
    let lim = line.len() + 1;
    st.input = LineInput { line, pos: 0, lim };
    let ret = {
        let mut p = Parse { st };
        bison::parse(&mp::TABLES, &mut p)
    };
    if ret != 0 {
        st.local_free_vars();
        return false;
    }
    let v = std::mem::take(&mut st.v);
    let lineno = st.lineno;
    drop(g);

    let mut path = v.path.clone().unwrap_or_default();
    while let Some(&b'/') = path.last() {
        path.pop();
    }
    let nc = master.lock().nc.clone().expect("no null map cache");
    // Add null map entries to the null map cache.
    if v.ty.as_deref().is_some_and(|t| cstr::eq(t, b"null")) {
        nc.lock().update(0, &path, None, lineno as i64);
        return true;
    }
    // Ignore all subsequent matching nulled entries.
    if nc.lock().lookup_distinct(&path).is_some() {
        return true;
    }
    if v.debug || v.verbose {
        logopt = if v.debug { log::LOGOPT_DEBUG } else { 0 };
        logopt |= if v.verbose { log::LOGOPT_VERBOSE } else { 0 };
    }
    let mut new = None;
    let entry = match master::master_find_mapent(&master, &path) {
        None => {
            let e = master::master_new_mapent(&path, age);
            new = Some(e.clone());
            e
        }
        Some(e) => {
            let ea = e.lock().age;
            if ea != 0 && ea == age && !cstr::eq(&path, b"/-") {
                info!(m_logopt, "ignoring duplicate indirect mount {}", path);
                return false;
            }
            e
        }
    };
    let mut format = v.format.clone();
    if format.is_none() && defaults::conf_amd_mount_section_exists(&path) {
        format = Some(b"amd".to_vec());
    }
    let is_amd = format.as_deref().is_some_and(|f| cstr::eq(f, b"amd"));
    let mut ghost = v.ghost;
    if is_amd {
        let loglevel = defaults::conf_amd_get_log_options();
        let flags = defaults::conf_amd_get_flags(Some(&path));
        if loglevel <= libc::LOG_DEBUG as u32 && loglevel > libc::LOG_INFO as u32 {
            logopt = log::LOGOPT_DEBUG;
        } else if loglevel <= libc::LOG_INFO as u32 && loglevel > libc::LOG_ERR as u32 {
            logopt = log::LOGOPT_VERBOSE;
        }
        if flags & defaults::CONF_BROWSABLE_DIRS != 0 {
            ghost = true;
        }
    }
    if entry.lock().ap.is_none() {
        master::master_add_autofs_point(&entry, logopt, v.nobind, ghost, false);
    }
    let ap = entry.ap();
    {
        let mut a = ap.lock();
        a.flags &= !PROPAGATION_MASK;
        a.flags |= v.propagation;
        if v.random_selection {
            a.flags |= master::MOUNT_FLAG_RANDOM_SELECT;
        }
        if v.use_weight {
            a.flags |= master::MOUNT_FLAG_USE_WEIGHT_ONLY;
        }
        if v.symlnk {
            a.flags |= master::MOUNT_FLAG_SYMLINK;
        }
        if v.strictexpire {
            a.flags |= master::MOUNT_FLAG_STRICTEXPIRE;
        }
        if v.negative_timeout != 0 {
            a.negative_timeout = v.negative_timeout as u32;
        }
        if v.mode != 0 && v.mode < i64::MAX as u64 {
            a.mode = v.mode;
        }
    }
    let mut timeout = v.timeout;
    if timeout < 0 {
        timeout = if is_amd {
            defaults::conf_amd_get_dismount_interval(Some(&path)) as i64
        } else {
            let first = entry.maps().first().cloned();
            master::get_exp_timeout(&ap, first.as_deref())
        };
    }
    if is_amd
        && let Some(opts) = defaults::conf_amd_get_map_options(Some(&path))
        && cstr::strstr(&opts, b"cache:=all").is_some()
    {
        ap.lock().flags |= master::MOUNT_FLAG_AMD_CACHE_ALL;
    }
    let argv = v.local_argv.clone().unwrap_or_default();
    let source = master::master_add_map_source(&entry, v.ty.as_deref(), format.as_deref(), age, &argv);
    master::set_exp_timeout(&ap, Some(&source), timeout);
    source.lock().master_line = lineno;
    entry.lock().age = age;
    if let Some(e) = new {
        master::master_add_mapent(&master, e);
    }
    let _: Option<Arc<()>> = None;
    true
}
