//! `lib/nsswitch.c`, `lib/nss_tok.l` and `lib/nss_parse.y`: the `automount:`
//! line of `/etc/nsswitch.conf`.
//!
//! The scanner and parser keep their state between calls, as C's globals do:
//! the scanner's buffer (so a parse that aborts leaves what it hadn't read for
//! the next call, which goes on reading the next file after it), its start
//! state, and `act[]`, the status actions, which are never reset (each source
//! with a `[...]` gets every action seen so far).

use std::sync::Mutex;

use crate::libautofs::bison::{self, Flow, Grammar, Rhs};
use crate::libautofs::cstr;
use crate::libautofs::flex::{self, Act, Scanner};
use crate::sys;
use crate::tables::{nss_parse, nss_tok};

pub const NSS_STATUS_UNKNOWN: i32 = -1;
pub const NSS_STATUS_SUCCESS: i32 = 0;
pub const NSS_STATUS_NOTFOUND: i32 = 1;
pub const NSS_STATUS_UNAVAIL: i32 = 2;
pub const NSS_STATUS_TRYAGAIN: i32 = 3;
pub const NSS_STATUS_MAX: usize = 4;

pub const NSS_ACTION_UNKNOWN: i32 = 0;
pub const NSS_ACTION_CONTINUE: i32 = 1;
pub const NSS_ACTION_RETURN: i32 = 2;

const NSSWITCH_FILE: &[u8] = b"/etc/nsswitch.conf";

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NssAction {
    pub action: i32,
    pub negated: bool,
}

/// A `struct nss_source`.
#[derive(Debug, Clone)]
pub struct NssSource {
    pub source: Vec<u8>,
    pub action: [NssAction; NSS_STATUS_MAX],
}

/// `set_action()`.
fn set_action(act: &mut [NssAction; NSS_STATUS_MAX], status: &[u8], action: &[u8], negated: bool) -> bool {
    let a = if cstr::caseeq(action, b"continue") {
        NSS_ACTION_CONTINUE
    } else if cstr::caseeq(action, b"return") {
        NSS_ACTION_RETURN
    } else {
        return false;
    };
    let i = if cstr::caseeq(status, b"SUCCESS") {
        NSS_STATUS_SUCCESS
    } else if cstr::caseeq(status, b"NOTFOUND") {
        NSS_STATUS_NOTFOUND
    } else if cstr::caseeq(status, b"UNAVAIL") {
        NSS_STATUS_UNAVAIL
    } else if cstr::caseeq(status, b"TRYAGAIN") {
        NSS_STATUS_TRYAGAIN
    } else {
        return false;
    };
    act[i as usize] = NssAction { action: a, negated };
    true
}

/// `check_nss_result()`: 1 to stop with success, 0 to stop with failure, -1 to
/// go on.
pub fn check_nss_result(this: &NssSource, result: i32) -> i32 {
    for (status, a) in this.action.iter().enumerate() {
        if a.action == NSS_ACTION_UNKNOWN {
            continue;
        }
        if a.negated && result != status as i32 && a.action == NSS_ACTION_RETURN {
            return if result == NSS_STATUS_SUCCESS { 1 } else { 0 };
        }
    }
    let a = this.action.get(result as usize).copied().unwrap_or_default();
    match result {
        NSS_STATUS_SUCCESS => {
            if a.action != NSS_ACTION_CONTINUE {
                return 1;
            }
        }
        NSS_STATUS_NOTFOUND | NSS_STATUS_UNAVAIL | NSS_STATUS_TRYAGAIN if a.action == NSS_ACTION_RETURN => {
            return 0;
        }
        _ => {}
    }
    -1
}

/// `add_source()`.
fn add_source(list: &mut Vec<NssSource>, source: &[u8]) -> usize {
    list.push(NssSource { source: cstr::c(source).to_vec(), action: [NssAction::default(); NSS_STATUS_MAX] });
    list.len() - 1
}

/// The `%union`: `char strval[128]`.
#[derive(Clone)]
pub struct Val([u8; 128]);

impl std::fmt::Debug for Val {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", String::from_utf8_lossy(self.s()))
    }
}

impl Val {
    fn s(&self) -> &[u8] {
        cstr::c(&self.0)
    }

    /// `strcpy(strval, s)`, fortified.
    fn set(&mut self, s: &[u8]) {
        let s = cstr::c(s);
        if s.len() >= self.0.len() {
            sys::chk_fail();
        }
        self.0[..s.len()].copy_from_slice(s);
        self.0[s.len()] = 0;
    }
}

struct FileInput {
    data: Vec<u8>,
    pos: usize,
}

impl flex::Input for FileInput {
    fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.data.len() - self.pos);
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        n
    }
}

/// The scanner's and parser's globals.
struct State {
    scanner: Scanner,
    lval: Val,
    act: [NssAction; NSS_STATUS_MAX],
    automount_found: bool,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

struct Parse<'a> {
    st: &'a mut State,
    input: FileInput,
    list: &'a mut Vec<NssSource>,
}

fn logmsg(s: &[u8]) {
    crate::libautofs::log::logmsg(s);
}

/// `nss_ignore()`.
fn nss_ignore(s: &[u8]) {
    logmsg!("ignored unsupported autofs nsswitch source \"{}\"", s);
}

/// `nss_error()` (also bison's `yyerror()`).
fn nss_error(s: &[u8]) {
    logmsg!("syntax error in nsswitch config near [ {} ]\n", s);
}

const KNOWN: [&[u8]; 7] = [b"files", b"yp", b"nis", b"ldap", b"nisplus", b"hesiod", b"sss"];

impl Grammar for Parse<'_> {
    type Value = Val;

    /// `nss_lex()`: the scanner and its rule actions.
    fn lex(&mut self) -> i32 {
        loop {
            let act = self.st.scanner.scan(&mut self.input);
            let text = self.st.scanner.yytext().to_vec();
            match act {
                Act::Rule(1) => {
                    self.st.automount_found = true;
                    self.st.scanner.begin(nss_tok::AUTOMOUNT);
                }
                Act::Rule(2) | Act::Rule(3) | Act::Rule(7) => {}
                Act::Rule(4) => {
                    self.st.lval.set(&text);
                    return nss_parse::SOURCE;
                }
                Act::Rule(5) => {
                    self.st.scanner.begin(nss_tok::ACTIONSTR);
                    self.st.scanner.yyless(0);
                }
                Act::Rule(6) | Act::Rule(15) => {
                    self.st.scanner.begin(nss_tok::INITIAL);
                    return nss_parse::NL;
                }
                Act::Rule(8) => {
                    self.st.lval.set(&text);
                    return nss_parse::STATUS;
                }
                Act::Rule(9) => {
                    self.st.lval.set(&text);
                    return nss_parse::ACTION;
                }
                Act::Rule(10) => return nss_parse::LBRACKET,
                Act::Rule(11) => {
                    self.st.scanner.begin(nss_tok::AUTOMOUNT);
                    return nss_parse::RBRACKET;
                }
                Act::Rule(12) => return nss_parse::EQUAL,
                Act::Rule(13) => return nss_parse::BANG,
                Act::Rule(14) => {
                    self.st.scanner.begin(nss_tok::AUTOMOUNT);
                    self.st.scanner.yyless(0);
                }
                Act::Rule(16) => {
                    // ECHO: nss_echo().
                    logmsg(cstr::c(&text));
                }
                Act::Rule(n) => panic!("nss scanner: no rule {n}"),
                Act::Eof(_) => return 0,
            }
        }
    }

    fn yylval(&self) -> &Val {
        &self.st.lval
    }

    fn action(&mut self, rule: i32, rhs: &mut Rhs<'_, Val>) -> Flow {
        let a = |k: usize| rhs.arg(k).s().to_vec();
        let _ = &a;
        match rule {
            7 => {
                let s = a(1);
                if KNOWN.iter().any(|k| cstr::eq(&s, k)) {
                    add_source(self.list, &s);
                } else {
                    nss_ignore(&s);
                }
            }
            8 => {
                let s = a(1);
                if KNOWN.iter().any(|k| cstr::eq(&s, k)) {
                    let i = add_source(self.list, &s);
                    for (n, act) in self.st.act.iter().enumerate() {
                        if act.action != NSS_ACTION_UNKNOWN {
                            self.list[i].action[n] = *act;
                        }
                    }
                } else {
                    nss_ignore(&s);
                }
            }
            9 | 10 => {
                nss_error(b"missing close bracket");
                return Flow::Abort;
            }
            11 => {
                nss_error(&a(3));
                return Flow::Abort;
            }
            12 => {
                nss_error(&a(2));
                return Flow::Abort;
            }
            15 => {
                let (s, ac) = (a(1), a(3));
                set_action(&mut self.st.act, &s, &ac, false);
            }
            16 => {
                let (s, ac) = (a(2), a(4));
                set_action(&mut self.st.act, &s, &ac, true);
            }
            17 => {
                nss_error(&a(3));
                return Flow::Abort;
            }
            18 => {
                nss_error(&a(2));
                return Flow::Abort;
            }
            19 => {
                nss_error(&a(4));
                return Flow::Abort;
            }
            20 => {
                nss_error(&a(3));
                return Flow::Abort;
            }
            21 => {
                nss_error(&a(2));
                return Flow::Abort;
            }
            _ => {}
        }
        Flow::Continue
    }

    fn error(&mut self, msg: &str) {
        nss_error(msg.as_bytes());
    }
}

/// `nsswitch_parse()`: the sources of the `automount:` line (or `files` if there
/// isn't one); `Err(())` (C's 1) if the file can't be read or doesn't parse.
#[allow(clippy::result_unit_err)]
pub fn nsswitch_parse(list: &mut Vec<NssSource>) -> Result<(), ()> {
    let data = match sys::open_read_file(NSSWITCH_FILE) {
        Ok(Ok(d)) => d,
        // The file opens but can't be read (a directory): flex's YY_INPUT
        // sees fread() fail and calls yy_fatal_error(), which exits.
        Ok(Err(_)) => {
            sys::write_stderr(b"input in flex scanner failed\n");
            sys::exit(2);
        }
        Err(e) => {
            logerr!("open_fopen_r", "211", "failed to open file: {}", sys::strerror(e));
            logerr!("nsswitch_parse", "172", "couldn't open {}", NSSWITCH_FILE);
            return Err(());
        }
    };
    let mut g = STATE.lock().unwrap();
    let st = g.get_or_insert_with(|| State {
        scanner: Scanner::new(&nss_tok::TABLES),
        lval: Val([0; 128]),
        act: [NssAction::default(); NSS_STATUS_MAX],
        automount_found: false,
    });
    st.automount_found = false;
    let status = {
        let mut p = Parse { st, input: FileInput { data, pos: 0 }, list };
        bison::parse(&nss_parse::TABLES, &mut p)
    };
    let mut status = status;
    if !st.automount_found {
        add_source(list, b"files");
        status = 0;
    }
    if status != 0 { Err(()) } else { Ok(()) }
}
