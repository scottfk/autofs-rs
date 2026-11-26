//! The flex 2.6.4 scanner skeleton, as flex generates it for upstream's three
//! scanners (`master_tok.l`, `nss_tok.l` and `amd_tok.l`), driven by their tables
//! (`crate::tables::*_tok`). The skeleton is the same for all three but for two
//! variants flex picks per scanner: variable trailing context (`r/s` with both
//! parts of variable length) makes it keep a state buffer and an accepting list
//! (the `REJECT` machinery), and `^` patterns make it track the beginning of
//! line. Each scanner's rule actions live with its grammar; `scan()` returns the
//! number of the rule that matched (or the end-of-file action of the start
//! state), and the action calls back into `yytext()`, `begin()` and `yyless()`.
//!
//! The buffer handling is kept as flex has it (the two end-of-buffer NULs, the
//! hold character, refills through `YY_INPUT` of at most `YY_READ_BUF_SIZE`
//! bytes, the move of a partial token to the front), since it decides what a
//! token spanning a refill or a NUL in the input does.

/// The tables and the constants flex writes into one scanner's skeleton.
#[derive(Debug)]
pub struct Tables {
    pub reject: bool,
    pub uses_bol: bool,
    pub end_of_buffer: i32,
    pub meta_limit: i32,
    pub jam_base: i32,
    pub nul_ec: i32,
    pub jam_state: i32,
    pub trailing_mask: i32,
    pub trailing_head_mask: i32,
    /// Rules whose trailing context (0) or head (1) has a fixed length `n`:
    /// flex trims `yytext` at the start of their action.
    pub trail: &'static [(i32, i32, i32)],
    pub acclist: &'static [i16],
    pub accept: &'static [i16],
    pub ec: &'static [i16],
    pub meta: &'static [i16],
    pub base: &'static [i16],
    pub def: &'static [i16],
    pub nxt: &'static [i16],
    pub chk: &'static [i16],
}

const YY_BUF_SIZE: usize = 16384;
const YY_READ_BUF_SIZE: usize = 8192;
const YY_END_OF_BUFFER_CHAR: u8 = 0;
const YY_EXIT_FAILURE: i32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BufStatus {
    New,
    Normal,
    EofPending,
}

enum Eob {
    EndOfFile,
    ContinueScan,
    LastMatch,
}

/// What `scan()` found: a rule's action to run, or the end of the input in a
/// start state (the scanner's `<<EOF>>` rule for it, or `yyterminate()`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Act {
    Rule(i32),
    Eof(i32),
}

/// `YY_INPUT`: fill `buf` with up to `buf.len()` bytes, returning how many (0 at
/// the end of the input).
pub trait Input {
    fn read(&mut self, buf: &mut [u8]) -> usize;
}

/// One scanner's state: the globals of the generated C (`yy_c_buf_p`,
/// `yy_hold_char`, `yy_start`...) and its one buffer.
#[derive(Debug)]
pub struct Scanner {
    t: &'static Tables,
    init: bool,
    start: i32,
    have_buffer: bool,
    // The buffer (YY_CURRENT_BUFFER).
    ch_buf: Vec<u8>,
    buf_size: usize,
    b_n_chars: usize,
    b_buf_pos: usize,
    status: BufStatus,
    at_bol: bool,
    fill_buffer: bool,
    // The globals.
    n_chars: usize,
    c_buf_p: usize,
    hold_char: u8,
    text_ptr: usize,
    leng: usize,
    did_buffer_switch_on_eof: bool,
    // Backing up, for scanners without REJECT.
    last_accepting_state: i32,
    last_accepting_cpos: usize,
    // The REJECT machinery.
    state_buf: Vec<i32>,
    state_ptr: usize,
    lp: i32,
    looking_for_trail_begin: i32,
    full_match: usize,
    full_state: usize,
    full_lp: i32,
}

fn fatal(msg: &str) -> ! {
    // YY_FATAL_ERROR: yy_fatal_error() prints the message and exits.
    eprintln!("{msg}");
    std::process::exit(YY_EXIT_FAILURE);
}

impl Scanner {
    pub const fn new(t: &'static Tables) -> Scanner {
        Scanner {
            t,
            init: false,
            start: 0,
            have_buffer: false,
            ch_buf: Vec::new(),
            buf_size: 0,
            b_n_chars: 0,
            b_buf_pos: 0,
            status: BufStatus::New,
            at_bol: true,
            fill_buffer: true,
            n_chars: 0,
            c_buf_p: 0,
            hold_char: 0,
            text_ptr: 0,
            leng: 0,
            did_buffer_switch_on_eof: false,
            last_accepting_state: 0,
            last_accepting_cpos: 0,
            state_buf: Vec::new(),
            state_ptr: 0,
            lp: 0,
            looking_for_trail_begin: 0,
            full_match: 0,
            full_state: 0,
            full_lp: 0,
        }
    }

    /// `yytext`, without its terminating NUL.
    pub fn yytext(&self) -> &[u8] {
        &self.ch_buf[self.text_ptr..self.text_ptr + self.leng]
    }

    /// `yyleng`.
    pub fn yyleng(&self) -> usize {
        self.leng
    }

    /// `BEGIN(state)`.
    pub fn begin(&mut self, state: i32) {
        self.start = 1 + 2 * state;
    }

    /// `YY_START`.
    pub fn yy_start(&self) -> i32 {
        (self.start - 1) / 2
    }

    /// `yyless(n)` in a rule action.
    pub fn yyless(&mut self, n: usize) {
        let yy_cp = self.text_ptr + self.leng;
        self.ch_buf[yy_cp] = self.hold_char;
        let yy_cp = self.text_ptr + n;
        self.c_buf_p = yy_cp;
        self.do_before_action(self.text_ptr, yy_cp);
    }

    /// `YY_FLUSH_BUFFER`: drop what's buffered, so the next `scan()` reads afresh.
    pub fn flush_buffer(&mut self) {
        if !self.have_buffer {
            return;
        }
        self.b_n_chars = 0;
        self.ch_buf[0] = YY_END_OF_BUFFER_CHAR;
        self.ch_buf[1] = YY_END_OF_BUFFER_CHAR;
        self.b_buf_pos = 0;
        self.at_bol = true;
        self.status = BufStatus::New;
        self.load_buffer_state();
    }

    fn create_buffer(&mut self) {
        self.buf_size = YY_BUF_SIZE;
        self.ch_buf = vec![0; YY_BUF_SIZE + 2];
        self.have_buffer = true;
        self.init_buffer();
    }

    /// `yy_init_buffer()` (the input is never interactive here).
    fn init_buffer(&mut self) {
        self.flush_buffer();
        self.fill_buffer = true;
    }

    /// `yyrestart(yyin)`.
    fn restart(&mut self) {
        if !self.have_buffer {
            self.create_buffer();
        }
        self.init_buffer();
        self.load_buffer_state();
    }

    fn load_buffer_state(&mut self) {
        self.n_chars = self.b_n_chars;
        self.text_ptr = self.b_buf_pos;
        self.c_buf_p = self.b_buf_pos;
        self.hold_char = self.ch_buf[self.c_buf_p];
    }

    fn do_before_action(&mut self, yy_bp: usize, yy_cp: usize) {
        self.text_ptr = yy_bp;
        self.leng = yy_cp - yy_bp;
        self.hold_char = self.ch_buf[yy_cp];
        self.ch_buf[yy_cp] = 0;
        self.c_buf_p = yy_cp;
    }

    fn sc(&self, c: u8) -> i32 {
        self.t.ec[c as usize] as i32
    }

    /// One DFA transition from `state` on character class `c`.
    fn trans(&self, mut state: i32, mut c: i32) -> i32 {
        let t = self.t;
        while t.chk[(t.base[state as usize] as i32 + c) as usize] as i32 != state {
            state = t.def[state as usize] as i32;
            if state >= t.meta_limit {
                c = t.meta[c as usize] as i32;
            }
        }
        t.nxt[(t.base[state as usize] as i32 + c) as usize] as i32
    }

    fn push_state(&mut self, s: i32) {
        if self.state_ptr >= self.state_buf.len() {
            self.state_buf.resize(self.state_ptr + 1, 0);
        }
        self.state_buf[self.state_ptr] = s;
        self.state_ptr += 1;
    }

    fn start_state(&self) -> i32 {
        self.start + if self.t.uses_bol { self.at_bol as i32 } else { 0 }
    }

    /// `yy_get_previous_state()`.
    fn get_previous_state(&mut self) -> i32 {
        let mut s = self.start_state();
        if self.t.reject {
            self.state_ptr = 0;
            self.push_state(s);
        }
        let mut cp = self.text_ptr;
        while cp < self.c_buf_p {
            let ch = self.ch_buf[cp];
            let c = if ch != 0 { self.sc(ch) } else { self.t.nul_ec };
            if !self.t.reject && self.t.accept[s as usize] != 0 {
                self.last_accepting_state = s;
                self.last_accepting_cpos = cp;
            }
            s = self.trans(s, c);
            if self.t.reject {
                self.push_state(s);
            }
            cp += 1;
        }
        s
    }

    /// `yy_try_NUL_trans()`: the transition on a NUL in the input, or 0 if it jams.
    fn try_nul_trans(&mut self, s: i32) -> i32 {
        if !self.t.reject && self.t.accept[s as usize] != 0 {
            self.last_accepting_state = s;
            self.last_accepting_cpos = self.c_buf_p;
        }
        let n = self.trans(s, self.t.nul_ec);
        let jam = n == self.t.jam_state;
        if self.t.reject && !jam {
            self.push_state(n);
        }
        if jam { 0 } else { n }
    }

    /// `yy_get_next_buffer()`.
    fn get_next_buffer(&mut self, input: &mut dyn Input) -> Eob {
        let dest = 0usize;
        let source = self.text_ptr;
        if self.c_buf_p > self.n_chars + 1 {
            fatal("fatal flex scanner internal error--end of buffer missed");
        }
        if !self.fill_buffer {
            return if self.c_buf_p - self.text_ptr == 1 { Eob::EndOfFile } else { Eob::LastMatch };
        }
        let number_to_move = self.c_buf_p - self.text_ptr - 1;
        for i in 0..number_to_move {
            self.ch_buf[dest + i] = self.ch_buf[source + i];
        }
        if self.status == BufStatus::EofPending {
            self.b_n_chars = 0;
            self.n_chars = 0;
        } else {
            let mut num_to_read = self.buf_size as isize - number_to_move as isize - 1;
            while num_to_read <= 0 {
                if self.t.reject {
                    fatal("input buffer overflow, can't enlarge buffer because scanner uses REJECT");
                }
                // Not enough room in the buffer: grow it.
                let new_size = self.buf_size * 2;
                if new_size == 0 {
                    self.buf_size += self.buf_size / 8;
                } else {
                    self.buf_size *= 2;
                }
                self.ch_buf.resize(self.buf_size + 2, 0);
                num_to_read = self.buf_size as isize - number_to_move as isize - 1;
            }
            let num_to_read = (num_to_read as usize).min(YY_READ_BUF_SIZE);
            let n = input.read(&mut self.ch_buf[number_to_move..number_to_move + num_to_read]);
            self.n_chars = n;
            self.b_n_chars = n;
        }
        let ret = if self.n_chars == 0 {
            if number_to_move == 0 {
                self.restart();
                Eob::EndOfFile
            } else {
                self.status = BufStatus::EofPending;
                Eob::LastMatch
            }
        } else {
            Eob::ContinueScan
        };
        if self.n_chars + number_to_move > self.buf_size {
            // Extend the array by 50%, plus the number we really need.
            let new_size = self.n_chars + number_to_move + (self.n_chars >> 1);
            self.ch_buf.resize(new_size, 0);
            self.buf_size = new_size - 2;
        }
        self.n_chars += number_to_move;
        self.b_n_chars = self.n_chars;
        if self.ch_buf.len() < self.n_chars + 2 {
            self.ch_buf.resize(self.n_chars + 2, 0);
        }
        self.ch_buf[self.n_chars] = YY_END_OF_BUFFER_CHAR;
        self.ch_buf[self.n_chars + 1] = YY_END_OF_BUFFER_CHAR;
        self.text_ptr = 0;
        ret
    }

    /// The scanning loop of `yylex()` up to the action switch: match the longest
    /// token and return the rule to run (`YY_DO_BEFORE_ACTION` done), handling
    /// the end-of-buffer action itself as the skeleton does. `wrap` is the
    /// scanner's `yywrap()` result (all three return 1).
    pub fn scan(&mut self, input: &mut dyn Input) -> Act {
        let t = self.t;
        if !self.init {
            self.init = true;
            if self.start == 0 {
                self.start = 1;
            }
            if !self.have_buffer {
                self.create_buffer();
            }
            self.load_buffer_state();
        }
        {
            let mut yy_cp = self.c_buf_p;
            self.ch_buf[yy_cp] = self.hold_char;
            let mut yy_bp = yy_cp;
            let mut s = self.start_state();
            if t.reject {
                self.state_ptr = 0;
                self.push_state(s);
            }
            // yy_match / yy_find_action, re-entered after the end-of-buffer action.
            let mut entry = 0; // 0 = yy_match, 1 = yy_find_action
            loop {
                if entry == 0 {
                    loop {
                        let c = self.sc(self.ch_buf[yy_cp]);
                        if !t.reject && t.accept[s as usize] != 0 {
                            self.last_accepting_state = s;
                            self.last_accepting_cpos = yy_cp;
                        }
                        s = self.trans(s, c);
                        if t.reject {
                            self.push_state(s);
                        }
                        yy_cp += 1;
                        if t.base[s as usize] as i32 == t.jam_base {
                            break;
                        }
                    }
                }
                // yy_find_action
                let act;
                if t.reject {
                    self.state_ptr -= 1;
                    s = self.state_buf[self.state_ptr];
                    self.lp = t.accept[s as usize] as i32;
                    loop {
                        if self.lp != 0 && self.lp < t.accept[s as usize + 1] as i32 {
                            let mut a = t.acclist[self.lp as usize] as i32;
                            if a & t.trailing_head_mask != 0 || self.looking_for_trail_begin != 0 {
                                if a == self.looking_for_trail_begin {
                                    self.looking_for_trail_begin = 0;
                                    a &= !t.trailing_head_mask;
                                    act = a;
                                    break;
                                }
                            } else if a & t.trailing_mask != 0 {
                                self.looking_for_trail_begin = a & !t.trailing_mask;
                                self.looking_for_trail_begin |= t.trailing_head_mask;
                            } else {
                                self.full_match = yy_cp;
                                self.full_state = self.state_ptr;
                                self.full_lp = self.lp;
                                act = a;
                                break;
                            }
                            self.lp += 1;
                            continue;
                        }
                        yy_cp -= 1;
                        self.state_ptr -= 1;
                        s = self.state_buf[self.state_ptr];
                        self.lp = t.accept[s as usize] as i32;
                    }
                } else {
                    let mut a = t.accept[s as usize] as i32;
                    if a == 0 {
                        yy_cp = self.last_accepting_cpos;
                        s = self.last_accepting_state;
                        a = t.accept[s as usize] as i32;
                    }
                    act = a;
                }
                self.do_before_action(yy_bp, yy_cp);
                if act != t.end_of_buffer {
                    if let Some(&(_, kind, n)) = t.trail.iter().find(|x| x.0 == act) {
                        self.ch_buf[yy_cp] = self.hold_char;
                        yy_cp = if kind == 0 { yy_cp - n as usize } else { yy_bp + n as usize };
                        self.c_buf_p = yy_cp;
                        self.do_before_action(yy_bp, yy_cp);
                    }
                    if t.uses_bol && self.leng > 0 {
                        // YY_RULE_SETUP
                        self.at_bol = self.ch_buf[self.text_ptr + self.leng - 1] == b'\n';
                    }
                    return Act::Rule(act);
                }
                // case YY_END_OF_BUFFER:
                let amount_of_matched_text = yy_cp - self.text_ptr - 1;
                self.ch_buf[yy_cp] = self.hold_char;
                if self.status == BufStatus::New {
                    self.n_chars = self.b_n_chars;
                    self.status = BufStatus::Normal;
                }
                if self.c_buf_p <= self.n_chars {
                    // This was really a NUL.
                    self.c_buf_p = self.text_ptr + amount_of_matched_text;
                    s = self.get_previous_state();
                    let next = self.try_nul_trans(s);
                    yy_bp = self.text_ptr;
                    if next != 0 {
                        self.c_buf_p += 1;
                        yy_cp = self.c_buf_p;
                        s = next;
                        entry = 0;
                    } else {
                        yy_cp = self.c_buf_p;
                        entry = 1;
                    }
                    continue;
                }
                match self.get_next_buffer(input) {
                    Eob::EndOfFile => {
                        self.did_buffer_switch_on_eof = false;
                        // yywrap() returns 1.
                        self.c_buf_p = self.text_ptr;
                        return Act::Eof(self.yy_start());
                    }
                    Eob::ContinueScan => {
                        self.c_buf_p = self.text_ptr + amount_of_matched_text;
                        s = self.get_previous_state();
                        yy_cp = self.c_buf_p;
                        yy_bp = self.text_ptr;
                        entry = 0;
                    }
                    Eob::LastMatch => {
                        self.c_buf_p = self.n_chars;
                        s = self.get_previous_state();
                        yy_cp = self.c_buf_p;
                        yy_bp = self.text_ptr;
                        entry = 1;
                    }
                }
                let _ = s;
            }
        }
    }
}
