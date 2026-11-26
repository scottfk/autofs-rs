//! The bison 3.8.2 `yacc.c` skeleton (`yyparse()`), as bison generates it for
//! upstream's three grammars, driven by their tables (`crate::tables::*_parse`).
//! The rule actions are the grammar's own (`Grammar::action()`); everything
//! else is the skeleton's: when a lookahead token is read (only when the state
//! has no default reduction), the error recovery through the `error` token,
//! "syntax error" through `yyerror()`, and the stack limits.

/// The tables and the constants of one parser.
#[derive(Debug)]
pub struct Tables {
    pub yyfinal: i32,
    pub yylast: i32,
    pub yyntokens: i32,
    pub yymaxutok: i32,
    pub yypact_ninf: i32,
    pub yytable_ninf: i32,
    pub table_error_never: bool,
    pub yyinitdepth: i32,
    pub yymaxdepth: i32,
    pub translate: &'static [i16],
    pub pact: &'static [i16],
    pub defact: &'static [i16],
    pub pgoto: &'static [i16],
    pub defgoto: &'static [i16],
    pub table: &'static [i16],
    pub check: &'static [i16],
    pub r1: &'static [i16],
    pub r2: &'static [i16],
}

pub const YYEMPTY: i32 = -2;
pub const YYEOF: i32 = 0;
pub const YYERROR_TOKEN: i32 = 256;
pub const YYUNDEF: i32 = 257;
const YYSYMBOL_YYEOF: i32 = 0;
const YYSYMBOL_YYERROR: i32 = 1;
const YYSYMBOL_YYUNDEF: i32 = 2;

/// What a rule action does after running.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flow {
    Continue,
    Accept,
    Abort,
}

/// The values of the rule being reduced: `$$` and `$1`..`$n`.
#[derive(Debug)]
pub struct Rhs<'a, V> {
    pub val: &'a mut V,
    stack: &'a [V],
    base: usize,
}

impl<V> Rhs<'_, V> {
    /// `$k`, 1-based.
    pub fn arg(&self, k: usize) -> &V {
        &self.stack[self.base + k]
    }
}

/// A grammar: its scanner (`yylex()` with `yylval`), its actions and `yyerror()`.
pub trait Grammar {
    type Value: Clone;
    /// `yylex()`; the semantic value is left in `yylval()`.
    fn lex(&mut self) -> i32;
    /// The scanner's `yylval`.
    fn yylval(&self) -> &Self::Value;
    /// The action of rule `rule` (bison's numbering).
    fn action(&mut self, rule: i32, rhs: &mut Rhs<'_, Self::Value>) -> Flow;
    /// `yyerror()`.
    fn error(&mut self, msg: &str);
}

/// `yyparse()`: 0 if accepted, 1 if aborted, 2 if the stack was exhausted.
pub fn parse<G: Grammar>(t: &Tables, g: &mut G) -> i32 {
    let translate = |c: i32| -> i32 {
        if (0..=t.yymaxutok).contains(&c) { t.translate[c as usize] as i32 } else { YYSYMBOL_YYUNDEF }
    };
    let pact_is_default = |n: i32| n == t.yypact_ninf;
    let table_is_error = |n: i32| !t.table_error_never && n == t.yytable_ninf;

    let mut yystate: i32 = 0;
    let mut yyerrstatus = 0;
    let mut stacksize = t.yyinitdepth as usize;
    // The state and value stacks. Slots above the top keep what was last
    // there, as in C: an empty rule's `$$` starts out as that stale value.
    let mut ss: Vec<i32> = vec![0; stacksize];
    let mut vs: Vec<G::Value> = vec![g.yylval().clone(); stacksize];
    let mut ssp: usize = 0;
    let mut vsp: usize = 0;
    let mut yychar = YYEMPTY;
    let mut yytoken;
    let mut yyn: i32;

    enum L {
        NewState,
        SetState,
        Backup,
        Default,
        ErrLab,
        ErrLab1,
    }
    let mut at = L::SetState;
    loop {
        match at {
            L::NewState => {
                ssp += 1;
                at = L::SetState;
            }
            L::SetState => {
                ss[ssp] = yystate;
                if stacksize - 1 <= ssp {
                    // YYSTACK_RELOCATE
                    if t.yymaxdepth as usize <= stacksize {
                        g.error("memory exhausted");
                        return 2;
                    }
                    stacksize = (stacksize * 2).min(t.yymaxdepth as usize);
                    ss.resize(stacksize, 0);
                    vs.resize(stacksize, g.yylval().clone());
                    if stacksize - 1 <= ssp {
                        return 1;
                    }
                }
                if yystate == t.yyfinal {
                    return 0;
                }
                at = L::Backup;
            }
            L::Backup => {
                yyn = t.pact[yystate as usize] as i32;
                if pact_is_default(yyn) {
                    at = L::Default;
                    continue;
                }
                if yychar == YYEMPTY {
                    yychar = g.lex();
                }
                if yychar <= YYEOF {
                    yychar = YYEOF;
                    yytoken = YYSYMBOL_YYEOF;
                } else if yychar == YYERROR_TOKEN {
                    yychar = YYUNDEF;
                    let _ = YYSYMBOL_YYERROR;
                    at = L::ErrLab1;
                    continue;
                } else {
                    yytoken = translate(yychar);
                }
                yyn += yytoken;
                if yyn < 0 || t.yylast < yyn || t.check[yyn as usize] as i32 != yytoken {
                    at = L::Default;
                    continue;
                }
                yyn = t.table[yyn as usize] as i32;
                if yyn <= 0 {
                    if table_is_error(yyn) {
                        at = L::ErrLab;
                        continue;
                    }
                    yyn = -yyn;
                    if let Err(r) = reduce(t, g, yyn, &mut ss, &mut vs, &mut ssp, &mut vsp, &mut yystate) {
                        return r;
                    }
                    at = L::NewState;
                    continue;
                }
                if yyerrstatus > 0 {
                    yyerrstatus -= 1;
                }
                yystate = yyn;
                vsp += 1;
                vs[vsp] = g.yylval().clone();
                yychar = YYEMPTY;
                at = L::NewState;
            }
            L::Default => {
                yyn = t.defact[yystate as usize] as i32;
                if yyn == 0 {
                    at = L::ErrLab;
                    continue;
                }
                if let Err(r) = reduce(t, g, yyn, &mut ss, &mut vs, &mut ssp, &mut vsp, &mut yystate) {
                    return r;
                }
                at = L::NewState;
            }
            L::ErrLab => {
                if yyerrstatus == 0 {
                    g.error("syntax error");
                }
                if yyerrstatus == 3 {
                    if yychar <= YYEOF {
                        if yychar == YYEOF {
                            return 1;
                        }
                    } else {
                        yychar = YYEMPTY;
                    }
                }
                at = L::ErrLab1;
            }
            L::ErrLab1 => {
                yyerrstatus = 3;
                loop {
                    yyn = t.pact[yystate as usize] as i32;
                    if !pact_is_default(yyn) {
                        yyn += YYSYMBOL_YYERROR;
                        if 0 <= yyn && yyn <= t.yylast && t.check[yyn as usize] as i32 == YYSYMBOL_YYERROR {
                            yyn = t.table[yyn as usize] as i32;
                            if 0 < yyn {
                                break;
                            }
                        }
                    }
                    if ssp == 0 {
                        return 1;
                    }
                    ssp -= 1;
                    vsp -= 1;
                    yystate = ss[ssp];
                }
                vsp += 1;
                vs[vsp] = g.yylval().clone();
                yystate = yyn;
                at = L::NewState;
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn reduce<G: Grammar>(
        t: &Tables,
        g: &mut G,
        yyn: i32,
        ss: &mut [i32],
        vs: &mut [G::Value],
        ssp: &mut usize,
        vsp: &mut usize,
        yystate: &mut i32,
    ) -> Result<(), i32> {
        let yylen = t.r2[yyn as usize] as usize;
        // yyval = yyvsp[1-yylen]
        let mut yyval = vs[*vsp + 1 - yylen].clone();
        let base = *vsp - yylen;
        let flow = {
            let mut rhs = Rhs { val: &mut yyval, stack: vs, base };
            g.action(yyn, &mut rhs)
        };
        match flow {
            Flow::Continue => {}
            Flow::Accept => return Err(0),
            Flow::Abort => return Err(1),
        }
        *ssp -= yylen;
        *vsp -= yylen;
        *vsp += 1;
        vs[*vsp] = yyval;
        let lhs = t.r1[yyn as usize] as i32 - t.yyntokens;
        let top = ss[*ssp];
        let i = t.pgoto[lhs as usize] as i32 + top;
        *yystate = if 0 <= i && i <= t.yylast && t.check[i as usize] as i32 == top {
            t.table[i as usize] as i32
        } else {
            t.defgoto[lhs as usize] as i32
        };
        Ok(())
    }
}
