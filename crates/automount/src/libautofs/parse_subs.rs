//! `lib/parse_subs.c`: the parsing helpers the lookup and parse modules share.
//! This phase has the ones map reading needs.

use crate::libautofs::cstr;
use crate::libautofs::log;

pub const LKP_INDIRECT: u32 = 0x0002;
pub const LKP_DIRECT: u32 = 0x0004;

/// `strmcmp(str, pat, mchr)`: 0 if `str` is `pat`, or a prefix of it longer
/// than `mchr` characters.
pub fn strmcmp(s: &[u8], pat: &[u8], mchr: usize) -> i32 {
    let at = |v: &[u8], i: usize| v.get(i).copied().unwrap_or(0);
    let mut i = 0;
    while at(s, i) == at(pat, i) {
        if at(s, i) == 0 {
            return 0;
        }
        i += 1;
    }
    if at(s, i) == 0 && i > mchr {
        return 0;
    }
    at(pat, i) as i32 - at(s, i) as i32
}

/// `sanitize_path(path, origlen, type, logopt)`.
///
/// QUIRKs kept: a byte of 128 or more counts as "below 32" (C's `char` is
/// signed) and rejects the path; and the trailing `/` is never removed (the
/// test measures the string past its end).
pub fn sanitize_path(path: &[u8], origlen: usize, ty: u32, logopt: u32) -> Option<Vec<u8>> {
    let at = |i: usize| path.get(i).copied().unwrap_or(0);
    if ty & (LKP_INDIRECT | LKP_DIRECT) != 0 {
        let tmp = if at(0) == b'"' { &path[1..] } else { path };
        let slash = cstr::strchr(tmp, b'/');
        if slash.is_some() {
            if ty == LKP_INDIRECT {
                return None;
            }
            if tmp.first().copied().unwrap_or(0) != b'/' {
                return None;
            }
        } else if ty == LKP_DIRECT {
            return None;
        }
    }
    let mut out = Vec::with_capacity(origlen);
    let (mut seen_slash, mut quote, mut dquote) = (false, false, false);
    for i in 0..origlen {
        let ch = at(i);
        if !quote {
            if ch == b'"' {
                dquote = !dquote;
                continue;
            }
            if !dquote {
                if (ch as i8) < 32 {
                    return None;
                }
                if ch == b'\\' {
                    quote = true;
                    continue;
                }
            }
            if ch == b'/' {
                if seen_slash {
                    continue;
                }
                seen_slash = true;
            } else {
                seen_slash = false;
            }
        }
        quote = false;
        out.push(ch);
    }
    if dquote {
        let shown = &path[..origlen.min(path.len())];
        debug!(logopt, "sanitize_path", "unmatched quote in {}", cstr::c(shown));
        return None;
    }
    let _ = log::LOGOPT_NONE;
    Some(out)
}

/// `skipspace()`: past blanks; a `#` starts a comment to the end.
pub fn skipspace(s: &[u8]) -> usize {
    let mut i = 0;
    loop {
        match s.get(i).copied().unwrap_or(0) {
            b' ' | 0x08 | b'\t' | b'\n' | 0x0b | 0x0c | b'\r' => i += 1,
            b'#' => return cstr::c(s).len(),
            _ => return i,
        }
    }
}

/// `check_colon()`: whether `:/` comes before the end.
pub fn check_colon(s: &[u8]) -> bool {
    let s = cstr::c(s);
    s.windows(2).any(|w| w == b":/")
}

/// `chunklen()`: the length of a chunk delimited by white space.
pub fn chunklen(s: &[u8], mut expect_colon: bool) -> usize {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut i = 0;
    let mut n = 0;
    let mut quote = false;
    while at(i) != 0 {
        let c = at(i);
        let mut done_quote = true;
        match c {
            b'\\' => {
                if !quote {
                    quote = true;
                    i += 1;
                    n += 1;
                    continue;
                }
            }
            b'"' => {
                if !quote {
                    while at(i) != 0 {
                        i += 1;
                        n += 1;
                        if at(i) == b'"' {
                            break;
                        }
                        if at(i) == b':' && at(i + 1) == b'/' {
                            expect_colon = false;
                        }
                    }
                }
            }
            b':' => {
                if expect_colon && at(i + 1) == b'/' {
                    expect_colon = false;
                }
                i += 1;
                n += 1;
                continue;
            }
            b' ' | b'\t' if expect_colon => {
                i += 1;
                n += 1;
                continue;
            }
            b' ' | b'\t' | 0x08 | b'\n' | 0x0b | 0x0c | b'\r' => {
                if !quote {
                    return n;
                }
            }
            _ => done_quote = true,
        }
        let _ = done_quote;
        quote = false;
        if at(i) == 0 {
            // The inner quote loop reached the end; the for loop's increment
            // steps past the NUL and the loop condition reads beyond it, which
            // in C is the next string byte (always a NUL here).
            return n + 1;
        }
        i += 1;
        n += 1;
    }
    n
}

/// `dequote(str, origlen)`.
pub fn dequote(s: &[u8], origlen: usize, logopt: u32) -> Option<Vec<u8>> {
    let at = |i: isize| if i < 0 { 0 } else { s.get(i as usize).copied().unwrap_or(0) };
    let mut len = origlen as isize;
    let mut i = len - 1;
    while i >= 0 && cstr::isspace(at(i)) {
        let j = i - 1;
        if j > 0 && (at(j) == b'\\' || at(j) == b'"') {
            break;
        }
        i -= 1;
        len -= 1;
    }
    let mut out = Vec::new();
    let (mut quote, mut dquote) = (false, false);
    let mut k = 0usize;
    while len > 0 && at(k as isize) != 0 {
        let c = at(k as isize);
        k += 1;
        len -= 1;
        if !quote {
            if c == b'"' {
                dquote = !dquote;
                continue;
            }
            if !dquote && c == b'\\' {
                quote = true;
                continue;
            }
        }
        quote = false;
        out.push(c);
    }
    if dquote {
        let shown = &s[..origlen.min(s.len())];
        debug!(logopt, "dequote", "unmatched quote in {}", cstr::c(shown));
        return None;
    }
    Some(out)
}

/// `starts_with_null_opt()`.
pub fn starts_with_null_opt(s: &[u8]) -> bool {
    let s = cstr::c(s);
    if s.len() >= 5 && s[0] == b'-' {
        let sep = s.get(5).copied().unwrap_or(0);
        if (sep == 0 || sep == b' ' || sep == b',') && &s[..5] == b"-null" {
            return true;
        }
    }
    false
}

/// A `struct map_type_info`.
#[derive(Debug, Clone, Default)]
pub struct MapTypeInfo {
    pub ty: Option<Vec<u8>>,
    pub format: Option<Vec<u8>>,
    pub map: Option<Vec<u8>>,
}

const MAP_TYPE: [&[u8]; 10] =
    [b"file", b"program", b"yp", b"nis", b"nisplus", b"ldap", b"ldaps", b"hesiod", b"userdir", b"hosts"];
const FORMAT_TYPE: [&[u8]; 3] = [b"sun", b"hesiod", b"amd"];

/// `parse_map_type_info()`: `[type[,format]:]map [options]`, done on a copy as
/// C does it (cutting the copy with NULs and reading C strings back out).
pub fn parse_map_type_info(s: &[u8]) -> Option<MapTypeInfo> {
    let mut buf = cstr::c(s).to_vec();
    buf.push(0);
    buf.push(0);
    let at = |b: &[u8], i: usize| b.get(i).copied().unwrap_or(0);
    let mut ty: Option<usize> = None;
    let mut fmt: Option<usize> = None;
    let mut map: Option<usize> = None;
    if cstr::strchr(&buf, b':').is_none() {
        let mut pos = 0;
        while at(&buf, pos) == b' ' {
            buf[pos] = 0;
            pos += 1;
        }
        map = Some(pos);
    } else {
        'types: for m_type in MAP_TYPE {
            let mut pos = 0;
            if !cstr::neq(m_type, &buf[pos..], m_type.len()) {
                continue;
            }
            ty = Some(pos);
            pos += m_type.len();
            if at(&buf, pos) == b' ' || at(&buf, pos) == b':' {
                while at(&buf, pos) == b' ' {
                    buf[pos] = 0;
                    pos += 1;
                }
                if at(&buf, pos) != b':' {
                    return None;
                }
                buf[pos] = 0;
                pos += 1;
                while at(&buf, pos) != 0 && at(&buf, pos) == b' ' {
                    buf[pos] = 0;
                    pos += 1;
                }
                map = Some(pos);
                break 'types;
            }
            if at(&buf, pos) == b',' {
                buf[pos] = 0;
                pos += 1;
                for f_type in FORMAT_TYPE {
                    if !cstr::neq(f_type, &buf[pos..], f_type.len()) {
                        continue;
                    }
                    fmt = Some(pos);
                    pos += f_type.len();
                    if at(&buf, pos) == b' ' || at(&buf, pos) == b':' {
                        while at(&buf, pos) == b' ' {
                            buf[pos] = 0;
                            pos += 1;
                        }
                        if at(&buf, pos) != b':' {
                            return None;
                        }
                        buf[pos] = 0;
                        pos += 1;
                        while at(&buf, pos) != 0 && at(&buf, pos) == b' ' {
                            buf[pos] = 0;
                            pos += 1;
                        }
                        map = Some(pos);
                        break;
                    }
                }
            }
        }
        if ty.is_none() {
            let mut pos = 0;
            while at(&buf, pos) == b' ' {
                buf[pos] = 0;
                pos += 1;
            }
            map = Some(pos);
        }
    }
    // Look for a space terminator: ignore local options.
    let mut t = 0;
    while at(&buf, t) != 0 {
        if buf[t] == b' ' {
            buf[t] = 0;
            break;
        }
        if buf[t] == b'\\' {
            t += 1;
        }
        t += 1;
    }
    let get = |p: Option<usize>| p.map(|p| cstr::c(&buf[p.min(buf.len())..]).to_vec());
    Some(MapTypeInfo { ty: get(ty), format: get(fmt), map: get(map) })
}

/// `match_cached_key()` for sun maps: the cached entry for `key` from this
/// source (or its wildcard), copied to `key` itself for an indirect lookup.
/// Returns the entry's position. (amd maps' partial matching comes with the
/// amd parser.)
pub fn match_cached_key(
    ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>,
    source: &crate::daemon::master::MapSource,
    c: &mut crate::libautofs::cache::CacheInner,
    key: &[u8],
) -> Option<crate::libautofs::cache::Pos> {
    use crate::daemon::master::{MAP_FLAG_FORMAT_AMD, MOUNT_FLAG_REMOUNT};
    use crate::libautofs::cache::{CHE_OK, CHE_UPDATED};
    if source.lock().flags & MAP_FLAG_FORMAT_AMD != 0 {
        panic!("amd key matching isn't ported yet (phase 2)");
    }
    let mut me = c.lookup(key);
    if let Some(p) = me {
        let e = c.get(p);
        if e.mapent.is_none() || (e.source != source.id && e.key.first() != Some(&b'/')) {
            let mut n = c.lookup_key_next(p);
            while let Some(q) = n {
                if c.get(q).source == source.id {
                    break;
                }
                n = c.lookup_key_next(q);
            }
            me = n;
            if me.is_none() {
                me = c.lookup_distinct(b"*").filter(|&w| c.get(w).source == source.id);
            }
        }
    }
    let p = me?;
    let (flags, ty) = {
        let a = ap.lock();
        (a.flags, a.ty)
    };
    if flags & MOUNT_FLAG_REMOUNT == 0 && ty == LKP_INDIRECT && c.get(p).key.first() == Some(&b'*') {
        let now = crate::sys::monotonic_time();
        let m = c.get(p).mapent.clone();
        let ret = c.update(source.id, key, m.as_deref(), now);
        if ret & (CHE_OK | CHE_UPDATED) == 0 {
            return None;
        }
        // The positions may have moved; the entry for the key is what's used.
        return c.lookup_distinct(key).or(Some(p));
    }
    Some(p)
}
