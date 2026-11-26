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
