//! `lib/parse_subs.c`: the parsing helpers the lookup and parse modules share.
//! This phase has the ones map reading needs.

use crate::libautofs::cstr;
use crate::libautofs::log;
use crate::sys;

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
/// Returns the entry's position. For amd maps, the key, a `prefix/*` entry for
/// one of its parent paths, or `*`.
pub fn match_cached_key(
    ap: &std::sync::Arc<crate::daemon::master::AutofsPoint>,
    source: &crate::daemon::master::MapSource,
    c: &mut crate::libautofs::cache::CacheInner,
    key: &[u8],
) -> Option<crate::libautofs::cache::Pos> {
    use crate::daemon::master::{MAP_FLAG_FORMAT_AMD, MOUNT_FLAG_REMOUNT};
    use crate::libautofs::cache::{CHE_OK, CHE_UPDATED};
    if source.lock().flags & MAP_FLAG_FORMAT_AMD != 0 {
        // The key itself, else successively shorter `dir/*` entries, else `*`.
        if let Some(p) = c.lookup_distinct(key) {
            return Some(p);
        }
        let mut lkp_key = cstr::c(key).to_vec();
        while let Some(prefix) = cstr::strrchr(&lkp_key, b'/') {
            lkp_key.truncate(prefix);
            if let Some(p) = c.partial_match_wild(&lkp_key) {
                return Some(p);
            }
        }
        return c.lookup_distinct(b"*");
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

// ---------------------------------------------------------------------------
// amd selectors, network proximity and option merging.

pub const PROXIMITY_ERROR: u32 = 0x0000;
pub const PROXIMITY_LOCAL: u32 = 0x0001;
pub const PROXIMITY_SUBNET: u32 = 0x0002;
pub const PROXIMITY_NET: u32 = 0x0004;
pub const PROXIMITY_OTHER: u32 = 0x0008;
pub const PROXIMITY_UNSUPPORTED: u32 = 0x0010;

pub const SEL_HOST: u32 = 0x0000_0040;
pub const SEL_HOSTD: u32 = 0x0000_0080;
pub const SEL_XHOST: u32 = 0x0000_0100;
pub const SEL_NETGRP: u32 = 0x0000_1000;
pub const SEL_NETGRPD: u32 = 0x0000_2000;
pub const SEL_IN_NETWORK: u32 = 0x0000_4000;
pub const SEL_EXISTS: u32 = 0x0010_0000;
pub const SEL_TRUE: u32 = 0x0080_0000;
pub const SEL_FALSE: u32 = 0x0100_0000;

pub const SEL_COMP_NONE: u32 = 0x0000;
pub const SEL_COMP_EQUAL: u32 = 0x0001;
pub const SEL_COMP_NOTEQUAL: u32 = 0x0002;
pub const SEL_COMP_NOT: u32 = 0x0004;

pub const SEL_FLAG_MACRO: u32 = 0x0001;
pub const SEL_FLAG_FUNC1: u32 = 0x0002;
pub const SEL_FLAG_FUNC2: u32 = 0x0004;
pub const SEL_FLAG_STR: u32 = 0x0100;
pub const SEL_FLAG_NUM: u32 = 0x0200;
pub const SEL_FLAG_BOOL: u32 = 0x0400;
pub const SEL_FLAGS_TYPE_MASK: u32 = 0x00FF;
pub const SEL_FLAGS_VALUE_MASK: u32 = 0xFF00;

/// A `struct sel`: one of the selectors amd maps know.
#[derive(Debug)]
pub struct Sel {
    pub selector: u32,
    pub name: &'static [u8],
    pub flags: u32,
}

const MS: u32 = SEL_FLAG_MACRO | SEL_FLAG_STR;
const F1: u32 = SEL_FLAG_FUNC1 | SEL_FLAG_BOOL;
const F2: u32 = SEL_FLAG_FUNC2 | SEL_FLAG_BOOL;

/// `sel_table[]`.
pub static SEL_TABLE: [Sel; 28] = [
    Sel { selector: 0x0000_0001, name: b"arch", flags: MS },
    Sel { selector: 0x0000_0002, name: b"karch", flags: MS },
    Sel { selector: 0x0000_0004, name: b"os", flags: MS },
    Sel { selector: 0x0000_0008, name: b"osver", flags: MS },
    Sel { selector: 0x0000_0010, name: b"full_os", flags: MS },
    Sel { selector: 0x0000_0020, name: b"vendor", flags: MS },
    Sel { selector: SEL_HOST, name: b"host", flags: MS },
    Sel { selector: SEL_HOSTD, name: b"hostd", flags: MS },
    Sel { selector: SEL_XHOST, name: b"xhost", flags: F1 },
    Sel { selector: 0x0000_0200, name: b"domain", flags: MS },
    Sel { selector: 0x0000_0400, name: b"byte", flags: MS },
    Sel { selector: 0x0000_0800, name: b"cluster", flags: MS },
    Sel { selector: SEL_NETGRP, name: b"netgrp", flags: F2 },
    Sel { selector: SEL_NETGRPD, name: b"netgrpd", flags: F2 },
    Sel { selector: SEL_IN_NETWORK, name: b"in_network", flags: F1 },
    Sel { selector: SEL_IN_NETWORK, name: b"netnumber", flags: F1 },
    Sel { selector: SEL_IN_NETWORK, name: b"network", flags: F1 },
    Sel { selector: SEL_IN_NETWORK, name: b"wire", flags: F1 },
    Sel { selector: 0x0000_8000, name: b"uid", flags: SEL_FLAG_MACRO | SEL_FLAG_NUM },
    Sel { selector: 0x0001_0000, name: b"gid", flags: SEL_FLAG_MACRO | SEL_FLAG_NUM },
    Sel { selector: 0x0002_0000, name: b"key", flags: MS },
    Sel { selector: 0x0004_0000, name: b"map", flags: MS },
    Sel { selector: 0x0008_0000, name: b"path", flags: MS },
    Sel { selector: SEL_EXISTS, name: b"exists", flags: F1 },
    Sel { selector: 0x0020_0000, name: b"autodir", flags: MS },
    Sel { selector: 0x0040_0000, name: b"dollar", flags: MS },
    Sel { selector: SEL_TRUE, name: b"true", flags: F1 },
    Sel { selector: SEL_FALSE, name: b"false", flags: F1 },
];

/// `sel_lookup()`.
pub fn sel_lookup(name: &[u8]) -> Option<&'static Sel> {
    SEL_TABLE.iter().find(|s| cstr::eq(s.name, name))
}

/// A `struct selector`. `arg1` is both `comp.value` and `func.arg1` (a union in C).
#[derive(Debug, Clone)]
pub struct Selector {
    pub sel: &'static Sel,
    pub compare: u32,
    pub arg1: Option<Vec<u8>>,
    pub arg2: Option<Vec<u8>>,
}

const MASK_A: u32 = 0x7F00_0000;
const MASK_B: u32 = 0xBFFF_0000;
const MASK_C: u32 = 0xDFFF_FF00;
const NI_MAXHOST: usize = 1025;
const INET_ADDRSTRLEN: usize = 16;
const MAX_NETWORK_LEN: usize = 255;

fn in6_linklocal(a: &[u8]) -> bool {
    a.len() == 16 && a[0] == 0xfe && a[1] & 0xc0 == 0x80
}

fn in6_loopback(a: &[u8]) -> bool {
    a.len() == 16 && a[..15].iter().all(|&b| b == 0) && a[15] == 1
}

fn words(a: &[u8]) -> [u32; 4] {
    let mut w = [0u32; 4];
    for (i, c) in a.chunks(4).take(4).enumerate() {
        w[i] = u32::from_ne_bytes(c.try_into().unwrap_or([0; 4]));
    }
    w
}

/// `get_proximity()`: how close an address is to this host's interfaces.
pub fn get_proximity(host: &sys::SockAddr) -> u32 {
    let mut ha = 0u32;
    match host.family {
        libc::AF_INET => ha = u32::from_be_bytes(host.addr[..4].try_into().unwrap()),
        libc::AF_INET6 => {
            if in6_linklocal(&host.addr) {
                return PROXIMITY_UNSUPPORTED;
            }
        }
        _ => return PROXIMITY_ERROR,
    }
    let ifa = match sys::getifaddrs() {
        Ok(i) => i,
        Err(e) => {
            logerr!("get_proximity", "267", "getifaddrs: {}", sys::strerror(e));
            return PROXIMITY_ERROR;
        }
    };
    let usable = |i: &&sys::IfAddr| {
        i.flags & libc::IFF_UP as u32 != 0 && i.flags & libc::IFF_POINTOPOINT as u32 == 0 && i.addr.is_some()
    };
    let mut at_least_one = false;
    for this in ifa.iter().filter(usable) {
        let a = this.addr.as_ref().unwrap();
        match a.family {
            libc::AF_INET => {
                if host.family == libc::AF_INET6 {
                    continue;
                }
                if a.addr == host.addr {
                    return PROXIMITY_LOCAL;
                }
                // QUIRK (harmless): s_addr, in network order, is compared with
                // INADDR_LOOPBACK in host order.
                if u32::from_ne_bytes(host.addr[..4].try_into().unwrap()) != libc::INADDR_LOOPBACK {
                    at_least_one = true;
                }
            }
            libc::AF_INET6 => {
                if host.family == libc::AF_INET {
                    continue;
                }
                if a.addr == host.addr {
                    return PROXIMITY_LOCAL;
                }
                if !in6_linklocal(&a.addr) && !in6_loopback(&a.addr) {
                    at_least_one = true;
                }
            }
            _ => {}
        }
    }
    if !at_least_one {
        return PROXIMITY_UNSUPPORTED;
    }
    for this in ifa.iter().filter(usable) {
        let a = this.addr.as_ref().unwrap();
        match a.family {
            libc::AF_INET => {
                if host.family == libc::AF_INET6 {
                    continue;
                }
                let ia = u32::from_be_bytes(a.addr[..4].try_into().unwrap());
                let mut mask = this
                    .netmask
                    .as_ref()
                    .and_then(|m| m.addr.get(..4))
                    .map_or(0, |m| u32::from_be_bytes(m.try_into().unwrap()));
                if ia & mask == ha & mask {
                    return PROXIMITY_SUBNET;
                }
                if (ia >> 31) & 1 == 0 {
                    mask = MASK_A;
                } else if (ia >> 30) & 1 == 0 {
                    mask = MASK_B;
                } else if (ia >> 29) & 1 == 0 {
                    mask = MASK_C;
                } else {
                    continue;
                }
                if ia & mask == ha & mask {
                    return PROXIMITY_NET;
                }
            }
            libc::AF_INET6 => {
                if host.family == libc::AF_INET {
                    continue;
                }
                if in6_linklocal(&a.addr) {
                    continue;
                }
                let (h, i) = (words(&host.addr), words(&a.addr));
                let m = words(this.netmask.as_ref().map_or(&[][..], |m| &m.addr[..]));
                if (0..4).all(|k| h[k] & m[k] == i[k] & m[k]) {
                    return PROXIMITY_SUBNET;
                }
            }
            _ => {}
        }
    }
    PROXIMITY_OTHER
}

/// `inet_fill_net()`: complete a partial dotted quad (`10.1` -> `10.1.0.0`).
fn inet_fill_net(net_num: &[u8]) -> Option<Vec<u8>> {
    let net_num = cstr::c(net_num);
    if net_num.len() > INET_ADDRSTRLEN {
        return None;
    }
    if !net_num.first().is_some_and(|&c| cstr::isdigit(c)) {
        return None;
    }
    let size = NI_MAXHOST + 1;
    let mut net = vec![0u8; size + 1];
    net[..net_num.len()].copy_from_slice(net_num);
    let strcat = |net: &mut Vec<u8>, s: &[u8]| {
        let l = cstr::c(net).len();
        if l + s.len() >= size {
            sys::chk_fail();
        }
        net[l..l + s.len()].copy_from_slice(s);
    };
    let mut np = 0usize;
    let mut dots: i32 = 3;
    loop {
        let c = net[np];
        np += 1;
        if c == 0 {
            break;
        }
        if net[np] == b'.' {
            np += 1;
            dots -= 1;
            if net[np] == 0 && dots != 0 {
                strcat(&mut net, b"0");
            }
            continue;
        }
        if (net[np] != 0 && !cstr::isdigit(net[np])) || dots < 0 {
            return None;
        }
    }
    while dots != 0 {
        dots -= 1;
        strcat(&mut net, b".0");
    }
    Some(cstr::c(&net).to_vec())
}

/// `get_network_number()`. QUIRK: the network number, already in host order,
/// goes through `ntohl()` before `inet_ntop()`, so it comes out byte-swapped.
fn get_network_number(network: &[u8]) -> Option<Vec<u8>> {
    if cstr::c(network).len() + 1 > MAX_NETWORK_LEN {
        return None;
    }
    let n = sys::getnetbyname_net(network)?;
    let h = u32::from_be(n).to_ne_bytes();
    Some(format!("{}.{}.{}.{}", h[0], h[1], h[2], h[3]).into_bytes())
}

/// `get_network_proximity()`.
pub fn get_network_proximity(name: Option<&[u8]>) -> u32 {
    let Some(name) = name else { return PROXIMITY_ERROR };
    let name = cstr::c(name);
    let name_or_num = match get_network_number(name) {
        Some(n) => n,
        None => {
            if name.len() > NI_MAXHOST {
                return PROXIMITY_ERROR;
            }
            let this = match cstr::strchr(name, b'/') {
                Some(m) => &name[..m],
                None => name,
            };
            if cstr::strchr(this, b'.').is_none() {
                this.to_vec()
            } else {
                match inet_fill_net(this) {
                    Some(n) => n,
                    None => return PROXIMITY_ERROR,
                }
            }
        }
    };
    let ni = match sys::getaddrinfo(
        &name_or_num,
        libc::AF_UNSPEC,
        libc::SOCK_DGRAM,
        libc::AI_V4MAPPED | libc::AI_ADDRCONFIG | libc::AI_CANONNAME,
    ) {
        Ok(n) => n,
        Err(e) => {
            logerr!(
                "get_network_proximity",
                "515",
                "hostname lookup for {} failed: {}",
                name_or_num,
                sys::gai_strerror(e)
            );
            return PROXIMITY_ERROR;
        }
    };
    let mut proximity = PROXIMITY_OTHER;
    for this in &ni {
        proximity = proximity.min(get_proximity(&this.addr));
    }
    proximity
}

/// `in_network()`.
pub fn in_network(network: &[u8]) -> bool {
    let p = get_network_proximity(Some(network));
    !(p == PROXIMITY_ERROR || p > PROXIMITY_SUBNET)
}

/// `hasopt()`: where `opt` appears as a whole option in `s`.
fn hasopt(s: &[u8], opt: &[u8]) -> bool {
    let s = cstr::c(s);
    let opt = cstr::c(opt);
    let mut rest = 0usize;
    while let Some(off) = cstr::strstr(&s[rest..], opt) {
        let p = rest + off;
        let after = s.get(p + opt.len()).copied().unwrap_or(0);
        if (p == rest || s[p - 1] == b',') && (after == 0 || after == b'=' || after == b',') {
            return true;
        }
        match cstr::strchr(&s[p..], b',') {
            Some(c) => rest = p + c + 1,
            None => break,
        }
    }
    false
}

const MAX_OPTIONS_LEN: usize = 256;
const MAX_OPTION_LEN: usize = 40;

/// `merge_options()`: `opt1`'s options that `opt2` doesn't override, then `opt2`.
///
/// QUIRK: the running length is reset (`resultlen =+ ...`) instead of added to
/// for most options, so the length checks can pass while the 257-byte result
/// buffer overflows, which `_FORTIFY_SOURCE` stops; an `opt1` of 257 bytes or
/// more trips it too.
pub fn merge_options(opt1: Option<&[u8]>, opt2: Option<&[u8]>) -> Option<Vec<u8>> {
    let o1 = opt1.map(cstr::c).filter(|o| !o.is_empty());
    let o2 = opt2.map(cstr::c).filter(|o| !o.is_empty());
    let (o1, o2) = match (o1, o2) {
        (None, None) => return None,
        (Some(a), None) => return Some(a.to_vec()),
        (None, Some(b)) => return Some(b.to_vec()),
        (Some(a), Some(b)) => (a, b),
    };
    if o1 == o2 {
        return Some(o1.to_vec());
    }
    if o1.len() > MAX_OPTIONS_LEN {
        // strcpy(str, opt1) into str[MAX_OPTIONS_LEN + 1].
        sys::chk_fail();
    }
    let mut result: Vec<u8> = Vec::new();
    let cat = |result: &mut Vec<u8>, s: &[u8]| {
        if result.len() + s.len() > MAX_OPTIONS_LEN {
            sys::chk_fail();
        }
        result.extend_from_slice(s);
    };
    let mut resultlen = 0usize;
    for tok in o1.split(|&c| c == b',').filter(|t| !t.is_empty()) {
        let mut this = tok;
        if let Some(eq) = cstr::strchr(tok, b'=') {
            this = &tok[..eq];
            if !hasopt(o2, this) {
                if resultlen + this.len() > MAX_OPTIONS_LEN {
                    return None;
                }
                cat(&mut result, tok);
                cat(&mut result, b",");
                resultlen += tok.len() + 1;
                continue;
            }
        }
        let is = |s: &[u8]| this == s;
        if (is(b"rw") && hasopt(o2, b"ro"))
            || (is(b"ro") && hasopt(o2, b"rw"))
            || (is(b"bg") && hasopt(o2, b"fg"))
            || (is(b"fg") && hasopt(o2, b"bg"))
            || (is(b"soft") && hasopt(o2, b"hard"))
            || (is(b"hard") && hasopt(o2, b"soft"))
        {
            continue;
        }
        if this.starts_with(b"no") {
            if this.len() - 2 > MAX_OPTION_LEN {
                return None;
            }
            if hasopt(o2, &this[2..]) {
                continue;
            }
        } else {
            if this.len() + 2 > MAX_OPTION_LEN {
                return None;
            }
            if hasopt(o2, &[b"no", this].concat()) {
                continue;
            }
        }
        if hasopt(o2, this) {
            continue;
        }
        if resultlen + this.len() + 1 > MAX_OPTIONS_LEN {
            return None;
        }
        cat(&mut result, this);
        cat(&mut result, b",");
        resultlen = this.len() + 1;
    }
    if resultlen + o2.len() > MAX_OPTIONS_LEN {
        return None;
    }
    cat(&mut result, o2);
    if result.last() == Some(&b',') {
        result.pop();
    }
    Some(result)
}

const EXPAND_LEADING_SLASH: u32 = 0x0001;
const EXPAND_TRAILING_SLASH: u32 = 0x0002;
const EXPAND_LEADING_DOT: u32 = 0x0004;
const EXPAND_TRAILING_DOT: u32 = 0x0008;

/// `expand_slash_or_dot()`: `None` where C returns NULL.
fn expand_slash_or_dot(s: &[u8], ty: u32) -> Option<Vec<u8>> {
    if ty == 0 {
        return Some(s.to_vec());
    }
    if ty & EXPAND_LEADING_SLASH != 0 {
        return Some(cstr::xpg_basename(s));
    }
    if ty & EXPAND_TRAILING_SLASH != 0 {
        return Some(sys::xpg_dirname(s));
    }
    if ty & (EXPAND_LEADING_DOT | EXPAND_TRAILING_DOT) != 0 {
        let dot = cstr::strchr(s, b'.');
        if ty & EXPAND_LEADING_DOT != 0 {
            return dot.map(|d| s[d + 1..].to_vec());
        }
        return Some(match dot {
            Some(d) => s[..d].to_vec(),
            None => s.to_vec(),
        });
    }
    None
}

/// `expandamdent()`: `$`-expand an amd map entry. C's two passes (count, then
/// copy) give the same text, so this returns it; its length is C's result.
pub fn expandamdent(src: &[u8], svc: &[crate::libautofs::macros::SubstVar]) -> Vec<u8> {
    use crate::libautofs::defaults;
    use crate::libautofs::macros;
    let flags = defaults::conf_amd_get_flags(None);
    let normalize = flags & defaults::CONF_NORMALIZE_SLASHES != 0;
    let src = cstr::c(src);
    let mut dst = Vec::new();
    let mut squote = false;
    let mut i = 0usize;
    while i < src.len() {
        let ch = src[i];
        i += 1;
        match ch {
            b'$' => {
                if src.get(i) == Some(&b'{') {
                    i += 1;
                    let Some(rel) = cstr::strchr(&src[i..], b'}') else {
                        // Ignore the rest of the string.
                        return dst;
                    };
                    let p = i + rel;
                    let mut start = i;
                    let mut ty = 0;
                    if src[i] == b'/' || src[i] == b'.' {
                        start += 1;
                        ty = if src[i] == b'.' { EXPAND_LEADING_DOT } else { EXPAND_LEADING_SLASH };
                    }
                    let mut end = p;
                    if p > 0 && (src[p - 1] == b'/' || src[p - 1] == b'.') {
                        end -= 1;
                        ty = if src[p - 1] == b'.' { EXPAND_TRAILING_DOT } else { EXPAND_TRAILING_SLASH };
                    }
                    let sv = if end >= start { macros::macro_findvar(svc, &src[start..], end - start) } else { None };
                    match sv {
                        Some(sv) => {
                            let val = expand_slash_or_dot(&sv.val, ty).unwrap_or(sv.val);
                            dst.extend_from_slice(cstr::c(&val));
                        }
                        None => {
                            dst.extend_from_slice(b"${");
                            dst.extend_from_slice(&src[i..p]);
                            dst.push(b'}');
                        }
                    }
                    i = p + 1;
                } else {
                    dst.push(ch);
                }
            }
            b'\\' => {
                if squote || !normalize {
                    dst.push(ch);
                } else if i < src.len() {
                    dst.push(src[i]);
                    i += 1;
                }
            }
            b'/' => {
                dst.push(ch);
                if squote || !normalize {
                    continue;
                }
                // A double slash at the start is allowed.
                if i == 1 && src.get(i) == Some(&b'/') {
                    dst.push(b'/');
                    i += 1;
                }
                while src.get(i) == Some(&b'/') {
                    i += 1;
                }
            }
            b'\'' => {
                dst.push(ch);
                squote = !squote;
            }
            _ => dst.push(ch),
        }
    }
    dst
}

/// `expand_selectors()`: the expanded string, or `None` (C's 0) when it
/// expands to nothing.
pub fn expand_selectors(
    logopt: u32,
    mapstr: Option<&[u8]>,
    sv: &[crate::libautofs::macros::SubstVar],
) -> Option<Vec<u8>> {
    let mapstr = mapstr?;
    let e = expandamdent(mapstr, sv);
    if e.is_empty() {
        error!(logopt, "expand_selectors", "failed to expand map entry");
        return None;
    }
    Some(e)
}

/// `construct_argv()`: the program and its argument vector (`argv[0]` is the
/// second word), or `None` (C's -1). Words are split at each space (so two
/// spaces make an empty word) and may be single quoted; the space after a
/// closing quote starts an empty word too.
pub fn construct_argv(s: &[u8]) -> Option<(Vec<u8>, Vec<Vec<u8>>)> {
    let s = cstr::c(s);
    // next_arg(): (the word, where the next one starts).
    let next_arg = |pos: usize| -> Option<(Vec<u8>, usize)> {
        if pos >= s.len() {
            return None;
        }
        let (start, mut ptr) = if s[pos] == b'\'' { (pos + 1, pos + 1) } else { (pos, pos) };
        if s[pos] == b'\'' {
            while ptr < s.len() && s[ptr] != b'\'' {
                ptr += 1;
            }
        } else {
            while ptr < s.len() && s[ptr] != b' ' {
                ptr += 1;
            }
        }
        let word = s[start..ptr].to_vec();
        if ptr < s.len() {
            ptr += 1;
        }
        Some((word, ptr))
    };
    let (program, mut next) = next_arg(0)?;
    let mut args = Vec::new();
    while next < s.len() {
        let Some((a, n)) = next_arg(next) else { break };
        args.push(a);
        next = n;
    }
    Some((program, args))
}
