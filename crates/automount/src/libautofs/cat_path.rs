//! `lib/cat_path.c`.

/// `_strncmp(s1, s2, n)`: compare the first `n` bytes and that `n == strlen(s1)`.
pub fn strncmp_len(s1: &[u8], s2: &[u8], n: usize) -> i64 {
    let s1 = crate::libautofs::cstr::c(s1);
    let len = s1.len();
    if n != 0 && n != len {
        return n as i64 - len as i64;
    }
    for i in 0..n {
        let a = s1.get(i).copied().unwrap_or(0);
        let b = s2.get(i).copied().unwrap_or(0);
        if a != b {
            return a as i64 - b as i64;
        }
        if a == 0 {
            break;
        }
    }
    0
}

/// `cat_path(buf, len, dir, base)`: `dir/base` with the slashes between them
/// collapsed, in a buffer of `len` bytes; `None` (C's 0) if it doesn't fit.
pub fn cat_path(len: usize, dir: &[u8], base: &[u8]) -> Option<Vec<u8>> {
    let c = crate::libautofs::cstr::c;
    let d: Vec<u8> = [c(dir), b"\0"].concat();
    let b: Vec<u8> = [c(base), b"\0"].concat();
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len + 1];
    let (mut s, mut di, mut bi) = (0usize, 0usize, 0usize);
    let mut left = len;
    buf[s] = d[di];
    if buf[s] != 0 {
        loop {
            s += 1;
            di += 1;
            buf[s] = d[di];
            if buf[s] == 0 {
                break;
            }
            left -= 1;
            if left == 0 {
                break;
            }
        }
    }
    if left == 0 {
        buf[s] = 0;
        return None;
    }
    // Strip trailing slashes of dir (C's `left++ < len` runs once more when
    // the loop stops on it).
    loop {
        if s == 0 {
            break;
        }
        s -= 1;
        if buf[s] != b'/' {
            break;
        }
        let ok = left < len;
        left += 1;
        if !ok {
            break;
        }
        buf[s] = 0;
    }
    s += 1;
    buf[s] = b'/';
    left -= 1;
    if b[bi] == b'/' {
        while b[bi + 1] == b'/' {
            bi += 1;
        }
        bi += 1;
    }
    loop {
        left -= 1;
        if left == 0 {
            break;
        }
        s += 1;
        buf[s] = b[bi];
        bi += 1;
        if buf[s] == 0 {
            break;
        }
    }
    if left == 0 {
        return None;
    }
    buf.truncate(s);
    Some(buf)
}

/// `ncat_path(buf, len, dir, base, blen)`: `cat_path()` of the first `blen`
/// bytes of `base`.
pub fn ncat_path_len(len: usize, dir: &[u8], base: &[u8], blen: usize) -> Option<Vec<u8>> {
    let alen = crate::libautofs::cstr::c(base).len().min(blen);
    if blen > 4096 || alen == 0 {
        return None;
    }
    cat_path(len, dir, &base[..alen])
}

/// `ncat_path()` into a `PATH_MAX + 1` buffer.
pub fn ncat_path(dir: &[u8], base: &[u8], blen: usize) -> Option<Vec<u8>> {
    ncat_path_len(4096 + 1, dir, base, blen)
}
