//! C string helpers on byte strings, with the C locale's character classes and
//! the C library's conversions (`atol()`, `strtoul()`...). A byte string ends at
//! its first NUL, as in C.

/// The string up to its first NUL.
pub fn c(s: &[u8]) -> &[u8] {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    &s[..end]
}

pub fn isblank(c: u8) -> bool {
    c == b' ' || c == b'\t'
}

pub fn isspace(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

pub fn isalpha(c: u8) -> bool {
    c.is_ascii_alphabetic()
}

pub fn isdigit(c: u8) -> bool {
    c.is_ascii_digit()
}

pub fn tolower(c: u8) -> u8 {
    c.to_ascii_lowercase()
}

/// `strcmp(a, b) == 0`.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    c(a) == c(b)
}

/// `strcasecmp(a, b) == 0`.
pub fn caseeq(a: &[u8], b: &[u8]) -> bool {
    let (a, b) = (c(a), c(b));
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| tolower(*x) == tolower(*y))
}

/// `strncmp(a, b, n) == 0`.
pub fn neq(a: &[u8], b: &[u8], n: usize) -> bool {
    let (a, b) = (c(a), c(b));
    for i in 0..n {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
    }
    true
}

/// `strncasecmp(a, b, n) == 0`.
pub fn ncaseeq(a: &[u8], b: &[u8], n: usize) -> bool {
    let (a, b) = (c(a), c(b));
    for i in 0..n {
        let x = tolower(a.get(i).copied().unwrap_or(0));
        let y = tolower(b.get(i).copied().unwrap_or(0));
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
    }
    true
}

/// `strchr(s, ch)`'s index.
pub fn strchr(s: &[u8], ch: u8) -> Option<usize> {
    c(s).iter().position(|&b| b == ch)
}

/// `strrchr(s, ch)`'s index.
pub fn strrchr(s: &[u8], ch: u8) -> Option<usize> {
    c(s).iter().rposition(|&b| b == ch)
}

/// `strstr(hay, needle)`'s index.
pub fn strstr(hay: &[u8], needle: &[u8]) -> Option<usize> {
    let (h, n) = (c(hay), c(needle));
    if n.is_empty() {
        return Some(0);
    }
    h.windows(n.len()).position(|w| w == n)
}

/// `strtol(s, &end, base)`: the value (saturated as glibc does) and how many
/// bytes were used (0 if no number).
pub fn strtol(s: &[u8], base: u32) -> (i64, usize) {
    let (v, n, neg) = strtou_raw(s, base);
    let v = if neg {
        if v > i64::MAX as u128 + 1 { i64::MIN } else { (v as i128).wrapping_neg() as i64 }
    } else if v > i64::MAX as u128 {
        i64::MAX
    } else {
        v as i64
    };
    (v, n)
}

/// `strtoul(s, &end, base)`: the value as glibc gives it (a leading `-` negates
/// in the unsigned type) and how many bytes were used.
pub fn strtoul(s: &[u8], base: u32) -> (u64, usize) {
    let (v, n, neg) = strtou_raw(s, base);
    let v = if v > u64::MAX as u128 {
        u64::MAX
    } else if neg {
        (v as u64).wrapping_neg()
    } else {
        v as u64
    };
    (v, n)
}

fn strtou_raw(s: &[u8], base: u32) -> (u128, usize, bool) {
    let s = c(s);
    let mut i = 0;
    while i < s.len() && isspace(s[i]) {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut base = base;
    let digit = |b: u8| -> Option<u32> { (b as char).to_digit(36) };
    if (base == 0 || base == 16)
        && i + 1 < s.len()
        && s[i] == b'0'
        && (s[i + 1] | 0x20) == b'x'
        && s.get(i + 2).and_then(|&b| digit(b)).is_some_and(|d| d < 16)
    {
        i += 2;
        base = 16;
    } else if base == 0 {
        base = if i < s.len() && s[i] == b'0' { 8 } else { 10 };
    }
    let start = i;
    let mut v: u128 = 0;
    while i < s.len() {
        match digit(s[i]) {
            Some(d) if d < base => {
                v = (v * base as u128 + d as u128).min(u128::from(u64::MAX) + 1);
                i += 1;
            }
            _ => break,
        }
    }
    if i == start {
        // No digits: end is the start of the string. "0x" with no hex digit
        // after it was handled above (only the "0" counts).
        return (0, 0, false);
    }
    (v, i, neg)
}

/// `atol(s)`.
pub fn atol(s: &[u8]) -> i64 {
    strtol(s, 10).0
}

/// `atoi(s)`: `(int) strtol(s, NULL, 10)`.
pub fn atoi(s: &[u8]) -> i32 {
    strtol(s, 10).0 as i32
}

/// glibc's GNU `basename()` (from `<string.h>`): what follows the last `/`.
pub fn gnu_basename(s: &[u8]) -> &[u8] {
    let s = c(s);
    match s.iter().rposition(|&b| b == b'/') {
        Some(p) => &s[p + 1..],
        None => s,
    }
}

/// POSIX `basename()` (glibc's `__xpg_basename()`).
pub fn xpg_basename(s: &[u8]) -> Vec<u8> {
    let s = c(s);
    if s.is_empty() {
        return b".".to_vec();
    }
    let mut end = s.len();
    while end > 1 && s[end - 1] == b'/' {
        end -= 1;
    }
    let t = &s[..end];
    if t == b"/" {
        return b"/".to_vec();
    }
    match t.iter().rposition(|&b| b == b'/') {
        Some(p) => t[p + 1..].to_vec(),
        None => t.to_vec(),
    }
}
