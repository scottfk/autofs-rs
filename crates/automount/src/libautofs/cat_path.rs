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
