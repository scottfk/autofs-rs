//! autofs' `lib/`, what `libautofs.so` holds, plus the two parser skeletons.

pub mod alarm;
pub mod args;
pub mod bison;
pub mod cache;
pub mod cat_path;
pub mod cstr;
pub mod csync;
pub mod defaults;
pub mod dev_ioctl;
pub mod flex;
pub mod log;
pub mod macros;
pub mod mounts;
pub mod nsswitch;
pub mod parse_subs;

/// Something [`bfmt!`] can print.
pub trait Piece {
    fn put(&self, out: &mut Vec<u8>);
}

impl Piece for [u8] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Piece for &[u8] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl<const N: usize> Piece for &[u8; N] {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self[..]);
    }
}
impl Piece for Vec<u8> {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Piece for &Vec<u8> {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self);
    }
}
impl Piece for &str {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}
impl Piece for String {
    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}
macro_rules! int_piece {
    ($($t:ty),*) => {$(
        impl Piece for $t {
            fn put(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(self.to_string().as_bytes());
            }
        }
    )*};
}
int_piece!(i32, u32, i64, u64, usize, u16, u8, isize);

/// [`bfmt!`]'s worker.
pub fn format_pieces(fmt: &str, pieces: &[&dyn Piece]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fmt.len() + 32);
    let mut rest = fmt;
    let mut i = 0;
    while let Some(p) = rest.find("{}") {
        out.extend_from_slice(&rest.as_bytes()[..p]);
        if let Some(a) = pieces.get(i) {
            a.put(&mut out);
        }
        i += 1;
        rest = &rest[p + 2..];
    }
    out.extend_from_slice(rest.as_bytes());
    out
}
