//! Differential tests: key lookups (`lookup_nss_mount()` and the lookup and
//! parse modules), through the test drivers with recording mount modules.

mod common;

use common::{Case, check_drv};

/// A lookup case: `master`, the maps, and lookups as `(path, key)` by uid 0.
fn lk(name: &str, master: &str, lookups: &[(&str, &str)]) -> Case {
    let mut args: Vec<String> = vec!["-d".into()];
    for (p, k) in lookups {
        args.extend([p.to_string(), k.to_string(), "0".into(), "0".into()]);
    }
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    Case::new(name, &a).master(master)
}

#[test]
fn lookup_file_basic() {
    check_drv(
        lk(
            "lk_basic",
            "/mnt/net /etc/autofs/auto.net -rw,soft\n",
            &[("/mnt/net", "a"), ("/mnt/net", "b"), ("/mnt/net", "nope"), ("/mnt/net", "nope")],
        )
        .map("auto.net", "a server:/export/a\nb -ro,hard s1,s2:/b\n"),
    );
}
