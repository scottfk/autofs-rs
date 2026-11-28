//! Differential tests: hostile input on the host tier. Malformed and huge
//! maps (`--dumpmaps` and key lookups), program maps that flood, stall or
//! emit garbage, and hostile keys, through the daemon and the test drivers.

mod common;

use common::{Case, check, check_drv};

/// A lookup case: `master`, the maps, and lookups as `(path, key)` by uid 0.
fn lk(name: &str, master: &str, lookups: &[(&str, &str)]) -> Case {
    let mut args: Vec<String> = vec!["-d".into()];
    for (p, k) in lookups {
        args.extend([p.to_string(), k.to_string(), "0".into(), "0".into()]);
    }
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    Case::new(name, &a).master(master)
}

/// Keys looked up under `/mnt/a`, from the file map `auto.a`.
fn file_keys(name: &str, map: &[u8], keys: &[&str]) -> Case {
    let l: Vec<(&str, &str)> = keys.iter().map(|k| ("/mnt/a", *k)).collect();
    lk(name, "/mnt/a /etc/autofs/auto.a\n", &l).etc_bytes("autofs/auto.a", map)
}

/// `-m` with `-d` over the master map and one map `auto.a` under `/mnt/a`.
fn dump(name: &str, map: &[u8]) -> Case {
    Case::new(name, &["-d", "-m"]).master("/mnt/a /etc/autofs/auto.a\n").etc_bytes("autofs/auto.a", map)
}

/// Bytes that look random but are the same every run (an LCG).
fn garbage(n: usize, mut seed: u32) -> Vec<u8> {
    (0..n)
        .map(|_| {
            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
            (seed >> 16) as u8
        })
        .collect()
}

// ---- malformed and huge file maps ----

fn malformed_map() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"ok s:/ok\n");
    m.extend_from_slice(b"crlf s:/crlf\r\n");
    m.extend_from_slice(b"nul s:/a\0b\n");
    m.extend_from_slice(b"k\0ey s:/nulkey\n");
    m.extend_from_slice(b"high \xff\xfe:/x\n");
    m.extend_from_slice(b"quote \"s:/unterminated\n");
    m.extend_from_slice(b"cont s:/c \\\n  -ro\n");
    m.extend_from_slice(b"\t \t\n");
    m.extend_from_slice(b"   lead s:/lead\n");
    m.extend_from_slice(b"onlykey\n");
    m.extend_from_slice(b"hash#x s:/hash\n");
    m.extend_from_slice(b"opts -\n");
    m.extend_from_slice(b"dash - s:/d\n");
    m.extend_from_slice(b"\"qkey\" s:/qkey\n");
    m.extend_from_slice(b"esc\\ key s:/esckey\n");
    m.extend_from_slice(b"+\n");
    m.extend_from_slice(b"+nonexistent.map\n");
    m.extend_from_slice(b"after s:/after\n");
    m.extend_from_slice(b"last s:/last \\");
    m
}

const MALFORMED_KEYS: &[&str] = &[
    "ok",
    "crlf",
    "nul",
    "k",
    "high",
    "quote",
    "cont",
    "lead",
    "onlykey",
    "hash#x",
    "hash",
    "opts",
    "dash",
    "qkey",
    "\"qkey\"",
    "esc key",
    "esc\\ key",
    "after",
    "last",
];

#[test]
fn hostile_map_malformed() {
    check_drv(file_keys("h_malformed", &malformed_map(), MALFORMED_KEYS));
}

#[test]
fn hostile_dump_malformed() {
    check(dump("h_dump_malformed", &malformed_map()));
}

/// Lines and keys at and over the length limits (`KEY_MAX_LEN`, the scanner's
/// buffers, `MAPENT_MAX_LEN`).
fn long_map() -> (Vec<u8>, Vec<String>) {
    let mut m = Vec::new();
    let mut keys = Vec::new();
    for n in [254usize, 255, 256, 257, 1024, 4095, 4096, 4097] {
        let k = "k".repeat(n);
        m.extend_from_slice(format!("{k} s:/{n}\n").as_bytes());
        keys.push(k);
    }
    for n in [16383usize, 16384, 16385, 20000, 70000] {
        let k = format!("v{n}");
        m.extend_from_slice(format!("{k} s:/{}\n", "x".repeat(n)).as_bytes());
        keys.push(k);
    }
    for n in [16384usize, 70000] {
        let k = format!("o{n}");
        m.extend_from_slice(format!("{k} -{} s:/o\n", "r".repeat(n)).as_bytes());
        keys.push(k);
    }
    let k = "c".to_string();
    m.extend_from_slice(b"c ");
    for i in 0..3000 {
        m.extend_from_slice(format!("s{i}:/x \\\n").as_bytes());
    }
    m.extend_from_slice(b"\n");
    keys.push(k);
    m.extend_from_slice(b"tail s:/tail\n");
    keys.push("tail".into());
    (m, keys)
}

#[test]
fn hostile_map_long() {
    let (m, keys) = long_map();
    let k: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
    check_drv(file_keys("h_long", &m, &k));
}

#[test]
fn hostile_dump_long() {
    check(dump("h_dump_long", &long_map().0));
}

#[test]
fn hostile_map_garbage() {
    for seed in [1u32, 2, 3] {
        let mut m = garbage(20000, seed);
        m.extend_from_slice(b"\nok s:/ok\n");
        check_drv(file_keys(&format!("h_garbage{seed}"), &m, &["ok", "\u{1}", "x"]));
    }
}

#[test]
fn hostile_dump_garbage() {
    for seed in [1u32, 2, 3] {
        check(dump(&format!("h_dump_garbage{seed}"), &garbage(20000, seed)));
    }
}

/// Printable garbage: the scanner's paths through quotes, escapes and options.
#[test]
fn hostile_map_printable_garbage() {
    for seed in [4u32, 5, 6, 7] {
        let alphabet = b"ab:/ \t\n\\\"-,=&*$#{}()[]";
        let m: Vec<u8> = garbage(8000, seed).iter().map(|b| alphabet[*b as usize % alphabet.len()]).collect();
        check_drv(file_keys(&format!("h_printable{seed}"), &m, &["a", "b", "ab", "*", "-", "&"]));
    }
}

/// 50000 entries: a lookup near the end, and the wildcard.
#[test]
fn hostile_map_huge() {
    let mut m = String::new();
    for i in 0..50000 {
        m.push_str(&format!("key{i} srv{}:/export/{i}\n", i % 7));
    }
    m.push_str("* w:/&\n");
    check_drv(file_keys("h_huge", m.as_bytes(), &["key0", "key49999", "nokey"]));
}

/// Includes: one that includes itself, a chain deeper than
/// `MAX_INCLUDE_DEPTH`, and an include of a directory.
#[test]
fn hostile_map_includes() {
    let mut c =
        file_keys("h_includes", b"+auto.a\na s:/a\n+auto.i0\n+/etc/autofs\n", &["a", "i16", "i17", "i20", "zz"]);
    for i in 0..21 {
        c = c.map(&format!("auto.i{i}"), &format!("i{i} s:/i{i}\n+auto.i{}\n", i + 1));
    }
    check_drv(c);
}

#[test]
fn hostile_master_malformed() {
    let mut m = Vec::new();
    m.extend_from_slice(b"/mnt/ok /etc/autofs/auto.a\n");
    m.extend_from_slice(b"/mnt/nul\0x /etc/autofs/auto.a\n");
    m.extend_from_slice(b"/mnt/quote \"/etc/autofs/auto.a\n");
    m.extend_from_slice(b"relative /etc/autofs/auto.a\n");
    m.extend_from_slice(b"/mnt/nomap\n");
    m.extend_from_slice(b"/mnt/badtype nosuchtype:/x\n");
    m.extend_from_slice(b"/mnt/badfmt file,nosuchfmt:/etc/autofs/auto.a\n");
    m.extend_from_slice(b"/mnt/opts /etc/autofs/auto.a --timeout=abc --negative-timeout=-1 -DX -D\n");
    m.extend_from_slice(format!("/mnt/{} /etc/autofs/auto.a\n", "p".repeat(5000)).as_bytes());
    m.extend_from_slice(format!("/mnt/lopt /etc/autofs/auto.a -{}\n", "o".repeat(20000)).as_bytes());
    m.extend_from_slice(b"/mnt/dup /etc/autofs/auto.a\n/mnt/dup /etc/autofs/auto.a\n");
    m.extend_from_slice(b"/mnt/../mnt/dots /etc/autofs/auto.a\n");
    m.extend_from_slice(b"/mnt/trail/ /etc/autofs/auto.a\n");
    m.extend_from_slice(b"+\n+auto.master\n");
    m.extend_from_slice(&garbage(3000, 9));
    m.extend_from_slice(b"\n/mnt/end /etc/autofs/auto.a\n");
    let c = Case::new("h_master", &["-d", "-m"]).etc_bytes("autofs/auto.master", &m).map("auto.a", "a s:/a\n");
    check(c);
    let c = lk("h_master_lk", "", &[("/mnt/ok", "a"), ("/mnt/end", "a"), ("/mnt/dup", "a"), ("/mnt/opts", "a")])
        .etc_bytes("autofs/auto.master", &m)
        .map("auto.a", "a s:/a\n");
    check_drv(c);
}

// ---- hostile keys ----

fn hostile_keys() -> Vec<String> {
    let mut k: Vec<String> = [
        "..",
        ".",
        "a/b",
        "/",
        "/abs",
        "a/../b",
        "-o",
        "--",
        "*",
        "&",
        "\\",
        "\"",
        "'",
        ";id",
        "$(id)",
        "`id`",
        "a b",
        "a\tb",
        "a\nb",
        "%s%n",
        "${HOME}",
        "$HOME",
        "~",
        "\u{e9}",
        "\u{202e}x",
        "a:b",
        "a,b",
        "\u{7f}",
        "#",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for n in [255usize, 256, 4096] {
        k.push("L".repeat(n));
    }
    k
}

/// Every hostile key against a wildcard that substitutes it, in sun format.
#[test]
fn hostile_keys_sun_wildcard() {
    let keys = hostile_keys();
    let k: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
    check_drv(file_keys("h_keys_sun", b"* -fstype=nfs,ro srv:/export/&\n", &k));
}

/// The same keys against a bind wildcard and a direct-path wildcard.
#[test]
fn hostile_keys_sun_bind() {
    let keys = hostile_keys();
    let k: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();
    check_drv(file_keys("h_keys_bind", b"* -fstype=bind :/srv/&\n", &k));
}

/// The keys through amd's `${key}` and `${/key}`.
#[test]
fn hostile_keys_amd() {
    let keys = hostile_keys();
    let mut l: Vec<(&str, &str)> = keys.iter().map(|k| ("/mnt/a", k.as_str())).collect();
    l.extend(keys.iter().map(|k| ("/mnt/b", k.as_str())));
    check_drv(
        lk("h_keys_amd", "/mnt/a file,amd:/etc/autofs/amd.a\n/mnt/b file,amd:/etc/autofs/amd.b\n", &l)
            .map("amd.a", "* type:=link;fs:=/srv/${key}\n")
            .map("amd.b", "* type:=nfs;rhost:=${key};rfs:=/x/${/key}/${key/}\n"),
    );
}

/// The keys handed to a program map, which echoes them back.
#[test]
fn hostile_keys_program() {
    let keys = hostile_keys();
    let l: Vec<(&str, &str)> = keys.iter().map(|k| ("/mnt/p", k.as_str())).collect();
    check_drv(lk("h_keys_prog", "/mnt/p /etc/autofs/auto.prog\n", &l).etc_mode(
        "autofs/auto.prog",
        b"#!/bin/sh\nprintf 's:/%s\\n' \"$1\"\n",
        0o755,
    ));
}

// ---- program maps ----

const HOSTILE_PROG: &str = r#"#!/bin/sh
case "$1" in
flood) head -c 70000 /dev/zero | tr '\0' x; echo ;;
floodline) head -c 70000 /dev/zero | tr '\0' x ;;
floodlines) i=0; while [ $i -lt 3000 ]; do echo "s$i:/x \\"; i=$((i+1)); done; echo ;;
floodentry) printf -- '-ro '; head -c 20000 /dev/zero | tr '\0' 'o'; echo ' s:/x' ;;
errflood) head -c 300000 /dev/zero | tr '\0' e >&2; echo s:/e ;;
nul) printf 's:/a\000b\n' ;;
nulfirst) printf '\000s:/a\n' ;;
binary) head -c 4000 @T@/garbage ;;
crlf) printf 's:/x\r\n' ;;
cr) printf 's:/x\rs:/y' ;;
nonl) printf 's:/nonl' ;;
twolines) printf 's:/one\ns:/two\n' ;;
blankfirst) printf '\ns:/second\n' ;;
backslash) printf '\\' ;;
quote) printf '"s:/x' ;;
dash) printf -- '-' ;;
comment) printf '#s:/x\n' ;;
hash) printf 's:/a#b\n' ;;
multi) printf '/ s:/root /a s:/a /a s:/dup /../x s:/up' ;;
multibad) printf '/a /b /c' ;;
manyhosts) i=0; while [ $i -lt 500 ]; do printf 'h%d,' $i; i=$((i+1)); done; echo 'z:/x' ;;
slow) sleep 1; echo s:/slow ;;
bg) (sleep 1; echo late) & echo s:/now ;;
bgerr) (exec >/dev/null; sleep 1; echo late >&2) & echo s:/now ;;
closeout) exec >&-; sleep 1; exit 0 ;;
closeboth) exec >&- 2>&-; sleep 1; echo gone ;;
kill9) echo s:/k; kill -9 $$ ;;
segv) echo s:/k; kill -SEGV $$ ;;
exit1) echo s:/x; exit 1 ;;
exit255) echo s:/x; exit 255 ;;
*) echo "s:/$1" ;;
esac
"#;

const HOSTILE_PROG_KEYS: &[&str] = &[
    "flood",
    "floodline",
    "floodlines",
    "floodentry",
    "errflood",
    "nul",
    "nulfirst",
    "binary",
    "crlf",
    "cr",
    "nonl",
    "twolines",
    "blankfirst",
    "backslash",
    "quote",
    "dash",
    "comment",
    "hash",
    "multi",
    "multibad",
    "manyhosts",
    "slow",
    "bg",
    "bgerr",
    "closeout",
    "closeboth",
    "kill9",
    "segv",
    "exit1",
    "exit255",
];

fn prog(name: &str, keys: &[&str]) -> Case {
    let l: Vec<(&str, &str)> = keys.iter().map(|k| ("/mnt/p", *k)).collect();
    lk(name, "/mnt/p /etc/autofs/auto.prog\n", &l)
        .etc_mode("autofs/auto.prog", HOSTILE_PROG.as_bytes(), 0o755)
        .file("garbage", &garbage(4000, 11))
        // Without its directory the child's "failed to set PWD" warning goes
        // to stderr, and a flood then deadlocks (hostile_program_deadlock).
        .setup("mkdir -p /mnt/p")
}

#[test]
fn hostile_program_output() {
    for k in HOSTILE_PROG_KEYS {
        check_drv(prog(&format!("h_prog_{k}"), &[k]));
    }
}

/// Program maps that aren't programs: not executable, a directory, garbage,
/// an interpreter that doesn't exist.
#[test]
fn hostile_program_not_runnable() {
    let l = [("/mnt/p", "a"), ("/mnt/q", "a"), ("/mnt/r", "a")];
    let c = lk(
        "h_prog_bad",
        "/mnt/p program:/etc/autofs/auto.g\n/mnt/q program:/etc/autofs/auto.i\n/mnt/r program:/etc/autofs\n",
        &l,
    )
    .etc_mode("autofs/auto.g", &garbage(3000, 12), 0o755)
    .etc_mode("autofs/auto.i", b"#!/no/such/interpreter\n", 0o755);
    check_drv(c);
}

/// QUIRK: `lookup_one()` drains whichever pipe `poll()` reports with blocking
/// reads until EOF, so a program with output pending on stderr and more than
/// a pipe's worth on stdout (or the other way round) blocks on the pipe that
/// isn't read, and the lookup never returns. The drivers are killed after five
/// seconds; both have printed the same lines by then.
#[test]
fn hostile_program_deadlock() {
    for (k, mkdir) in [("flood", false), ("errthenflood", true), ("floodthenerr", true), ("bothflood", true)] {
        let mut c = prog(&format!("h_prog_dead_{k}{}", if mkdir { "" } else { "_nopwd" }), &[k, "after"])
            .wrap("timeout -s KILL 5")
            .etc_mode("autofs/auto.prog", DEADLOCK_PROG.as_bytes(), 0o755);
        if !mkdir {
            c.setup.clear();
        }
        check_drv(c);
    }
}

const DEADLOCK_PROG: &str = r#"#!/bin/sh
case "$1" in
flood) head -c 70000 /dev/zero | tr '\0' x; echo ;;
errthenflood) echo first >&2; head -c 70000 /dev/zero | tr '\0' x; echo ;;
floodthenerr) head -c 70000 /dev/zero | tr '\0' e >&2; sleep 0.2; head -c 70000 /dev/zero | tr '\0' x; echo ;;
bothflood) head -c 200000 /dev/zero | tr '\0' e >&2 & head -c 200000 /dev/zero | tr '\0' o; wait; echo ;;
*) echo "s:/$1" ;;
esac
"#;

// ---- configuration files ----

/// `autofs.conf` lines at `fgets()`'s 256-byte chunking (a long line is read
/// as several), garbage, NUL bytes, unterminated sections, and values that
/// don't parse.
fn hostile_conf() -> Vec<u8> {
    let mut c = Vec::new();
    c.extend_from_slice(b"[ autofs ]\n");
    c.extend_from_slice(format!("timeout = {}\n", "9".repeat(300)).as_bytes());
    c.extend_from_slice(format!("{}browse_mode = yes\n", " ".repeat(255 - 16)).as_bytes());
    // The second 256-byte chunk is "browse_mode = no" (one byte later it
    // would be "rowse_mode = no", and the browse_mode above would stand).
    c.extend_from_slice(format!("x{}browse_mode = no\n", "y".repeat(255)).as_bytes());
    c.extend_from_slice(format!("{} = 1\n", "k".repeat(254)).as_bytes());
    c.extend_from_slice(b"mount_wait = -5\n");
    c.extend_from_slice(b"umount_wait = 12abc\n");
    c.extend_from_slice(b"logging = \0debug\n");
    c.extend_from_slice(b"= novalue\n");
    c.extend_from_slice(b"nokey\n");
    c.extend_from_slice(b"[ unterminated\n");
    c.extend_from_slice(format!("[ {} ]\n", "s".repeat(300)).as_bytes());
    c.extend_from_slice(b"[ amd ]\n");
    c.extend_from_slice(b"dismount_interval = 99999999999999999999\n");
    c.extend_from_slice(b"pid_file = /x\n");
    c.extend_from_slice(b"[ /mnt/a ]\n");
    c.extend_from_slice(b"map_type = nosuchtype\n");
    c.extend_from_slice(&garbage(2000, 21));
    c.extend_from_slice(b"\n[ autofs ]\n");
    c
}

#[test]
fn hostile_conf_dump() {
    check(
        Case::new("h_conf", &["-d", "-m"])
            .master("/mnt/a /etc/autofs/auto.a\n")
            .map("auto.a", "a s:/a\n")
            .etc_bytes("autofs/autofs.conf", &hostile_conf()),
    );
}

#[test]
fn hostile_conf_lookup() {
    check_drv(
        file_keys("h_conf_lk", b"a s:/a\n* s:/&\n", &["a", "b"]).etc_bytes("autofs/autofs.conf", &hostile_conf()),
    );
}

/// Config files that are directories, and an old-style config of garbage.
#[test]
fn hostile_conf_not_files() {
    check(
        Case::new("h_conf_dir", &["-d", "-m"])
            .master("/mnt/a /etc/autofs/auto.a\n")
            .map("auto.a", "a s:/a\n")
            .setup("mkdir -p /etc/autofs/autofs.conf")
            .etc_bytes("conf.d/autofs", &garbage(3000, 22)),
    );
    check(
        Case::new("h_conf_dir2", &["-d", "-m"])
            .master("/mnt/a /etc/autofs/auto.a\n")
            .map("auto.a", "a s:/a\n")
            .setup("mkdir -p /etc/conf.d/autofs"),
    );
    check(
        Case::new("h_master_dir", &["-d", "-m"])
            .setup("rm -f /etc/autofs/auto.master; mkdir -p /etc/autofs/auto.master"),
    );
    check(
        Case::new("h_map_dir", &["-d", "-m"])
            .master("/mnt/a /etc/autofs/auto.a\n")
            .setup("mkdir -p /etc/autofs/auto.a"),
    );
}

/// `nsswitch.conf` garbage, long lines, odd actions and unknown sources.
#[test]
fn hostile_nsswitch() {
    let mut n = Vec::new();
    n.extend_from_slice(b"hosts: files\n");
    n.extend_from_slice(b"automount: files [NOTFOUND=bogus] [=return] [SUCCESS=] [!UNAVAIL=continue] nosuchsrc ");
    n.extend_from_slice("x".repeat(5000).as_bytes());
    n.extend_from_slice(b" nis [\n");
    n.extend_from_slice(&garbage(2000, 23));
    n.extend_from_slice(b"\nautomount: files\n");
    check(
        Case::new("h_nss", &["-d", "-m"])
            .master("/mnt/a auto.a\n")
            .map("auto.a", "a s:/a\n")
            .etc_bytes("nsswitch.conf", &n),
    );
    check_drv(
        lk("h_nss_lk", "/mnt/a auto.a\n", &[("/mnt/a", "a")]).map("auto.a", "a s:/a\n").etc_bytes("nsswitch.conf", &n),
    );
    check(
        Case::new("h_nss_dir", &["-d", "-m"])
            .master("/mnt/a auto.a\n")
            .map("auto.a", "a s:/a\n")
            .setup("rm -f /etc/nsswitch.conf; mkdir /etc/nsswitch.conf"),
    );
}

// ---- amd maps ----

fn amd_garbage_map() -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(b"/defaults type:=nfs;opts:=rw\n");
    m.extend_from_slice(b"ok rhost:=s;rfs:=/ok\n");
    m.extend_from_slice(b"unterm rhost:=${unterminated;rfs:=/x\n");
    m.extend_from_slice(b"nested rhost:=${${key}};rfs:=/x\n");
    m.extend_from_slice(b"sel host==;os!=;==x;!= rhost:=s;rfs:=/x\n");
    m.extend_from_slice(b"fn in(;exists();true(x,y);netgrp(a,b,c);xhost() rhost:=s\n");
    m.extend_from_slice(b"noeq rhost;rfs\n");
    m.extend_from_slice(b"semis ;;;;;;\n");
    m.extend_from_slice(b"dashes - - - || - ||\n");
    m.extend_from_slice(b"quotes \"rhost:=s;rfs:=/q\n");
    m.extend_from_slice(b"badtype type:=nosuch;fs:=/x\n");
    m.extend_from_slice(b"cache cache:=x;type:=link;fs:=/c\n");
    m.extend_from_slice(format!("longsel host=={} rhost:=s;rfs:=/x\n", "h".repeat(5000)).as_bytes());
    m.extend_from_slice(format!("longval rhost:=s;rfs:=/{}\n", "v".repeat(20000)).as_bytes());
    m.extend_from_slice(format!("longopt opts:={};rhost:=s;rfs:=/x\n", "o,".repeat(5000)).as_bytes());
    m.extend_from_slice(format!("manyexp type:=link;fs:={}\n", "${key}".repeat(5000)).as_bytes());
    m.extend_from_slice(format!("manyloc {}\n", "type:=link;fs:=/l ".repeat(2000)).as_bytes());
    m.extend_from_slice(b"pfx/* type:=link;fs:=/p/${key}\n");
    m.extend_from_slice(&garbage(2000, 31));
    m.extend_from_slice(b"\nlast type:=link;fs:=/last\n");
    m
}

#[test]
fn hostile_amd_garbage() {
    let keys = [
        "ok",
        "unterm",
        "nested",
        "sel",
        "fn",
        "noeq",
        "semis",
        "dashes",
        "quotes",
        "badtype",
        "cache",
        "longsel",
        "longval",
        "longopt",
        "manyexp",
        "manyloc",
        "pfx/x",
        "pfx/../..",
        "last",
    ];
    let l: Vec<(&str, &str)> = keys.iter().map(|k| ("/mnt/a", *k)).collect();
    check_drv(lk("h_amd", "/mnt/a file,amd:/etc/autofs/amd.a\n", &l).etc_bytes("autofs/amd.a", &amd_garbage_map()));
    check(
        Case::new("h_amd_dump", &["-d", "-m"])
            .master("/mnt/a file,amd:/etc/autofs/amd.a\n")
            .etc_bytes("autofs/amd.a", &amd_garbage_map()),
    );
}

#[test]
fn hostile_amd_printable_garbage() {
    for seed in [32u32, 33, 34] {
        let alphabet = b"ab:=;/ \t\n\\\"-|!${}(),*";
        let m: Vec<u8> = garbage(6000, seed).iter().map(|b| alphabet[*b as usize % alphabet.len()]).collect();
        let l = [("/mnt/a", "a"), ("/mnt/a", "b"), ("/mnt/a", "ab"), ("/mnt/a", "/defaults")];
        check_drv(
            lk(&format!("h_amd_pg{seed}"), "/mnt/a file,amd:/etc/autofs/amd.a\n", &l).etc_bytes("autofs/amd.a", &m),
        );
    }
}

// ---- sun entries: macros, options, multi-mounts ----

#[test]
fn hostile_sun_expansion() {
    let mut m = String::new();
    m.push_str(&format!("manyamp srv:/{}\n", "&".repeat(5000)));
    m.push_str(&format!("manyvar srv:/{}\n", "$HOST".repeat(3000)));
    m.push_str("bigdef srv:/${BIG}/${BIG}/${BIG}\n");
    m.push_str("selfref srv:/${SELF}\n");
    m.push_str(&format!("longvar srv:/${{{}}}\n", "V".repeat(5000)));
    m.push_str("badvar srv:/${\n");
    m.push_str(&format!("opts -{} srv:/x\n", "ro,".repeat(5000)));
    m.push_str(&format!("fstype -fstype={} :/x\n", "f".repeat(300)));
    m.push_str(&format!("hosts {}:/x\n", (0..2000).map(|i| format!("h{i}(1)")).collect::<Vec<_>>().join(",")));
    m.push_str(&format!("weight srv({}):/x\n", "9".repeat(50)));
    m.push_str("weightbad srv(:/x srv(1:/x srv():/x\n");
    m.push_str("ipv6 [::1]:/x [fe80::1%eth0]:/y [::1:/z\n");
    m.push_str(&format!("multi {}\n", (0..2000).map(|i| format!("/o{i} s:/{i}")).collect::<Vec<_>>().join(" ")));
    m.push_str("multidup / s:/a / s:/b /x s:/x /x s:/y\n");
    m.push_str("multiodd /a /b s:/b /c\n");
    m.push_str("multidots /. s:/a /.. s:/b /a/../b s:/c //x s:/d\n");
    m.push_str(&format!("multideep /{} s:/deep\n", (0..300).map(|i| format!("d{i}")).collect::<Vec<_>>().join("/")));
    let keys = [
        "manyamp",
        "manyvar",
        "bigdef",
        "selfref",
        "longvar",
        "badvar",
        "opts",
        "fstype",
        "hosts",
        "weight",
        "weightbad",
        "ipv6",
        "multi",
        "multidup",
        "multiodd",
        "multidots",
        "multideep",
    ];
    let l: Vec<(&str, &str)> = keys.iter().map(|k| ("/mnt/a", *k)).collect();
    let master = format!("/mnt/a /etc/autofs/auto.a -DBIG={} -DSELF=${{SELF}}\n", "b".repeat(123));
    check_drv(lk("h_sun_exp", &master, &l).map("auto.a", &m));
    let master = format!("/mnt/a /etc/autofs/auto.a -DBIG={}\n", "b".repeat(124));
    check_drv(lk("h_sun_exp_def", &master, &[("/mnt/a", "bigdef")]).map("auto.a", &m));
}
