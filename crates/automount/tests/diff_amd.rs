//! Differential tests: amd maps (`modules/amd_tok.l`, `modules/amd_parse.y`,
//! `modules/parse_amd.c` and the amd key matching of the lookup modules),
//! through the test drivers with recording mount modules.

mod common;

use common::{Case, check_drv};

/// An amd case: `/mnt/a` from `amd.a`, keys looked up by uid 0.
fn amd(name: &str, map: &str, keys: &[&str]) -> Case {
    let mut args: Vec<String> = vec!["-d".into()];
    for k in keys {
        args.extend(["/mnt/a".to_string(), k.to_string(), "0".into(), "0".into()]);
    }
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    Case::new(name, &a).master("/mnt/a file,amd:/etc/autofs/amd.a\n").map("amd.a", map)
}

#[test]
fn amd_basic() {
    check_drv(amd(
        "amd_basic",
        "/defaults type:=nfs;opts:=rw,intr\n\
         a rhost:=srv;rfs:=/export/a\n\
         b type:=link;fs:=/tmp/target\n\
         c type:=auto;fs:=/etc/autofs/amd.sub\n\
         d type:=ext4;dev:=/dev/sdb1\n\
         * type:=link;fs:=/srv/${key}\n",
        &["a", "b", "c", "d", "zz"],
    ));
}

#[test]
fn amd_types() {
    check_drv(
        amd(
            "amd_types",
            "/defaults opts:=rw\n\
             sub type:=link;fs:=/srv;sublink:=x/y\n\
             subabs type:=link;fs:=/srv;sublink:=/abs\n\
             lx type:=linkx;fs:=/etc\n\
             lxmissing type:=linkx;fs:=/nonexistent\n\
             lofs type:=lofs;rfs:=/srv/r\n\
             lofsfs type:=lofs;rfs:=/srv/r;fs:=/tmp/lofs\n\
             lofsnorfs type:=lofs;rfs:=\n\
             xfs type:=xfs;dev:=/dev/x\n\
             cdfs type:=cdfs;dev:=/dev/sr0\n\
             ufs type:=ufs;dev:=/dev/u\n\
             nodev type:=ext2\n\
             emptydev type:=ext3;dev:=\n\
             nfsl type:=nfsl;rhost:=${host};rfs:=/srv\n\
             nfsl2 type:=nfsl;rhost:=elsewhere;rfs:=/srv\n\
             nfsnofs type:=nfs;rhost:=s;rfs:=/x;fs:=\n\
             nfsnorfs type:=nfs;rhost:=s;rfs:=\n\
             nfs4 type:=nfs4;rhost:=s;rfs:=/x\n\
             norhost type:=nfs;rhost:=;rfs:=/x\n\
             auto2 type:=auto;fs:=/etc/autofs/amd.sub;maptype:=file\n\
             autoexec type:=auto;fs:=/x;maptype:=exec\n\
             autonofs type:=auto;fs:=\n\
             jfs type:=jfs;dev:=/dev/j\n\
             direct type:=direct\n\
             cachefs type:=cachefs;fs:=/c\n\
             bogus type:=bogus\n\
             qtype type:=\"link\";fs:=/q\n\
             passwd type:=auto;maptype:=passwd;fs:=/p\n\
             ndbm type:=auto;maptype:=ndbm;fs:=/p\n\
             hesiod type:=auto;maptype:=hesiod;fs:=/p\n\
             qmaptype type:=auto;maptype:=\"nis\";fs:=/p\n\
             link type:=link;fs:=/l;opts:=ro\n\
             nolink type:=link\n",
            &[
                "sub",
                "subabs",
                "lx",
                "lxmissing",
                "lofs",
                "lofsfs",
                "lofsnorfs",
                "xfs",
                "cdfs",
                "ufs",
                "nodev",
                "emptydev",
                "nfsl",
                "nfsl2",
                "nfsnofs",
                "nfsnorfs",
                "nfs4",
                "norhost",
                "auto2",
                "autoexec",
                "autonofs",
                "jfs",
                "direct",
                "cachefs",
                "bogus",
                "qtype",
                "passwd",
                "ndbm",
                "hesiod",
                "qmaptype",
                "link",
                "nolink",
            ],
        )
        .conf("[ amd ]\nautofs_use_lofs = no\n"),
    );
}

#[test]
fn amd_use_lofs() {
    check_drv(
        amd("amd_lofs", "l type:=link;fs:=/l;opts:=ro\nn type:=link;fs:=/n\n", &["l", "n"])
            .conf("[ amd ]\nautofs_use_lofs = yes\n"),
    );
}

#[test]
fn amd_program_mounts() {
    check_drv(
        amd(
            "amd_program",
            "ok type:=program;fs:=/tmp/pm/ok;mount:=\"/bin/sh sh -c 'echo mounted $0 >&2' ${fs}\";umount:=\"/bin/true true\"\n\
             again type:=program;fs:=/tmp/pm/ok;mount:=\"/bin/true true\"\n\
             bad type:=program;fs:=/tmp/pm/bad;mount:=\"/bin/false false\"\n\
             nomount type:=program;fs:=/tmp/pm/x\n\
             nofs type:=program;fs:=;mount:=\"/bin/true true\"\n\
             missing type:=program;fs:=/tmp/pm/m;mount:=\"/nonexistent/prog prog\"\n\
             unexp type:=program;fs:=/tmp/pm/u;mount:=\"${nosuchvar}\"\n\
             twice type:=program;fs:=/tmp/pm/t;mount:=\"/bin/true true\";umount:=a;unmount:=b\n\
             quoted type:=program;fs:=/tmp/pm/q;mount:=\"/bin/sh 'sh' -c 'echo  two  spaces >&2'\"\n",
            &["ok", "again", "bad", "nomount", "nofs", "missing", "unexp", "twice", "quoted"],
        )
        .setup("mkdir -p /tmp/pm"),
    );
}

#[test]
fn amd_selectors() {
    check_drv(amd(
        "amd_selectors",
        "os os==linux;type:=link;fs:=/linux os!=linux;type:=link;fs:=/other\n\
         osne os!=linux;type:=link;fs:=/1 type:=link;fs:=/2\n\
         uid uid==0;type:=link;fs:=/root uid!=0;type:=link;fs:=/user\n\
         uidne uid!=0;type:=link;fs:=/a uid==;type:=link;fs:=/b\n\
         hostsel host==${host};type:=link;fs:=/me\n\
         hostne host!=;type:=link;fs:=/hostne\n\
         hosteq host==;type:=link;fs:=/hosteq\n\
         keysel key==keysel;type:=link;fs:=/k\n\
         mapsel map==/etc/autofs/amd.a;type:=link;fs:=/m\n\
         pathsel path==/mnt/a/pathsel;type:=link;fs:=/p\n\
         autodir autodir==/a;type:=link;fs:=/ad\n\
         exists exists(/etc);type:=link;fs:=/e\n\
         nexists !exists(/nonexistent);type:=link;fs:=/ne\n\
         exmacro exists(${path});type:=link;fs:=/em type:=link;fs:=/em2\n\
         true true(x);type:=link;fs:=/t\n\
         false false(x);type:=link;fs:=/f type:=link;fs:=/f2\n\
         nottrue !true(x);type:=link;fs:=/nt type:=link;fs:=/nt2\n\
         notfalse !false(x);type:=link;fs:=/nf\n\
         innet in_network(127.0.0.1);type:=link;fs:=/in\n\
         innet2 network(10.255.255.0/24);type:=link;fs:=/in2 type:=link;fs:=/out\n\
         innet3 wire(loopback);type:=link;fs:=/w type:=link;fs:=/w2\n\
         innet4 netnumber(127.0);type:=link;fs:=/nn type:=link;fs:=/nn2\n\
         xhost xhost(localhost);type:=link;fs:=/xh type:=link;fs:=/xh2\n\
         xhostme xhost(${host});type:=link;fs:=/xme\n\
         netgrp netgrp(nogroup);type:=link;fs:=/ng type:=link;fs:=/ng2\n\
         netgrp2 netgrp(nogroup,somehost);type:=link;fs:=/ng type:=link;fs:=/ng3\n\
         netgrpd !netgrpd(nogroup);type:=link;fs:=/ngd\n\
         two os==linux;uid==0;type:=link;fs:=/two\n\
         three key==three;os==nope;uid==0;type:=link;fs:=/three type:=link;fs:=/three2\n\
         tri key==tri;os==nope;key==tri;type:=link;fs:=/tri\n\
         two2 os==nope;key==two2;type:=link;fs:=/two2\n\
         none os==nope;type:=link;fs:=/x os==nope2;type:=link;fs:=/y\n\
         cut os==nope;type:=link;fs:=/c1 || type:=link;fs:=/c2\n\
         cut2 type:=link;fs:= || type:=link;fs:=/c3\n\
         bytes byte==little;type:=link;fs:=/le byte==big;type:=link;fs:=/be\n\
         quotedsel os==\"linux\";type:=link;fs:=/qs\n\
         dotted domain==a.b.c;type:=link;fs:=/d type:=link;fs:=/d2\n",
        &[
            "os",
            "osne",
            "uid",
            "uidne",
            "hostsel",
            "hostne",
            "hosteq",
            "keysel",
            "mapsel",
            "pathsel",
            "autodir",
            "exists",
            "nexists",
            "exmacro",
            "true",
            "false",
            "nottrue",
            "notfalse",
            "innet",
            "innet2",
            "innet3",
            "innet4",
            "xhost",
            "xhostme",
            "netgrp",
            "netgrp2",
            "netgrpd",
            "two",
            "three",
            "tri",
            "two2",
            "none",
            "cut",
            "cut2",
            "bytes",
            "quotedsel",
            "dotted",
        ],
    ));
}

#[test]
fn amd_syntax() {
    let long = "x".repeat(2100);
    let longopts = (0..120).map(|i| format!("o{i}")).collect::<Vec<_>>().join(",");
    check_drv(amd(
        "amd_syntax",
        &format!(
            "other foo;type:=link;fs:=/x\n\
             echo !;type:=link;fs:=/x\n\
             colon type:=link;fs:=/x;:\n\
             trailing type:=link;fs:=/x;\n\
             twosep type:=link;fs:=/x;;rhost:=h\n\
             comment type:=link;fs:=/x # a comment\n\
             tab type:=link;fs:=/x\t \ttype:=link;fs:=/y\n\
             dq type:=link;fs:=\"/quoted path\"\n\
             dqbad type:=link;fs:=\"/a\"b\n\
             sq type:=link;fs:=/it's\n\
             sq2 type:=link;fs:='/a b'\n\
             emptyfs fs:=;type:=link\n\
             emptyother pref:=;type:=link;fs:=/e\n\
             prefnull pref:=null;type:=link;fs:=/pn\n\
             pref pref:=p/;type:=auto;fs:=/etc/autofs/amd.sub\n\
             emptyrhost rhost:=;rfs:=/x\n\
             mountempty type:=program;mount:=;fs:=/tmp/x\n\
             delay delay:=5;cachedir:=/c;type:=link;fs:=/d\n\
             dev dev:=/dev/x;type:=ext2\n\
             opts opts:=ro,soft,intr;type:=link;fs:=/o\n\
             optsq opts:=\"ro,soft\";type:=link;fs:=/o\n\
             optscomma opts:=ro,,soft,;type:=link;fs:=/o\n\
             optsassign opts:=,ro;type:=link;fs:=/o\n\
             optsempty opts:=;type:=link;fs:=/o\n\
             ignored opts:=fullybrowsable,nounmount,ping=3,retry=2,public,softlookup,xlatecookie,ro;type:=link;fs:=/o\n\
             utimeout opts:=utimeout=30,ro;type:=link;fs:=/o\n\
             utimeoutlast opts:=ro,utimeout=30;type:=link;fs:=/o\n\
             utimeoutauto type:=auto;opts:=ro,utimeout=30;fs:=/etc/autofs/amd.sub\n\
             addopts addopts:=nosuid;type:=link;fs:=/o\n\
             remopts remopts:=nodev;type:=link;fs:=/o\n\
             badmnt opts:=a=;type:=link;fs:=/o\n\
             cache cache:=all;type:=link;fs:=/c\n\
             cache2 cache:=inc,sync;type:=link;fs:=/c\n\
             cache3 cache:=\"re\";type:=link;fs:=/c\n\
             cachebad cache:=bogus;type:=link;fs:=/c\n\
             fsbare fs:\n\
             hyphen -\n\
             hyphenopts -opts:=ro type:=link;fs:=/h\n\
             crlf type:=link;fs:=/crlf\r\n\
             long type:=link;fs:=/{long}\n\
             longopts opts:={longopts};type:=link;fs:=/lo\n\
             sublinkonly sublink:=s;type:=nfs;rhost:=h;rfs:=/r;fs:=/f\n\
             spaces   type:=link;fs:=/s    \n\
             bad==sel type:=link;fs:=/x\n\
             cutonly ||\n\
             semis ;;;\n"
        ),
        &[
            "other",
            "echo",
            "colon",
            "trailing",
            "twosep",
            "comment",
            "tab",
            "dq",
            "dqbad",
            "sq",
            "sq2",
            "emptyfs",
            "emptyother",
            "prefnull",
            "pref",
            "emptyrhost",
            "mountempty",
            "delay",
            "dev",
            "opts",
            "optsq",
            "optscomma",
            "optsassign",
            "optsempty",
            "ignored",
            "utimeout",
            "utimeoutlast",
            "utimeoutauto",
            "addopts",
            "remopts",
            "badmnt",
            "cache",
            "cache2",
            "cache3",
            "cachebad",
            "fsbare",
            "hyphen",
            "hyphenopts",
            "crlf",
            "long",
            "longopts",
            "sublinkonly",
            "spaces",
            "cutonly",
            "semis",
        ],
    ));
}

#[test]
fn amd_long_opts_overflow() {
    // An opts list over 1023 bytes overflows prepend_opt()'s buffer.
    let opts = (0..300).map(|i| format!("o{i}")).collect::<Vec<_>>().join(",");
    check_drv(amd("amd_long_opts", &format!("k opts:={opts};type:=link;fs:=/o\n"), &["k"]));
    // So does one option of 1024 bytes or more.
    let one = format!("o{}", "x".repeat(1100));
    check_drv(amd("amd_long_opt", &format!("k opts:={one};type:=link;fs:=/o\n"), &["k"]));
}

#[test]
fn amd_defaults() {
    let map = "/defaults opts:=ro,nosuid;type:=link;fs:=/def/${key}\n\
               plain\n\
               own fs:=/own\n\
               merge -opts:=rw type:=link;fs:=/m\n\
               reset -opts:=rw - type:=link;fs:=/r\n\
               mergeonly -type:=link;fs:=/mo\n\
               mergeempty - type:=link;fs:=/me\n\
               addopts addopts:=noexec\n\
               nfs type:=nfs;rhost:=h;rfs:=/x\n";
    let keys = ["plain", "own", "merge", "reset", "mergeonly", "mergeempty", "addopts", "nfs"];
    check_drv(amd("amd_defaults", map, &keys));
    check_drv(amd("amd_defaults_sel", map, &keys).conf("[ amd ]\nselectors_in_defaults = yes\n"));
    check_drv(
        amd("amd_map_defaults", map, &["plain", "own"])
            .conf("[ amd ]\nmap_defaults = type:=link;fs:=/conf;opts:=noatime\n"),
    );
    let sel = "/defaults os==nope;fs:=/no key==k;type:=link;fs:=/yes;opts:=x\nk\nj\n";
    check_drv(amd("amd_defaults_selectors", sel, &["k", "j"]).conf("[ amd ]\nselectors_in_defaults = yes\n"));
    check_drv(amd("amd_defaults_selectors_off", sel, &["k", "j"]));
    let merge = "/defaults -opts:=rw os==nope;fs:=/no\nk type:=link;fs:=/k\n";
    check_drv(amd("amd_defaults_merge", merge, &["k"]).conf("[ amd ]\nselectors_in_defaults = yes\n"));
    check_drv(amd("amd_defaults_bad", "/defaults foo bar\nk type:=link;fs:=/k\n", &["k"]));
    check_drv(
        amd("amd_defaults_maptype", "k type:=auto;fs:=/s\n/defaults opts:=ro\n", &["k"])
            .conf("[ amd ]\nmap_type = file\n"),
    );
    check_drv(amd("amd_defaults_hesiod", "k type:=auto;fs:=/s\n", &["k"]).conf("[ amd ]\nmap_type = hesiod\n"));
    check_drv(
        amd("amd_defaults_hesiod2", "/defaults opts:=ro\nk type:=auto;fs:=/s\n", &["k"])
            .conf("[ amd ]\nmap_type = hesiod\n"),
    );
}

#[test]
fn amd_defaults_reset_crash() {
    // A `-` in /defaults with selectors_in_defaults dereferences NULL.
    check_drv(
        amd("amd_defaults_reset_crash", "/defaults - os==x;fs:=/n\nk type:=link;fs:=/k\n", &["k"])
            .conf("[ amd ]\nselectors_in_defaults = yes\n"),
    );
}

#[test]
fn amd_merge_options() {
    check_drv(amd(
        "amd_merge",
        "/defaults opts:=rw,soft,intr,nodev,rsize=8192;remopts:=hard\n\
         a type:=nfs;rhost:=127.0.0.1;rfs:=/x;addopts:=ro,hard,dev,rsize=4096,new\n\
         b type:=nfs;rhost:=8.8.8.8;rfs:=/x;addopts:=ro\n\
         c type:=nfs;rhost:=8.8.8.8;rfs:=/x;remopts:=nosuid;addopts:=bg\n\
         d type:=nfs;rhost:=8.8.8.8;rfs:=/x;opts:=a,b;remopts:=a,b;addopts:=c\n\
         e type:=nfs;rhost:=8.8.8.8;rfs:=/x;opts:=;addopts:=z\n\
         f type:=nfs;rhost:=10.1;rfs:=/x;remopts:=r\n\
         g type:=nfs;rhost:=127.0.0.1/8;rfs:=/x\n\
         h type:=nfs;rhost:=1.2.3.4.5;rfs:=/x\n\
         i type:=nfs;rhost:=::1;rfs:=/x\n\
         j type:=nfs;rhost:=fe80::1;rfs:=/x\n\
         k type:=nfs;rhost:=localhost;rfs:=/x;opts:=fg,ro;addopts:=bg,rw,nointr\n\
         l type:=nfs;rhost:=loopback;rfs:=/x\n\
         m type:=nfs;rhost:=a.b;rfs:=/x\n",
        &["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m"],
    ));
}

#[test]
fn amd_merge_overflow() {
    // merge_options()'s running length is reset, so a long result overflows.
    let a: String = (0..30).map(|i| format!("opta{i:02}")).collect::<Vec<_>>().join(",");
    let b: String = (0..15).map(|i| format!("addb{i:02}")).collect::<Vec<_>>().join(",");
    check_drv(amd("amd_merge_overflow", &format!("k type:=link;fs:=/o;opts:={a};addopts:={b}\n"), &["k"]));
    // Just short enough.
    let c: String = (0..20).map(|i| format!("addb{i:02}")).collect::<Vec<_>>().join(",");
    check_drv(amd("amd_merge_fits", &format!("k type:=link;fs:=/o;opts:=opta,optb;addopts:={c}\n"), &["k"]));
    let o = "o".repeat(300);
    check_drv(amd("amd_merge_long_opt1", &format!("k type:=link;fs:=/o;opts:={o},xx;addopts:=zz\n"), &["k"]));
}

#[test]
fn amd_expansion() {
    check_drv(amd(
        "amd_expand",
        "lead type:=link;fs:=${/path}\n\
         trail type:=link;fs:=${path/}\n\
         ldot type:=link;fs:=/d/${.host}\n\
         tdot type:=link;fs:=/d/${host.}\n\
         both type:=link;fs:=/d/${/path/}\n\
         unknown type:=link;fs:=/d/${nope}/${/nope}\n\
         unterm type:=link;fs:=/d/${path\n\
         empty type:=link;fs:=/d/${}\n\
         slashvar type:=link;fs:=/d/${/}\n\
         dollar type:=link;fs:=/d/$x/${dollar}\n\
         slashes type:=link;fs:=//a///b//c/\n\
         backslash type:=link;fs:=/a\\\\b\\c\n\
         quoteslash type:=link;fs:='//a//b'//c\n\
         rhostexp type:=nfs;rhost:=${key}.example;rfs:=/${key}\n\
         sublinkexp type:=link;fs:=/s;sublink:=${key}/sub\n\
         vars type:=link;fs:=/v/${map}/${path}/${uid}/${gid}/${autodir}/${arch}/${os}/${byte}/${cluster}\n",
        &[
            "lead",
            "trail",
            "ldot",
            "tdot",
            "both",
            "unknown",
            "unterm",
            "empty",
            "slashvar",
            "dollar",
            "slashes",
            "backslash",
            "quoteslash",
            "rhostexp",
            "sublinkexp",
            "vars",
        ],
    ));
    check_drv(
        amd(
            "amd_expand_noslash",
            "slashes type:=link;fs:=//a///b//c/\nbackslash type:=link;fs:=/a\\\\b\\c\n",
            &["slashes", "backslash"],
        )
        .conf("[ amd ]\nnormalize_slashes = no\n"),
    );
}

#[test]
fn amd_keys() {
    check_drv(amd(
        "amd_keys",
        "exact type:=link;fs:=/exact\n\
         dir/* type:=link;fs:=/dir/${key}\n\
         dir/sub/* type:=link;fs:=/dirsub/${key}\n\
         ab* type:=link;fs:=/ab\n\
         a/b/c type:=link;fs:=/abc\n\
         * type:=link;fs:=/wild/${key}\n",
        &["exact", "dir/x", "dir/sub/y", "dir/sub/y/z", "a/q", "a/b/c", "other", "${key}x", "with${dollar}"],
    ));
    check_drv(amd("amd_keys_nowild", "dir/* type:=link;fs:=/dir/${key}\n", &["dir/x", "other", "dir"]));
}

const AMD_PROG: &str = r#"#!/bin/sh
case "$1" in
/defaults) echo "/defaults opts:=ro;type:=link" ;;
a) echo "a fs:=/prog/a" ;;
short) echo "s" ;;
dir/\*) echo "dir/* fs:=/prog/dir/\${key}" ;;
spaced) printf 'spaced \t fs:=/sp\n' ;;
*) exit 1 ;;
esac
"#;

#[test]
fn amd_program_map() {
    let keys = ["a", "short", "dir/x", "dir/y/z", "spaced", "none"];
    let mut args: Vec<String> = vec!["-d".into()];
    for k in keys {
        args.extend(["/mnt/p".to_string(), k.to_string(), "0".into(), "0".into()]);
    }
    let a: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    check_drv(Case::new("amd_prog_map", &a).master("/mnt/p program,amd:/etc/autofs/amd.prog\n").etc_mode(
        "autofs/amd.prog",
        AMD_PROG.as_bytes(),
        0o755,
    ));
    let mut nd = AMD_PROG.replace("/defaults) echo", "/defaults) exit 1; echo");
    nd.push('\n');
    check_drv(
        Case::new("amd_prog_map_nodefaults", &["-d", "/mnt/p", "a", "0", "0"])
            .master("/mnt/p program,amd:/etc/autofs/amd.prog\n")
            .etc_mode("autofs/amd.prog", nd.as_bytes(), 0o755),
    );
}

#[test]
fn amd_conf_sections() {
    // A master map entry whose path has an amd section is an amd map.
    check_drv(
        Case::new("amd_conf_section", &["-d", "/mnt/s", "k", "0", "0", "/mnt/s", "j", "0", "0"])
            .master("/mnt/s /etc/autofs/amd.s\n")
            .map("amd.s", "k type:=link;fs:=/k\nj type:=link;fs:=${autodir}/j\n")
            .conf(
                "[ amd ]\nauto_dir = /amdtop\nlog_options = all\nmap_type = file\n\
                 [ /mnt/s ]\nmap_name = /etc/autofs/amd.s\nmap_defaults = opts:=ro\n\
                 autofs_use_lofs = yes\nselectors_in_defaults = yes\n",
            ),
    );
}

#[test]
fn amd_hostnames() {
    let map = "k type:=nfs;rhost:=localhost;rfs:=/x\nj type:=nfs;rhost:=nonexistent.invalid;rfs:=/x\n";
    check_drv(amd("amd_normalize", map, &["k", "j"]).conf("[ amd ]\nnormalize_hostnames = yes\n"));
    check_drv(
        amd("amd_domain_strip", map, &["k", "j"]).conf("[ amd ]\nnormalize_hostnames = yes\ndomain_strip = yes\n"),
    );
}

#[test]
fn amd_nfsl_domain() {
    // With a domain, ${host} and ${hostd} differ, so nfsl never links.
    let map = "h type:=nfsl;rhost:=${host};rfs:=/srv;fs:=/usr/share\n\
               hd type:=nfsl;rhost:=${hostd};rfs:=/srv;fs:=/usr/share\n\
               other type:=nfsl;rhost:=elsewhere;rfs:=/srv;fs:=/usr/share\n";
    check_drv(amd("amd_nfsl_domain", map, &["h", "hd", "other"]).conf("[ amd ]\nlocal_domain = example.com\n"));
    check_drv(amd("amd_nfsl_nodomain", map, &["h", "hd", "other"]));
}

#[test]
fn amd_keys_reread() {
    // A map changed since it was read is searched again for each key
    // (lookup_one() and match_key()).
    let map = "exact type:=link;fs:=/exact\n\
               ab* type:=link;fs:=/ab\n\
               dir/* type:=link;fs:=/dir/${key}\n\
               dir/sub/* type:=link;fs:=/dirsub/${key}\n\
               /defaults opts:=ro\n";
    let keys = ["exact", "a/q", "dir/x", "dir/sub/y", "dir/sub/y/z", "dir", "nope", "abc"];
    check_drv(amd("amd_keys_reread", map, &keys).setup("touch -d '+1 day' /etc/autofs/amd.a"));
    let wild = format!("{map}* type:=link;fs:=/wild/${{key}}\n");
    check_drv(amd("amd_keys_reread_wild", &wild, &keys).setup("touch -d '+1 day' /etc/autofs/amd.a"));
}
