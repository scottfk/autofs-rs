//! Differential tests: `automount -m` (`--dumpmaps`) and the startup before
//! the daemon detaches, against the C reference.

mod common;

use common::{Case, check};

const BASIC_MASTER: &str = "\
# a comment
/net\t/etc/autofs/auto.test --timeout=60 -fstype=nfs4,hard
/misc   file:/etc/autofs/auto.misc
/-\t/etc/autofs/auto.direct
";

fn basic() -> Case {
    Case::dump("basic")
        .master(BASIC_MASTER)
        .map("auto.test", "a\t-ro\tserver:/a\nb  server:/b\n# c\n* host:/&\n")
        .map("auto.misc", "cd -fstype=iso9660,ro :/dev/cdrom\n")
        .map("auto.direct", "/x/y  srv:/y\n/x/z srv:/z\n")
}

#[test]
fn dump_basic() {
    check(basic().named("dump_basic"));
}

#[test]
fn dump_basic_debug() {
    check(basic().named("dump_basic_debug").args(&["-d", "-m"]));
}

#[test]
fn dump_basic_verbose() {
    check(basic().named("dump_basic_verbose").args(&["--verbose", "--dumpmaps"]));
}

#[test]
fn dump_one_map() {
    check(basic().named("dump_one_map").args(&["-m", "file", "auto.test"]));
}

#[test]
fn dump_one_map_files() {
    check(basic().named("dump_one_map_files").args(&["-m", "files", "/etc/autofs/auto.misc"]));
}

#[test]
fn dump_one_map_missing() {
    check(basic().named("dump_one_map_missing").args(&["-m", "file", "auto.nothere"]));
}

#[test]
fn dump_one_map_wrong_type() {
    check(basic().named("dump_one_map_wrong_type").args(&["-m", "yp", "auto.test"]));
}

#[test]
fn dump_no_master() {
    check(Case::dump("no_master"));
}

#[test]
fn dump_no_master_debug() {
    check(Case::new("no_master_debug", &["-d", "-m"]));
}

#[test]
fn dump_empty_master() {
    check(Case::dump("empty_master").master(""));
}

#[test]
fn dump_auto_underscore_master() {
    check(
        Case::new("auto_underscore", &["-d", "-m"])
            .map("auto_master", "/x /etc/autofs/auto.x\n")
            .map("auto.x", "k v\n"),
    );
}

/// One master map line per case (a rejected line can leave the scanner in a
/// state that decides what the next line does; that has its own cases below).
const MASTER_LINES: &[&str] = &[
    "/a /etc/autofs/auto.a",
    "/a\t/etc/autofs/auto.a\t-ro,soft",
    "/b : x",
    "/c",
    "relative /etc/autofs/auto.a",
    "/d -hosts",
    "/d -hosts -nosuid,nodev",
    "/e -null",
    "/f -xfn",
    "/g /etc/autofs/auto.a -t 30 --negative-timeout 40 -browse -symlink",
    "/g /etc/autofs/auto.a --timeout=30 -n=40 --nobrowse",
    "/g /etc/autofs/auto.a -t30",
    "/h /etc/autofs/auto.a --mode 0700 -strictexpire -shared",
    "/h /etc/autofs/auto.a --mode=755 -slave -private",
    "/h /etc/autofs/auto.a --mode 0999",
    "/i /etc/autofs/auto.a -o,,x",
    "/i /etc/autofs/auto.a -rw,,soft",
    "/j /etc/autofs/auto.a = x",
    "/j /etc/autofs/auto.a -rw =",
    "/k /etc/autofs/auto.a --timeout 5 -Dfoo=bar --slashify-colons",
    "/k /etc/autofs/auto.a -D foo=bar --no-slashify-colons",
    "/k /etc/autofs/auto.a -r -w -v -d -g --ghost --verbose --debug",
    "/k /etc/autofs/auto.a -nobind -nobrowse",
    "/k /etc/autofs/auto.a -fstype=nfs,vers=\"4\",rw",
    "/k /etc/autofs/auto.a !bad",
    "\"/l\" /etc/autofs/auto.a",
    "/m \"/etc/autofs/auto.a\"",
    "/n /etc/autofs/auto.a \\\n  -ro",
    "/o ldap:ou=auto.home,dc=example,dc=com",
    "/o ldap://server/ou=auto.home,dc=example,dc=com -rw",
    "/o ldap:server:ou=x",
    "/o ou=auto.home,dc=example",
    "/o cn=x,automountMapName=y",
    "/o automountMapName=auto.x",
    "/o //server/cn=x",
    "/p yp:auto.p",
    "/p nis auto.p",
    // nisplus comes with its module in phase 2.
    "/q multi /etc/autofs/auto.a -- /etc/autofs/auto.b",
    "/q multi file:/etc/autofs/auto.a -ro -- file,sun:/etc/autofs/auto.b -rw",
    "/q multi,sun /etc/autofs/auto.a",
    // This one crashes in the parser (append_argv() through a NULL vector).
    "/q multi -hosts",
    "/q multi /etc/autofs/auto.a --",
    "/q multi auto.a -- auto.b -- /etc/autofs/auto.a",
    "/q multi file:/etc/autofs/auto.missing -- /etc/autofs/auto.b",
    "/q multi yp:auto.a -- /etc/autofs/auto.b",
    "/q multi file_this_name_is_long_ok -- /etc/autofs/auto.b",
    "/r file /etc/autofs/auto.a",
    "/r file  :  /etc/autofs/auto.a",
    "/r file,amd:/etc/autofs/auto.amd",
    "/r file,amd:auto.amd",
    "/r program,amd:/etc/autofs/auto.a",
    "/s/ /etc/autofs/auto.a",
    "/ /etc/autofs/auto.a",
    "// /etc/autofs/auto.a",
    "/t /etc/autofs/auto.a # comment",
    "/u\\ v /etc/autofs/auto.a",
    "/w /etc/autofs/auto.a\x00junk",
];

#[test]
fn dump_master_lines() {
    for (i, line) in MASTER_LINES.iter().enumerate() {
        check(
            Case::new(&format!("master_line_{i}"), &["-d", "-m"])
                .etc_bytes("autofs/auto.master", format!("{line}\n").as_bytes())
                .map("auto.a", "k v\n")
                .map("auto.b", "l w\n")
                .map("auto.amd", AMD_MAP),
        );
    }
}

const AMD_MAP: &str =
    "/defaults type:=nfs;opts:=rw\nk1 rhost:=s1;rfs:=/x\nsub/dir type:=link;fs:=/tmp\n* type:=nfs;rhost:=${key}\n";

#[test]
fn dump_master_lines_after_error() {
    // Each rejected line, then a good one: what the scanner's leftover state
    // does to the next entry.
    for (i, line) in MASTER_LINES.iter().enumerate() {
        check(
            Case::new(&format!("master_after_{i}"), &["-d", "-m"])
                .etc_bytes("autofs/auto.master", format!("{line}\n/z /etc/autofs/auto.a -ro\n/y auto.b\n").as_bytes())
                .map("auto.a", "k v\n")
                .map("auto.b", "l w\n")
                .map("auto.amd", AMD_MAP),
        );
    }
}

#[test]
fn dump_master_quotes_and_escapes() {
    check(
        Case::new("master_escapes", &["-d", "-m"])
            .master("/a\\ b /etc/autofs/auto.a\n/c/ /etc/autofs/auto\\ x\n/// /etc/autofs/auto.a\n")
            .map("auto.a", "k v\n")
            .map("auto x", "q r\n"),
    );
}

#[test]
fn dump_master_types() {
    check(
        Case::new("master_types", &["-d", "-m"])
            .master(
                "/a file:/etc/autofs/auto.a\n\
                 /b file,sun:/etc/autofs/auto.a\n\
                 /c file /etc/autofs/auto.a\n\
                 /d exec:/etc/autofs/auto.prog\n\
                 /e program:/etc/autofs/auto.prog\n\
                 /f hesiod:foo\n\
                 /g userdir:foo\n\
                 /h sss:foo\n\
                 /i file,hesiod:/etc/autofs/auto.a\n",
            )
            .map("auto.a", "k v\n")
            .etc_mode("autofs/auto.prog", b"#!/bin/sh\necho x\n", 0o755),
    );
}

#[test]
fn dump_master_multi_hesiod_crash() {
    check(Case::new("multi_hesiod", &["-m"]).master("/a multi,hesiod /etc/autofs/auto.a\n").map("auto.a", "k v\n"));
}

#[test]
fn dump_master_include() {
    check(
        Case::new("master_include", &["-d", "-m"])
            .master("/a /etc/autofs/auto.a\n+auto.master2\n+auto.master\n+/etc/autofs/auto.nothere\n")
            .map("auto.master2", "/b /etc/autofs/auto.a\n+auto.master2\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_master_dir() {
    check(
        Case::new("master_dir", &["-d", "-m"])
            .master("/a /etc/autofs/auto.a\n+dir:/etc/autofs/master.d\n")
            .map("master.d/10-b.autofs", "/b /etc/autofs/auto.a\n")
            .map("master.d/9-c.autofs", "/c /etc/autofs/auto.a\n")
            .map("master.d/x.conf", "/x /etc/autofs/auto.a\n")
            .map("master.d/.hidden.autofs", "/h /etc/autofs/auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_map_include() {
    check(
        Case::new("map_include", &["-d", "-m"])
            .master("/a /etc/autofs/auto.a\n/b auto.b\n")
            .map("auto.a", "k v\n+auto.b\n+auto.a\nz y\n")
            .map("auto.b", "bk bv\n+/etc/autofs/auto.c\n")
            .map("auto.c", "ck cv\n"),
    );
}

#[test]
fn dump_map_scanner() {
    check(
        Case::new("map_scanner", &["-d", "-m"])
            .master("/a /etc/autofs/auto.a\n/- /etc/autofs/auto.d\n")
            .map(
                "auto.a",
                "plain value\n\
             cont first \\\n  second\n\
             \"quoted key\" v1\n\
             esc\\ key v2\n\
             tab\tv3\n\
             star *\n\
             * wild\n\
             bad/key v4\n\
             multi -o /a s:/a \\\n /b s:/b\n\
             next v5\n  continued badly\n\
             \"unterminated v6\n\
             empty\n\
             trailing v7   \n\
             k8 \"quoted value\" more\n\
             k9 a\\\"b\n\
             last v9",
            )
            .map("auto.d", "/d/a v\nrel v\n/d//b v\n/d/c/ v\n"),
    );
}

#[test]
fn dump_map_long_key() {
    let long = "k".repeat(300);
    check(
        Case::new("long_key", &["-d", "-m"])
            .master("/a /etc/autofs/auto.a\n")
            .map("auto.a", &format!("{long} v\nok v\n")),
    );
}

#[test]
fn dump_map_missing() {
    check(
        Case::new("map_missing", &["-d", "-m"])
            .master("/a /etc/autofs/auto.nothere\n/b auto.nothere\n/c auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_map_unreadable_dir() {
    check(Case::new("map_dir", &["-d", "-m"]).master("/a /etc/autofs/sub\n/b sub\n").map("sub/x", "k v\n"));
}

#[test]
fn dump_duplicates() {
    check(
        Case::new("duplicates", &["-m"])
            .master("/a /etc/autofs/auto.a\n/a /etc/autofs/auto.b\n/a /etc/autofs/auto.a\n/- auto.d\n/- auto.e\n")
            .map("auto.a", "k v\n")
            .map("auto.b", "k w\nl x\n")
            .map("auto.d", "/x v\n")
            .map("auto.e", "/y v\n"),
    );
}

#[test]
fn dump_hash_order() {
    let mut m = String::new();
    for i in 0..300 {
        m.push_str(&format!("key{i} val{i}\n"));
    }
    check(Case::new("hash_order", &["-m"]).master("/a /etc/autofs/auto.a\n").map("auto.a", &m));
}

#[test]
fn dump_small_hash_table() {
    let mut m = String::new();
    for i in 0..20 {
        m.push_str(&format!("key{i} val{i}\n"));
    }
    check(
        Case::new("small_hash", &["-m"])
            .master("/a /etc/autofs/auto.a\n+auto.inc\n")
            .conf("[ autofs ]\nmap_hash_table_size = 3\n")
            .map("auto.a", &m)
            .map("auto.inc", "/b /etc/autofs/auto.b\n")
            .map("auto.b", "key1 x\nkey2 y\n+auto.a\n"),
    );
}

#[test]
fn dump_zero_hash_table() {
    check(
        Case::new("zero_hash", &["-m"])
            .master("/a /etc/autofs/auto.a\n")
            .conf("[ autofs ]\nmap_hash_table_size = 0\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_global_options() {
    check(basic().named("dump_global_options").args(&["-O", "rsize=8192", "-O", "x", "-m"]));
}

#[test]
fn dump_global_options_no_append() {
    check(
        basic()
            .named("dump_global_options_no_append")
            .args(&["-O", "rsize=8192", "-d", "-m"])
            .conf("[ autofs ]\nappend_options = no\n"),
    );
}

#[test]
fn dump_master_from_conf() {
    check(
        Case::new("master_from_conf", &["-d", "-m"])
            .conf("[ autofs ]\nmaster_map_name = /etc/autofs/other.master\ntimeout=30\nbrowse_mode = no\n")
            .map("other.master", "/a auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_conf_parsing() {
    check(
        Case::new("conf_parsing", &["-d", "-m"])
            .conf(
                "# comment\n\
                 [ autofs ]\n\
                 \x20 timeout = 99\n\
                 logging = debug\n\
                 master_map_name = \"auto.other\" # trailing\n\
                 mount_type = x\n\
                 pid_file = y\n\
                 restart_mounts = z\n\
                 plock = q\n\
                 nfs_vers = 3\n\
                 [amd]\n\
                 map_options = cache:=all\n\
                 [ /amdmnt ]\n\
                 map_type = file\n",
            )
            .map("auto.other", "/a auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_old_conf() {
    check(
        Case::new("old_conf", &["-d", "-m"])
            .etc("conf.d/autofs", "USE_MISC_DEVICE=\"yes\"\nDEFAULT_MASTER_MAP_NAME=\"auto.old\"\n")
            .map("auto.old", "/o auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_conf_env() {
    check(basic().named("dump_conf_env").env("timeout=7").env("logging=verbose").args(&["-m"]));
}

#[test]
fn dump_nsswitch() {
    check(
        Case::new("nsswitch", &["-d", "-m"])
            .etc("nsswitch.conf", "passwd: files\nautomount: files [NOTFOUND=return] nis # c\n")
            .master("/a auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_nsswitch_errors() {
    check(
        Case::new("nsswitch_errors", &["-d", "-m"])
            .etc("nsswitch.conf", "automount: files [NOTFOUND=foo] yp\nAUTOMOUNT: bogus files\n")
            .master("/a auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_nsswitch_missing() {
    check(
        Case::new("nsswitch_missing", &["-d", "-m"])
            .setup("rm -f /etc/nsswitch.conf")
            .master("/a /etc/autofs/auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_old_style_name() {
    check(
        Case::new("old_style_name", &["-d", "-m", "file:/etc/autofs/auto.a"])
            .master("/x auto.a\n")
            .map("auto.a", "/y v\n"),
    );
}

#[test]
fn dump_mtab_link() {
    check(
        basic()
            .named("dump_mtab_link")
            .args(&["-d", "-m"])
            .setup("rm -f /etc/mtab && ln -s /proc/self/mounts /etc/mtab"),
    );
}

#[test]
fn dump_mount_verbose() {
    check(basic().named("dump_mount_verbose").args(&["-d", "-m"]).conf("[ autofs ]\nmount_verbose = yes\n"));
}

#[test]
fn opt_version() {
    check(Case::new("version", &["-V"]));
}

#[test]
fn opt_help() {
    check(Case::new("help", &["--help"]));
}

#[test]
fn opt_unknown() {
    check(Case::new("unknown", &["-Q"]));
}

#[test]
fn opt_bad_number() {
    check(Case::new("bad_number", &["-t", "12x"]));
}

#[test]
fn opt_bad_debug_level() {
    check(Case::new("bad_debug", &["--debug=x", "-m"]));
}

#[test]
fn opt_log_priority_errors() {
    check(Case::new("logpri_bad", &["-l", "loud"]));
    check(Case::new("logpri_punct", &["-l", "!"]));
    check(Case::new("logpri_nopath", &["-l", "debug"]));
}

#[test]
fn opt_empty_args() {
    check(basic().named("opt_empty_args").args(&["", "-m", "", ""]));
}

#[test]
fn not_root() {
    check(Case::new("not_root", &["-m"]).run_as_nobody());
}

#[test]
fn daemon_no_kernel() {
    check(basic().named("daemon_no_kernel").args(&["-f"]));
}

#[test]
fn core_limit() {
    check(basic().named("core_limit").setup("ulimit -c 0"));
}

/// hydra's setup: `/net` through an executable (program) map.
fn hydra() -> Case {
    Case::dump("hydra")
        .master("/net\t/etc/autofs/auto.netv4\n")
        .etc_mode("autofs/auto.netv4", b"#!/bin/bash\necho \"-fstype=nfs4 $1:/\"\n", 0o755)
        .conf("[ autofs ]\ntimeout = 300\nbrowse_mode = no\nmount_nfs_default_protocol = 4\n[ amd ]\ndismount_interval = 300\n")
        .etc("conf.d/autofs", "USE_MISC_DEVICE=\"yes\"\n")
}

#[test]
fn dump_hydra() {
    check(hydra());
}

#[test]
fn dump_hydra_debug() {
    check(hydra().named("hydra_debug").args(&["-d", "-m"]));
}

#[test]
fn dump_hydra_program_map() {
    check(hydra().named("hydra_program").args(&["-m", "program", "auto.netv4"]));
}

#[test]
fn dump_program_not_executable() {
    check(
        Case::new("program_noexec", &["-d", "-m"])
            .master("/p program:/etc/autofs/auto.p\n/q exec:auto.p\n/r program:/etc/autofs/missing\n")
            .map("auto.p", "#!/bin/sh\n"),
    );
}

#[test]
fn dump_non_ascii_keys() {
    check(
        Case::new("non_ascii", &["-d", "-m"])
            .master("/a /etc/autofs/auto.a\n/- /etc/autofs/auto.d\n")
            .etc_bytes("autofs/auto.a", "caf\u{e9} v1\nplain v2\n\u{1F600} v3\n".as_bytes())
            .etc_bytes("autofs/auto.d", b"/d/\xff v\n/d/ok v\n"),
    );
}

#[test]
fn dump_conf_indented() {
    check(
        Case::new("conf_indented", &["-d", "-m"])
            .conf("[ autofs ]\n  master_map_name = /etc/autofs/ignored\nmap_hash_table_size\t=\t2\n")
            .master("/a /etc/autofs/auto.a\n")
            .map("ignored", "/i /etc/autofs/auto.a\n")
            .map("auto.a", "k1 v\nk2 v\nk3 v\nk4 v\n"),
    );
}

#[test]
fn dump_nsswitch_actions_carry_over() {
    check(
        Case::new("nss_carry", &["-d", "-m"])
            .etc(
                "nsswitch.conf",
                "automount: files [NOTFOUND=return] files [!UNAVAIL=continue] nis [SUCCESS=continue] files\n",
            )
            .master("/a auto.a\n/b auto.missing\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_nsswitch_echo_and_long() {
    let long = "x".repeat(140);
    check(
        Case::new("nss_echo", &["-d", "-m"])
            .etc("nsswitch.conf", &format!("automount: files ! | {long} [=]\n"))
            .master("/a auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_nsswitch_error_recovery() {
    // A syntax error, then tokens bison discards while recovering (no second
    // message), then the source the `error SOURCE` rule wants.
    check(
        Case::new("nss_recovery", &["-d", "-m"])
            .etc("nsswitch.conf", "automount: [ [ [ files\n")
            .master("/a auto.a\n")
            .map("auto.a", "k v\n"),
    );
}

#[test]
fn dump_amd_sections() {
    check(
        Case::new("amd_sections", &["-d", "-m"])
            .conf(
                "[ amd ]\nbrowsable_dirs = yes\nlog_options = all\nsearch_path = /etc/autofs/amd:/etc/autofs\n\
                 [ /amd1 ]\nmap_name = auto.amd\nmap_type = file\n[ /amd2 ]\nmap_options = cache:=all\n",
            )
            .master("/amd1 auto.amd\n/amd2 /etc/autofs/auto.amd\n/amd3 file,amd:auto.inamd\n")
            .map("auto.amd", AMD_MAP)
            .map("amd/auto.inamd", "a type:=nfs\n"),
    );
}
