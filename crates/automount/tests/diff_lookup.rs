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

/// One map, many keys looked up under `/mnt/a`.
fn many(name: &str, master_opts: &str, map: &str, keys: &[&str]) -> Case {
    let l: Vec<(&str, &str)> = keys.iter().map(|k| ("/mnt/a", *k)).collect();
    lk(name, &format!("/mnt/a /etc/autofs/auto.a {master_opts}\n"), &l).map("auto.a", map)
}

const SUN_MAP: &str = "\
wild1 -fstype=ext4,ro :/dev/sdb1
bind1 -fstype=bind :/srv/x
auto1 -fstype=autofs,timeout=30 file:/etc/autofs/auto.sub
ldl -fstype=autofs ldap:ou=x
local :/srv/local
amp server:/home/&
macro ${HOST}:/x/$USER/$UID/${GID}/$HOME/$SHOST/$OSNAME/$ARCH/$CPU/$dollar/$nothere/${unterm
strict1 -strict,fstype=xfs :/dev/sdc
nonstrict1 -nonstrict,bg,nofg,use-weight-only s:/x
noweight -no-use-weight-only s1(5) s2(3):/x
multiopt -ro -hard,intr -soft s:/y
quoted \"s:/with space\" s2:/x
esc s:/a\\ b
colons -fstype=nfs s:/a:b:c
colonslash :/a:b
badloc s/x
badchar s;x:/y
emptyhost ,s:/x
emptyhost2 s,,t:/x
nocolon justaname

browse1 -nobrowse,browse,timeout=5 s:/z
hosts1 -fstype=autofs,hosts junk
empty -ro
* srv:/wild/&
";

#[test]
fn lookup_sun_entries() {
    check_drv(many(
        "lk_sun",
        "-rw -DFOO=bar",
        SUN_MAP,
        &[
            "wild1",
            "bind1",
            "auto1",
            "ldl",
            "local",
            "amp",
            "macro",
            "strict1",
            "nonstrict1",
            "noweight",
            "multiopt",
            "quoted",
            "esc",
            "colons",
            "colonslash",
            "badloc",
            "badchar",
            "emptyhost",
            "emptyhost2",
            "nocolon",
            "browse1",
            "hosts1",
            "empty",
            "other",
            "other",
            "x y",
            "sub/dir",
        ],
    ));
}

#[test]
fn lookup_sun_no_append() {
    check_drv(
        many("lk_noappend", "-rw,soft", SUN_MAP, &["multiopt", "amp", "wild1", "anything"])
            .conf("[ autofs ]\nappend_options = no\n"),
    );
}

#[test]
fn lookup_sun_no_slashify() {
    check_drv(many("lk_noslash", "--no-slashify-colons", SUN_MAP, &["colons", "colonslash"]));
}

#[test]
fn lookup_users() {
    // uid 0 and a user from the host's /etc/passwd, and an unknown uid.
    let master = "/mnt/u /etc/autofs/auto.u\n";
    let mut c = lk("lk_users", master, &[]);
    c.args = ["-d", "/mnt/u", "k", "0", "0", "/mnt/u", "k", "65534", "65534", "/mnt/u", "k", "4242", "4242"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    check_drv(c.map("auto.u", "k -fstype=bind :/home/$USER/$UID:$GID:$GROUP:$HOME\n"));
}

#[test]
fn lookup_direct() {
    check_drv(
        lk(
            "lk_direct",
            "/- /etc/autofs/auto.direct -ro\n",
            &[("/-", "/mnt/d/x"), ("/-", "/mnt/d/y"), ("/-", "/mnt/d/none"), ("/-", "rel")],
        )
        .map("auto.direct", "/mnt/d/x s:/x\n/mnt/d/y -fstype=ext2 :/dev/z\n"),
    );
}

#[test]
fn lookup_includes() {
    check_drv(
        lk(
            "lk_includes",
            "/mnt/a /etc/autofs/auto.a\n/mnt/b auto.b\n",
            &[
                ("/mnt/a", "k1"),
                ("/mnt/a", "k2"),
                ("/mnt/a", "k3"),
                ("/mnt/a", "k4"),
                ("/mnt/b", "k2"),
                ("/mnt/b", "zz"),
            ],
        )
        .map("auto.a", "k1 s:/1\n+auto.b\n+/etc/autofs/auto.c\n")
        .map("auto.b", "k2 s:/2\n+auto.a\n")
        .map("auto.c", "k3 s:/3\n* s:/w/&\n"),
    );
}

#[test]
fn lookup_nsswitch_sources() {
    check_drv(
        lk("lk_nss", "/mnt/a auto.a\n/mnt/b auto.missing\n", &[("/mnt/a", "k"), ("/mnt/a", "q"), ("/mnt/b", "k")])
            .etc("nsswitch.conf", "automount: files [NOTFOUND=return] nis\n")
            .map("auto.a", "k s:/k\n"),
    );
}

#[test]
fn lookup_negative_cache() {
    check_drv(
        many("lk_negative", "", "k s:/k\nbad s;x:/y\n", &["nope", "nope", "bad", "bad", "k"])
            .conf("[ autofs ]\nnegative_timeout = 0\n"),
    );
    check_drv(
        many("lk_negative_off", "", "k s:/k\n", &["nope", "nope"])
            .conf("[ autofs ]\ndisable_not_found_message = yes\n"),
    );
}

#[test]
fn lookup_browse() {
    check_drv(
        many("lk_browse", "-browse", "k1 s:/1\nk2 -null\nk3 -null,x\n*  s:/w\nsub/k s:/x\nk4 s:/4\n", &["k1"])
            .conf("[ autofs ]\nbrowse_mode = yes\n"),
    );
    check_drv(many("lk_nobrowse", "-nobrowse", "k1 s:/1\n", &["k1"]));
}

const PROG: &str = r#"#!/bin/sh
case "$1" in
env) env | sort | grep -v '^_=\|^LD_LIBRARY_PATH=' >&2; echo "s:/env" ;;
quoted) printf -- '-ro \\\n  s:/a\\ b\n' ;;
multi) printf 's:/first\nignored second line\n' ;;
fail) echo "s:/x"; exit 3 ;;
empty) exit 0 ;;
spaces) printf '   \n' ;;
stderr) echo "err one" >&2; printf 'err two' >&2; echo "s:/e" ;;
long) head -c 3000 /dev/zero | tr '\0' x >&2; echo "s:/l" ;;
pwd) pwd >&2; echo "s:/p" ;;
*) echo "-fstype=nfs4,hard $1:/" ;;
esac
"#;

fn prog_case(name: &str, keys: &[&str]) -> Case {
    let l: Vec<(&str, &str)> = keys.iter().map(|k| ("/mnt/p", *k)).collect();
    lk(name, "/mnt/p /etc/autofs/auto.prog -DFOO=bar\n", &l).etc_mode("autofs/auto.prog", PROG.as_bytes(), 0o755)
}

#[test]
fn lookup_program() {
    check_drv(prog_case(
        "lk_prog",
        &["ronda", "ronda", "quoted", "multi", "fail", "fail", "empty", "spaces", "stderr", "long", "pwd"],
    ));
}

#[test]
fn lookup_program_env() {
    check_drv(prog_case("lk_prog_env", &["env"]));
    check_drv(prog_case("lk_prog_env_std", &["env"]).conf("[ autofs ]\nforce_standard_program_map_env = yes\n"));
}

#[test]
fn lookup_program_cwd() {
    check_drv(prog_case("lk_prog_cwd", &["pwd"]).setup("mkdir -p /mnt/p"));
}

#[test]
#[ignore = "hydra's map gives a multi-mount entry (\"/ ronda:/\"): phase 4"]
fn lookup_program_hydra() {
    // hydra's auto.netv4 with a fake showmount.
    let netv4 = "#!/bin/bash\nkey=\"$1\"\nopts=\"-fstype=nfs4,hard,nodev,nosuid\"\nSMNT=@T@/showmount\n\
                 $SMNT --no-headers -e $key | LC_ALL=C cut -d' ' -f1 | LC_ALL=C head -n1 | \\\n\
                 awk -v key=\"$key\" -v opts=\"$opts\" -- '\n\
                 BEGIN { ORS=\"\"; first=1 }\n { if (first) { print opts; first=0 }; print \" \\\\\\n\\t\" \"/\", key \":\" \"/\" }\n\
                 END { if (!first) print \"\\n\"; else exit 1 }\n' | sed 's/#/\\\\#/g'\n";
    let showmount = "#!/bin/sh\n[ \"$3\" = ronda ] && printf '/ 192.168.1.0/24\\n/media 192.168.1.0/24\\n'\nexit 0\n";
    let c = lk("lk_hydra", "/mnt/net /etc/autofs/auto.netv4\n", &[("/mnt/net", "ronda"), ("/mnt/net", "nohost")])
        .etc_mode("autofs/auto.netv4", netv4.as_bytes(), 0o755)
        .file("showmount", showmount.as_bytes())
        .setup("chmod 755 @T@/showmount")
        .conf("[ autofs ]\ntimeout = 300\nbrowse_mode = no\nmount_nfs_default_protocol = 4\n");
    check_drv(c);
}

#[test]
fn lookup_multi() {
    check_drv(
        lk(
            "lk_multi",
            "/mnt/m multi /etc/autofs/auto.a -ro -- /etc/autofs/auto.b -- auto.prog\n",
            &[("/mnt/m", "a"), ("/mnt/m", "b"), ("/mnt/m", "both"), ("/mnt/m", "fromprog"), ("/mnt/m", "none")],
        )
        .map("auto.a", "a s:/a\nboth s:/both-a\n")
        .map("auto.b", "b -fstype=ext2 :/dev/b\nboth s:/both-b\n")
        .etc_mode("autofs/auto.prog", b"#!/bin/sh\n[ \"$1\" = fromprog ] && echo s:/prog\n", 0o755),
    );
}

#[test]
fn lookup_dequote_edges() {
    // An option chunk of a backslash and a space: dequote()'s look-behind
    // stops at index 1, not 0.
    check_drv(many("lk_dequote", "", "escopt -\\  s:/x\ntrail \"s:/q\\\"\" \n", &["escopt", "trail"]));
}
