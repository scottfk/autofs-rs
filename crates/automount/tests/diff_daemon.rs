//! Differential tests: the daemon, on the root test VM (`make vmcheck`). See
//! `tests/common/vm.rs`.

mod common;

use common::vm::{VmCase, check_vm};

const NEEDS_VM: &str = "needs the root test VM (make vmcheck)";

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_indirect_basic() {
    let _ = NEEDS_VM;
    check_vm(
        VmCase::new("d_indirect_basic", "/mnt/a /etc/autofs/auto.a\n")
            .map("auto.a", "k -fstype=bind :/etc/autofs\nt -fstype=tmpfs :tmpfs\n")
            .steps(
                "ready\ntrig /mnt/a/k; waitlog 'mounted /mnt/a/k'\nsnap\n\
                 trig /mnt/a/nope; waitlog 'failed to mount /mnt/a/nope'\n\
                 trig /mnt/a/t; waitlog 'mounted /mnt/a/t'\nsnap\n",
            ),
    );
}

const MAP: &str = "k -fstype=bind :/etc/autofs\nt -fstype=tmpfs,size=1m :tmpfs\nro -ro,fstype=tmpfs :tmpfs\n\
                   bad -fstype=nosuchfs :/dev/null\nnull -null\n* -fstype=tmpfs :tmpfs\n";

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_nobrowse() {
    check_vm(VmCase::new("d_nobrowse", "/mnt/a /etc/autofs/auto.a -nobrowse\n").map("auto.a", MAP).steps(
        "ready 'mounted indirect on'\nquiet 0.3\nsnap\nls /mnt/a >> $C/out/steps\n\
             trig /mnt/a/t; waitlog 'mounted /mnt/a/t'\nsnap\nls /mnt/a >> $C/out/steps\n\
             trig /mnt/a/bad; waitlog 'failed to mount /mnt/a/bad'\nls /mnt/a >> $C/out/steps\n\
             trig /mnt/a/null; quiet 0.5\ntrig /mnt/a/wild; waitlog 'mounted /mnt/a/wild'\nsnap\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_browse_and_prune() {
    check_vm(VmCase::new("d_prune", "/mnt/a /etc/autofs/auto.a --timeout=600\n").map("auto.a", MAP).steps(
        "ready\nls /mnt/a >> $C/out/steps\ntrig /mnt/a/k; waitlog 'mounted /mnt/a/k'\n\
         trig /mnt/a/ro; waitlog 'mounted /mnt/a/ro'\nsnap\n\
         sig USR1; waitlog 'umounting /mnt/a/ro succeeded'; waitlog 'umounting /mnt/a/k succeeded'; quiet 1\nsnap\n\
         ls /mnt/a >> $C/out/steps\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_negative_cache() {
    check_vm(
        VmCase::new("d_negative", "/mnt/a /etc/autofs/auto.a\n")
            .map("auto.a", "k -fstype=tmpfs :tmpfs\nbad -fstype=nosuchfs :/dev/null\n")
            .conf("[ autofs ]\nnegative_timeout = 60\n")
            .steps(
                "ready\ntrig /mnt/a/bad; waitlog 'failed to mount /mnt/a/bad'\nquiet 0.3\n\
                 trig /mnt/a/bad; quiet 0.5\ntrig /mnt/a/nokey; waitlog 'failed to mount /mnt/a/nokey'\nquiet 0.3\n\
                 trig /mnt/a/nokey; quiet 0.5\nsnap\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_two_mounts_and_null() {
    check_vm(
        VmCase::new(
            "d_two",
            "/mnt/a /etc/autofs/auto.a\n/mnt/b /etc/autofs/auto.b -ro\n/mnt/c -null\n/mnt/c /etc/autofs/auto.a\n",
        )
        .map("auto.a", "k -fstype=tmpfs :tmpfs\n")
        .map("auto.b", "x -fstype=tmpfs :tmpfs\n")
        .unordered_log()
        .steps(
            "waitlog 'mounted indirect on /mnt/b'; quiet 0.5\nsnap\ntrig /mnt/b/x; waitlog 'mounted /mnt/b/x'\n\
             trig /mnt/a/k; waitlog 'mounted /mnt/a/k'\nsnap\n",
        ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_hup_reload() {
    check_vm(
        VmCase::new("d_hup", "/mnt/a /etc/autofs/auto.a\n/mnt/b /etc/autofs/auto.a\n")
            .map("auto.a", "k -fstype=tmpfs :tmpfs\ngone -fstype=tmpfs :tmpfs\n")
            .unordered_log()
            .steps(
                "waitlog 'mounted indirect on /mnt/b'; quiet 0.5\ntrig /mnt/a/k; waitlog 'mounted /mnt/a/k'\nsnap\nquiet 2\n\
                 printf 'k -fstype=tmpfs :tmpfs\\nnew -fstype=tmpfs :tmpfs\\n' > /etc/autofs/auto.a\n\
                 printf '/mnt/a /etc/autofs/auto.a\\n/mnt/c /etc/autofs/auto.a\\n' > /etc/autofs/auto.master\n\
                 touch -d '1 minute ago' /etc/autofs/auto.master\n\
                 sig HUP; waitlog 'mounted indirect on /mnt/c'; waitlog 'shut down path /mnt/b'; quiet 1.5\nsnap\n\
                 ls /mnt/a /mnt/c >> $C/out/steps\ntrig /mnt/a/new; waitlog 'mounted /mnt/a/new'\nsnap\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_busy_shutdown() {
    check_vm(VmCase::new("d_busy", "/mnt/a /etc/autofs/auto.a\n").map("auto.a", MAP).steps(
        "ready\ntrig /mnt/a/t; waitlog 'mounted /mnt/a/t'\n(cd /mnt/a/t && sleep 4) &\nquiet 0.5\n\
         sig TERM; waitlog 'autofs stopped' 100 x; note busy\nsnap\nwait\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_forced_shutdown() {
    check_vm(VmCase::new("d_force", "/mnt/a /etc/autofs/auto.a\n").map("auto.a", MAP).steps(
        "ready\ntrig /mnt/a/t; waitlog 'mounted /mnt/a/t'\n(cd /mnt/a/t && sleep 3) &\nquiet 0.5\n\
         sig USR2; waitlog 'autofs stopped' 100 x\nsnap\nwait\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_log_priority_fifo() {
    check_vm(VmCase::new("d_fifo", "/mnt/a /etc/autofs/auto.a\n").map("auto.a", MAP).args(&["-f"]).steps(
        "waitlog x 10 x; quiet 1\nls -l /run | grep fifo | cut -c1-10 >> $C/out/steps\n\
         $AUTOMOUNT -l debug /mnt/a >> $C/out/steps 2>&1; note rc=$?\nquiet 0.5\n\
         trig /mnt/a/t; quiet 1\n$AUTOMOUNT -l 3 /mnt/a >> $C/out/steps 2>&1; note rc=$?\nquiet 0.5\n\
         trig /mnt/a/ro; quiet 1\n$AUTOMOUNT -l 9 /mnt/a >> $C/out/steps 2>&1; note rc=$?\n\
         $AUTOMOUNT -l info /nonexistent >> $C/out/steps 2>&1; note rc=$?\n\
         $AUTOMOUNT -l info >> $C/out/steps 2>&1; note rc=$?\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_already_running() {
    check_vm(VmCase::new("d_running", "/mnt/a /etc/autofs/auto.a\n").map("auto.a", MAP).steps(
        "ready\ncat /run/autofs-running | sed 's/[0-9]*/PID/' >> $C/out/steps\n\
         $AUTOMOUNT -f /etc/autofs/auto.master >> $C/out/steps 2>&1; note rc=$?\n\
         $AUTOMOUNT >> $C/out/steps 2>&1; note rc=$?\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_program_map() {
    let prog = "#!/bin/sh\ncase \"$1\" in\nok) echo '-fstype=tmpfs :tmpfs' ;;\n\
                env) echo \"-fstype=tmpfs,mode=0$AUTOFS_UID$AUTOFS_GID :tmpfs\" ;;\n*) exit 1 ;;\nesac\n";
    check_vm(
        VmCase::new("d_program", "/mnt/p /etc/autofs/auto.p\n")
            .etc_mode("autofs/auto.p", prog, 0o755)
            .steps(
                "waitlog 'mounted indirect on'; quiet 0.3\ntrig /mnt/p/ok; waitlog 'mounted /mnt/p/ok'\n\
                 trig /mnt/p/env; waitlog 'mounted /mnt/p/env'\ntrig /mnt/p/no; waitlog 'failed to mount /mnt/p/no'\nsnap\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_force_unlink() {
    check_vm(
        VmCase::new("d_force_unlink", "/mnt/a /etc/autofs/auto.a\n")
            .map("auto.a", MAP)
            .args(&["-f", "-d", "-F"])
            .steps("ready\nsnap\n"),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_pid_file_and_detach() {
    check_vm(
        VmCase::new("d_detach", "/mnt/a /etc/autofs/auto.a\n").map("auto.a", MAP).args(&["-p", "/run/am.pid"]).steps(
            "quiet 1.5\nnote parent_gone=$(kill -0 $PID 2>/dev/null && echo no || echo yes)\n\
             P=$(cat /run/am.pid); note pidfile=$( [ -n \"$P\" ] && echo yes)\nsnap\ntrig /mnt/a/t\nsnap\n\
             kill -TERM $P; n=0; while kill -0 $P 2>/dev/null && [ $n -lt 100 ]; do n=$((n+1)); sleep 0.1; done\n\
             note stopped=$(kill -0 $P 2>/dev/null && echo no || echo yes)\nls /run | grep -v fifo >> $C/out/steps\n",
        ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_ioctl_fallback() {
    // /dev/autofs answering nothing: the legacy ioctls on each mount.
    check_vm(VmCase::new("d_legacy_ioctl", "/mnt/a /etc/autofs/auto.a\n").map("auto.a", MAP).pre("mount --bind /dev/null /dev/autofs\n").steps(
        "ready\ntrig /mnt/a/t; waitlog 'mounted /mnt/a/t'\ntrig /mnt/a/nope; waitlog 'failed to mount /mnt/a/nope'\nsnap\n\
         sig USR1; waitlog 'umounting /mnt/a/t succeeded'; quiet 0.5\nsnap\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_unlink_and_exit() {
    check_vm(
        VmCase::new("d_unlink_exit", "/mnt/a /etc/autofs/auto.a\n/mnt/b /etc/autofs/auto.a\n")
            .map("auto.a", MAP)
            .args(&["-d", "-U"])
            .pre("mkdir -p /mnt/a/x /mnt/b; mount -t tmpfs tmpfs /mnt/a; mkdir /mnt/a/x; mount -t tmpfs tmpfs /mnt/a/x\n")
            .steps("waitlog 'autofs stopped' 100 x\nsnap\n"),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_no_master_map() {
    check_vm(
        VmCase::new("d_no_master", "-").args(&["-f", "-d", "-M", "3"]).steps("waitlog 'no mounts in table' 80\nsnap\n"),
    );
    check_vm(VmCase::new("d_empty_master", "# nothing\n").steps("waitlog 'no mounts in table' 50; quiet 0.5\n"));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_options() {
    check_vm(
        VmCase::new("d_options", "/mnt/a /etc/autofs/auto.a\n")
            .map("auto.a", "m -fstype=tmpfs,size=${SZ}k :tmpfs\nbad -fstype=nosuchfs :/dev/null\n")
            .args(&["-f", "-d", "-O", "mode=0700", "-DSZ=256", "-n", "1", "-t", "1234", "-P", "5", "-r"])
            .steps(
                "ready\ntrig /mnt/a/m; waitlog 'mounted /mnt/a/m'\nsnap\ntrig /mnt/a/bad; waitlog 'failed to mount /mnt/a/bad'\n\
                 quiet 2\ntrig /mnt/a/bad; waitlog 'failed to mount /mnt/a/bad' 50\nsnap\n",
            ),
    );
}

const EXPIRE_CYCLE: [&str; 9] = [
    "st_expire: state",
    "expire_proc: exp_proc",
    "expire_proc_indirect: expire ",
    "remaining in /mnt",
    "remaining in /-",
    "expire_proc_direct: send expire to trigger",
    "expire_cleanup: got thid",
    "expire_cleanup: sigchld",
    "st_ready(): state = 2",
];

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_timeout_expiry() {
    check_vm(
        VmCase::new("d_timeout", "/mnt/a /etc/autofs/auto.a --timeout=2\n")
            .map("auto.a", MAP)
            .drop_lines(&EXPIRE_CYCLE)
            .steps(
                "ready\ntrig /mnt/a/t; waitlog 'mounted /mnt/a/t'\ntrig /mnt/a/k; waitlog 'mounted /mnt/a/k'\nsnap\n\
                 waitlog 'umounting /mnt/a/t succeeded' 100; waitlog 'umounting /mnt/a/k succeeded' 100; quiet 1.5\nsnap\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_symlinks() {
    // Local paths as symlinks: the bind module's symlink option.
    check_vm(
        VmCase::new("d_symlinks", "/mnt/a /etc/autofs/auto.a\n/mnt/s /etc/autofs/auto.a -symlink\n")
            .map("auto.a", "l -fstype=bind,symlink :/etc/autofs\ntc -fstype=bind,ro, :/etc\nb -fstype=bind :/etc/autofs\nself -fstype=bind :/mnt/a/self\n")
            .unordered_log()
            .steps(
                "waitlog 'mounted indirect on /mnt/s'; quiet 0.5\ntrig /mnt/a/l/; waitlog 'mounted /mnt/a/l'\n\
                 trig /mnt/a/tc/; waitlog 'mounted /mnt/a/tc'\ntrig /mnt/s/b/; waitlog 'mounted /mnt/s/b'\n\
                 trig /mnt/a/self; waitlog 'failed to mount /mnt/a/self'\n\
                 ls -l --time-style=+ /mnt/a /mnt/s | sed 's/.* \\([^ ]* -> \\)/\\1/' >> $C/out/steps\nsnap\n\
                 sig USR1; waitlog 'removing symlink /mnt/a/l'; quiet 1\nls /mnt/a /mnt/s >> $C/out/steps\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_amd_section() {
    check_vm(
        VmCase::new("d_amd", "/mnt/m /etc/autofs/amd.m\n")
            .map("amd.m", "x type:=link;fs:=/etc/autofs\nt type:=program;fs:=/tmp/amdt;mount:=\"/bin/sh sh -c 'mkdir -p /tmp/amdt'\"\n")
            .map("amd.n", "y type:=link;fs:=/etc\n")
            .conf("[ amd ]\ndismount_interval = 600\n[ /mnt/m ]\nmap_type = file\n[ /mnt/n ]\nmap_name = /etc/autofs/amd.n\n")
            .unordered_log()
            .steps(
                "waitlog 'mounted indirect on /mnt/n'; quiet 0.5\ntrig /mnt/m/x/; waitlog 'mounted /mnt/m/x'\n\
                 trig /mnt/n/y/; waitlog 'mounted /mnt/n/y'\ntrig /mnt/m/t; waitlog '/mnt/m/t'; quiet 0.5\n\
                 ls -l --time-style=+ /mnt/m /mnt/n | sed 's/.* \\([^ ]* -> \\)/\\1/' >> $C/out/steps\nsnap\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_verbose_and_request_ids() {
    check_vm(
        VmCase::new("d_verbose", "/mnt/a /etc/autofs/auto.a\n")
            .map("auto.a", MAP)
            .conf("[ autofs ]\nmount_verbose = yes\nuse_mount_request_log_id = yes\n")
            .steps("waitlog 'mounted indirect on'; quiet 0.3\ntrig /mnt/a/t; waitlog 'mounted /mnt/a/t'\ntrig /mnt/a/nope; quiet 1\n"),
    );
}

const DMAP: &str = "/mnt/d1 -fstype=tmpfs,size=1m :tmpfs\n/mnt/d2 -fstype=bind :/etc/autofs\n\
                    /mnt/deep/er/d3 -fstype=tmpfs :tmpfs\n/mnt/bad -fstype=nosuchfs :/dev/null\n";

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_direct_basic() {
    check_vm(VmCase::new("d_direct_basic", "/- /etc/autofs/auto.d\n").map("auto.d", DMAP).steps(
        "waitlog 'mounted trigger /mnt/bad'; quiet 0.5\nsnap\n\
                 trig /mnt/d1; waitlog 'mounted /mnt/d1'\ntrig /mnt/d2/; waitlog 'mounted /mnt/d2'\n\
                 trig /mnt/deep/er/d3; waitlog 'mounted /mnt/deep/er/d3'\n\
                 trig /mnt/bad; waitlog 'failed to mount /mnt/bad'\nsnap\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_direct_expire() {
    check_vm(
        VmCase::new("d_direct_expire", "/- /etc/autofs/auto.d --timeout=2\n")
            .map("auto.d", DMAP)
            .drop_lines(&EXPIRE_CYCLE)
            .steps(
                "waitlog 'mounted trigger /mnt/bad'; quiet 0.5\ntrig /mnt/d1; waitlog 'mounted /mnt/d1'\nsnap\n\
                 waitlog 'expired /mnt/d1' 100; quiet 1.5\nsnap\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_direct_hup() {
    check_vm(VmCase::new("d_direct_hup", "/- /etc/autofs/auto.d\n").map("auto.d", DMAP).steps(
        "waitlog 'mounted trigger /mnt/bad'; quiet 0.5\ntrig /mnt/d1; waitlog 'mounted /mnt/d1'\n\
                 printf '/mnt/d1 -fstype=tmpfs :tmpfs\\n/mnt/new -fstype=tmpfs :tmpfs\\n' > /etc/autofs/auto.d\n\
                 quiet 2\nsig HUP; waitlog 'mounted trigger /mnt/new'; quiet 1\nsnap\n\
                 trig /mnt/new; waitlog 'mounted /mnt/new'\nsnap\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_direct_shutdown() {
    // A busy direct mount at shutdown, then the rest.
    check_vm(VmCase::new("d_direct_shutdown", "/- /etc/autofs/auto.d\n").map("auto.d", DMAP).steps(
        "waitlog 'mounted trigger /mnt/bad'; quiet 0.5\ntrig /mnt/d1; waitlog 'mounted /mnt/d1'\n\
                 trig /mnt/d2/; waitlog 'mounted /mnt/d2'\nstopd\n",
    ));
}

// `m` has `:/` locations: a `:tmpfs` there would swallow the rest of the
// entry (chunklen() skips blanks until it has seen a `:/`). `odd` gives each
// offset its own options; `noroot` has no root offset; `syn` has an offset
// without a location; `bs` has an escaped blank in an offset path.
const MDIR: &str = "/mnt/mm / -fstype=tmpfs :tmpfs /in -fstype=tmpfs :tmpfs /in/deeper -fstype=tmpfs :tmpfs\n";

const MMAP: &str = "m -fstype=tmpfs / :/tmpfs /sub :/tmpfs /a/b -fstype=bind :/etc/autofs\n\
                    odd / -fstype=tmpfs :tmpfs /sub -fstype=tmpfs :tmpfs\n\
                    noroot /x -fstype=tmpfs :tmpfs /y -fstype=tmpfs :tmpfs\n\
                    \"q\" -fstype=tmpfs \"/\" :tmpfs \"/sp ace\" :tmpfs\n\
                    dup -fstype=tmpfs / :tmpfs /x :tmpfs /x :tmpfs\nsyn -fstype=tmpfs / :tmpfs /z\n\
                    bs -fstype=tmpfs / :/t /a\\ b :/t /c :/t\n";

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_multi_indirect() {
    check_vm(
        VmCase::new("d_multi_ind", "/mnt/a /etc/autofs/auto.a\n")
            .map("auto.a", MMAP)
            .steps(
                "ready\ntrig /mnt/a/m; waitlog 'mounted /mnt/a/m'; quiet 0.5\nsnap\n\
                 trig /mnt/a/m/sub; waitlog 'mounted /mnt/a/m/sub'\ntrig /mnt/a/m/a/b/; waitlog 'mounted /mnt/a/m/a/b'\nsnap\n\
                 trig /mnt/a/noroot; waitlog 'mounted /mnt/a/noroot'; quiet 0.5\ntrig /mnt/a/noroot/y; waitlog 'mounted /mnt/a/noroot/y'\n\
                 trig /mnt/a/q; waitlog 'mounted /mnt/a/q'; quiet 0.5\ntrig '/mnt/a/q/sp ace'; waitlog 'mounted /mnt/a/q/sp ace'\n\
                 trig /mnt/a/dup; waitlog '/mnt/a/dup'; quiet 0.5\ntrig /mnt/a/odd; waitlog 'mounted /mnt/a/odd'\n\
                 trig /mnt/a/bs; waitlog 'mounted /mnt/a/bs'; quiet 0.5\ntrig '/mnt/a/bs/a b'; waitlog 'mounted /mnt/a/bs/a b'\ntrig /mnt/a/syn; waitlog '/mnt/a/syn'; quiet 0.5\nsnap\nstopd\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_multi_direct() {
    check_vm(
        VmCase::new("d_multi_dir", "/- /etc/autofs/auto.d\n")
            .map("auto.d", MDIR)
            .steps(
                "waitlog 'mounted trigger /mnt/mm'; quiet 0.5\ntrig /mnt/mm; waitlog 'mounted /mnt/mm'; quiet 0.5\nsnap\n\
                 trig /mnt/mm/in; waitlog 'mounted /mnt/mm/in'; quiet 0.5\ntrig /mnt/mm/in/deeper; waitlog 'mounted /mnt/mm/in/deeper'\n\
                 snap\nstopd\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_multi_expire() {
    check_vm(
        VmCase::new("d_multi_expire", "/mnt/a /etc/autofs/auto.a --timeout=2\n")
            .map("auto.a", MMAP)
            .drop_lines(&EXPIRE_CYCLE)
            .steps(
                "ready\ntrig /mnt/a/m; waitlog 'mounted /mnt/a/m'; quiet 0.5\ntrig /mnt/a/m/sub; waitlog 'mounted /mnt/a/m/sub'\nsnap\n\
                 waitlog 'expired /mnt/a/m' 100; quiet 1.5\nsnap\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_multi_busy_shutdown() {
    check_vm(VmCase::new("d_multi_busy", "/mnt/a /etc/autofs/auto.a\n").map("auto.a", MMAP).steps(
        "ready\ntrig /mnt/a/m; waitlog 'mounted /mnt/a/m'; quiet 0.5\ntrig /mnt/a/m/sub; waitlog 'mounted /mnt/a/m/sub'\n\
         (cd /mnt/a/m/sub && sleep 4) &\nquiet 0.5\nsig TERM; waitlog 'autofs stopped' 100 x; note busy\nsnap\nwait\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_multi_forced_shutdown() {
    check_vm(VmCase::new("d_multi_force", "/- /etc/autofs/auto.d\n").map("auto.d", MDIR).steps(
        "waitlog 'mounted trigger /mnt/mm'; quiet 0.5\ntrig /mnt/mm; waitlog 'mounted /mnt/mm'; quiet 0.5\n\
         trig /mnt/mm/in; waitlog 'mounted /mnt/mm/in'; quiet 0.5\n(cd /mnt/mm/in && sleep 3) &\nquiet 0.5\n\
         sig USR2; waitlog 'autofs stopped' 100 x\nsnap\nwait\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_multi_direct_noroot_expire() {
    // No root offset: the trigger keeps its descriptor so the tree expires.
    check_vm(
        VmCase::new("d_multi_nr", "/- /etc/autofs/auto.d --timeout=2\n")
            .map("auto.d", "/mnt/nr /x -fstype=tmpfs :/t /y -fstype=tmpfs :/t\n")
            .drop_lines(&EXPIRE_CYCLE)
            .steps(
                "waitlog 'mounted trigger /mnt/nr'; quiet 0.5\ntrig /mnt/nr; waitlog 'mounted /mnt/nr'; quiet 0.5\n\
                 trig /mnt/nr/x; waitlog 'mounted /mnt/nr/x'\nsnap\nwaitlog 'umounted offset mount /mnt/nr/x' 100; quiet 2\nsnap\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_multi_forced_shutdown_indirect() {
    check_vm(VmCase::new("d_multi_force_ind", "/mnt/a /etc/autofs/auto.a\n").map("auto.a", MMAP).steps(
        "ready\ntrig /mnt/a/m; waitlog 'mounted /mnt/a/m'; quiet 0.5\ntrig /mnt/a/m/sub; waitlog 'mounted /mnt/a/m/sub'\n\
         (cd /mnt/a/m/sub && sleep 3) &\nquiet 0.5\nsig USR2; waitlog 'autofs stopped' 100 x\nsnap\nwait\n",
    ));
}

// Locations are `:/path` or `file:/path`: a bare `/path` makes the entry a
// multi-mount.
const SUBMAP: &str = "sub -fstype=autofs file:/etc/autofs/auto.sub\n\
                      opts -fstype=autofs,browse,timeout=3,symlink,nobind,ro, :/etc/autofs/auto.sub\n\
                      nest -fstype=autofs :/etc/autofs/auto.nest\nbad -fstype=autofs :/etc/autofs/nosuch\n";
const SUB: &str = "x -fstype=tmpfs :/t\nl -fstype=bind :/etc/autofs\n";
const NEST: &str = "in -fstype=autofs,nobrowse :/etc/autofs/auto.sub\n";

fn subcase(name: &str, master: &str) -> VmCase {
    VmCase::new(name, master).map("auto.a", SUBMAP).map("auto.sub", SUB).map("auto.nest", NEST)
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_submount_basic() {
    check_vm(subcase("d_sub_basic", "/mnt/a /etc/autofs/auto.a\n").unordered_log().steps(
        "ready\ntrig /mnt/a/sub; waitlog 'mounted indirect on /mnt/a/sub'; quiet 0.5\nsnap\n\
         trig /mnt/a/sub/x; waitlog 'mounted /mnt/a/sub/x'\ntrig /mnt/a/opts; waitlog 'mounted indirect on /mnt/a/opts'; quiet 0.5\n\
         ls /mnt/a/opts >> $C/out/steps\ntrig /mnt/a/opts/l/; waitlog 'mounted /mnt/a/opts/l'\n\
         trig /mnt/a/nest/in/x; waitlog 'mounted /mnt/a/nest/in/x'\ntrig /mnt/a/bad; waitlog 'failed to mount /mnt/a/bad'\n\
         trig /mnt/a/sub/nope; waitlog 'failed to mount /mnt/a/sub/nope'\nsnap\nstopd\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_submount_expire() {
    check_vm(subcase("d_sub_expire", "/mnt/a /etc/autofs/auto.a --timeout=2\n").drop_lines(&EXPIRE_CYCLE).steps(
        "ready\ntrig /mnt/a/sub/x; waitlog 'mounted /mnt/a/sub/x'\nsnap\n\
         waitlog 'shut down path /mnt/a/sub' 150; quiet 1.5\nsnap\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_submount_direct() {
    check_vm(
        VmCase::new("d_sub_direct", "/- /etc/autofs/auto.d\n")
            .map("auto.d", "/mnt/ds -fstype=autofs /etc/autofs/auto.sub\n")
            .map("auto.sub", SUB)
            .unordered_log()
            .steps(
                "waitlog 'mounted trigger /mnt/ds'; quiet 0.5\ntrig /mnt/ds/x; waitlog 'mounted /mnt/ds/x'\nsnap\nstopd\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_submount_busy_shutdown() {
    check_vm(subcase("d_sub_busy", "/mnt/a /etc/autofs/auto.a\n").unordered_log().steps(
        "ready\ntrig /mnt/a/sub/x; waitlog 'mounted /mnt/a/sub/x'\n(cd /mnt/a/sub/x && sleep 4) &\nquiet 0.5\n\
         sig TERM; waitlog 'autofs stopped' 100 x; note busy\nsnap\nwait\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_submount_prune_and_hup() {
    check_vm(subcase("d_sub_hup", "/mnt/a /etc/autofs/auto.a\n").unordered_log().steps(
        "ready\ntrig /mnt/a/sub/x; waitlog 'mounted /mnt/a/sub/x'\ntrig /mnt/a/opts; waitlog 'mounted indirect on /mnt/a/opts'\n\
         quiet 1\nsig USR1; quiet 2\nsnap\nprintf 'y -fstype=tmpfs :/t\\n' >> /etc/autofs/auto.sub\nquiet 2\n\
         sig HUP; quiet 2\ntrig /mnt/a/sub/y; waitlog 'mounted /mnt/a/sub/y'\nsnap\nstopd\n",
    ));
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_mount_modules() {
    // ext2/3/4 with their fsck run (a clean image, a read-only one, one that
    // needs repair, a missing one), AFS symlinks, and a "changer" that isn't.
    let pre = "mkfs.ext2 -q -F /tmp/e2.img 1M\nmkfs.ext3 -q -F /tmp/e3.img 2M\nmkfs.ext2 -q -F /tmp/bad.img 1M\n\
               debugfs -w -R \"clri <2>\" /tmp/bad.img >/dev/null 2>&1\n\
               debugfs -w -R \"ssv state 0\" /tmp/bad.img >/dev/null 2>&1\n";
    check_vm(
        VmCase::new("d_modules", "/mnt/a /etc/autofs/auto.a\n")
            .map(
                "auto.a",
                "e2 -fstype=ext2,loop :/tmp/e2.img\ne3ro -fstype=ext3,ro,loop :/tmp/e3.img\ne2ro -fstype=ext2,loop,ro :/tmp/e2.img\nbad -fstype=ext2,loop :/tmp/bad.img\n\
                 gone -fstype=ext4 :/tmp/nosuch.img\nafs -fstype=afs :/etc/autofs\nchg -fstype=changer :/dev/null\n\
                 chg2 -fstype=changer :/dev/nosuch\n",
            )
            .pre(pre)
            .steps(
                "ready\ntrig /mnt/a/e2; waitlog 'mounted /mnt/a/e2'\ntrig /mnt/a/e3ro; waitlog 'mounted /mnt/a/e3ro'\ntrig /mnt/a/e2ro; waitlog 'failed to mount /mnt/a/e2ro\\|mounted /mnt/a/e2ro'\n\
                 trig /mnt/a/bad; waitlog 'failed to mount /mnt/a/bad'\ntrig /mnt/a/gone; waitlog 'failed to mount /mnt/a/gone'\n\
                 trig /mnt/a/afs/; waitlog 'mounted /mnt/a/afs'\ntrig /mnt/a/chg; waitlog 'failed to mount /mnt/a/chg'\n\
                 trig /mnt/a/chg2; waitlog 'failed to mount /mnt/a/chg2'\nls -l /mnt/a | awk '{print $1, $NF}' >> $C/out/steps\nsnap\n",
            ),
    );
}

// Restart over existing mounts (README.active-restart): the daemon is
// killed with SIGKILL, leaving its autofs and real mounts, and started again
// over them, so it reconnects to each.

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_restart_indirect() {
    check_vm(
        VmCase::new("d_restart_ind", "/mnt/a /etc/autofs/auto.a\n/mnt/n /etc/autofs/auto.a -nobrowse\n")
            .map("auto.a", MAP)
            .unordered_log()
            .steps(
                "waitlog 'mounted indirect on /mnt/n'; quiet 0.5\ntrig /mnt/a/t; waitlog 'mounted /mnt/a/t'\n\
                 trig /mnt/a/k/; waitlog 'mounted /mnt/a/k'\ntrig /mnt/n/t; waitlog 'mounted /mnt/n/t'\nsnap\n\
                 restartd\nwaitlog 're-connected to mount /mnt/n' 100; quiet 2\nsnap\n\
                 trig /mnt/a/ro; waitlog 'mounted /mnt/a/ro'\nsnap\nstopd\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_restart_direct() {
    // Not with a mounted multi-mount: C deadlocks reconnecting to one in a
    // direct map (see QUIRKS.md, "Where the port differs").
    check_vm(
        VmCase::new("d_restart_dir", "/- /etc/autofs/auto.d\n")
            .map("auto.d", &format!("{DMAP}{MDIR}"))
            .unordered_log()
            .steps(
                "waitlog 'mounted trigger /mnt/mm'; quiet 0.5\ntrig /mnt/d1; waitlog 'mounted /mnt/d1'\n\
                 trig /mnt/deep/er/d3; waitlog 'mounted /mnt/deep/er/d3'\nsnap\n\
                 restartd\nwaitlog 're-connected to mount /mnt/mm' 100; quiet 2\nsnap\n\
                 trig /mnt/d2/; waitlog 'mounted /mnt/d2'\ntrig /mnt/mm/in; waitlog 'mounted /mnt/mm/in'\nsnap\nstopd\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_restart_multi_indirect() {
    check_vm(
        VmCase::new("d_restart_multi", "/mnt/a /etc/autofs/auto.a --timeout=3\n")
            .map("auto.a", MMAP)
            .unordered_log()
            .drop_lines(&EXPIRE_CYCLE)
            .steps(
                "ready\ntrig /mnt/a/m; waitlog 'mounted /mnt/a/m'; quiet 0.5\ntrig /mnt/a/m/sub; waitlog 'mounted /mnt/a/m/sub'\nsnap\n\
                 restartd\nwaitlog 're-connected to mount /mnt/a' 100; quiet 1\nsnap\n\
                 trig /mnt/a/m/a/b/; waitlog 'mounted /mnt/a/m/a/b'\nsnap\n\
                 waitlog 'umounting /mnt/a/m succeeded' 200; quiet 1.5\nsnap\nstopd\n",
            ),
    );
}

#[test]
#[ignore = "needs the root test VM (make vmcheck)"]
fn daemon_restart_submount() {
    check_vm(subcase("d_restart_sub", "/mnt/a /etc/autofs/auto.a\n").unordered_log().steps(
        "ready\ntrig /mnt/a/sub/x; waitlog 'mounted /mnt/a/sub/x'\nsnap\n\
         restartd\nwaitlog 're-connected to mount /mnt/a/sub' 100; quiet 2\nsnap\n\
         trig /mnt/a/sub/l/; waitlog 'mounted /mnt/a/sub/l'\nsnap\nstopd\n",
    ));
}
