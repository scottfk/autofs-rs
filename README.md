# autofs-rs

A drop-in port/reimplementation of the Linux automounter, autofs 5, in Rust: the
`automount` daemon, its shared code (`libautofs.so`) and its lookup, parse and mount
modules. Currently just something fun for me to tinker with in Claude, and the follow-on
to [rpcbind-rs](https://github.com/scottfk/rpcbind-rs) and
[nfs-utils-rs](https://github.com/scottfk/nfs-utils-rs).

## Goals

- **Drop-in compatible with autofs 5.1.9** (Gentoo's `net-fs/autofs`), as built for hydra:
  the same options; the same handling of `/etc/autofs/autofs.conf`, `/etc/conf.d/autofs`,
  `/etc/nsswitch.conf`, the master map and the `file`, `program`, `dir`, `multi`, `hosts`,
  `userhome`, `yp` and `nisplus` maps, in both sun and amd formats; the same mounts, made
  with the same `mount`/`umount` command lines and options, in the same order; the same
  answers to the kernel (ready, fail, expire) and the same expire behavior; the same
  messages, syslog lines, exit statuses and `--dumpmaps` output. Upstream quirks are
  reproduced on purpose and listed in QUIRKS.md. Improvements come later, as deliberate
  changes.
- **No libtirpc.** The RPC that autofs does (NFS `NULL` pings and `rpcbind`/portmap
  lookups to pick a server, `MOUNTPROC_EXPORT` for `-hosts` maps, NIS for `yp` maps) comes
  from the `tirpc` crate of rpcbind-rs, which reimplements the parts of libtirpc 1.3.7 that
  show on the wire or in messages, and gets client additions here as needed.
- **Linux only.**
- **Small and boring:** `libc` as the only outside crate dependency, no async, and
  `unsafe` confined to `sys` modules. Threads where upstream has threads, since the
  daemon's behavior (one thread per mount point, per request and per expire run) shows in
  what the kernel and the logs see.

LDAP, SSS, Hesiod and SASL support are out of scope: hydra's build has them off (see
below), and so does this port.

## Status

Phase 1 (groundwork, configuration, the master map and `--dumpmaps`) is done (PR #2):
`automount -m` and `automount -m TYPE NAME` work for file, dir, program and `-hosts`
maps in sun format, with the configuration, `nsswitch.conf`, master map includes and map
includes, and match C byte for byte in 152 differential cases (stdout, stderr, exit
status and every `mount`/`umount` command), crashes included. Starting the daemon stops
after the kernel protocol check (which needs root on the test VM). Next: phase 2 (maps
and lookups).

The plan and its status live in the [roadmap](#roadmap) below, which is updated as each
step lands.

The reference is the `autofs-5.1.9` release tarball plus Gentoo's
`autofs-5.1.9-c99.patch`, built as `net-fs/autofs-5.1.9-r2` builds it
([tools/build-reference.sh](tools/build-reference.sh)), against the system libtirpc 1.3.7
and libnsl:

- USE="-ldap +libtirpc -mount-locking -sasl -selinux -systemd": no LDAP, SASL, SSS or
  Hesiod lookups, no mount locking, no systemd support;
- `--with-confdir=/etc/conf.d --with-mapdir=/etc/autofs --enable-sloppy-mount
  --enable-force-shutdown --enable-ignore-busy --disable-ext-env`;
- `/usr/sbin/automount`, `/usr/lib64/libautofs.so`, and 17 modules in
  `/usr/lib64/autofs` (plus five compatibility symlinks such as `mount_nfs4.so` and
  `lookup_files.so`).

The reference build imports and exports the same libc, libtirpc and libnsl symbols as
the installed daemon, library and modules. The one difference is a `memset` import in
`lookup_multi.so`: the installed copy was built in March 2026 with an older GCC.

How hydra uses it today: `autofs` is in the default runlevel, started by Gentoo's init
script (`automount -p /var/run/autofs.pid`, `USE_MISC_DEVICE="yes"`), with
`timeout = 300`, `browse_mode = no` and `mount_nfs_default_protocol = 4` in
`autofs.conf`. The master map has one entry, `/net /etc/autofs/auto.netv4`, an
executable (program) map that asks `showmount -e` for a host's first export and returns
an NFSv4 mount of the server's `/`. That is how `/net/ronda` gets mounted.

## Layout

Upstream's code in scope is about 35,000 lines of C and 3,000 of headers, plus three
flex/bison grammars of about 3,300 lines together (the master map, `nsswitch.conf` and
amd maps). The modules call into the daemon and the daemon into the modules, so the port
is one crate whose modules follow upstream's directories and files:

| Path | What |
|---|---|
| `crates/automount/src/libautofs/` | `lib/`, what `libautofs.so` holds: `defaults.c` (`autofs.conf`, the `[amd]` sections, `/etc/conf.d/autofs`), `macros.c`, `cache.c`, `parse_subs.c`, `mounts.c`, `args.c`, `cat_path.c`, `log.c`, and `nsswitch.c` with its grammar; later `rpc_subs.c`, `dev-ioctl-lib.c` and `alarm.c`. Also the flex and bison skeletons (below) |
| `crates/automount/src/daemon/` | `daemon/`: `automount.c`, `master.c` and the master map grammar, `lookup.c`, `module.c`, `spawn.c`; later `state.c`, `direct.c`, `indirect.c`, `mount.c`, `flag.c` |
| `crates/automount/src/modules/` | `modules/`: so far `lookup_file`, `lookup_dir`, `lookup_hosts` (its map read), `lookup_program` and `lookup_yp` (their setup), `parse_sun` (its setup), `mount_nfs` and `mount_bind` (their setup) |
| `crates/automount/src/tables/` | the flex and bison tables of the three grammars, generated by `tools/gen-tables.py` from the reference build |
| `crates/automount/tests/` | differential tests and the harness (adapted from nfs-utils-rs) |
| `contrib/gentoo/` | packaging |
| `tools/` | the reference build, the table extractor, and the checks run on the test VM |

The `tirpc` crate will come from rpcbind-rs as a git dependency pinned to a commit, with
its first user (phase 2). Client pieces autofs needs that rpcinfo and sm-notify didn't go
into rpcbind-rs first, as their own PRs, so rpcbind's differential suite keeps checking
them.

The grammars aren't rewritten. Where a scanner or parser gives up decides what autofs
does next: whether the parser reads a lookahead token before reducing, and which start
state an aborted entry leaves the scanner in for the next one. So the port runs flex's
and bison's own tables (extracted from the generated C of the reference build) through
Rust copies of the two skeletons as flex 2.6.4 and bison 3.8.2 generate them for these
grammars (`libautofs/flex.rs`, `libautofs/bison.rs`), and only the rule actions are ported
by hand, next to each grammar.

## Testing

The kernel won't let an unprivileged user namespace mount `autofs` (`EPERM`), so testing
comes in two tiers:

- **Unprivileged, on the host,** as in nfs-utils-rs: each case runs the C build and then
  the port in a private user, mount, network and pid namespace (ids mapped from your
  subordinate ranges, its own `/etc`, `/run`, loopback and `/dev/log`), and compares
  stdout, stderr, the exit status, syslog lines and files. This covers everything that
  doesn't need the kernel's autofs: option handling, configuration, the master map,
  `nsswitch.conf`, map reading and parsing (`--dumpmaps`, and a small driver that calls a
  lookup and parse module's entry points the way the daemon does and records the
  `mount` calls they would make), program maps, macro expansion, amd selectors, and the
  RPC side against fake servers in the probe (pings, portmap, exports, NIS).
- **As root, on the test VM,** for the daemon itself: each case runs in a private mount
  namespace with the real kernel autofs and `/dev/autofs`, with `mount`, `umount` and
  `mount.nfs` replaced by recorders that log their arguments and do a bind or tmpfs mount
  instead, and compares the mount tree (from `/proc/self/mountinfo`), the recorded
  commands, what processes see when they walk into the mount points (the kernel's answer
  to each trigger, its errno and timing), expiry under a fake clock, logs and exit
  statuses. The last phase adds real NFS mounts between the two NFS test VMs.

## Roadmap

1. **Groundwork, configuration and the master map (done, PR #2):** the workspace; the harness; logging, `defaults.c` (every
   `autofs.conf` setting, old-style `/etc/conf.d/autofs` names, `[amd]` and per-mount amd
   sections), `macros.c`, `args.c`, the cache; the flex and bison skeletons and the
   `nsswitch.conf` and master map grammars; `master.c`'s reading of the master map
   (includes, `+map` entries, `dir:` maps, options, map type and format, `-hosts`,
   `-null`); `automount`'s option handling, `-V`, `--help`, the root check and the kernel
   protocol check; and `-m`/`--dumpmaps` for file, dir, program and `-hosts` maps in sun
   format, with the module setup it does (the bind mount check through `spawn.c`).
2. **Maps and lookups (planned):** the `tirpc` dependency; `parse_sun` in full
   (multi-mounts and offsets, replicated locations, `-fstype=`, option merging, `&` and
   `*` keys, escapes);
   `parse_amd` with the amd grammar, selectors and macros; `lookup_file`, `lookup_dir`,
   `lookup_multi`, `lookup_program` (its environment, stdout/stderr handling and
   timeout), `lookup_userhome`, `lookup_hosts` (exports through `MOUNTPROC_EXPORT`),
   `lookup_yp` and `lookup_nisplus`; `--dumpmaps` for every map type (`multi`, amd), and
   the module driver for lookups.
3. **The daemon, indirect mounts (planned):** startup (the pid file, daemonizing, the
   running check, `-F`/`-U`, `-f`, `-t`, `-n`/`-P`, `-M`, `-O`, `-D`, `-r`), the master
   map at boot, `/dev/autofs` and the ioctl fallback, `-l`/`--set-log-priority` and the
   command FIFO, the kernel packet pipe, the state machine and its queue, indirect
   mounts with `browse_mode` on and off, `spawn.c`'s
   `mount`/`umount` calls, `mount_generic` and `mount_bind`, negative caching, expiry on
   the timeout, and `SIGHUP` (reload), `SIGUSR1` (prune), `SIGUSR2` and `SIGTERM`
   (shutdown, with and without busy mounts).
4. **Direct mounts, multi-mounts and nesting (planned):** direct maps, offset mounts
   and multi-mount trees, `mount_autofs` (nested `-fstype=autofs` submounts),
   `mount_ext2` (with its `fsck` run), `mount_afs`, `mount_changer`, map reloads that add,
   change or remove entries while mounts are in use, and restart over existing mounts
   (`README.active-restart`).
5. **NFS (planned):** `mount_nfs` and `replicated.c` (proximity, version and protocol
   probing with `NULL` pings and portmap lookups, weights, `-r` random selection,
   `mount_nfs_default_protocol`, `nfs_mount_uses_string_options`, fallback when a
   server doesn't answer), against fake servers in the probe and then against
   `hydra-nfs-peer`.
6. **Hostile input (planned):** malformed and huge maps, program maps that hang, flood
   or emit garbage, hostile keys (path tricks, overlong, odd characters) from processes
   walking into a mount point, hostile `MOUNTPROC_EXPORT`, NIS and ping replies, kernel
   packets racing with expiry and shutdown, and descriptor or thread exhaustion.
7. **Packaging (planned):** a Gentoo ebuild in localrepo, rehearsed on the test VMs (the
   `/net` program map against a real NFS server, reloads, expiry, a server going away)
   with rpcbind-rs and nfs-utils-rs, then rolled back through a binary package of the C
   build.

Open questions, to settle in the phase where they come up:

- Whether the modules also need their C ABI (`dlopen()`able `.so` files with
  `lookup_init()`, `parse_mount()` and so on, calling back into `libautofs.so` and the
  daemon). Every module hydra has comes from autofs itself (`lookup_sss.so`, the only
  third-party one, comes with sssd, which isn't installed), so the plan is one Rust binary
  with the modules built in, looked up by the same names. A map type with no module then
  fails as C fails to `dlopen()` a missing one, and the files under `/usr/lib64/autofs`
  and `libautofs.so` go away; both differences are listed in QUIRKS.md.
- How `lookup_yp` and `lookup_nisplus` work without libnsl. The plan for `yp` is the YP
  client calls autofs uses (`yp_get_default_domain`, `yp_bind` through `ypbind`,
  `yp_match`, `yp_all`, `yp_order`) on the `tirpc` crate, checked against fake `ypbind`
  and `ypserv` in the probe. NIS+ is all but dead; the plan is to reproduce what C does
  when there is no NIS+ server, and to settle that in phase 2.
- How to run the root tier: building on the host and running the harness inside the
  test VM, or the full `cargo test` there. Settled in phase 3.

Not planned unless needed: LDAP, SSS, Hesiod and SASL lookups, mount locking, systemd
integration, and `fedfs` (none of which hydra's build has).

## License

GPL-2.0-or-later, as autofs (see [LICENSE](LICENSE), upstream's `COPYING`, and upstream's
`COPYRIGHT`, which licenses everything in the distribution under GPL version 2 or later
unless a file says otherwise; none of the files in scope do). The `tirpc` crate from
rpcbind-rs is BSD-3-Clause.
