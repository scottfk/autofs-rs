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

Phases 1 to 5a are done, and phase 5b is in PR #9. `--dumpmaps` works for every map type
hydra's build has, keys are looked up as the daemon looks them up (sun and amd maps; file,
program, `multi`, `-hosts` and NIS maps), and the daemon runs indirect and direct mounts: startup
and daemonizing, the master map with its amd sections, the kernel's mount and expire
requests, browsing, the negative cache, expiry, `SIGHUP`/`SIGUSR1`/`SIGUSR2`/`SIGTERM`,
`-l` through the command FIFO, the ioctl fallback, multi-mount entries with their offset
triggers, submounts (`-fstype=autofs`), restart over existing mounts, and every mount
module, NFS included: replicated locations, proximity, and the probe that picks the
servers (hydra's `/net` map works end to end), `-hosts` maps and amd `type:=host`
locations (the mount daemon's export lists), and NIS maps (libnsl's YP client, bound
through binding files or ypbind). Everything matches C, byte for byte in some 230
differential cases on the host and in 55 daemon cases run as root on the test VM, and a
rehearsal against a real NFS server on the second test VM. Next: phase 6 (hostile input).

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
| `crates/automount/src/libautofs/` | `lib/`, what `libautofs.so` holds: `defaults.c` (`autofs.conf`, the `[amd]` sections, `/etc/conf.d/autofs`), `macros.c`, `cache.c`, `parse_subs.c`, `mounts.c`, `args.c`, `cat_path.c`, `log.c`, `dev-ioctl-lib.c`, `alarm.c`, `nsswitch.c` with its grammar, and `rpc_subs.c`; `yp.rs` stands in for the YP client calls of libnsl 2.0.1. Also the flex and bison skeletons (below), and pthread-style locks (`csync.rs`) |
| `crates/automount/src/daemon/` | `daemon/`: `automount.c`, `master.c` and the master map grammar, `lookup.c`, `module.c`, `spawn.c`, `state.c`, `indirect.c`, `direct.c`, `mount.c`, `flag.c` |
| `crates/automount/src/modules/` | `modules/`: `lookup_file`, `lookup_dir`, `lookup_program`, `lookup_multi`, `lookup_userhome`, `parse_sun`, `parse_amd` (with the amd grammar), `lookup_hosts`, `lookup_yp`, `replicated`, and every mount module (`mount_bind`, `mount_generic`, `mount_nfs`, `mount_autofs`, `mount_ext2`, `mount_afs`, `mount_changer`) |
| `crates/automount/src/tables/` | the flex and bison tables of the three grammars, generated by `tools/gen-tables.py` from the reference build |
| `crates/automount/tests/` | differential tests and the harness (adapted from nfs-utils-rs) |
| `contrib/gentoo/` | packaging |
| `tools/` | the reference build, the table extractor, and the checks run on the test VM |

The `tirpc` crate comes from rpcbind-rs as a git dependency pinned to a commit (see
`Cargo.toml`). Client pieces autofs needs that rpcinfo and sm-notify didn't go into
rpcbind-rs first, as their own PRs, so rpcbind's differential suite keeps checking them;
NIS needed nothing new there (libnsl's calls are ordinary `clnt_create()` clients).

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
- **As root, on the test VM** (`hydra-autofs-test`, `make vmcheck`), for the daemon itself:
  the reference build and the port are copied over, and each case runs twice
  (`tests/vm/run-case.sh`) in a private mount namespace with the real kernel autofs and
  `/dev/autofs`, overlays on `/etc` and `/usr`, and `mount` and `umount` replaced by
  recorders that log their arguments and run the real programs (NFS mounts become tmpfs
  mounts). A case's steps trigger lookups by walking into the mount points, send signals
  and change maps, and snapshot the mount table; the daemon's log (`-f -d`), the recorded
  commands, the snapshots and notes, the exit status, and the mounts and files left at the
  end are compared after thread ids, kernel tokens and pids are normalized. Where C's own
  ordering is a race (several mounts shutting down at once), a case compares its log as
  sorted lines. NFS, mount daemon, rpcbind, ypbind and ypserv servers are faked
  (`fake-nfsd`) in a network namespace of the case's own, with the NIS domain set in a
  UTS namespace and binding files laid over `/var`. Phase 5b was also rehearsed with real
  NFS mounts from `hydra-nfs-peer` (its NIC on the `nfstest` network turned on for the
  run), and the last phase adds more of those.

## Roadmap

1. **Groundwork, configuration and the master map (done, PR #2):** the workspace; the harness; logging, `defaults.c` (every
   `autofs.conf` setting, old-style `/etc/conf.d/autofs` names, `[amd]` and per-mount amd
   sections), `macros.c`, `args.c`, the cache; the flex and bison skeletons and the
   `nsswitch.conf` and master map grammars; `master.c`'s reading of the master map
   (includes, `+map` entries, `dir:` maps, options, map type and format, `-hosts`,
   `-null`); `automount`'s option handling, `-V`, `--help`, the root check and the kernel
   protocol check; and `-m`/`--dumpmaps` for file, dir, program and `-hosts` maps in sun
   format, with the module setup it does (the bind mount check through `spawn.c`).
2. **Maps and lookups (done, PR #3):** `--dumpmaps` for every map type (`multi`, amd,
   `-hosts`, NIS+); `lookup_nss_mount()` and the negative cache; key lookups in
   `lookup_file`, `lookup_program` (its environment, stdout/stderr handling),
   `lookup_multi` and `lookup_userhome`; `parse_sun` for plain entries (`&` and `$`
   expansion, option merging, replicated locations, `-fstype=`, `[no]strict`,
   `[no-]use-weight-only`, escapes); `lookup_ghost()`; and the test drivers.
   Moved out: multi-mount entries to phase 4 (hydra's `/net` program map answers with
   one, and so does every `-hosts` lookup), `-hosts` export lists and NIS to phase 5 (they
   need the RPC client, and hydra uses neither).
2b. **amd maps (done, PR #4):** the amd scanner and grammar, `parse_amd` (selectors,
   `/defaults` and `map_defaults`, `-`/`||` locations, `${...}` expansion, option merging,
   the `auto`, `link`, `linkx`, `nfs`, `nfsl`, `lofs`, `ext`, `xfs`, `ufs`, `cdfs` and
   `program` mount types), amd key matching (`/defaults`, `prefix/*` keys) in the file
   and program maps, network proximity, and external mounts. Moved out: `type:=host`
   locations to phase 5 (they mount through the hosts map).
3. **The daemon, indirect mounts (done, PR #5):** startup (the pid file, daemonizing,
   the running check, `-F`/`-U`, `-f`, `-t`, `-n`/`-P`, `-M`, `-O`, `-D`, `-r`), the master
   map at boot (with the amd mount sections of `autofs.conf`), `/dev/autofs` and the ioctl
   fallback, `-l`/`--set-log-priority` and the command FIFO, the kernel packet pipe, the
   state machine and its queue, indirect mounts with `browse_mode` on and off, `spawn.c`'s
   `mount`/`umount` calls, `mount_generic` and `mount_bind` (binds and symlinks), negative
   caching, expiry on the timeout, and `SIGHUP` (reload), `SIGUSR1` (prune), `SIGUSR2` and
   `SIGTERM` (shutdown, with and without busy mounts). Moved out: entries that mount
   through `mount_nfs` (no `-fstype`, local `:/path` ones included, which `mount_nfs` binds)
   to phase 5, with `replicated.c`.
4. **Direct mounts, multi-mounts and nesting (done):** in two parts.
   - **4a (done, PR #6):** direct maps (triggers, expiry, reloads that add and
     remove entries, shutdown), offset mounts and multi-mount trees in indirect and direct
     maps (nested offsets, quoted paths, duplicate offsets, `-hosts`-style entries without
     a root), and the offset handling in the expire threads. hydra's `/net` program map
     answers with a multi-mount of NFS mounts (`/ host:/`), so its end-to-end case waits
     for `mount_nfs` in phase 5.
   - **4b (done, PR #7):** `mount_autofs` (nested `-fstype=autofs` submounts,
     their expiry, shutdown, prune and reload), `mount_ext2` (with its `fsck` run),
     `mount_afs`, `mount_changer`, and restart over existing mounts
     (`README.active-restart`: indirect, direct, offset and submount reconnects). Lookup
     and parse modules are shared by nested and concurrent lookups, as C's contexts are.
5. **NFS and RPC maps:** in two parts, on rpcbind-rs's `tirpc` crate (pinned; PR #13
   there added `CLSET_TIMEOUT` and `AUTH_SYS` clients).
   - **5a (done, PR #8):** `lib/rpc_subs.c` (clients on sockets of our own, the
     rpcbind `GETADDR` and portmap `GETPORT` lookups, `NULL` pings), `mount_nfs` and
     `replicated.c`: host lists with weights, proximity, version and protocol probing,
     `use-weight-only`, `mount_nfs_default_protocol`, `nfs_mount_uses_string_options`,
     local hosts bind mounted, round-robin names mounted by address. Tested against fake
     rpcbind and NFS servers (`fake-nfsd`) in a network namespace of each case's own,
     in the subnet, on the same network and further away.
   - **5b (done, PR #9):** `-hosts` maps (export lists from `MOUNTPROC_EXPORT`, browsing,
     the export update on a reload) and amd `type:=host` locations (the host's tree
     through a hosts map instance, with a symlink for another key); `lookup_yp`, with
     libnsl's YP client calls (`yp_match`, `yp_all`, binding files of both versions and
     ypbind versions 3 and 2) on `tirpc`, tested against fake `ypbind` and `ypserv`; and
     a rehearsal against `hydra-nfs-peer`'s real NFS server (`-hosts`, sun and amd host
     mounts, a reload, a replicated entry with a dead host: the same mounts and log as
     C). Found: a reload of a browsable `-hosts` map with a host mounted crashes C
     (QUIRKS.md).
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
- How to run the root tier: settled in phase 3. The host builds both programs and drives
  the VM over ssh (`tests/common/vm.rs`); only the binaries and the case runner go there.

Not planned unless needed: LDAP, SSS, Hesiod and SASL lookups, mount locking, systemd
integration, and `fedfs` (none of which hydra's build has).

## License

GPL-2.0-or-later, as autofs (see [LICENSE](LICENSE), upstream's `COPYING`, and upstream's
`COPYRIGHT`, which licenses everything in the distribution under GPL version 2 or later
unless a file says otherwise; none of the files in scope do). The `tirpc` crate from
rpcbind-rs is BSD-3-Clause.
