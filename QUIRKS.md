# Upstream quirks, kept on purpose

autofs-rs reproduces autofs **5.1.9** (with Gentoo's c99 patch, libtirpc 1.3.7 and glibc),
as Gentoo builds it, exactly, including behavior that looks like a bug. Each item here is
marked `QUIRK` in the source, or described where the code follows C step by step. Fixing
one is a deliberate, separate change (ideally upstream as well), not something to slip
into the port. Quirks of the shared `tirpc` crate are listed in rpcbind-rs's QUIRKS.md.

Severity: **high** means someone who can name a path in a mount point, write a map or
answer an RPC can get mounts, data or crashes they shouldn't; **medium** means it's
surprising and user-visible; **low** means it's cosmetic or hard to hit.

The last section lists where the port can't or doesn't follow C, and why.

## Logging (lib/log.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| low | Every logging function sends its message to syslog at `LOG_INFO`, whatever its level, unless the message carries a mount request id prefix (`use_mount_request_log_id`); only then does the level count. | `log::emit` | (syslog comes with the daemon, phase 3) |
| low | `main()` reports a failed `setrlimit()` with `printf()` and no newline, so the message runs into whatever comes next on stdout (`--dumpmaps`' header, or the second such message). | `automount::main` | `dump_basic`, `core_limit` |

## Configuration (lib/defaults.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | `uname()`'s result is tested the wrong way round, so when it works the amd defaults `arch`, `karch`, `os` and `osver` are set to nothing (and the `${arch}`-style macros built from them are missing, so amd's `os==...`-style selectors fail with "failed to get selector"). `autofs_use_lofs` gets `auto_dir`'s default (`/a`). | `ConfCache::load_amd_defaults` | `amd_selectors`, `amd_expansion` |
| medium | Lines that don't start with a letter or `[` are ignored, indented ones included: `  timeout = 5` does nothing. | `defaults::parse_line` | `dump_conf_indented` |
| low | Lines are read 256 bytes at a time, so a longer line is parsed as several and the "was truncated, ignored" message can never appear. | `defaults::fgets_chunks` | - |
| low | The "neither file has changed" test can never be true (`stat = fstat(...) != -1` assigns the comparison), so both files are reread every time the configuration is read. | `defaults_read_config` | - |
| low | Settings with defaults (`timeout`, `logging`, `browse_mode`...) are exported to the environment under their own names (`setenv("timeout", "600", 0)`), where programs autofs runs see them, and an environment variable of that name overrides both the default and the file. | `ConfCache::add`, `update` | `dump_conf_env` |

## Macros (lib/macros.c, lib/mounts.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| low | The amd `cluster` default looks up `domain` with a length of 4, which no variable matches, so it's never set from the domain. | `macros::add_std_amd_vars` | - |
| low | `macro_free_global_table()` resets the table to start at `OSVERS`, so `hostd`, `domain`, `xhost`, `host`, `byte`, `false`, `true` and `dollar` are gone after it. | `macros::macro_free_global_table` | - |

## The map entry cache (lib/cache.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | Caching a second entry for a key (from another map source) links it after the key's last entry with `existing->next = me`, dropping whatever followed that entry in the hash chain: other keys that hashed to the same bucket disappear from the cache. | `CacheInner::add` | `dump_small_hash_table` |
| low | `map_hash_table_size = 0` divides by zero (`SIGFPE`) on the first key. | `cache::hash` | `dump_zero_hash_table` |
| low | `cache_lookup_key_next()` tests the entry it started from instead of the one it's looking at, so for a multi-mount entry that isn't the root it loops forever. | `CacheInner::lookup_key_next` | - |

## The master map (daemon/master_tok.l, daemon/master_parse.y, daemon/master.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | The scanner's start state survives a rejected entry: after a syntax error part way through a line, the next line is scanned in whatever state the scanner was left in (and can be rejected for no reason of its own). Only `-xfn` resets it on purpose. | `master_parse` (the scanner state is global, as in C) | `dump_master_lines_after_error` |
| low | Tokens that don't set a value (`OPT_TIMEOUT`, `COMMA`...) carry whatever the last token left in `master_lval`, and some error messages print that. | `master_parse::Val` | `dump_master_lines` |
| medium | A `multi` entry whose format is `hesiod` frees the parsed path twice (in the action, then in `master_parse_entry()`): glibc stops with "free(): double free detected in tcache 2" and `SIGABRT`. | `State::local_free_vars` | `dump_master_multi_hesiod_crash` |
| medium | `-hosts` or `-null` in a `multi` map list makes `append_argv()` read through a NULL vector: `SIGSEGV`. | `Parse::add_multi_mapstr` | `dump_master_lines` (`/q multi -hosts`) |
| low | A map name, type or option of 2048 bytes or more, or a `multi`/map type that doesn't fit the scanner's 1024-byte buffer, trips `_FORTIFY_SOURCE` ("*** buffer overflow detected ***", `SIGABRT`). | `Val::set`, the `{MULTI}`/`{MTYPE}` actions | - |
| low | `--dumpmaps TYPE NAME MASTER` ignores `MASTER`: both branches of the test create the master list with the default name. | `automount::main` | - |
| low | The old-style `type:name` test for `sss` uses `\|\|` where the others use `&&`, so any master map name with `,` or `:` as its fourth character is read as `source:name`. | `lookup::lookup_nss_read_master` | - |
| low | An included map (`+name` in a map) is read, and then so are the maps included before it in the same map (C walks the instance list from the new instance onward). They're already cached, so only `--debug` and `--verbose` output shows it. | `lookup::lookup_nss_read_map` | `dump_map_include` |

## nsswitch.conf (lib/nss_tok.l, lib/nss_parse.y)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | The `[STATUS=action]` table is a global that is never reset: each source with brackets gets every action seen so far on the line, and on earlier reads. | `nsswitch::State::act` | `dump_nsswitch_actions_carry_over` |
| low | A parse that's abandoned part way leaves the rest of its buffer in the scanner; the next read of `nsswitch.conf` scans that first, then the file again. | `nsswitch::State::scanner` | `dump_nsswitch_errors` |
| low | Characters the `automount:` line's rules don't cover (`#`, `!`, `\|`, `=` outside brackets) are logged on a line of their own by flex's default rule, and the rest of a comment is read as sources ("ignored unsupported autofs nsswitch source"). | `Parse::lex` (rule 16) | `dump_nsswitch`, `dump_nsswitch_echo_and_long` |
| low | The syntax error message has an extra newline (a blank line on stderr). A source name of 128 bytes or more trips `_FORTIFY_SOURCE` and aborts. | `nsswitch::nss_error`, `Val::set` | `dump_nsswitch_errors`, `dump_nsswitch_echo_and_long` |

## File maps (modules/lookup_file.c, lib/parse_subs.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | Keys with a byte of 128 or more are dropped: `sanitize_path()` compares a signed `char` with 32. | `parse_subs::sanitize_path` | `dump_non_ascii_keys` |
| low | `sanitize_path()` never removes a trailing `/` from a key (its test measures the string past its end). | `parse_subs::sanitize_path` | `dump_map_scanner` |
| low | A line that starts with a blank after an entry continues it, but `read_one()` reads the continuation without keeping it; anything but blanks on it makes the whole entry a "bad map entry". | `lookup_file::read_one` | `dump_map_scanner` |

## Key lookups (daemon/lookup.c, lib/mounts.c, modules/parse_sun.c, modules/lookup_program.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | A request from a uid with no passwd entry keeps the previous request's user variables (`$USER`, `$HOME`, `$UID`...): `set_tsd_user_vars()` gives up without replacing them. | `mounts::set_tsd_user_vars` | `lookup_users` |
| low | Colons after a `:/` become slashes in the expanded entry, including colons that came from macros (`$UID:$GID` in a location). | `parse_sun::expandsunent` | `lookup_users`, `lookup_sun_no_slashify` |
| low | `sun_mount()` passes `nobrowse`, `browse` and `timeout=` on only for `fstype=autofs`, drops `bg` and `nofg` silently, and adds the map's `-D` macros to an autofs mount's options. | `ParseSun::sun_mount` | `lookup_sun_entries` |
| low | A program map's child changes to the mount point directory before running the program; when that fails (the directory doesn't exist yet) its warning goes to the program's stderr and comes back as a `>> ` line. | `LookupProgram::lookup_one` | `lookup_program` |

## Multi maps (modules/lookup_multi.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| low | A map with a format (`multi file,sun:/m1 -- ...`) is opened as the module `file,sun`, which doesn't exist, so the whole multi map fails. A type word of 20 bytes or more (any map name starting `file`, `yp`, `nis`, `ldap` or `sss`) trips `_FORTIFY_SOURCE`. | `lookup_multi::nss_open_lookup` | `dump_master_lines` |
| low | The map read checks each map's NSS status against `LKP_FAIL` (1): `NOTFOUND` and `TRYAGAIN` count as failures, `UNAVAIL` as a success. All the maps read into the multi map's one cache under the multi map's source, so a key in two of them shows once (the first). `--dumpmaps` numbers every map `map[1]`. | `LookupMulti::read_map`, `master::print_map_info` | `dump_master_lines` |
| low | `lookup_userhome.so` can't be selected: the master map's `userdir` type asks for `lookup_userdir.so`, which doesn't exist, and no nsswitch source or `multi` prefix names `userhome`. | `modules/lookup_userhome.rs` | - |
| low | Closing the maps stops at the first one whose close fails (`rv = rv \|\| close_lookup()`); the rest stay open. | `LookupMulti::done` | - |

## amd maps (modules/amd_tok.l, modules/amd_parse.y, modules/parse_amd.c, lib/parse_subs.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | A selector value or option that isn't a word of two or more characters starting with a letter (`uid==0`, `addopts:=z`, a lone `${host}`) doesn't scan as one: flex's default rule logs its characters on lines of their own, and the selector compares with an empty value (or the option is dropped). | `amd_parse::State::lex` (rule 56) | `amd_selectors`, `amd_syntax` |
| medium | `add_selector()` links a new selector in front of the list's last one, so a location keeps only its first and latest selectors; `match_selectors()` then evaluates the head (the latest) once per selector, and the first is never looked at. | `Parse::add_selector`, `parse_amd::match_selectors` | `amd_selectors` (`tri`, `two2`) |
| medium | With `selectors_in_defaults`, a `-` location in `/defaults` copies a defaults entry that is still NULL: `SIGSEGV`. | `parse_amd::select_default_entry` | `amd_defaults_reset_crash` |
| low | `sel!=` with no value is an equality test. | `Parse::action` (rule 21) | `amd_selectors` |
| low | `cache:=` is tested the wrong way round (`strncmp()` without `!`): anything but `inc...` is `inc`, and `inc...` is `all`. | `Parse::match_cache_option` | (the cache option is used by the daemon, phase 3) |
| low | A location with no file system type gets `nfs` by assignment, clearing its other flags (the `\|\|` cut, once it has been checked). | `parse_amd::update_with_defaults` | - |
| low | `sublink` is never taken from the variables (it's looked up with a length of 2, `su`), and an expanded `umount` is added to them as `umoun`. | `update_with_defaults`, `expand_entry` | - |
| low | Without `selectors_in_defaults`, a `/defaults` entry of more than one location is ignored in favor of the internal `opts:=rw,defaults`. | `parse_amd::select_default_entry` | `amd_defaults_selectors_off` |
| low | `nfsl` links only when `${host}` and `${hostd}` both equal `rhost` (`strcasecmp() \|\| strcasecmp()`), so with a domain it always mounts over NFS. | `parse_amd::do_nfsl_mount` | `amd_nfsl_domain` |
| low | An opts list, or one option, of 1024 bytes or more trips `_FORTIFY_SOURCE` in `prepend_opt()`; `merge_options()` resets its running length for most options (`resultlen =+ ...`), so a merged list over 256 bytes trips it too, as does a first list of 257 bytes or more. | `Parse::prepend_opt`, `parse_subs::merge_options` | `amd_long_opts_overflow`, `amd_merge_overflow` |
| low | A file map that changed since it was read is searched again for each key, and a `prefix*` key matches without the `/` before the `*` (`ab*` matches `a/q`). | `LookupFile::match_key` | `amd_keys_reread` |
| low | An amd program map's answer shorter than the key it should repeat is read past its end, into what the previous answer (the `/defaults` one) left in the buffer. | `lookup_program::skip_key` | `amd_program_map` (`short`) |
| low | A network named in `/etc/networks` (`wire(loopback)`) has its number byte-swapped (`ntohl()` of a number already in host order) before it's looked up. | `parse_subs::get_network_number` | `amd_selectors` (`innet3`) |
| low | A program's words are split at every space, and a closing quote ends a word, so two spaces, or a space after a quoted word, make an empty argument. | `parse_subs::construct_argv` | `amd_program_mounts` (`quoted`) |
| low | `rmdir_path()` unlinks a symbolic link that's the last component and still fails. | `automount::rmdir_path` | - |

## The daemon (daemon/automount.c, daemon/state.c, daemon/indirect.c, daemon/direct.c, daemon/flag.c, lib/mounts.c, modules/mount_*.c, modules/parse_sun.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| low | The command FIFO (`/run/autofs.cmd.fifo`) is removed by its own thread after `main()` asks it to stop, and `main()` exits without waiting, so the FIFO is usually left behind. | `automount::finish_cmd_pipe_handler` | every daemon case (left out of the comparison: it's a race) |
| low | Bind mount options with an empty member (a trailing comma, `-fstype=bind,ro,`) make the entry a symlink: the empty option compares equal to `symlink` (`_strncmp()` with a length of 0). | `mount_bind::has_symlink_opt` | `daemon_symlinks` (`tc`) |
| low | `umount_ent()` checks that a mount really went (and logs "the umount binary reported that ... was unmounted") only when `umount` *failed*. | `mounts::umount_ent_state` | - |
| low | A flag file whose pid is only read on the last of three tries counts as stale (`while (tries--)` leaves 0 either way). | `flag::flag_is_owned` | - |
| low | A location without `:/` (`:tmpfs`) in a multi-mount entry that has one later (`/a/b :/etc/autofs`) swallows the rest of the entry: `chunklen()` skips blanks while it still expects a colon followed by `/`. | `parse_subs::chunklen` | `daemon_multi_indirect` |
| low | At a forced shutdown, a direct or offset trigger that `askumount()` reports busy is detached without the "forcing umount" message: the path after the busy check reuses the 0 from `askumount()`. | `direct::do_umount_autofs_direct`, `direct::umount_autofs_offset` | - |
| low | The duplicate offset message is spelled "duplcate offset detected". | `cache::update_offset` | `daemon_multi_indirect` (`dup`) |
| low | autofs's `assert()` only logs (`state.c:578: assertion failed: ...`) and carries on: a submount told to shut down while it's still pruning gets there, and goes on to shut down. | `state::start_expire`, `c_assert!` | `daemon_submount_prune_and_hup` |
| low | A `-fstype=autofs` entry whose map is a bare path (`/etc/autofs/auto.sub`) is a multi-mount entry (its location starts with `/`), so the submount isn't made; `:/path` and `file:/path` work. | `parse_sun::check_is_multi` | `daemon_submount_basic` (comment) |
| low | `afs` entries fail on current kernels: the kernel has already made the key's directory, so the module's `symlink()` gets `EEXIST`. | `mount_afs` | `daemon_mount_modules` |
| low | With several mounts, the order in which they shut down, reload or expire is a race between threads (and between `stderr` writes, which can run two messages together); C's own log order varies from run to run. | `state::st_queue_handler` | `daemon_two_mounts_and_null`, `daemon_hup_reload` (compared unordered) |

## NFS mounts (modules/mount_nfs.c, modules/replicated.c, lib/rpc_subs.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| low | A host whose name gives 127.0.0.1 and one other IPv4 address counts as round robin (and is mounted by address): the loopback check compares the network-order address with the host-order `INADDR_LOOPBACK`. | `replicated::add_host_addrs` | - |
| low | Blanks after an NFS option are never skipped: the loop that should step back over them tests the `,` (or NUL) it stopped at. | `mount_nfs` | - |
| low | A host that can't be looked up skips its `host:/path` entry only if no host was listed alone before it (`a,`): after one (`empty` is cleared there and nowhere else), the path still goes to the hosts gathered so far. | `replicated::parse_location` | `daemon_nfs_single_hosts` (`none`) |
| low | A host's `addr_len` is `INET_ADDRSTRLEN` or `INET6_ADDRSTRLEN`, not the address's size, and `tcp6`/`udp6` skip IPv4 hosts by comparing it with `INET_ADDRSTRLEN`. | `replicated::add_new_host`, `replicated::check_address_proto` | - |
| low | The `nosymlink` warning says "depricated". | `mount_nfs` | - |

## Startup (daemon/automount.c, lib/mounts.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| low | `check_nfs_mount_version()` looks for the nfs-utils version in its buffer after every read, a C string from the start: the first line of a read (cut at its newline), or what was left of the last one moved to the front. `mount.nfs -V` gives one line, so `nfs_mount_uses_string_options` is 1 with nfs-utils 1.1.1 or later, and single NFS hosts are probed (unless `mount_wait` is set). | `automount::check_nfs_mount_version` | every case (`mount.nfs -V` is run and recorded), `daemon_nfs_hydra_net` |
| low | `-V` lists `LIBXML2_WORKAROUND`, which `config.h` defines even without LDAP. | `automount::show_build_info` | `opt_version` |
| low | Opening the `sun` parser (for any map) opens the NFS and bind mount modules, and the bind module checks that bind mounts work by mounting one `/tmp/autoXXXXXX` directory on another, even for `--dumpmaps`. | `mount_bind::mount_init` | every dump case (`cmds`) |

## Where the port differs

| What | Why |
|---|---|
| `nisplus` maps fail to open, with the `dlopen()` message hydra's build gives (`lookup_nisplus.so: undefined symbol: nis_list`): libnsl 2 has no NIS+ functions, so C can't load the module either. | hydra's libnsl. |
| The modules are built in: there are no `/usr/lib64/autofs/*.so` files or `libautofs.so`, and a map type without a module fails with the message `dlopen()` would give for the missing file. | Every module hydra has comes from autofs itself (see the README). |
| `-Dname` without `=` is ignored. C's `macro_parse_globalvar()` walks off the end of its stack buffer looking for the `=`. | Undefined behavior; there's nothing to match. |
| The master map scanner's 1024-byte `buff` grows instead of overrunning into the variables after it, and the scanner's own `master_error()` logs an empty line where C prints whatever a register held (`logmsg("%s")` without an argument; only for tokens over 2048 bytes). | Memory corruption and an uninitialized read; the hostile input phase looks at what the overrun does in the reference binary. |
| Three amd error messages have a `%s` without an argument: "sublink option requires option fs" (two of them) and "mount type ... not valid as ufs mount type" print whatever a register held in C; the port prints the location's type there. | Undefined behavior. |
| An amd program map answer shorter than its key is read from a model of the reused answer buffer (the last answer's bytes past its NUL). In C what's there depends on the heap; glibc hands back the chunk the last answer freed, which the model follows. | Reading past the end of a string. |
| A busy expire or map read thread that's asked to cancel stops at the point C tests for a cancel (`pthread_testcancel()`) or between steps, not at any cancellation point (`read()`, `nanosleep()`...) inside. | Rust has no thread cancellation. |
| An autofs point's pipe and ioctl descriptors start as 0: C `malloc()`s the structure and only sets them when it opens the pipe, so with `-U` they're whatever the memory held (0 on a fresh heap). | Uninitialized memory. |
| Restarting over a mounted multi-mount in a direct map reconnects to it. C deadlocks there: `mount_autofs_direct()` holds the map cache's read lock while it reconnects each trigger, and re-reading the multi-mount entry takes the same cache's write lock (`cache_writelock()` in the same thread), so the daemon hangs at startup. | An upstream self-deadlock; the port's cache locks are only held briefly. Not compared (`daemon_restart_direct` leaves the multi-mount unmounted). |
| "error 0x%d getting portmap client" and "error 0x%d getting service port" have no argument for their `%d`, so C prints whatever a register held; the port prints the status. | Undefined behavior. |
| A bracketed host (`[addr]:/path`) that's neither numeric nor found makes C `free()` a pointer one byte into its copy of the name, and glibc aborts; the port logs the failed lookup and goes on to the next host. | An invalid `free()`. |
| When a host name can't be looked up and there's no address, C goes on to call through a NULL client (`rpc_portmap_getport()`, `rpc_ping_proto()`: `create_client()` returns `getaddrinfo()`'s positive error, which the callers take for success); the port fails the call (`-EIO`). | A NULL pointer call. |
| A panic (a path not ported yet) aborts the daemon, rather than leaving the kernel waiting on a request thread that's gone. | Only for what isn't ported. |
