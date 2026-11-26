# Contributing

Thanks for stopping by. This is a personal project, a Rust port of the Linux automounter,
[autofs](https://git.kernel.org/pub/scm/linux/storage/autofs/autofs.git) 5 (the
`automount` daemon and its modules), that I tinker with in my spare time, but
contributions are welcome. Here's how things work.

## What this project is

autofs-rs aims to be a **drop-in replacement** for `automount`. Given the same options,
configuration files and maps, and the same processes walking into its mount points, it
should make the same mounts with the same `mount` command lines, give the kernel the same
answers, expire the same mounts at the same times, log the same lines and exit the same
way. It is not a redesign: if upstream has an odd edge case, we copy the odd edge case and
list it in QUIRKS.md.

The upstream release we track is pinned in `tools/REFERENCE_TAG`, built the way Gentoo
builds it (see the README). Behavior is checked against a build of that release, not
against the man pages or what seems sensible. Where libtirpc decides the behavior (XDR,
client timeouts and retries, error messages, netconfig), we follow the libtirpc version
the reference links, 1.3.7, through the `tirpc` crate shared with
[rpcbind-rs](https://github.com/scottfk/rpcbind-rs).

The layout follows upstream's sources (`automount.c`, `master.c`, `parse_sun.c`,
`lookup_file.c` and so on); the README describes it as it grows.

## What's useful to contribute

- **Behavior differences.** If autofs-rs does something different from C autofs at the
  pinned release, that's a bug. Please send the options, `autofs.conf`, the maps, what you
  did to trigger it, and both results (the logs with `--debug` are ideal). A new
  differential test case is even better.
- **Quirk fixes, as separate changes.** Fixing something listed in QUIRKS.md is welcome,
  but as its own PR that says which quirk it fixes. Ideally it gets fixed upstream too.
- **Reference bumps.** Moving `tools/REFERENCE_TAG` to a newer upstream release, plus the
  fixes needed so the tests pass again.
- **Documentation.** Corrections or additions, especially install notes for other distros
  and init systems.

## What doesn't fit

- **"Improvements" that change behavior quietly.** New options, changed defaults and nicer
  messages belong upstream in autofs first. Once they ship in a release, we'll match them.
- **New dependencies** without a strong reason. The only outside crate is `libc`, and I'd
  like to keep it that way. In particular, the port doesn't link libtirpc or libnsl.
- **`unsafe` outside the `sys` modules.** If you need a new syscall or ioctl, add a safe
  wrapper there.
- **Changes to the `tirpc` crate here.** It lives in rpcbind-rs; send those there.
- **LDAP, SSS, Hesiod or SASL support**, unless the reference build turns them on first.

## Building and testing

You need Rust 1.88 or newer (edition 2024). For the tests you also need a C compiler,
flex, bison, the libtirpc, libnsl and rpcsvc-proto headers and libraries to build
upstream autofs, unprivileged user namespaces, and a subordinate id range of at least
65536 for your user in `/etc/subuid` and `/etc/subgid` (with `newuidmap`/`newgidmap` from
shadow). The daemon's tests need real root and the kernel's autofs, so they run on a test
VM; the README says how.

```sh
make                # release build
make reference      # build the C reference at the pinned release into ../autofs
make check          # build the reference if needed and run everything
make clippy         # cargo clippy --all-targets -D warnings
make fmt            # cargo fmt
make tables         # regenerate the grammar tables from the reference build
```

The scanners and parsers run flex's and bison's tables through Rust copies of their
skeletons (see the README). The tables in `crates/automount/src/tables/` are generated
by `tools/gen-tables.py` from the C that flex and bison write when the reference is
built; don't edit them, and regenerate them after a reference bump. A change to a
grammar's behavior goes in its rule actions, next to the grammar.

**Before sending a PR, please make sure `make check`, `make clippy` and `make fmt` are
clean.**

### Differential tests

Most testing is done by running the C reference and autofs-rs side by side on the same
input, the way rpcbind-rs and nfs-utils-rs do it:

- Each case runs in private namespaces with its own `/etc`, `/run` and maps, and `mount`
  and `umount` replaced by recorders.
- The same configuration and the same triggers are given to each, and everything they
  do is compared: stdout, stderr, syslog lines, the exit status, the recorded mount
  commands, the mount tree, what processes see in the mount points, and any RPC calls
  they make to the fake servers.

When you fix a difference or change behavior, add cases that cover it, including error
paths and malformed input. Unit tests are fine for internal helpers, but a differential
test is what shows the behavior matches.

## Code conventions

- **Port, don't paraphrase.** Each function's doc comment names the upstream function it
  ports (e.g. `` `handle_packet_missing_indirect()` `` or `` `parse_mount()` ``). Keep the
  structure close enough to the C that someone can read the two side by side.
- **Bytes, not strings.** Keys, map entries, paths, options and host names are
  `Vec<u8>`/`&[u8]`, as they are in C. Don't round-trip through `String` where non-UTF-8
  input could show up (it can: keys come from whatever path a process walks into, and
  maps come from files, programs and the network).
- **Bounds before trust.** Every length read from the kernel, a map or the wire is checked
  against what's left and against upstream's limits (`KEY_MAX_LEN`, `PATH_MAX`) before
  anything is allocated.
- **Mark quirks.** Reproduced upstream bugs get a `QUIRK:` comment in the code and a row in
  QUIRKS.md.
- **Every `unsafe` block gets a `// SAFETY:` comment.** The lints enforce this
  (`undocumented_unsafe_blocks`, `unsafe_op_in_unsafe_fn`).
- **US-English spelling** in comments, docs and identifiers, except where a name or string
  must match upstream.
- **Script headers.** Shell scripts, C probes and the Makefile have a changelog comment at
  the top, one line per change: `YYYYMMDD - <description> - <author>`. Please add a line
  when you change one.

## How to submit changes

The repo lives at <https://github.com/scottfk/autofs-rs>.

1. Fork the repo and create a branch.
2. Make your change, with tests.
3. In the PR description, explain **what** changed and **why**. For a behavior fix,
   include the input that showed the difference.
4. If you bumped or tested against a different upstream release, kernel or libtirpc, say
   which.

There's no CLA. Contributions are accepted under the project's license (see
[LICENSE](LICENSE)), the same as upstream autofs'.

## Issues

You can open issues for questions, not just bugs. If something about the build or the
reference setup is confusing, ask. I can't promise a fast response, but I do read them.

## Code of conduct

Be straightforward and respectful. That's the whole policy. See
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
