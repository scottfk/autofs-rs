# Security

autofs-rs reimplements `automount`, which runs as root for its whole life. It answers
the kernel for any process that walks into one of its mount points, so every key it
looks up is chosen by whoever can name a path there, local users included; it turns
those keys into `mount` command lines and runs them as root; it runs program maps as
root with the key as an argument; and it reads maps, export lists and server replies
from the network (NIS, `MOUNTPROC_EXPORT`, NFS pings). Security bugs here matter, even
though this is a hobby project.

## Status and supported versions

autofs-rs is pre-release (0.x). There are no maintained release branches: only the
latest `main` gets fixes.

## What counts as a security issue

These are the kinds of bugs I most want to hear about:

- **Hostile keys.** A key (a path a process walks into) that escapes the mount point,
  injects options or arguments into a `mount` command line or a program map's
  invocation, or reaches a map entry C wouldn't match.
- **Untrusted input.** Crashes, panics, hangs, unbounded memory, thread or descriptor
  use from map contents, program map output, NIS replies, export lists or NFS server
  replies.
- **Mount tricks.** A mount made somewhere C wouldn't make it, with options C wouldn't use
  (`nosuid`, `nodev` dropped, for instance), a symlink followed that C doesn't follow,
  or an expire or shutdown that unmounts something it shouldn't.
- **Privilege boundaries.** Descriptors or environment leaking into `mount`, `umount` or
  program maps, the pid file, the command FIFO, or `/dev/autofs` access.
- **Memory safety.** Unsoundness in the `unsafe` code, or anything reachable from safe code
  that causes undefined behavior.
- **Divergence from upstream that weakens security.** For example, a check that C does and
  autofs-rs skips.

Upstream behavior that is reproduced on purpose will be listed in QUIRKS.md. Reports about
it are still welcome, especially if the impact is worse than described. It will be fixed as
deliberate changes.

If the same bug is also present in **upstream autofs or libtirpc**, please report it to
the [autofs list](https://lore.kernel.org/autofs/) maintainers as well. Upstream's fix is
what autofs-rs will follow. Bugs in the shared `tirpc` crate belong to
[rpcbind-rs](https://github.com/scottfk/rpcbind-rs); the same address below works for both.

## How to report

For anything that could be exploited, **please don't put the details in a public issue.**
Email them to me instead:

    scone-void-baggage (at) duck (dot) com

(Replace `(at)` with `@` and `(dot)` with `.`, and remove the spaces.)

If you don't get a reply, open an issue on <https://github.com/scottfk/autofs-rs/issues>
that only says you've sent a security report, without any details.

For low-risk problems, such as hardening suggestions or issues that need root already (a
malicious `autofs.conf` or map file owned by root, for instance), a normal public issue
is fine.

Useful things to include:

- The commit you tested.
- The options, configuration and maps the daemon ran with, and what triggered the
  problem (a script is ideal).
- What happened, and what C autofs does at the pinned release (`tools/REFERENCE_TAG`).

## What to expect

This is a spare-time project, so I can't promise a response time, but I'll acknowledge
security reports as soon as I can, fix confirmed bugs on `main`, and credit you in the
commit unless you'd rather I didn't.
