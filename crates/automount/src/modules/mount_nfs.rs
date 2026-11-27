//! `modules/mount_nfs.c`: NFS mounts. The location's hosts are parsed and,
//! when there's a choice, probed (`replicated`); a local host's path is bind
//! mounted instead; the others are tried in order with `mount -t nfs`.
//! It keeps the bind module open (opened by the first instance, closed by the
//! last) and seeds `random()` for server selection.

use std::sync::{Arc, Mutex};

use crate::daemon::automount::{MP_MODE, mkdir_path, rmdir_path};
use crate::daemon::master::{
    AutofsPoint, LKP_INDIRECT, MOUNT_FLAG_GHOST, MOUNT_FLAG_NOBIND, MOUNT_FLAG_RANDOM_SELECT, MOUNT_FLAG_REMOUNT,
    MOUNT_FLAG_SYMLINK, MOUNT_FLAG_USE_WEIGHT_ONLY,
};
use crate::daemon::module::{self, MountMod};
use crate::daemon::spawn::{self, MNT_FORCE_FAIL};
use crate::libautofs::cat_path::strncmp_len;
use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::libautofs::parse_subs::PROXIMITY_LOCAL;
use crate::libautofs::rpc_subs::{self, RPC_CLOSE_DEFAULT};
use crate::modules::replicated::{
    self, Host, NFS_PROTO_DEFAULT, NFS_PROTO_MASK, NFS_VERS_DEFAULT, NFS_VERS_MASK, NFS2_REQUESTED, NFS3_REQUESTED,
    NFS4_ONLY_REQUESTED, NFS4_VERS_DEFAULT, NFS4_VERS_MASK, TCP_REQUESTED, TCP_SUPPORTED, TCP6_REQUESTED,
    UDP_REQUESTED, UDP6_REQUESTED,
};
use crate::sys;

/// `mount_bind` and `init_ctr`.
static STATE: Mutex<(Option<Box<dyn MountMod>>, u32)> = Mutex::new((None, 0));

#[derive(Debug)]
pub struct MountNfs;

/// `mount_init()`.
pub fn mount_init() -> Option<MountNfs> {
    let have = STATE.lock().unwrap().0.is_some();
    if !have {
        if let Some(b) = module::open_mount(b"bind", Some(b"mount(nfs): ")) {
            let mut s = STATE.lock().unwrap();
            s.0 = Some(b);
            s.1 += 1;
        }
    } else {
        STATE.lock().unwrap().1 += 1;
    }
    sys::seed_random(sys::monotonic_time());
    if STATE.lock().unwrap().0.is_some() { Some(MountNfs) } else { None }
}

impl MountMod for MountNfs {
    /// `mount_mount()`.
    fn mount(
        &mut self,
        ap: &Arc<AutofsPoint>,
        root: &[u8],
        name: &[u8],
        what: Option<&[u8]>,
        fstype: &[u8],
        options: Option<&[u8]>,
    ) -> i32 {
        mount_nfs(ap, root, name, what, fstype, options)
    }

    fn done(self: Box<Self>) -> i32 {
        let b = {
            let mut s = STATE.lock().unwrap();
            s.1 = s.1.wrapping_sub(1);
            if s.1 == 0 { s.0.take() } else { None }
        };
        b.map_or(0, module::close_mount)
    }
}

/// `_strncmp(pat, cp, n) == 0`.
fn opt_is(pat: &[u8], cp: &[u8], n: usize) -> bool {
    strncmp_len(pat, cp, n) == 0
}

fn mount_nfs(
    ap: &Arc<AutofsPoint>,
    root: &[u8],
    name: &[u8],
    what: Option<&[u8]>,
    fstype: &[u8],
    options: Option<&[u8]>,
) -> i32 {
    let (apflags, logopt, ty, dev) = {
        let a = ap.lock();
        (a.flags, a.logopt, a.ty, a.dev)
    };
    let mut flags = apflags & (MOUNT_FLAG_RANDOM_SELECT | MOUNT_FLAG_USE_WEIGHT_ONLY);
    let name = cstr::c(name);
    let mut symlink = name.first() != Some(&b'/') && apflags & MOUNT_FLAG_SYMLINK != 0;
    let mut nobind = apflags & MOUNT_FLAG_NOBIND != 0;
    let mut nosymlink = false;
    let mut port: i32 = -1;
    let mut ro = false;
    let mut rdma = false;
    if apflags & MOUNT_FLAG_REMOUNT != 0 {
        return 0;
    }
    let verbose = defaults::defaults_get_mount_verbose() != 0;
    let mountlog = |m: Vec<u8>| {
        if verbose { crate::libautofs::log::log_info(logopt, &m) } else { crate::libautofs::log::log_debug(logopt, &m) }
    };
    let null = |o: Option<&[u8]>| o.map(|v| cstr::c(v).to_vec()).unwrap_or_else(|| b"(null)".to_vec());
    mountlog(bfmt!(
        "mount(nfs): root={} name={} what={}, fstype={}, options={}",
        root,
        name,
        null(what),
        fstype,
        null(options)
    ));
    let mount_default_proto = defaults::defaults_get_mount_nfs_default_proto();
    let mut vers = NFS_VERS_DEFAULT | NFS_PROTO_DEFAULT;
    if cstr::eq(fstype, b"nfs4") {
        vers = NFS4_VERS_DEFAULT | TCP_SUPPORTED | NFS4_ONLY_REQUESTED;
    } else if mount_default_proto == 4 {
        vers |= NFS4_VERS_DEFAULT;
    }
    // "nosymlink" is only accepted (and warned about) now; options for NFS
    // go on, as C leaves them in its buffer.
    let mut nfsoptions: Option<Vec<u8>> = None;
    if let Some(o) = options {
        let o = cstr::c(o);
        let at = |i: usize| o.get(i).copied().unwrap_or(0);
        let mut np: Vec<u8> = vec![0; o.len() + 2];
        let mut w = 0;
        let mut comma = 0usize;
        while at(comma) != 0 {
            while at(comma) == b',' {
                comma += 1;
            }
            while at(comma) == b' ' || at(comma) == b'\t' {
                comma += 1;
            }
            let cp = comma;
            while at(comma) != 0 && at(comma) != b',' {
                comma += 1;
            }
            // Trailing white space: C's loop tests *comma, which is ',' or
            // NUL, so it never moves end.
            let end = comma as isize - 1;
            let o_len = (end - cp as isize + 1).max(0) as usize;
            let c = &o[cp.min(o.len())..];
            if opt_is(b"proto=rdma", c, o_len) || opt_is(b"rdma", c, o_len) {
                rdma = true;
            }
            if opt_is(b"nosymlink", c, o_len) {
                warn!(
                    logopt,
                    "mount(nfs): the \"nosymlink\" option is depricated and will soon be removed, use the \"nobind\" option instead"
                );
                nosymlink = true;
            } else if opt_is(b"symlink", c, o_len) {
                if name.first() != Some(&b'/') {
                    symlink = true;
                }
            } else if opt_is(b"nobind", c, o_len) {
                nobind = true;
            } else if opt_is(b"no-use-weight-only", c, o_len) {
                flags &= !MOUNT_FLAG_USE_WEIGHT_ONLY;
            } else if opt_is(b"use-weight-only", c, o_len) {
                flags |= MOUNT_FLAG_USE_WEIGHT_ONLY;
            } else {
                if opt_is(b"vers=4", c, 6) || opt_is(b"nfsvers=4", c, 9) {
                    vers &= !NFS_VERS_MASK;
                    vers |= NFS4_VERS_MASK | TCP_SUPPORTED | NFS4_ONLY_REQUESTED;
                } else if opt_is(b"vers=3", c, o_len) || opt_is(b"nfsvers=3", c, o_len) {
                    vers &= !(NFS4_VERS_MASK | NFS_VERS_MASK | NFS4_ONLY_REQUESTED);
                    vers |= NFS3_REQUESTED;
                } else if opt_is(b"vers=2", c, o_len) || opt_is(b"nfsvers=2", c, o_len) {
                    vers &= !(NFS4_VERS_MASK | NFS_VERS_MASK | NFS4_ONLY_REQUESTED);
                    vers |= NFS2_REQUESTED;
                } else if c.starts_with(b"port=") && (o_len as isize - 5) < 25 {
                    let n = o_len.saturating_sub(5);
                    port = cstr::atoi(&c[5..5 + n.min(c.len().saturating_sub(5))]);
                    if port < 0 {
                        port = 0;
                    }
                } else if opt_is(b"proto=udp", c, o_len) || opt_is(b"udp", c, o_len) {
                    vers &= !TCP_REQUESTED;
                    vers |= UDP_REQUESTED;
                } else if opt_is(b"proto=udp6", c, o_len) || opt_is(b"udp6", c, o_len) {
                    vers &= !(TCP_REQUESTED | TCP6_REQUESTED);
                    vers |= UDP_REQUESTED | UDP6_REQUESTED;
                } else if opt_is(b"proto=tcp", c, o_len) || opt_is(b"tcp", c, o_len) {
                    vers &= !UDP_REQUESTED;
                    vers |= TCP_REQUESTED;
                } else if opt_is(b"proto=tcp6", c, o_len) || opt_is(b"tcp6", c, o_len) {
                    vers &= !(UDP_REQUESTED | UDP6_REQUESTED);
                    vers |= TCP_REQUESTED | TCP6_REQUESTED;
                }
                // Options that also make sense for bind mounts.
                else if opt_is(b"ro", c, o_len) {
                    ro = true;
                } else if opt_is(b"rw", c, o_len) {
                    ro = false;
                }
                let n = comma - cp + 1;
                for k in 0..n {
                    np[w + k] = at(cp + k);
                }
                w += n;
            }
        }
        // Both tcp and udp given?
        if vers & NFS_PROTO_MASK == 0 {
            vers |= NFS_PROTO_MASK;
        }
        let nfso = cstr::c(&np).to_vec();
        mountlog(bfmt!(
            "mount(nfs): nfs options=\"{}\", nobind={}, nosymlink={}, ro={}",
            nfso,
            nobind as i32,
            nosymlink as i32,
            ro as i32
        ));
        nfsoptions = Some(nfso);
    }
    let Some(fullpath) = crate::libautofs::mounts::mount_fullpath(4096, root, name) else {
        error!(logopt, "mount_mount", "mount(nfs): mount point path too long");
        return 1;
    };
    let mut hosts: Vec<Host> = Vec::new();
    if !replicated::parse_location(logopt, &mut hosts, what, flags) {
        info!(logopt, "mount(nfs): no hosts available");
        return 1;
    }
    // rdma can't be probed: mount.nfs(8) has to find out.
    if !rdma {
        // A singleton, NFSv4 not asked for alone, and v4 the configured
        // default: probe v4 only, and let mount.nfs fall back. If that probe
        // fails, probe as usual. (NFSv4 over UDP can't be probed this way.)
        if hosts.len() == 1
            && mount_default_proto == 4
            && vers & NFS_VERS_MASK != 0
            && vers & NFS4_VERS_MASK != 0
            && vers & (UDP_REQUESTED | UDP6_REQUESTED) == 0
        {
            let h = &hosts[0];
            let mut v4_probe_ok = false;
            if let Some(mut tmp) = replicated::new_host(
                h.name.as_deref(),
                0,
                h.addr.as_ref(),
                h.addr_len,
                h.proximity,
                h.weight,
                h.options,
            ) {
                tmp.rr = h.rr;
                let mut l = vec![tmp];
                replicated::prune_host_list(logopt, &mut l, NFS4_VERS_MASK | TCP_SUPPORTED, port);
                if !l.is_empty() {
                    v4_probe_ok = true;
                }
            }
            if !v4_probe_ok {
                replicated::prune_host_list(logopt, &mut hosts, vers, port);
            }
        } else {
            replicated::prune_host_list(logopt, &mut hosts, vers, port);
        }
    }
    if hosts.is_empty() {
        info!(logopt, "mount(nfs): no hosts available");
        return 1;
    }
    debug!(logopt, "mount_mount", "mount(nfs): calling mkdir_path {}", fullpath);
    let status = mkdir_path(&fullpath, MP_MODE);
    if status != 0 && sys::errno() != libc::EEXIST {
        error!(logopt, "mount_mount", "mount(nfs): mkdir_path {} failed: {}", fullpath, sys::strerror(sys::errno()));
        return 1;
    }
    let existed = status != 0;
    let what_s = what.map(|w| cstr::c(w).to_vec()).unwrap_or_default();
    'hosts: {
        for this in &hosts {
            // Local: bind mount it, unless asked not to.
            if !(nosymlink || nobind) && this.proximity == PROXIMITY_LOCAL {
                debug!(logopt, "mount_mount", "mount(nfs): {} is local, attempt bind mount", name);
                let bind_options: &[u8] = if symlink {
                    b"symlink"
                } else if ro {
                    b"ro"
                } else {
                    b""
                };
                let err = {
                    let mut st = STATE.lock().unwrap();
                    let b = st.0.as_mut().expect("bind module");
                    b.mount(ap, root, name, this.path.as_deref(), b"bind", Some(bind_options))
                };
                if err == 0 {
                    return 0;
                }
                // mtab couldn't be updated: no more tries.
                if err == MNT_FORCE_FAIL {
                    break 'hosts;
                }
                // No host name: it can't be NFS.
                if this.name.is_none() {
                    continue;
                }
            }
            // Not local: an NFS mount.
            let mut loc: Vec<u8>;
            if this.rr != 0
                && let Some(addr) = this.addr.as_ref()
                && defaults::defaults_use_hostname_for_mounts() == 0
            {
                let Some(n_addr) = rpc_subs::get_addr_string(addr.raw()) else {
                    error!(logopt, "mount_mount", "get_addr_string: {}", sys::strerror(sys::errno()));
                    break 'hosts;
                };
                loc = if addr.family == libc::AF_INET6 { [b"[", &n_addr[..], b"]"].concat() } else { n_addr };
            } else {
                loc = this.name.clone().unwrap_or_else(|| b"localhost".to_vec());
            }
            loc.push(b':');
            loc.extend_from_slice(this.path.as_deref().unwrap_or(b""));
            // A fallback from a failed bind mount: is the local NFS server
            // there, to save a long wait for the mount to fail?
            if this.proximity == PROXIMITY_LOCAL {
                let host = this.name.clone().unwrap_or_else(|| b"localhost".to_vec());
                let ret = if !rdma { rpc_subs::rpc_ping(&host, port, vers, 2, 0, RPC_CLOSE_DEFAULT) } else { 1 };
                if ret <= 0 {
                    continue;
                }
            }
            let err = match &nfsoptions {
                Some(o) if !o.is_empty() => {
                    mountlog(bfmt!("mount(nfs): calling mount -t {} -s -o {} {} {}", fstype, o, loc, fullpath));
                    spawn::spawn_mount(logopt, &[b"-t", fstype, b"-s", b"-o", o, &loc, &fullpath])
                }
                _ => {
                    mountlog(bfmt!("mount(nfs): calling mount -t {} {} {}", fstype, loc, fullpath));
                    spawn::spawn_mount(logopt, &[b"-t", fstype, &loc, &fullpath])
                }
            };
            if err == 0 {
                mountlog(bfmt!("mount(nfs): mounted {} type {} on {}", loc, fstype, fullpath));
                return 0;
            }
        }
    }
    // forced_fail:
    info!(logopt, "mount(nfs): nfs: mount failure {} on {}", what_s, fullpath);
    if ty != LKP_INDIRECT {
        return 1;
    }
    if (apflags & MOUNT_FLAG_GHOST == 0 && !name.is_empty()) || !existed {
        rmdir_path(ap, &fullpath, dev);
    }
    1
}
