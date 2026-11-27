//! `modules/mount_autofs.c`: `-fstype=autofs` entries, a nested autofs
//! mount (a submount) with a map of its own, run by its own mount handler
//! thread as the master map's mounts are.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use crate::daemon::master::{
    self, AutofsPoint, MAP_FLAG_FORMAT_AMD, MOUNT_FLAG_AMD_CACHE_ALL, MOUNT_FLAG_GHOST, MOUNT_FLAG_NOBIND,
    MOUNT_FLAG_REMOUNT, MOUNT_FLAG_STRICTEXPIRE, MOUNT_FLAG_SYMLINK, StartupCond,
};
use crate::daemon::module::MountMod;
use crate::libautofs::args::Argv;
use crate::libautofs::cat_path::strncmp_len;
use crate::libautofs::cstr;
use crate::libautofs::mounts;
use crate::libautofs::parse_subs::parse_map_type_info;
use crate::sys;

const MODPREFIX: &str = "mount(autofs): ";
const PATH_MAX: usize = 4096;
const CHECK_RATIO: i64 = 4;
const AMD_CACHE_OPTION_ALL: u32 = crate::modules::amd_parse::AMD_CACHE_OPTION_ALL;

#[derive(Debug)]
pub struct MountAutofs;

/// `mount_init()`.
pub fn mount_init() -> Option<MountAutofs> {
    Some(MountAutofs)
}

/// The C string at `buf[i..]`.
fn cs(buf: &[u8], i: usize) -> Vec<u8> {
    cstr::c(&buf[i.min(buf.len())..]).to_vec()
}

/// `sscanf(cp, "timeout=%u", &tout)`: the value, if there is one.
fn scan_timeout(cp: &[u8]) -> Option<u32> {
    let at = |i: usize| cp.get(i).copied().unwrap_or(0);
    let mut i = 8;
    while matches!(at(i), b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r') {
        i += 1;
    }
    let neg = match at(i) {
        b'-' => {
            i += 1;
            true
        }
        b'+' => {
            i += 1;
            false
        }
        _ => false,
    };
    if !at(i).is_ascii_digit() {
        return None;
    }
    let mut v: u64 = 0;
    let mut sat = false;
    while at(i).is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((at(i) - b'0') as u64);
        if v > u32::MAX as u64 {
            sat = true;
        }
        i += 1;
    }
    // strtoul(): out of range is ULONG_MAX, stored in an unsigned int.
    let v = if sat { u32::MAX } else { v as u32 };
    Some(if neg { v.wrapping_neg() } else { v })
}

impl MountMod for MountAutofs {
    /// `mount_mount()`.
    fn mount(
        &mut self,
        ap: &Arc<AutofsPoint>,
        root: &[u8],
        name: &[u8],
        what: Option<&[u8]>,
        _fstype: &[u8],
        c_options: Option<&[u8]>,
    ) -> i32 {
        let (flags, logopt) = {
            let a = ap.lock();
            (a.flags, a.logopt)
        };
        let mut nobind = flags & MOUNT_FLAG_NOBIND != 0;
        let mut ghost = flags & MOUNT_FLAG_GHOST != 0;
        let mut symlnk = flags & MOUNT_FLAG_SYMLINK != 0;
        let mut strictexpire = flags & MOUNT_FLAG_STRICTEXPIRE != 0;
        let entry0 = ap.entry();
        let mut timeout = master::get_exp_timeout(ap, entry0.maps().first().map(|m| &**m));
        let mut hosts = false;
        let root = cstr::c(root);
        let name = cstr::c(name);
        let too_long = || {
            error!(logopt, "mount_mount", "{}string too long for mountpoint", MODPREFIX);
            1
        };
        // The root offset of a multi-mount ends with '/'.
        let mountpoint: Vec<u8> = if root.last() == Some(&b'/') {
            if root.len() > PATH_MAX {
                return too_long();
            }
            root[..root.len() - 1].to_vec()
        } else if name.first() == Some(&b'/') {
            let p = if flags & MOUNT_FLAG_REMOUNT != 0 { name } else { root };
            if p.len() > PATH_MAX {
                return too_long();
            }
            p.to_vec()
        } else {
            let p = [root, b"/", name].concat();
            if p.len() > PATH_MAX {
                return too_long();
            }
            p
        };

        // The options left for the map, as C leaves them in its buffer: each
        // kept option with the ',' (or NUL) after it.
        let mut options: Option<Vec<u8>> = None;
        if let Some(co) = c_options {
            let co = cstr::c(co);
            let at = |i: usize| co.get(i).copied().unwrap_or(0);
            let mut np: Vec<u8> = vec![0; co.len() + 1];
            let mut w = 0;
            let mut comma = 0;
            while at(comma) != 0 {
                while at(comma) == b',' {
                    comma += 1;
                }
                let cp = comma;
                while at(comma) != 0 && at(comma) != b',' {
                    comma += 1;
                }
                let c = &co[cp.min(co.len())..];
                let is = |pat: &[u8], n: usize| strncmp_len(pat, c, n) == 0;
                if is(b"nobrowse", 8) || is(b"nobrowsable", 11) {
                    ghost = false;
                } else if is(b"nobind", 6) {
                    nobind = true;
                } else if is(b"browse", 6) || is(b"browsable", 9) {
                    ghost = true;
                } else if is(b"symlink", 7) {
                    symlnk = true;
                } else if is(b"strictexpire", 12) {
                    strictexpire = true;
                } else if is(b"hosts", 5) {
                    hosts = true;
                } else if is(b"timeout=", 8) {
                    if cstr::strchr(c, b'=').is_some()
                        && let Some(t) = scan_timeout(c)
                    {
                        timeout = t as i64;
                    }
                } else {
                    let n = comma - cp + 1;
                    for k in 0..n {
                        np[w + k] = at(cp + k);
                    }
                    w += n;
                }
            }
            options = Some(np);
        }
        debug!(
            logopt,
            "mount_mount",
            "{}mountpoint={} what={} options={}",
            MODPREFIX,
            mountpoint,
            what.unwrap_or(b"(null)"),
            options.as_ref().map(|o| cs(o, 0)).unwrap_or_else(|| b"(null)".to_vec())
        );

        let entry_age = entry0.lock().age;
        let entry = master::master_new_mapent(&mountpoint, entry_age);
        master::master_add_autofs_point_parent(&entry, logopt, nobind, ghost, true, Some(ap.clone()));
        master::hold_submount_entry(&entry);
        let nap = entry.ap();
        {
            let mut n = nap.lock();
            if symlnk {
                n.flags |= MOUNT_FLAG_SYMLINK;
            }
            if strictexpire {
                n.flags |= MOUNT_FLAG_STRICTEXPIRE;
            }
        }

        // A hosts map is asked for through the options.
        let info = if hosts { parse_map_type_info(b"hosts:") } else { parse_map_type_info(what.unwrap_or(b"")) };
        let Some(mut info) = info else {
            error!(logopt, "mount_mount", "{}failed to parse map info", MODPREFIX);
            master::release_submount_entry(&entry);
            return 1;
        };
        let mut argv: Argv = Vec::new();
        if !hosts {
            argv.push(info.map.clone());
        }
        if let Some(o) = options.as_mut() {
            // do { if (*p == ',') *p++ = 0; argv[argc++] = p; } while ((p = strchr(p, ',')));
            // the strings are read after all the cuts.
            let mut starts = Vec::new();
            let mut p = 0usize;
            loop {
                if o.get(p) == Some(&b',') {
                    o[p] = 0;
                    p += 1;
                }
                starts.push(p);
                match cstr::strchr(&o[p.min(o.len())..], b',') {
                    Some(k) => p += k,
                    None => break,
                }
            }
            for st in starts {
                argv.push(Some(cs(o, st)));
            }
        }

        // An amd "auto" mount often reuses its parent's map; and an amd
        // submount's map gets its format (and type) from the parent's.
        let mut source = None;
        let pmaps = entry0.maps();
        if let Some(s) = pmaps.first()
            && s.lock().flags & MAP_FLAG_FORMAT_AMD != 0
        {
            if info.format.is_none() {
                info.format = Some(b"amd".to_vec());
                if info.ty.is_none() && s.ty().is_some() {
                    info.ty = s.ty();
                }
            }
            if let Some(found) =
                master::master_get_map_source(&entry0, info.ty.as_deref(), info.format.as_deref(), &argv)
            {
                let i = pmaps.iter().position(|m| Arc::ptr_eq(m, &found)).unwrap_or(0);
                entry.lock().maps = pmaps[i..].to_vec();
                source = Some(found);
            }
        }
        let source = match source {
            Some(s) => s,
            None => master::master_add_map_source(
                &entry,
                info.ty.as_deref(),
                info.format.as_deref(),
                sys::monotonic_time(),
                &argv,
            ),
        };
        master::set_exp_timeout(&nap, None, timeout);
        nap.lock().exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;

        if source.lock().flags & MAP_FLAG_FORMAT_AMD != 0
            && let Some((pref, cache_opts)) = mounts::mnts_take_amd_pref(&entry.path)
        {
            let mut n = nap.lock();
            if pref.is_some() {
                n.pref = pref;
            }
            if cache_opts & AMD_CACHE_OPTION_ALL != 0 {
                n.flags |= MOUNT_FLAG_AMD_CACHE_ALL;
            }
        }

        let suc = Arc::new(StartupCond::default());
        suc.mutex.lock();
        if !mounts::mnts_add_submount(&nap) {
            crit!(logopt, "mount_mount", "{}failed to allocate mount {}", MODPREFIX, mountpoint);
            suc.mutex.unlock();
            master::master_free_map_source(&source);
            master::release_submount_entry(&entry);
            return 1;
        }
        let (nap2, suc2) = (nap.clone(), suc.clone());
        let h = std::thread::Builder::new()
            .name("handle_mounts".into())
            .spawn(move || crate::daemon::automount::handle_mounts(nap2, suc2));
        let h = match h {
            Ok(h) => h,
            Err(_) => {
                crit!(logopt, "mount_mount", "{}failed to create mount handler thread for {}", MODPREFIX, mountpoint);
                suc.mutex.unlock();
                mounts::mnts_remove_submount(&nap.path());
                master::master_free_map_source(&source);
                master::release_submount_entry(&entry);
                return 1;
            }
        };
        while !suc.done.load(Ordering::SeqCst) {
            suc.cond.wait(&suc.mutex);
        }
        suc.mutex.unlock();
        if suc.status.load(Ordering::SeqCst) != 0 {
            crit!(logopt, "mount_mount", "{}failed to create submount for {}", MODPREFIX, mountpoint);
            mounts::mnts_remove_submount(&nap.path());
            master::master_free_map_source(&source);
            let _ = h.join();
            master::release_submount_entry(&entry);
            return 1;
        }
        use std::os::unix::thread::JoinHandleExt;
        nap.lock().thid = h.as_pthread_t();
        master::add_join(nap.id, h);
        0
    }

    fn done(self: Box<Self>) -> i32 {
        0
    }
}
