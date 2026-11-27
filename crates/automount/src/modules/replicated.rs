//! `modules/replicated.c`: an NFS location's host list (`host1,host2(w):/path
//! host3:/other`), each host's proximity, and, when there's a choice, the
//! probe that keeps the hosts answering the NFS version most of the closest
//! ones speak, cheapest first.

use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::libautofs::log::LOGOPT_ANY;
use crate::libautofs::parse_subs::{
    PROXIMITY_ERROR, PROXIMITY_LOCAL, PROXIMITY_NET, PROXIMITY_OTHER, PROXIMITY_SUBNET, PROXIMITY_UNSUPPORTED,
    get_proximity,
};
use crate::libautofs::rpc_subs::{
    self, ConnInfo, NFS_PORT, NFS_PROGRAM, NFS2_VERSION, NFS3_VERSION, NFS4_VERSION, PmapParms, RPC_CLOSE_DEFAULT,
};
use crate::sys;

use crate::daemon::master::{MOUNT_FLAG_RANDOM_SELECT, MOUNT_FLAG_USE_WEIGHT_ONLY};

pub const NFS2_SUPPORTED: u32 = 0x0010;
pub const NFS3_SUPPORTED: u32 = 0x0020;
pub const NFS4_SUPPORTED: u32 = 0x0040;
pub const NFS_VERS_DEFAULT: u32 = NFS3_SUPPORTED;
pub const NFS_VERS_MASK: u32 = NFS2_SUPPORTED | NFS3_SUPPORTED;
pub const NFS4_VERS_DEFAULT: u32 = NFS4_SUPPORTED;
pub const NFS4_VERS_MASK: u32 = NFS4_SUPPORTED;
pub const NFS2_REQUESTED: u32 = NFS2_SUPPORTED;
pub const NFS3_REQUESTED: u32 = NFS3_SUPPORTED;
pub const NFS4_REQUESTED: u32 = NFS4_SUPPORTED;
pub const NFS4_ONLY_REQUESTED: u32 = 0x0800;
pub const TCP_SUPPORTED: u32 = 0x0001;
pub const UDP_SUPPORTED: u32 = 0x0002;
pub const TCP_REQUESTED: u32 = TCP_SUPPORTED;
pub const UDP_REQUESTED: u32 = UDP_SUPPORTED;
pub const TCP6_REQUESTED: u32 = 0x0100;
pub const UDP6_REQUESTED: u32 = 0x0200;
pub const NFS_PROTO_DEFAULT: u32 = TCP_SUPPORTED | UDP_SUPPORTED;
pub const NFS_PROTO_MASK: u32 = TCP_SUPPORTED | UDP_SUPPORTED;
const NFS2_TCP_SUPPORTED: u32 = NFS2_SUPPORTED;
const NFS3_TCP_SUPPORTED: u32 = NFS3_SUPPORTED;
const NFS4_TCP_SUPPORTED: u32 = NFS4_SUPPORTED;
const NFS2_UDP_SUPPORTED: u32 = NFS2_SUPPORTED << 8;
const NFS3_UDP_SUPPORTED: u32 = NFS3_SUPPORTED << 8;
const NFS4_UDP_SUPPORTED: u32 = NFS4_SUPPORTED << 8;
const UDP_SELECTED_MASK: u32 = 0xFF00;
const RPC_TIMEOUT: i64 = 5;
/// `INET_ADDRSTRLEN`, `INET6_ADDRSTRLEN`: what C stores as a host's
/// `addr_len` (not the address's size).
const INET_ADDRSTRLEN: usize = 16;
const INET6_ADDRSTRLEN: usize = 46;

fn is_err(supported: u32) -> bool {
    supported & 0x8000 != 0
}

fn err(supported: u32) -> u32 {
    if is_err(supported) { (!supported).wrapping_add(1) } else { supported }
}

/// A `struct host`.
#[derive(Debug, Clone)]
pub struct Host {
    /// Identity, for C's pointer compares.
    id: usize,
    pub name: Option<Vec<u8>>,
    pub ent_num: i32,
    pub addr: Option<sys::SockAddr>,
    pub addr_len: usize,
    pub rr: u32,
    pub path: Option<Vec<u8>>,
    pub version: u32,
    pub options: u32,
    pub proximity: u32,
    pub weight: u32,
    pub cost: u64,
}

static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);

fn next_id() -> usize {
    NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

/// `new_host()`.
pub fn new_host(
    name: Option<&[u8]>,
    ent_num: i32,
    addr: Option<&sys::SockAddr>,
    addr_len: usize,
    proximity: u32,
    weight: u32,
    options: u32,
) -> Option<Host> {
    let (name, addr) = (name?, addr?);
    Some(Host {
        id: next_id(),
        name: Some(cstr::c(name).to_vec()),
        ent_num,
        addr: Some(addr.clone()),
        addr_len,
        rr: 0,
        path: None,
        version: 0,
        options,
        proximity,
        weight,
        cost: 0,
    })
}

/// `add_host()`: in proximity order, then (for a host with a cost) by cost.
fn add_host(list: &mut Vec<Host>, host: Host) {
    let mut i = 0;
    while i < list.len() && list[i].proximity < host.proximity {
        i += 1;
    }
    if host.cost != 0 {
        while i < list.len() && list[i].proximity == host.proximity && list[i].cost < host.cost {
            i += 1;
        }
    }
    list.insert(i, host);
}

/// `remove_host()`.
fn remove_host(list: &mut Vec<Host>, id: usize) -> Option<Host> {
    let i = list.iter().position(|h| h.id == id)?;
    Some(list.remove(i))
}

fn idx(list: &[Host], id: usize) -> Option<usize> {
    list.iter().position(|h| h.id == id)
}

fn addr_string(h: &Host) -> Vec<u8> {
    h.addr.as_ref().and_then(|a| rpc_subs::get_addr_string(a.raw())).unwrap_or_else(|| b"(null)".to_vec())
}

fn now_mono() -> libc::timespec {
    let mut t = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: t is a valid timespec.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) };
    t
}

/// `((float) random())/((float) RAND_MAX+1)`.
fn random_fraction() -> f64 {
    (sys::random() as f32 / (2147483647f32 + 1.0)) as f64
}

/// `get_portmap_client()`.
fn get_portmap_client(logopt: u32, pm_info: &mut ConnInfo, host: &Host, proto: i32) -> u32 {
    let status = rpc_subs::rpc_portmap_getclient(
        pm_info,
        host.name.as_deref(),
        host.addr.as_ref().map(|a| a.raw()),
        host.addr_len,
        proto,
        RPC_CLOSE_DEFAULT,
    ) as u32;
    if status == (-libc::EHOSTUNREACH) as u32 {
        debug!(logopt, "get_portmap_client", "host not reachable getting portmap client");
    } else if status != 0 {
        // QUIRK: C's "error 0x%d" has no argument; see QUIRKS.md.
        debug!(logopt, "get_portmap_client", "error 0x{} getting portmap client", status as i32);
    }
    status
}

/// `get_portmap_port()`.
fn get_portmap_port(
    logopt: u32,
    pm_info: &mut ConnInfo,
    parms: &mut PmapParms,
    vers: u32,
    version: u32,
    port: &mut u16,
) -> u32 {
    parms.vers = vers;
    let mut nfs_port = 0;
    let status = rpc_subs::rpc_portmap_getport(pm_info, parms, &mut nfs_port);
    if status == -libc::EHOSTUNREACH || status == -libc::ETIMEDOUT {
        debug!(logopt, "get_portmap_port", "host not reachable or timed out getting service port");
    } else if status < 0 && version & NFS_VERS_MASK == 0 {
        debug!(logopt, "get_portmap_port", "error 0x{} getting service port", status);
    }
    if status == 0 {
        *port = nfs_port;
    }
    status as u32
}

/// One version's client and ping in `get_nfs_info()`: `Err(())` to stop
/// probing (`goto done_ver`).
#[allow(clippy::too_many_arguments)]
fn probe_version(
    logopt: u32,
    rpc_info: &mut ConnInfo,
    vers: u32,
    label: &str,
    random_selection: bool,
    taken: &mut f64,
    count: &mut u32,
    supported: &mut u32,
    bit: u32,
    stop_on_timeout: bool,
) -> Result<(), ()> {
    let status = if rpc_info.proto == libc::IPPROTO_UDP {
        rpc_subs::rpc_udp_getclient(rpc_info, NFS_PROGRAM, vers)
    } else {
        rpc_subs::rpc_tcp_getclient(rpc_info, NFS_PROGRAM, vers)
    };
    if status == -libc::EHOSTUNREACH {
        debug!(logopt, "get_nfs_info", "host not reachable getting RPC client");
        *supported = status as u32;
        return Err(());
    } else if status == 0 {
        let start = now_mono();
        let status = rpc_subs::rpc_ping_proto(rpc_info);
        let end = now_mono();
        if status == -libc::ETIMEDOUT {
            debug!(logopt, "get_nfs_info", "host NFS ping timed out");
            *supported = status as u32;
            if stop_on_timeout {
                return Err(());
            }
        } else if status > 0 {
            let reply = if random_selection {
                let r = random_fraction();
                debug!(logopt, "get_nfs_info", "nfs {} random selection time: {}", label, format!("{r:.6}"));
                r
            } else {
                let r = rpc_subs::monotonic_elapsed(start, end);
                debug!(logopt, "get_nfs_info", "nfs {} rpc ping time: {}", label, format!("{r:.6}"));
                r
            };
            *taken += reply;
            *count += 1;
            if bit == NFS4_SUPPORTED {
                *supported = NFS4_SUPPORTED;
            } else {
                *supported |= bit;
            }
        }
    }
    Ok(())
}

/// `get_nfs_info()`: the versions the host answers over `proto`, and its
/// cost (the average ping time).
fn get_nfs_info(
    logopt: u32,
    host: &mut Host,
    pm_info: &mut ConnInfo,
    rpc_info: &mut ConnInfo,
    proto: i32,
    version: u32,
    mut port: i32,
) -> u32 {
    let random_selection = host.options & MOUNT_FLAG_RANDOM_SELECT != 0;
    let use_weight_only = host.options & MOUNT_FLAG_USE_WEIGHT_ONLY != 0;
    let mut supported: u32 = 0;
    let mut taken = 0f64;
    let mut count = 0u32;
    let name = host.name.clone().unwrap_or_default();
    if host.addr.is_some() {
        debug!(
            logopt,
            "get_nfs_info",
            "called with host {}({}) proto {} version 0x{}",
            name,
            addr_string(host),
            proto,
            format!("{version:x}")
        );
    } else {
        debug!(logopt, "get_nfs_info", "called for host {} proto {} version 0x{}", name, proto, format!("{version:x}"));
    }
    rpc_info.proto = proto;
    if port < 0 {
        if version & NFS4_REQUESTED != 0 && version & NFS4_ONLY_REQUESTED != 0 {
            rpc_info.port = NFS_PORT;
        } else {
            port = 0;
        }
    } else if port > 0 {
        rpc_info.port = port as u16;
    }
    let mut parms = PmapParms { prog: NFS_PROGRAM, prot: proto as u32, ..PmapParms::default() };

    'done: {
        let mut v3 = version & NFS4_REQUESTED == 0;
        if !v3 {
            if port == 0 {
                let status = get_portmap_client(logopt, pm_info, host, proto);
                if status != 0 {
                    if status == (-libc::EHOSTUNREACH) as u32 {
                        supported = status;
                    }
                    break 'done;
                }
                let status = get_portmap_port(logopt, pm_info, &mut parms, NFS4_VERSION, version, &mut rpc_info.port);
                if status != 0 {
                    if status == (-libc::EHOSTUNREACH) as u32 || status == (-libc::ETIMEDOUT) as u32 {
                        supported = status;
                    }
                    if (status as i32) < 0 && version & NFS_VERS_MASK != 0 {
                        // MOUNT_NFS_DEFAULT_PROTOCOL=4
                        v3 = true;
                    } else {
                        break 'done;
                    }
                }
            }
            if !v3 {
                if probe_version(
                    logopt,
                    rpc_info,
                    NFS4_VERSION,
                    "v4",
                    random_selection,
                    &mut taken,
                    &mut count,
                    &mut supported,
                    NFS4_SUPPORTED,
                    true,
                )
                .is_err()
                {
                    break 'done;
                }
                if version & NFS_VERS_MASK == 0 {
                    break 'done;
                }
            }
        }
        // v3_ver:
        if version & NFS3_REQUESTED != 0 {
            if port == 0 && pm_info.client.is_none() {
                let status = get_portmap_client(logopt, pm_info, host, proto);
                if status != 0 {
                    if status == (-libc::EHOSTUNREACH) as u32 {
                        supported = status;
                    }
                    break 'done;
                }
            }
            if port == 0 {
                let status = get_portmap_port(logopt, pm_info, &mut parms, NFS3_VERSION, version, &mut rpc_info.port);
                if status != 0 {
                    if status == (-libc::EHOSTUNREACH) as u32 || status == (-libc::ETIMEDOUT) as u32 {
                        supported = status;
                    }
                    break 'done;
                }
            }
            if probe_version(
                logopt,
                rpc_info,
                NFS3_VERSION,
                "v3",
                random_selection,
                &mut taken,
                &mut count,
                &mut supported,
                NFS3_SUPPORTED,
                true,
            )
            .is_err()
            {
                break 'done;
            }
        }
        // v2_ver:
        if version & NFS2_REQUESTED == 0 {
            break 'done;
        }
        if port == 0 && pm_info.client.is_none() {
            let status = get_portmap_client(logopt, pm_info, host, proto);
            if status != 0 {
                if status == (-libc::EHOSTUNREACH) as u32 {
                    supported = status;
                }
                break 'done;
            }
        }
        if port == 0 {
            let status = get_portmap_port(logopt, pm_info, &mut parms, NFS2_VERSION, version, &mut rpc_info.port);
            if status != 0 {
                if status == (-libc::EHOSTUNREACH) as u32 || status == (-libc::ETIMEDOUT) as u32 {
                    supported = status;
                }
                break 'done;
            }
        }
        let _ = probe_version(
            logopt,
            rpc_info,
            NFS2_VERSION,
            "v2",
            random_selection,
            &mut taken,
            &mut count,
            &mut supported,
            NFS2_SUPPORTED,
            false,
        );
    }
    // done_ver:
    if rpc_info.proto == libc::IPPROTO_UDP {
        rpc_subs::rpc_destroy_udp_client(rpc_info);
        rpc_subs::rpc_destroy_udp_client(pm_info);
    } else {
        rpc_subs::rpc_destroy_tcp_client(rpc_info);
        rpc_subs::rpc_destroy_tcp_client(pm_info);
    }
    if count != 0 {
        // The average response time to 7 significant places, as an integer.
        host.cost = if use_weight_only { 1 } else { ((taken * 1_000_000.0) / count as f64) as u64 };
        // Allow for user bias.
        if host.weight != 0 {
            host.cost = host.cost.wrapping_mul(host.weight as u64 + 1);
        }
        debug!(logopt, "get_nfs_info", "host {} cost {} weight {}", name, host.cost as i64, host.weight as i32);
    }
    supported
}

/// `check_address_proto()`.
fn check_address_proto(logopt: u32, host: &Host, version: u32) -> bool {
    let ipv6_requested = version & (TCP6_REQUESTED | UDP6_REQUESTED) != 0;
    let ret = !(ipv6_requested && host.addr_len == INET_ADDRSTRLEN);
    if !ret {
        debug!(logopt, "check_address_proto", "requested protocol does not match address");
    }
    ret
}

fn new_info(host: &Host) -> (ConnInfo, ConnInfo) {
    let mut timeout = RPC_TIMEOUT;
    if host.proximity == PROXIMITY_NET {
        timeout = RPC_TIMEOUT * 2;
    } else if host.proximity == PROXIMITY_OTHER {
        timeout = RPC_TIMEOUT * 8;
    }
    let rpc_info = ConnInfo {
        host: host.name.clone(),
        addr: host.addr.as_ref().map(|a| a.raw().to_vec()),
        addr_len: host.addr_len,
        program: NFS_PROGRAM,
        timeout: tirpc::clnt::Timeval::secs(timeout),
        close_option: RPC_CLOSE_DEFAULT,
        ..ConnInfo::default()
    };
    (ConnInfo::default(), rpc_info)
}

/// `get_vers_and_cost()`.
fn get_vers_and_cost(logopt: u32, host: &mut Host, version: u32, port: i32) -> bool {
    if !check_address_proto(logopt, host, version) {
        return false;
    }
    let (mut pm_info, mut rpc_info) = new_info(host);
    let vers = (NFS_VERS_MASK | NFS4_VERS_MASK | NFS4_ONLY_REQUESTED) & version;
    let mut ret = false;
    if version & TCP_REQUESTED != 0 {
        let supported = get_nfs_info(logopt, host, &mut pm_info, &mut rpc_info, libc::IPPROTO_TCP, vers, port);
        if is_err(supported) {
            let e = err(supported) as i32;
            if e == libc::EHOSTUNREACH || e == libc::ETIMEDOUT {
                return ret;
            }
        } else if supported != 0 {
            ret = true;
            host.version |= supported;
        }
    }
    if version & UDP_REQUESTED != 0 {
        let supported = get_nfs_info(logopt, host, &mut pm_info, &mut rpc_info, libc::IPPROTO_UDP, vers, port);
        if is_err(supported) {
            if !ret && err(supported) as i32 == libc::ETIMEDOUT {
                return ret;
            }
        } else if supported != 0 {
            ret = true;
            host.version |= supported << 8;
        }
    }
    ret
}

/// `get_supported_ver_and_cost()`: whether the host answers the selected
/// version, and its cost.
fn get_supported_ver_and_cost(logopt: u32, host: &mut Host, version: u32, port: i32) -> bool {
    let random_selection = host.options & MOUNT_FLAG_RANDOM_SELECT != 0;
    let use_weight_only = host.options & MOUNT_FLAG_USE_WEIGHT_ONLY != 0;
    let name = host.name.clone().unwrap_or_default();
    if host.addr.is_some() {
        debug!(
            logopt,
            "get_supported_ver_and_cost",
            "called with host {}({}) version 0x{}",
            name,
            addr_string(host),
            format!("{version:x}")
        );
    } else {
        debug!(logopt, "get_supported_ver_and_cost", "called with host {} version 0x{}", name, format!("{version:x}"));
    }
    if !check_address_proto(logopt, host, version) {
        return false;
    }
    let (mut pm_info, mut rpc_info) = new_info(host);
    let mut version = version;
    let proto = if version & UDP_SELECTED_MASK != 0 {
        version >>= 8;
        libc::IPPROTO_UDP
    } else {
        libc::IPPROTO_TCP
    };
    let vers = match version {
        NFS2_SUPPORTED => NFS2_VERSION,
        NFS3_SUPPORTED => NFS3_VERSION,
        NFS4_SUPPORTED => NFS4_VERSION,
        _ => {
            crit!(logopt, "get_supported_ver_and_cost", "called with invalid version: 0x{}\n", format!("{version:x}"));
            return false;
        }
    };
    rpc_info.proto = proto;
    let mut status = 0;
    let mut taken = 0f64;
    'done: {
        if port > 0 {
            rpc_info.port = port as u16;
        } else if vers & NFS4_VERSION != 0 && port < 0 {
            rpc_info.port = NFS_PORT;
        } else {
            let ret = rpc_subs::rpc_portmap_getclient(
                &mut pm_info,
                host.name.as_deref(),
                host.addr.as_ref().map(|a| a.raw()),
                host.addr_len,
                proto,
                RPC_CLOSE_DEFAULT,
            );
            if ret != 0 {
                debug!(logopt, "get_supported_ver_and_cost", "failed to get portmap client");
                return false;
            }
            let parms = PmapParms { prog: NFS_PROGRAM, prot: rpc_info.proto as u32, vers, port: 0 };
            let ret = rpc_subs::rpc_portmap_getport(&mut pm_info, &parms, &mut rpc_info.port);
            if ret < 0 {
                debug!(logopt, "get_supported_ver_and_cost", "failed to get service port");
                break 'done;
            }
        }
        status = if rpc_info.proto == libc::IPPROTO_UDP {
            rpc_subs::rpc_udp_getclient(&mut rpc_info, NFS_PROGRAM, vers)
        } else {
            rpc_subs::rpc_tcp_getclient(&mut rpc_info, NFS_PROGRAM, vers)
        };
        if status == -libc::EHOSTUNREACH {
            status = 0;
            debug!(logopt, "get_supported_ver_and_cost", "host not reachable getting RPC client");
            break 'done;
        } else if status == 0 {
            let start = now_mono();
            status = rpc_subs::rpc_ping_proto(&mut rpc_info);
            let end = now_mono();
            if status > 0 {
                if random_selection {
                    taken = random_fraction();
                    debug!(logopt, "get_supported_ver_and_cost", "random selection time {}", format!("{taken:.6}"));
                } else {
                    taken = rpc_subs::monotonic_elapsed(start, end);
                    debug!(logopt, "get_supported_ver_and_cost", "rpc ping time {}", format!("{taken:.6}"));
                }
            }
        }
    }
    if rpc_info.proto == libc::IPPROTO_UDP {
        rpc_subs::rpc_destroy_udp_client(&mut rpc_info);
        rpc_subs::rpc_destroy_udp_client(&mut pm_info);
    } else {
        rpc_subs::rpc_destroy_tcp_client(&mut rpc_info);
        rpc_subs::rpc_destroy_tcp_client(&mut pm_info);
    }
    if status != 0 {
        // The response time to 7 significant places, as an integer.
        host.cost = if use_weight_only { 1 } else { (taken * 1_000_000.0) as u64 };
        if host.weight != 0 {
            host.cost = host.cost.wrapping_mul(host.weight as u64 + 1);
        }
        debug!(logopt, "get_supported_ver_and_cost", "cost {} weight {}", host.cost as i64, host.weight as i32);
        return true;
    }
    false
}

/// `linux_version_code()` (lib/mounts.c).
fn linux_version_code() -> u32 {
    let rel = sys::uname_release();
    if rel.is_empty() {
        return 0;
    }
    let mut it = rel.split(|&c| c == b'.').filter(|s| !s.is_empty());
    let atoi = |s: &[u8]| crate::libautofs::cstr::atoi(s) as u32;
    let Some(p) = it.next().map(atoi) else { return 0 };
    let Some(q) = it.next().map(atoi) else { return p << 16 };
    let Some(r) = it.next().map(atoi) else { return (p << 16) + (q << 8) };
    (p << 16) + (q << 8) + r
}

/// `prune_host_list()`: probe the closest hosts, choose the NFS version most
/// of them answer, and keep the hosts (local ones and the rest) that answer
/// it, in proximity and cost order.
pub fn prune_host_list(logopt: u32, list: &mut Vec<Host>, vers: u32, port: i32) -> i32 {
    if list.is_empty() {
        return 0;
    }
    // The first entry after the local ones.
    let mut ti = list.iter().position(|h| h.proximity != PROXIMITY_LOCAL);
    // A list of local hosts only, or a single other host: no probe for the
    // common case. Unless mount.nfs passes text options to the kernel (then
    // probe singletons, unless MOUNT_WAIT says otherwise).
    let string_options =
        crate::daemon::automount::NFS_MOUNT_USES_STRING_OPTIONS.load(std::sync::atomic::Ordering::Relaxed) != 0;
    if string_options
        && defaults::defaults_get_mount_wait() == u32::MAX
        && linux_version_code() > (2 << 16) + (6 << 8) + 22
    {
        if ti.is_none() {
            return 1;
        }
    } else if ti.is_none_or(|i| i + 1 >= list.len()) {
        return 1;
    }
    let mut first = ti.map(|i| list[i].id);
    let mut proximity = list[ti.unwrap()].proximity;
    // Probe the hosts of the first proximity.
    while let Some(i) = ti {
        let next = list.get(i + 1).map(|h| h.id);
        if list[i].proximity != proximity {
            break;
        }
        if list[i].name.is_some() {
            let mut h = list[i].clone();
            let ok = get_vers_and_cost(logopt, &mut h, vers, port);
            list[i] = h;
            if !ok {
                if first == Some(list[i].id) {
                    first = next;
                    if let Some(n) = next {
                        proximity = list[idx(list, n).unwrap()].proximity;
                    }
                }
                let id = list[i].id;
                remove_host(list, id);
                ti = next.and_then(|n| idx(list, n));
                continue;
            }
        }
        ti = next.and_then(|n| idx(list, n));
    }
    // The probed hosts may all have gone, leaving only local ones.
    let Some(first_id) = first else { return 1 };
    let last = ti.map(|i| list[i].id);

    // The NFS version of the most closest servers.
    let (mut v4t, mut v3t, mut v2t, mut v4u, mut v3u, mut v2u) = (0u32, 0u32, 0u32, 0u32, 0u32, 0u32);
    let mut i = idx(list, first_id).unwrap();
    loop {
        let v = list[i].version;
        if v & NFS4_TCP_SUPPORTED != 0 {
            v4t += 1;
        }
        if v & NFS3_TCP_SUPPORTED != 0 {
            v3t += 1;
        }
        if v & NFS2_TCP_SUPPORTED != 0 {
            v2t += 1;
        }
        if v & NFS4_UDP_SUPPORTED != 0 {
            v4u += 1;
        }
        if v & NFS3_UDP_SUPPORTED != 0 {
            v3u += 1;
        }
        if v & NFS2_UDP_SUPPORTED != 0 {
            v2u += 1;
        }
        i += 1;
        if i >= list.len() || Some(list[i].id) == last {
            break;
        }
    }
    let mymax = |x: u32, y: u32| if x >= y { x } else { y };
    let mmax = |x: u32, y: u32, z: u32| if mymax(x, y) == x { mymax(x, z) } else { mymax(y, z) };
    let max_tcp = mmax(v4t, v3t, v2t);
    let max_udp = mmax(v4u, v3u, v2u);
    let max_count = mymax(max_tcp, max_udp);
    let mut selected_version = 0;
    for (n, v, what) in [
        (v4t, NFS4_TCP_SUPPORTED, "NFS4 over TCP"),
        (v3t, NFS3_TCP_SUPPORTED, "NFS3 over TCP"),
        (v2t, NFS2_TCP_SUPPORTED, "NFS2 over TCP"),
        (v4u, NFS4_UDP_SUPPORTED, "NFS4 over UDP"),
        (v3u, NFS3_UDP_SUPPORTED, "NFS3 over UDP"),
        (v2u, NFS2_UDP_SUPPORTED, "NFS2 over UDP"),
    ] {
        if max_count == n {
            selected_version = v;
            debug!(logopt, "prune_host_list", "selected subset of hosts that support {}", what);
            break;
        }
    }

    // The local hosts and those of the selected version go on a new list.
    let mut new: Vec<Host> = Vec::new();
    let mut i = 0;
    loop {
        if i >= list.len() {
            break;
        }
        let id = list[i].id;
        let next = list.get(i + 1).map(|h| h.id);
        if list[i].version & selected_version != 0 || list[i].proximity == PROXIMITY_LOCAL {
            let mut h = remove_host(list, id).unwrap();
            h.version = selected_version;
            add_host(&mut new, h);
        }
        match next {
            Some(n) if Some(n) != last => i = idx(list, n).unwrap(),
            _ => break,
        }
    }
    // The rest: those that answer the chosen version.
    let mut ti = last.and_then(|l| idx(list, l));
    let mut prev: Option<i32> = None;
    while let Some(i) = ti {
        let next = list.get(i + 1).map(|h| h.id);
        if list[i].name.is_none() {
            let id = list[i].id;
            let h = remove_host(list, id).unwrap();
            add_host(&mut new, h);
        } else if defaults::defaults_use_hostname_for_mounts() != 0 && prev == Some(list[i].ent_num) {
            // Mounting by name: probing one of its addresses is enough.
        } else {
            let mut h = list[i].clone();
            let ok = get_supported_ver_and_cost(logopt, &mut h, selected_version, port);
            list[i] = h;
            if ok {
                let id = list[i].id;
                let mut h = remove_host(list, id).unwrap();
                h.version = selected_version;
                prev = Some(h.ent_num);
                add_host(&mut new, h);
            }
        }
        ti = next.and_then(|n| idx(list, n));
    }
    *list = new;
    1
}

/// `add_new_host()`.
fn add_new_host(
    list: &mut Vec<Host>,
    host: &[u8],
    ent_num: i32,
    weight: u32,
    ai: &sys::AddrInfo,
    rr: u32,
    options: u32,
) -> bool {
    let mut prx = get_proximity(&ai.addr);
    // An address we can't use (IPv6 without support, say): carry on in the
    // hope of a usable one.
    if prx == PROXIMITY_UNSUPPORTED {
        return true;
    }
    // With weights deciding, or random selection, all but the local host
    // have the same proximity.
    if prx != PROXIMITY_LOCAL && options & (MOUNT_FLAG_USE_WEIGHT_ONLY | MOUNT_FLAG_RANDOM_SELECT) != 0 {
        prx = PROXIMITY_SUBNET;
    }
    if prx == PROXIMITY_ERROR {
        return false;
    }
    let addr_len = match ai.addr.family {
        libc::AF_INET => INET_ADDRSTRLEN,
        libc::AF_INET6 => INET6_ADDRSTRLEN,
        _ => return false,
    };
    let Some(mut new) = new_host(Some(host), ent_num, Some(&ai.addr), addr_len, prx, weight, options) else {
        return false;
    };
    new.rr = rr;
    add_host(list, new);
    true
}

/// `add_host_addrs()`: the host's addresses (numeric, else looked up).
fn add_host_addrs(list: &mut Vec<Host>, host: &[u8], ent_num: i32, weight: u32, options: u32) -> bool {
    let host = cstr::c(host);
    let mut name: &[u8] = host;
    if name.first() == Some(&b'[') && name.last() == Some(&b']') && name.len() >= 2 {
        name = &name[1..name.len() - 1];
    }
    if let Ok(ni) = sys::getaddrinfo(name, libc::AF_UNSPEC, libc::SOCK_DGRAM, libc::AI_NUMERICHOST | libc::AI_CANONNAME)
    {
        let mut ret = true;
        for a in &ni {
            ret = add_new_host(list, host, ent_num, weight, a, 0, options);
            if !ret {
                break;
            }
        }
        return ret;
    }
    let ni = match sys::getaddrinfo(name, libc::AF_UNSPEC, libc::SOCK_DGRAM, libc::AI_ADDRCONFIG | libc::AI_CANONNAME) {
        Ok(n) => n,
        Err(e) => {
            error!(LOGOPT_ANY, "add_host_addrs", "hostname lookup for {} failed: {}", name, sys::gai_strerror(e));
            // C then frees the name one byte into its copy when it was
            // bracketed (glibc aborts); see QUIRKS.md.
            return false;
        }
    };
    let (mut rr4, mut rr6) = (0, 0);
    for a in &ni {
        if a.addr.family == libc::AF_INET {
            // QUIRK: the network-order address against the host-order
            // INADDR_LOOPBACK, so 127.0.0.1 counts too.
            let s_addr = u32::from_ne_bytes(a.addr.addr[..4].try_into().unwrap());
            if s_addr != libc::INADDR_LOOPBACK {
                rr4 += 1;
            }
        } else if a.addr.family == libc::AF_INET6 {
            let b = &a.addr.addr;
            let loopback = b[..15].iter().all(|&x| x == 0) && b[15] == 1;
            let linklocal = b[0] == 0xfe && (b[1] & 0xc0) == 0x80;
            if !loopback && !linklocal {
                rr6 += 1;
            }
        }
    }
    let rr = if rr4 > 1 || rr6 > 1 { 1 } else { 0 };
    let mut ret = true;
    for a in &ni {
        ret = add_new_host(list, host, ent_num, weight, a, rr, options);
        if !ret {
            break;
        }
    }
    ret
}

/// `add_path()`: the path for the hosts that have none yet.
fn add_path(hosts: &mut [Host], path: &[u8]) {
    for h in hosts.iter_mut() {
        if h.path.is_none() {
            h.path = Some(cstr::c(path).to_vec());
        }
    }
}

/// `add_local_path()`: a local path (no host): always local, and NFS2/3.
fn add_local_path(hosts: &mut Vec<Host>, path: &[u8]) {
    let new = Host {
        id: next_id(),
        name: None,
        ent_num: 0,
        addr: None,
        addr_len: 0,
        rr: 0,
        path: Some(cstr::c(path).to_vec()),
        version: NFS_VERS_MASK,
        options: 0,
        proximity: PROXIMITY_LOCAL,
        weight: 0,
        cost: 0,
    };
    add_host(hosts, new);
}

/// `seek_delim()`: the next of `(, \t` (unescaped), else of `:/`.
fn seek_delim(s: &[u8], start: usize) -> Option<usize> {
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let mut d = None;
    let mut i = start;
    while at(i) != 0 {
        if matches!(at(i), b'(' | b',' | b' ' | b'\t' | b':') {
            d = Some(i);
            break;
        }
        i += 1;
    }
    if let Some(d) = d
        && at(d) != b':'
        && (d == start || at(d - 1) != b'\\')
    {
        return Some(d);
    }
    let mut p = start;
    while at(p) != 0 {
        if at(p) == b':' && at(p + 1) == b'/' {
            return Some(p);
        }
        p += 1;
    }
    None
}

/// `atoi()`.
fn atoi(s: &[u8]) -> i32 {
    crate::libautofs::cstr::atoi(s)
}

/// `parse_location()`: the hosts and paths of a location, done on a copy as
/// C cuts it up.
pub fn parse_location(logopt: u32, hosts: &mut Vec<Host>, list: Option<&[u8]>, options: u32) -> bool {
    let _ = logopt;
    let Some(list) = list else { return false };
    let mut s: Vec<u8> = cstr::c(list).to_vec();
    s.push(0);
    let at = |s: &[u8], i: usize| s.get(i).copied().unwrap_or(0);
    let mut empty = true;
    let mut ent_num = 1;
    let mut p: Option<usize> = Some(0);
    while let Some(mut pp) = p {
        if at(&s, pp) == 0 {
            break;
        }
        let mut next: Option<usize> = None;
        let mut weight = 0u32;
        while matches!(at(&s, pp), b' ' | b'\t' | b',') {
            pp += 1;
        }
        let Some(mut delim) = seek_delim(&s, pp) else {
            // Syntax error: no mount path.
            hosts.clear();
            return false;
        };
        if at(&s, delim) == b'(' {
            let w = delim + 1;
            s[delim] = 0;
            match s[w..].iter().position(|&c| c == b')' || c == 0).filter(|&k| s[w + k] == b')') {
                Some(k) => {
                    s[w + k] = 0;
                    weight = atoi(&s[w..]) as u32;
                    delim = w + k;
                }
                None => {
                    // Syntax error: mismatched brackets.
                    hosts.clear();
                    return false;
                }
            }
            delim += 1;
        }
        if at(&s, delim) == b':' {
            s[delim] = 0;
            let path = delim + 1;
            // There may be spaces in the path.
            let mut n = path;
            while at(&s, n) != 0 && !(at(&s, n) == b':' && at(&s, n + 1) == b'/') {
                n += 1;
            }
            // No spaces in host names, though.
            if at(&s, n) == b':' {
                while at(&s, n) != 0 && at(&s, n) != b' ' && at(&s, n) != b'\t' {
                    if n == 0 {
                        break;
                    }
                    n -= 1;
                }
                s[n] = 0;
                n += 1;
            }
            next = Some(n);
            if pp != delim {
                let host = cstr::c(&s[pp..]).to_vec();
                if !add_host_addrs(hosts, &host, ent_num, weight, options) && empty {
                    p = next;
                    continue;
                }
                let pth = cstr::c(&s[path..]).to_vec();
                add_path(hosts, &pth);
            } else {
                let pth = cstr::c(&s[path..]).to_vec();
                add_local_path(hosts, &pth);
            }
        } else if at(&s, delim) != 0 {
            s[delim] = 0;
            next = Some(delim + 1);
            let host = cstr::c(&s[pp..]).to_vec();
            if !add_host_addrs(hosts, &host, ent_num, weight, options) {
                p = next;
                continue;
            }
            empty = false;
        }
        ent_num += 1;
        p = next;
    }
    true
}

/// `dump_host_list()`.
pub fn dump_host_list(hosts: &[Host]) {
    for h in hosts {
        crate::libautofs::log::logmsg(&bfmt!(
            "name {} path {} version {} proximity {} weight {} cost {}",
            h.name.clone().unwrap_or_else(|| b"(null)".to_vec()),
            h.path.clone().unwrap_or_else(|| b"(null)".to_vec()),
            format!("{:x}", h.version),
            h.proximity,
            h.weight,
            h.cost as u32
        ));
    }
}

#[allow(dead_code)]
const _: u32 = NFS_PROTO_DEFAULT | NFS_VERS_DEFAULT | NFS4_VERS_DEFAULT | NFS_PROTO_MASK;
