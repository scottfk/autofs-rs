//! `lib/rpc_subs.c` (the libtirpc build): RPC clients made on sockets of our
//! own (bound to any port, not a reserved one), the rpcbind/portmap port
//! lookups, NULL pings of NFS servers, and the mount daemon's export list.
//! The RPC layer is rpcbind-rs's `tirpc` crate.

use std::sync::Mutex;

use tirpc::addr::Netbuf;
use tirpc::clnt::{
    Client, Control, Lib, RPC_CANTENCODEARGS, RPC_N2AXLATEFAILURE, RPC_PROGNOTREGISTERED, RPC_PROGUNAVAIL,
    RPC_PROGVERSMISMATCH, RPC_SUCCESS, RPC_TIMEDOUT, RPC_UNKNOWNADDR, RPC_UNKNOWNPROTO, Timeval,
};
use tirpc::rpcb_clnt::{PMAPPROC_GETPORT, PMAPVERS, RPCBPROC_GETADDR, RPCBPROG, RPCBVERS, RPCBVERS4};
use tirpc::rpcb_prot::{Rpcb, put_rpcb};
use tirpc::xdr::{self, XdrDecode, XdrEncode};

use crate::libautofs::cstr;
use crate::libautofs::log::LOGOPT_ANY;
use crate::sys;

pub const NFS_PROGRAM: u32 = 100003;
pub const NFS2_VERSION: u32 = 2;
pub const NFS3_VERSION: u32 = 3;
pub const NFS4_VERSION: u32 = 4;
pub const NFS_PORT: u16 = 2049;
const NFSPROC_NULL: u32 = 0;
const PMAPPORT: u16 = 111;

pub const RPC_PING_FAIL: i32 = 0x0000;
pub const RPC_PING_V2: i32 = NFS2_VERSION as i32;
pub const RPC_PING_V3: i32 = NFS3_VERSION as i32;
pub const RPC_PING_V4: i32 = NFS4_VERSION as i32;
pub const RPC_PING_UDP: i32 = 0x0100;
pub const RPC_PING_TCP: i32 = 0x0200;
pub const RPC_CLOSE_DEFAULT: u32 = 0x0000;
pub const RPC_CLOSE_NOLINGER: u32 = 0x0001;

const PMAP_TOUT_UDP: i64 = 3;
const PMAP_TOUT_TCP: i64 = 5;
const RPC_TOUT_UDP: i64 = PMAP_TOUT_UDP;
const RPC_TOUT_TCP: i64 = PMAP_TOUT_TCP;
/// `UDPMSGSIZE` and `RPCSMALLMSGSIZE` (rpc/clnt.h).
const UDPMSGSIZE: usize = 8800;
const RPCSMALLMSGSIZE: usize = 400;

// From include/replicated.h: the version and protocol bits.
use crate::modules::replicated::{NFS2_REQUESTED, NFS3_REQUESTED, NFS4_REQUESTED, TCP_REQUESTED, UDP_REQUESTED};

/// libtirpc's process-wide state (`rpc_createerr`, the netconfig database).
static LIB: Mutex<Option<Lib>> = Mutex::new(None);

fn with_lib<T>(f: impl FnOnce(&mut Lib) -> T) -> T {
    let mut g = LIB.lock().unwrap_or_else(|e| e.into_inner());
    f(g.get_or_insert_with(Lib::default))
}

/// A `struct conn_info`.
#[derive(Debug, Default)]
pub struct ConnInfo {
    pub host: Option<Vec<u8>>,
    /// The server's address (`struct sockaddr`), when known.
    pub addr: Option<Vec<u8>>,
    pub addr_len: usize,
    pub port: u16,
    pub program: u32,
    pub version: u32,
    pub proto: i32,
    pub send_sz: usize,
    pub recv_sz: usize,
    pub timeout: Timeval,
    pub close_option: u32,
    pub client: Option<Client>,
}

/// `struct pmap` (host order).
#[derive(Debug, Clone, Copy, Default)]
pub struct PmapParms {
    pub prog: u32,
    pub vers: u32,
    pub prot: u32,
    pub port: u32,
}

fn errno_neg() -> i32 {
    -sys::errno()
}

/// `connect_nb()`: a connect that gives up after the timeout's seconds.
fn connect_nb(fd: i32, addr: &[u8], tout: &Timeval) -> i32 {
    // SAFETY: plain fcntl() calls on a descriptor we own.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL, 0) };
    if flags < 0 {
        return errno_neg();
    }
    // SAFETY: as above.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return errno_neg();
    }
    let done = |ret: i32| {
        // SAFETY: as above.
        unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
        ret
    };
    // SAFETY: addr holds a socket address of its length.
    let r = unsafe { libc::connect(fd, addr.as_ptr() as *const libc::sockaddr, addr.len() as libc::socklen_t) };
    if r < 0 && sys::errno() != libc::EINPROGRESS {
        return done(errno_neg());
    }
    if r == 0 {
        return done(0);
    }
    let mut timeout = tout.sec as i32;
    if timeout != -1 {
        timeout = if timeout >= (i32::MAX - 1) / 1000 { i32::MAX - 1 } else { timeout * 1000 };
    }
    let mut pfd = [libc::pollfd { fd, events: libc::POLLOUT, revents: 0 }];
    // SAFETY: one valid pollfd.
    let r = unsafe { libc::poll(pfd.as_mut_ptr(), 1, timeout) };
    if r <= 0 {
        return done(if r == 0 { -libc::ETIMEDOUT } else { errno_neg() });
    }
    let mut ret: i32 = 0;
    if pfd[0].revents != 0 {
        let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
        // SAFETY: ret is an int of len bytes.
        let status = unsafe {
            libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_ERROR, &mut ret as *mut i32 as *mut libc::c_void, &mut len)
        };
        if status < 0 {
            let e = sys::errno();
            if pfd[0].revents & libc::POLLNVAL != 0 {
                logerr!("connect_nb", "149", "unexpected poll(2) error on connect: {}", sys::strerror(e));
            }
            return done(-e);
        }
        if ret != 0 {
            ret = -ret;
        }
    }
    done(ret)
}

/// The family of a raw socket address.
fn family_of(addr: &[u8]) -> i32 {
    if addr.len() < 2 {
        return libc::AF_UNSPEC;
    }
    u16::from_ne_bytes([addr[0], addr[1]]) as i32
}

/// `rpc_do_create_client()`: a datagram or (connected) stream client to
/// `addr` with `info`'s port. `fd` is made (and bound to any port) if it's -1.
fn rpc_do_create_client(addr: &mut Vec<u8>, info: &ConnInfo, fd: &mut i32) -> Result<Option<Client>, i32> {
    let ty = if info.proto == libc::IPPROTO_UDP { libc::SOCK_DGRAM } else { libc::SOCK_STREAM };
    let fam = family_of(addr);
    // The local address: any port. The remote one gets info's port.
    let (laddr, slen): (Vec<u8>, usize) = match fam {
        libc::AF_INET => {
            let n = std::mem::size_of::<libc::sockaddr_in>();
            if addr.len() < n {
                addr.resize(n, 0);
            }
            addr[2..4].copy_from_slice(&info.port.to_be_bytes());
            let mut l = vec![0u8; n];
            l[0..2].copy_from_slice(&(libc::AF_INET as u16).to_ne_bytes());
            (l, n)
        }
        libc::AF_INET6 => {
            let n = std::mem::size_of::<libc::sockaddr_in6>();
            if addr.len() < n {
                addr.resize(n, 0);
            }
            addr[2..4].copy_from_slice(&info.port.to_be_bytes());
            let mut l = vec![0u8; n];
            l[0..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            (l, n)
        }
        _ => return Err(-libc::EINVAL),
    };
    if info.client.is_none() && *fd == -1 {
        *fd = sys::open_sock(fam, ty, info.proto);
        if *fd < 0 {
            return Err(errno_neg());
        }
        // SAFETY: laddr is a socket address of slen bytes.
        if unsafe { libc::bind(*fd, laddr.as_ptr() as *const libc::sockaddr, slen as libc::socklen_t) } < 0 {
            return Err(errno_neg());
        }
    }
    let nb = Netbuf::from_bytes(&addr[..slen]);
    let clnt = if info.proto == libc::IPPROTO_UDP {
        with_lib(|lib| {
            tirpc::clnt::clnt_dg_create(lib, *fd, &nb, info.program, info.version, info.send_sz, info.recv_sz)
        })
    } else if info.proto == libc::IPPROTO_TCP {
        let r = connect_nb(*fd, &addr[..slen], &info.timeout);
        if r < 0 {
            return Err(r);
        }
        with_lib(|lib| {
            tirpc::clnt::clnt_vc_create(lib, *fd, &nb, info.program, info.version, info.send_sz, info.recv_sz)
        })
    } else {
        return Err(-libc::EINVAL);
    };
    let mut clnt = clnt;
    // Our timeout is in seconds.
    if let Some(c) = clnt.as_mut()
        && info.timeout.sec != 0
    {
        c.control(Control::SetTimeout(info.timeout));
    }
    Ok(clnt)
}

/// `create_client()`: a client to `info`'s address, or to each of the host's
/// addresses of the protocol in turn, reusing an old client's socket. As in
/// C, the status (0, -errno, or `getaddrinfo()`'s positive code) and the
/// client, which may be missing even when the status isn't negative.
fn create_client(info: &mut ConnInfo) -> (i32, Option<Client>) {
    let mut fd: i32 = -1;
    if let Some(mut old) = info.client.take() {
        fd = old.fd();
        old.control(Control::SetFdNclose);
        old.destroy();
    }
    let out_close = |fd: i32, ret: i32| {
        if fd != -1 {
            sys::close(fd);
        }
        (ret, None)
    };
    let mut client: Option<Client> = None;
    let mut done = false;
    if let Some(mut addr) = info.addr.clone() {
        let r = rpc_do_create_client(&mut addr, info, &mut fd);
        info.addr = Some(addr);
        match r {
            Ok(c) => {
                client = c;
                done = true;
            }
            Err(e) if e == -libc::EHOSTUNREACH => return out_close(fd, e),
            Err(e) if e == -libc::EINVAL => {
                error!(LOGOPT_ANY, "create_client", "connect() failed: {}", sys::strerror(-e));
                return out_close(fd, e);
            }
            Err(_) => {
                if fd != -1 {
                    sys::close(fd);
                    fd = -1;
                }
            }
        }
    }
    if !done {
        let socktype = if info.proto == libc::IPPROTO_UDP { libc::SOCK_DGRAM } else { libc::SOCK_STREAM };
        let host = info.host.clone().unwrap_or_default();
        let ai = match sys::getaddrinfo(&host, libc::AF_UNSPEC, socktype, libc::AI_ADDRCONFIG | libc::AI_CANONNAME) {
            Ok(a) => a,
            Err(e) => {
                error!(LOGOPT_ANY, "create_client", "hostname lookup for {} failed: {}", host, sys::gai_strerror(e));
                return out_close(fd, e);
            }
        };
        for h in ai {
            if h.protocol != info.proto {
                continue;
            }
            let mut a = h.addr.raw().to_vec();
            match rpc_do_create_client(&mut a, info, &mut fd) {
                Ok(c) => {
                    client = c;
                    break;
                }
                Err(e) if e == -libc::EHOSTUNREACH => return out_close(fd, e),
                Err(_) => {
                    if fd != -1 {
                        sys::close(fd);
                        fd = -1;
                    }
                }
            }
        }
    }
    let Some(mut client) = client else { return out_close(fd, -libc::ENOTCONN) };
    // Close the socket on destroy, as for the library's own sockets.
    client.control(Control::SetFdClose);
    (0, Some(client))
}

/// `rpc_udp_getclient()`.
pub fn rpc_udp_getclient(info: &mut ConnInfo, program: u32, version: u32) -> i32 {
    if info.client.is_none() {
        info.proto = libc::IPPROTO_UDP;
        info.timeout = Timeval::secs(RPC_TOUT_UDP);
        info.send_sz = UDPMSGSIZE;
        info.recv_sz = UDPMSGSIZE;
    }
    info.program = program;
    info.version = version;
    let (ret, client) = create_client(info);
    if ret < 0 {
        return ret;
    }
    info.client = client;
    0
}

/// `rpc_destroy_udp_client()`.
pub fn rpc_destroy_udp_client(info: &mut ConnInfo) {
    if let Some(c) = info.client.take() {
        c.destroy();
    }
}

/// `rpc_tcp_getclient()`.
pub fn rpc_tcp_getclient(info: &mut ConnInfo, program: u32, version: u32) -> i32 {
    if info.client.is_none() {
        info.proto = libc::IPPROTO_TCP;
        info.timeout = Timeval::secs(RPC_TOUT_TCP);
        info.send_sz = 0;
        info.recv_sz = 0;
    }
    info.program = program;
    info.version = version;
    let (ret, client) = create_client(info);
    if ret < 0 {
        return ret;
    }
    info.client = client;
    0
}

/// `SO_LINGER` off with a zero time: a reset rather than `TIME_WAIT`.
fn nolinger(fd: i32) {
    if fd >= 0 {
        let lin = libc::linger { l_onoff: 1, l_linger: 0 };
        // SAFETY: lin is a struct linger.
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_LINGER,
                &lin as *const libc::linger as *const libc::c_void,
                std::mem::size_of::<libc::linger>() as libc::socklen_t,
            )
        };
    }
}

/// `rpc_destroy_tcp_client()`.
pub fn rpc_destroy_tcp_client(info: &mut ConnInfo) {
    let Some(c) = info.client.take() else { return };
    if info.close_option == RPC_CLOSE_NOLINGER {
        nolinger(c.fd());
    }
    c.destroy();
}

/// `rpc_getrpcbyname()`: rpcbind's program number from `/etc/rpc`.
fn rpc_getrpcbyname(program: u32) -> u32 {
    static RPCB_MUTEX: Mutex<()> = Mutex::new(());
    let _g = RPCB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    for name in [&b"rpcbind"[..], b"portmap", b"portmapper", b"sunrpc"] {
        if let Some(n) = sys::getrpcbyname(name) {
            return n;
        }
    }
    program
}

/// `rpc_getrpcbport()`: rpcbind's port (network order) from `/etc/services`.
fn rpc_getrpcbport(proto: i32) -> u16 {
    static RPCB_MUTEX: Mutex<()> = Mutex::new(());
    let _g = RPCB_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(pname) = sys::getprotobynumber(proto) {
        for name in [&b"rpcbind"[..], b"portmapper", b"sunrpc"] {
            if let Some(p) = sys::getservbyname(name, &pname) {
                return p;
            }
        }
    }
    PMAPPORT.to_be()
}

/// `rpc_portmap_getclient()`: a client of the host's rpcbind.
pub fn rpc_portmap_getclient(
    info: &mut ConnInfo,
    host: Option<&[u8]>,
    addr: Option<&[u8]>,
    addr_len: usize,
    proto: i32,
    option: u32,
) -> i32 {
    info.host = host.map(|h| h.to_vec());
    info.addr = addr.map(|a| a.to_vec());
    info.addr_len = addr_len;
    info.program = rpc_getrpcbyname(RPCBPROG);
    info.port = u16::from_be(rpc_getrpcbport(proto));
    info.version = RPCBVERS;
    info.proto = proto;
    info.send_sz = RPCSMALLMSGSIZE;
    info.recv_sz = RPCSMALLMSGSIZE;
    info.timeout = Timeval::secs(if proto == libc::IPPROTO_TCP { PMAP_TOUT_TCP } else { PMAP_TOUT_UDP });
    info.close_option = option;
    info.client = None;
    let (ret, client) = create_client(info);
    if ret < 0 {
        return ret;
    }
    info.client = client;
    0
}

/// `rpc_get_netid()`: the netid for the family and protocol.
fn rpc_get_netid(family: i32, protocol: i32) -> Result<Option<Vec<u8>>, u32> {
    let fmly: &[u8] = match family {
        libc::AF_UNIX | libc::AF_INET => b"inet",
        libc::AF_INET6 => b"inet6",
        _ => return Err(RPC_UNKNOWNPROTO),
    };
    let Some(proto) = sys::getprotobynumber(protocol) else { return Err(RPC_UNKNOWNPROTO) };
    with_lib(|lib| {
        let mut found = None;
        if let Some(mut h) = lib.nc.setnetconfig() {
            while let Some(nc) = lib.nc.getnetconfig(&mut h) {
                if nc.protofmly != fmly || nc.proto != proto {
                    continue;
                }
                found = Some(nc.netid.clone());
                break;
            }
            lib.nc.endnetconfig(h);
        }
        Ok(found)
    })
}

/// `rpc_sockaddr2universal()`.
fn rpc_sockaddr2universal(addr: &[u8]) -> Option<Vec<u8>> {
    let fam = family_of(addr);
    let (s, port) = match fam {
        libc::AF_INET if addr.len() >= 8 => {
            let ip = std::net::Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]);
            (ip.to_string(), u16::from_be_bytes([addr[2], addr[3]]))
        }
        libc::AF_INET6 if addr.len() >= 24 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&addr[8..24]);
            (std::net::Ipv6Addr::from(b).to_string(), u16::from_be_bytes([addr[2], addr[3]]))
        }
        libc::AF_UNIX => return Some(cstr::c(&addr[2..]).to_vec()),
        _ => return None,
    };
    Some(format!("{}.{}.{}", s, port >> 8, port & 0xff).into_bytes())
}

/// `rpc_universal2port()`.
fn rpc_universal2port(uaddr: &[u8]) -> i32 {
    let s = cstr::c(uaddr);
    let parse = |p: &[u8]| -> Option<u64> {
        // strtoul(): leading blanks and a sign, then digits to the end.
        let t = std::str::from_utf8(p).ok()?;
        let t = t.trim_start();
        let t = t.strip_prefix('+').unwrap_or(t);
        if t.is_empty() || !t.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        t.parse::<u64>().ok()
    };
    let Some(i) = s.iter().rposition(|&c| c == b'.') else { return -1 };
    let Some(lo) = parse(&s[i + 1..]).filter(|v| *v <= 255) else { return -1 };
    let s2 = &s[..i];
    let Some(j) = s2.iter().rposition(|&c| c == b'.') else { return -1 };
    let Some(hi) = parse(&s2[j + 1..]).filter(|v| *v <= 255) else { return -1 };
    ((hi << 8) | lo) as i32
}

/// `rpc_rpcb_getport()`: `RPCBPROC_GETADDR`, version 4 then 3.
fn rpc_rpcb_getport(client: &mut Client, parms: &Option<Rpcb>, timeout: Timeval) -> (u32, u16) {
    for v in [RPCBVERS4, RPCBVERS] {
        client.control(Control::SetVers(v));
        let mut uaddr: Option<Vec<u8>> = None;
        let status = match parms {
            None => RPC_CANTENCODEARGS,
            Some(p) => client.call(
                RPCBPROC_GETADDR,
                &mut |x: &mut dyn XdrEncode| put_rpcb(x, p),
                &mut |x: &mut dyn XdrDecode| {
                    uaddr = xdr::get_string(x, u32::MAX);
                    uaddr.is_some()
                },
                timeout,
            ),
        };
        match status {
            RPC_SUCCESS => {
                let u = uaddr.unwrap_or_default();
                if u.is_empty() || u[0] == 0 {
                    return (RPC_PROGNOTREGISTERED, 0);
                }
                let p = rpc_universal2port(&u);
                if p == -1 {
                    return (RPC_N2AXLATEFAILURE, 0);
                }
                return (RPC_SUCCESS, p as u16);
            }
            RPC_PROGVERSMISMATCH => {
                if client.geterr().low() > RPCBVERS4 {
                    return (status, 0);
                }
            }
            RPC_PROGUNAVAIL | RPC_PROGNOTREGISTERED => {}
            _ => return (status, 0),
        }
    }
    (RPC_PROGNOTREGISTERED, 0)
}

/// `rpc_getport()`: rpcbind's `GETADDR`, then portmap's `GETPORT`.
fn rpc_getport(info: &ConnInfo, parms: &PmapParms, client: &mut Client) -> (u32, u16) {
    let paddr: Vec<u8> = match &info.addr {
        Some(a) => a.clone(),
        None => {
            let a = client.svc_addr();
            if a.len == 0 {
                return (RPC_UNKNOWNADDR, 0);
            }
            a.addr().to_vec()
        }
    };
    let netid = match rpc_get_netid(family_of(&paddr), info.proto) {
        Ok(n) => n,
        Err(st) => return (st, 0),
    };
    let Some(raddr) = rpc_sockaddr2universal(&paddr) else { return (RPC_UNKNOWNADDR, 0) };
    let rp = netid.map(|n| Rpcb { prog: parms.prog, vers: parms.vers, netid: n, addr: raddr, owner: Vec::new() });
    let (mut status, mut port) = rpc_rpcb_getport(client, &rp, info.timeout);
    if status == RPC_PROGNOTREGISTERED {
        // Last chance: version 2 has a procedure of its own.
        client.control(Control::SetVers(PMAPVERS));
        let mut p: u16 = 0;
        status = client.call(
            PMAPPROC_GETPORT,
            &mut |x: &mut dyn XdrEncode| {
                x.put_long(parms.prog) && x.put_long(parms.vers) && x.put_long(parms.prot) && x.put_long(parms.port)
            },
            &mut |x: &mut dyn XdrDecode| match x.get_long() {
                Some(v) => {
                    p = v as u16;
                    true
                }
                None => false,
            },
            info.timeout,
        );
        port = p;
    }
    (status, port)
}

/// `rpc_portmap_getport()`: 0 with the port, -ETIMEDOUT or -EIO.
pub fn rpc_portmap_getport(info: &mut ConnInfo, parms: &PmapParms, port: &mut u16) -> i32 {
    let proto = info.proto;
    let mut pmap_info = ConnInfo {
        proto,
        timeout: Timeval::secs(if proto == libc::IPPROTO_TCP { PMAP_TOUT_TCP } else { PMAP_TOUT_UDP }),
        ..ConnInfo::default()
    };
    let own = info.client.is_none();
    let mut client = match info.client.take() {
        Some(c) => c,
        None => {
            pmap_info.host = info.host.clone();
            pmap_info.addr = info.addr.clone();
            pmap_info.addr_len = info.addr_len;
            pmap_info.port = u16::from_be(rpc_getrpcbport(info.proto));
            pmap_info.program = rpc_getrpcbyname(RPCBPROG);
            pmap_info.version = RPCBVERS;
            pmap_info.proto = info.proto;
            pmap_info.send_sz = RPCSMALLMSGSIZE;
            pmap_info.recv_sz = RPCSMALLMSGSIZE;
            let (ret, c) = create_client(&mut pmap_info);
            if ret < 0 {
                return ret;
            }
            match c {
                Some(c) => c,
                // A NULL client: clnt_call() on it would crash C.
                None => return -libc::EIO,
            }
        }
    };
    let (status, p) = rpc_getport(&pmap_info, parms, &mut client);
    if own {
        // Only play with the close options if it went OK.
        if proto == libc::IPPROTO_TCP && status == RPC_SUCCESS && info.close_option == RPC_CLOSE_NOLINGER {
            nolinger(client.fd());
        }
        client.destroy();
    } else {
        info.client = Some(client);
    }
    if status == RPC_TIMEDOUT {
        return -libc::ETIMEDOUT;
    } else if status != RPC_SUCCESS {
        return -libc::EIO;
    }
    *port = p;
    0
}

/// `rpc_ping_proto()`: `NFSPROC_NULL`; 1 on an answer, -ETIMEDOUT or -EIO.
pub fn rpc_ping_proto(info: &mut ConnInfo) -> i32 {
    let proto = info.proto;
    let own = info.client.is_none();
    let mut client = match info.client.take() {
        Some(c) => c,
        None => {
            if info.proto == libc::IPPROTO_UDP {
                info.send_sz = UDPMSGSIZE;
                info.recv_sz = UDPMSGSIZE;
            }
            let (ret, c) = create_client(info);
            if ret < 0 {
                return ret;
            }
            match c {
                Some(c) => c,
                None => return -libc::EIO,
            }
        }
    };
    client.control(Control::SetTimeout(info.timeout));
    client.control(Control::SetRetryTimeout(info.timeout));
    let status = client.call(NFSPROC_NULL, &mut |_| true, &mut |_| true, info.timeout);
    if own {
        if proto == libc::IPPROTO_TCP && status == RPC_SUCCESS && info.close_option == RPC_CLOSE_NOLINGER {
            nolinger(client.fd());
        }
        client.destroy();
    } else {
        info.client = Some(client);
    }
    if status == RPC_TIMEDOUT {
        -libc::ETIMEDOUT
    } else if status != RPC_SUCCESS {
        -libc::EIO
    } else {
        1
    }
}

/// `__rpc_ping()`.
fn rpc_ping_one(host: &[u8], version: u32, proto: i32, port: i32, seconds: i64, micros: i64, option: u32) -> i32 {
    let mut info = ConnInfo {
        proto,
        host: Some(host.to_vec()),
        program: NFS_PROGRAM,
        version,
        timeout: Timeval { sec: seconds, usec: micros },
        close_option: option,
        ..ConnInfo::default()
    };
    if port > 0 {
        info.port = port as u16;
    } else {
        let parms = PmapParms { prog: NFS_PROGRAM, vers: version, prot: info.proto as u32, port: 0 };
        let mut p = 0;
        let status = rpc_portmap_getport(&mut info, &parms, &mut p);
        if status < 0 {
            return status;
        }
        info.port = p;
    }
    rpc_ping_proto(&mut info)
}

/// `rpc_ping()`: the first version and protocol asked for that answers.
pub fn rpc_ping(host: &[u8], port: i32, version: u32, seconds: i64, micros: i64, option: u32) -> i32 {
    let mut status = 0;
    let tries: [(u32, u32, u32, i32, i32); 4] = [
        (NFS2_REQUESTED, TCP_REQUESTED, NFS2_VERSION, libc::IPPROTO_TCP, RPC_PING_V2 | RPC_PING_TCP),
        (NFS2_REQUESTED, UDP_REQUESTED, NFS2_VERSION, libc::IPPROTO_UDP, RPC_PING_V2 | RPC_PING_UDP),
        (NFS3_REQUESTED, TCP_REQUESTED, NFS3_VERSION, libc::IPPROTO_TCP, RPC_PING_V3 | RPC_PING_TCP),
        (NFS3_REQUESTED, UDP_REQUESTED, NFS3_VERSION, libc::IPPROTO_UDP, RPC_PING_V3 | RPC_PING_UDP),
    ];
    for (v, p, nv, proto, ok) in tries {
        if version & v != 0 && version & p != 0 {
            status = rpc_ping_one(host, nv, proto, port, seconds, micros, option);
            if status > 0 {
                return ok;
            }
        }
    }
    // UDP isn't recommended for NFSv4: TCP only.
    if version & NFS4_REQUESTED != 0 {
        status = rpc_ping_one(host, NFS4_VERSION, libc::IPPROTO_TCP, port, seconds, micros, option);
        if status > 0 {
            return RPC_PING_V4 | RPC_PING_TCP;
        }
    }
    status
}

/// `monotonic_elapsed()`.
pub fn monotonic_elapsed(start: libc::timespec, end: libc::timespec) -> f64 {
    let t1 = start.tv_sec as f64 + (start.tv_nsec as f64 / (1000.0 * 1000.0 * 1000.0));
    let t2 = end.tv_sec as f64 + (end.tv_nsec as f64 / (1000.0 * 1000.0 * 1000.0));
    t2 - t1
}

/// `get_addr_string()`: the address part of a socket address as text.
pub fn get_addr_string(addr: &[u8]) -> Option<Vec<u8>> {
    match family_of(addr) {
        libc::AF_INET if addr.len() >= 8 => {
            Some(std::net::Ipv4Addr::new(addr[4], addr[5], addr[6], addr[7]).to_string().into_bytes())
        }
        libc::AF_INET6 if addr.len() >= 24 => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&addr[8..24]);
            Some(inet_ntop6(&b))
        }
        _ => None,
    }
}

/// `inet_ntop(AF_INET6, ...)` as glibc writes it (an IPv4-mapped address
/// ends in dotted quad, as std's `Display` agrees).
fn inet_ntop6(b: &[u8; 16]) -> Vec<u8> {
    std::net::Ipv6Addr::from(*b).to_string().into_bytes()
}
