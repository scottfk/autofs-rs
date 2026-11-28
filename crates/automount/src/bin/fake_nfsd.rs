//! Test server for the root tier (not installed): fake rpcbind, NFS and mount
//! daemons on the addresses of a configuration file, one line each:
//!
//!     ADDR PROTO VERSIONS [delay=MS] [norpcbind] [exports=DIR@HOST+HOST,DIR@...]
//!          [ypserv=DIR] [ypbind=DOMAIN@SERVER,...] [ypbindvers=2,3]
//!
//! `PROTO` is `tcp` or `udp`, `VERSIONS` the NFS versions answered on it
//! (`3,4`; empty with `-`). rpcbind (port 111) answers `PMAPPROC_GETPORT` and
//! `RPCBPROC_GETADDR` for those (NFS on 2049, mountd on 20048), NFS answers
//! `NULL` (`PROG_MISMATCH` for other versions) after the delay, and mountd
//! answers `MOUNTPROC_EXPORT` with the exports. When every socket is up it
//! writes its pid to `READY`, the second argument.
//!
//! `ypserv=DIR` adds a ypserv (on 834) serving `DIR/DOMAIN/MAP` files (DIR
//! relative to `$FAKE_NFSD_DIR`), each line a key, a space and the value:
//! `YPPROC_MATCH` and `YPPROC_ALL`, with `YP_NODOM`, `YP_NOMAP` and
//! `YP_NOKEY` for what isn't there. `ypbind=` adds a ypbind (TCP, on 835)
//! that binds each domain to its server (`YPBINDPROC_DOMAIN`, versions
//! `ypbindvers`, default 2 and 3); other domains get `YPBIND_FAIL_VAL`.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

const PMAP_PROG: u32 = 100000;
const NFS_PROG: u32 = 100003;
const MOUNT_PROG: u32 = 100005;
const NFS_PORT: u16 = 2049;
const MOUNT_PORT: u16 = 20048;
const YP_PROG: u32 = 100004;
const YPBIND_PROG: u32 = 100007;
const YP_PORT: u16 = 834;
const YPBIND_PORT: u16 = 835;

#[derive(Debug, Clone, Default)]
struct Svc {
    /// Versions per protocol (6 TCP, 17 UDP).
    vers: HashMap<u32, Vec<u32>>,
    delay: u64,
    norpcbind: bool,
    exports: Vec<(String, Vec<String>)>,
    ypserv: Option<std::path::PathBuf>,
    ypbind: Vec<(String, String)>,
    ypbindvers: Vec<u32>,
}

fn parse(conf: &str) -> HashMap<IpAddr, Svc> {
    let mut out: HashMap<IpAddr, Svc> = HashMap::new();
    for line in conf.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.len() < 3 || f[0].starts_with('#') {
            continue;
        }
        let addr: IpAddr = f[0].parse().expect("address");
        let proto = if f[1] == "tcp" { 6 } else { 17 };
        let vers: Vec<u32> =
            if f[2] == "-" { Vec::new() } else { f[2].split(',').map(|v| v.parse().unwrap()).collect() };
        let s = out.entry(addr).or_default();
        s.vers.insert(proto, vers);
        for o in &f[3..] {
            if let Some(d) = o.strip_prefix("delay=") {
                s.delay = d.parse().unwrap();
            } else if *o == "norpcbind" {
                s.norpcbind = true;
            } else if let Some(d) = o.strip_prefix("ypserv=") {
                let base = std::env::var("FAKE_NFSD_DIR").unwrap_or_else(|_| ".".into());
                s.ypserv = Some(std::path::Path::new(&base).join(d));
            } else if let Some(b) = o.strip_prefix("ypbind=") {
                for e in b.split(',') {
                    let (d, srv) = e.split_once('@').expect("DOMAIN@SERVER");
                    s.ypbind.push((d.to_string(), srv.to_string()));
                }
            } else if let Some(v) = o.strip_prefix("ypbindvers=") {
                s.ypbindvers = v.split(',').map(|v| v.parse().unwrap()).collect();
            } else if let Some(e) = o.strip_prefix("exports=") {
                for ex in e.split(',') {
                    let (dir, hosts) = ex.split_once('@').unwrap_or((ex, ""));
                    let hosts = hosts.split('+').filter(|h| !h.is_empty()).map(String::from).collect();
                    s.exports.push((dir.to_string(), hosts));
                }
            }
        }
    }
    out
}

/// A decoded call: xid, prog, vers, proc, and the arguments.
struct Call<'a> {
    xid: u32,
    prog: u32,
    vers: u32,
    proc_: u32,
    args: &'a [u8],
}

fn word(b: &[u8], i: usize) -> Option<u32> {
    b.get(i..i + 4).map(|w| u32::from_be_bytes(w.try_into().unwrap()))
}

fn decode(b: &[u8]) -> Option<Call<'_>> {
    let xid = word(b, 0)?;
    if word(b, 4)? != 0 || word(b, 8)? != 2 {
        return None;
    }
    let (prog, vers, proc_) = (word(b, 12)?, word(b, 16)?, word(b, 20)?);
    let mut i = 24;
    for _ in 0..2 {
        let len = word(b, i + 4)? as usize;
        i += 8 + len.div_ceil(4) * 4;
    }
    Some(Call { xid, prog, vers, proc_, args: b.get(i..)? })
}

fn put(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn put_str(out: &mut Vec<u8>, s: &[u8]) {
    put(out, s.len() as u32);
    out.extend_from_slice(s);
    out.resize(out.len() + (4 - s.len() % 4) % 4, 0);
}

fn get_str(b: &[u8], i: &mut usize) -> Option<Vec<u8>> {
    let len = word(b, *i)? as usize;
    let s = b.get(*i + 4..*i + 4 + len)?.to_vec();
    *i += 4 + len.div_ceil(4) * 4;
    Some(s)
}

/// The reply header with an accept status.
fn reply(xid: u32, stat: u32) -> Vec<u8> {
    let mut r = Vec::new();
    for v in [xid, 1, 0, 0, 0, stat] {
        put(&mut r, v);
    }
    r
}

/// The answer to a call on `port` of `addr`, for `proto`.
fn answer(svc: &Svc, addr: IpAddr, port: u16, proto: u32, b: &[u8]) -> Option<Vec<u8>> {
    let c = decode(b)?;
    let nfs_vers = |p: u32| svc.vers.get(&p).cloned().unwrap_or_default();
    match (port, c.prog) {
        (111, PMAP_PROG) => {
            let port_for = |prog: u32, vers: u32, prot: u32| -> u16 {
                match prog {
                    NFS_PROG if nfs_vers(prot).contains(&vers) => NFS_PORT,
                    MOUNT_PROG if svc.vers.contains_key(&prot) && (1..=3).contains(&vers) => MOUNT_PORT,
                    YP_PROG if svc.ypserv.is_some() && svc.vers.contains_key(&prot) && vers == 2 => YP_PORT,
                    YPBIND_PROG if !svc.ypbind.is_empty() && prot == 6 && ypbind_vers(svc).contains(&vers) => {
                        YPBIND_PORT
                    }
                    _ => 0,
                }
            };
            let mut r = reply(c.xid, 0);
            match (c.vers, c.proc_) {
                (_, 0) => {}
                (2, 3) => {
                    let (prog, vers, prot) = (word(c.args, 0)?, word(c.args, 4)?, word(c.args, 8)?);
                    put(&mut r, port_for(prog, vers, prot) as u32);
                }
                (3 | 4, 3) => {
                    let (prog, vers) = (word(c.args, 0)?, word(c.args, 4)?);
                    let mut i = 8;
                    let netid = get_str(c.args, &mut i)?;
                    let prot = if netid.starts_with(b"tcp") { 6 } else { 17 };
                    let p = port_for(prog, vers, prot);
                    if p == 0 {
                        put_str(&mut r, b"");
                    } else {
                        put_str(&mut r, format!("{}.{}.{}", addr, p >> 8, p & 0xff).as_bytes());
                    }
                }
                _ => return Some(reply(c.xid, 3)),
            }
            Some(r)
        }
        (NFS_PORT, NFS_PROG) => {
            let v = nfs_vers(proto);
            if svc.delay > 0 {
                std::thread::sleep(Duration::from_millis(svc.delay));
            }
            if !v.contains(&c.vers) {
                let mut r = reply(c.xid, 2);
                put(&mut r, v.iter().copied().min().unwrap_or(2));
                put(&mut r, v.iter().copied().max().unwrap_or(4));
                return Some(r);
            }
            if c.proc_ != 0 {
                return Some(reply(c.xid, 3));
            }
            Some(reply(c.xid, 0))
        }
        (MOUNT_PORT, MOUNT_PROG) => {
            if c.proc_ != 5 {
                return Some(reply(c.xid, if c.proc_ == 0 { 0 } else { 3 }));
            }
            // exports: list of (dir, groups) as optional data.
            let mut r = reply(c.xid, 0);
            for (dir, hosts) in &svc.exports {
                put(&mut r, 1);
                put_str(&mut r, dir.as_bytes());
                for h in hosts {
                    put(&mut r, 1);
                    put_str(&mut r, h.as_bytes());
                }
                put(&mut r, 0);
            }
            put(&mut r, 0);
            Some(r)
        }
        (YP_PORT, YP_PROG) => {
            let Some(dir) = &svc.ypserv else { return Some(reply(c.xid, 1)) };
            if c.vers != 2 {
                let mut r = reply(c.xid, 2);
                put(&mut r, 2);
                put(&mut r, 2);
                return Some(r);
            }
            let mut i = 0;
            match c.proc_ {
                0 => Some(reply(c.xid, 0)),
                3 => {
                    let (domain, map, key) =
                        (get_str(c.args, &mut i)?, get_str(c.args, &mut i)?, get_str(c.args, &mut i)?);
                    let mut r = reply(c.xid, 0);
                    match yp_map(dir, &domain, &map) {
                        Err(st) => {
                            put(&mut r, st as u32);
                            put_str(&mut r, b"");
                        }
                        Ok(ents) => match ents.iter().find(|(k, _)| *k == key) {
                            Some((_, v)) => {
                                put(&mut r, 1);
                                put_str(&mut r, v);
                            }
                            None => {
                                put(&mut r, -3i32 as u32);
                                put_str(&mut r, b"");
                            }
                        },
                    }
                    Some(r)
                }
                8 => {
                    let (domain, map) = (get_str(c.args, &mut i)?, get_str(c.args, &mut i)?);
                    let mut r = reply(c.xid, 0);
                    match yp_map(dir, &domain, &map) {
                        Err(st) => {
                            put(&mut r, 1);
                            put(&mut r, st as u32);
                            put_str(&mut r, b"");
                            put_str(&mut r, b"");
                        }
                        Ok(ents) => {
                            for (k, v) in ents {
                                put(&mut r, 1);
                                put(&mut r, 1);
                                put_str(&mut r, &v);
                                put_str(&mut r, &k);
                            }
                        }
                    }
                    put(&mut r, 0);
                    Some(r)
                }
                _ => Some(reply(c.xid, 3)),
            }
        }
        (YPBIND_PORT, YPBIND_PROG) => {
            let vers = ypbind_vers(svc);
            if !vers.contains(&c.vers) {
                let mut r = reply(c.xid, 2);
                put(&mut r, *vers.iter().min().unwrap());
                put(&mut r, *vers.iter().max().unwrap());
                return Some(r);
            }
            if c.proc_ == 0 {
                return Some(reply(c.xid, 0));
            }
            if c.proc_ != 1 {
                return Some(reply(c.xid, 3));
            }
            let mut i = 0;
            let domain = get_str(c.args, &mut i)?;
            let mut r = reply(c.xid, 0);
            match svc.ypbind.iter().find(|(d, _)| d.as_bytes() == domain.as_slice()) {
                None => {
                    put(&mut r, 2);
                    put(&mut r, 2);
                }
                Some((_, srv)) => {
                    put(&mut r, 1);
                    if c.vers == 3 {
                        // ypbind3_binding: no netconfig, no address, the name.
                        put(&mut r, 1);
                        put(&mut r, 0);
                        put(&mut r, 0);
                        put_str(&mut r, srv.as_bytes());
                        put(&mut r, 2);
                        put(&mut r, 2);
                    } else {
                        let a: std::net::Ipv4Addr = srv.parse().expect("a v2 binding needs an address");
                        r.extend_from_slice(&a.octets());
                        r.extend_from_slice(&YP_PORT.to_be_bytes());
                        r.extend_from_slice(&[0, 0]);
                    }
                }
            }
            Some(r)
        }
        _ => Some(reply(c.xid, 1)),
    }
}

/// The versions the fake ypbind answers.
fn ypbind_vers(svc: &Svc) -> Vec<u32> {
    if svc.ypbindvers.is_empty() { vec![2, 3] } else { svc.ypbindvers.clone() }
}

/// A map's entries, or the `ypstat` for a domain or map that isn't there.
/// A map's (key, value) entries.
type YpEntries = Vec<(Vec<u8>, Vec<u8>)>;

fn yp_map(dir: &std::path::Path, domain: &[u8], map: &[u8]) -> Result<YpEntries, i32> {
    use std::os::unix::ffi::OsStrExt;
    let d = dir.join(std::ffi::OsStr::from_bytes(domain));
    if domain.is_empty() || domain.contains(&b'/') || !d.is_dir() {
        return Err(-2);
    }
    if map.is_empty() || map.contains(&b'/') {
        return Err(-1);
    }
    let Ok(data) = std::fs::read(d.join(std::ffi::OsStr::from_bytes(map))) else { return Err(-1) };
    Ok(data
        .split(|&c| c == b'\n')
        .filter(|l| !l.is_empty())
        .map(|l| match l.iter().position(|&c| c == b' ') {
            Some(p) => (l[..p].to_vec(), l[p + 1..].to_vec()),
            None => (l.to_vec(), Vec::new()),
        })
        .collect())
}

fn serve_udp(sock: UdpSocket, svc: Arc<Svc>, addr: IpAddr, port: u16) {
    let mut buf = vec![0u8; 65536];
    loop {
        let Ok((n, from)) = sock.recv_from(&mut buf) else { continue };
        if let Some(r) = answer(&svc, addr, port, 17, &buf[..n]) {
            let _ = sock.send_to(&r, from);
        }
    }
}

fn serve_tcp_conn(mut s: TcpStream, svc: Arc<Svc>, addr: IpAddr, port: u16) {
    loop {
        let mut rec = Vec::new();
        loop {
            let mut h = [0u8; 4];
            if s.read_exact(&mut h).is_err() {
                return;
            }
            let h = u32::from_be_bytes(h);
            let mut frag = vec![0u8; (h & 0x7fff_ffff) as usize];
            if s.read_exact(&mut frag).is_err() {
                return;
            }
            rec.extend_from_slice(&frag);
            if h & 0x8000_0000 != 0 {
                break;
            }
        }
        if let Some(r) = answer(&svc, addr, port, 6, &rec) {
            let mut out = ((r.len() as u32) | 0x8000_0000).to_be_bytes().to_vec();
            out.extend_from_slice(&r);
            if s.write_all(&out).is_err() {
                return;
            }
        }
    }
}

fn serve_tcp(l: TcpListener, svc: Arc<Svc>, addr: IpAddr, port: u16) {
    for s in l.incoming().flatten() {
        let svc = svc.clone();
        std::thread::spawn(move || serve_tcp_conn(s, svc, addr, port));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let conf = std::fs::read_to_string(&args[1]).expect("configuration");
    let ready = &args[2];
    let mut threads = Vec::new();
    for (addr, svc) in parse(&conf) {
        let svc = Arc::new(svc);
        let mut ports = vec![NFS_PORT, MOUNT_PORT];
        if svc.ypserv.is_some() {
            ports.push(YP_PORT);
        }
        if !svc.norpcbind {
            ports.push(111);
        }
        for port in ports {
            let sa = SocketAddr::new(addr, port);
            if svc.vers.contains_key(&17) {
                let u = UdpSocket::bind(sa).expect("udp bind");
                let s = svc.clone();
                threads.push(std::thread::spawn(move || serve_udp(u, s, addr, port)));
            }
            if svc.vers.contains_key(&6) || (port == 111 && !svc.ypbind.is_empty()) {
                let t = TcpListener::bind(sa).expect("tcp bind");
                let s = svc.clone();
                threads.push(std::thread::spawn(move || serve_tcp(t, s, addr, port)));
            }
        }
    }
    for (addr, svc) in parse(&conf) {
        if svc.ypbind.is_empty() {
            continue;
        }
        let svc = Arc::new(svc);
        let t = TcpListener::bind(SocketAddr::new(addr, YPBIND_PORT)).expect("tcp bind");
        threads.push(std::thread::spawn(move || serve_tcp(t, svc, addr, YPBIND_PORT)));
    }
    std::fs::write(ready, format!("{}\n", std::process::id())).expect("ready file");
    for t in threads {
        let _ = t.join();
    }
}
