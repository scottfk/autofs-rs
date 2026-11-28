//! The YP (NIS) client calls `lookup_yp` makes, as libnsl 2.0.1 (the one on
//! hydra, built on libtirpc) does them: `yp_get_default_domain()`,
//! `yp_match()`, `yp_all()`, `yperr_string()` and the binding behind them
//! (`do_ypcall.c`, `yp_xdr.c`). The RPC layer is the `tirpc` crate.
//!
//! Binding: a binding file (`/var/yp/binding/DOMAIN.3`, an XDR
//! `ypbind3_binding`, or `DOMAIN.2`, a raw `ypbind2_resp` after a 2-byte
//! port), else ypbind on localhost (`YPBINDPROC_DOMAIN`, version 3 and then
//! 2), gives a server name for a UDP client of ypserv. libnsl keeps a list of
//! bindings, but only `yp_bind()` adds to it and autofs doesn't call that, so
//! every call binds afresh and unbinds after, as here.

use std::sync::Mutex;

use tirpc::clnt::{Client, Lib, RPC_PROGVERSMISMATCH, RPC_SUCCESS, Timeval};
use tirpc::rpcb_prot::get_netbuf;
use tirpc::xdr::{self, XdrDecode, XdrEncode, XdrMem};

use crate::libautofs::cstr;
use crate::libautofs::rpc_subs::with_lib;
use crate::sys;

pub const YPERR_SUCCESS: i32 = 0;
pub const YPERR_BADARGS: i32 = 1;
pub const YPERR_RPC: i32 = 2;
pub const YPERR_DOMAIN: i32 = 3;
pub const YPERR_MAP: i32 = 4;
pub const YPERR_KEY: i32 = 5;
pub const YPERR_YPERR: i32 = 6;
pub const YPERR_RESRC: i32 = 7;
pub const YPERR_NOMORE: i32 = 8;
pub const YPERR_PMAP: i32 = 9;
pub const YPERR_YPBIND: i32 = 10;
pub const YPERR_YPSERV: i32 = 11;
pub const YPERR_NODOM: i32 = 12;
pub const YPERR_BADDB: i32 = 13;
pub const YPERR_VERS: i32 = 14;
pub const YPERR_ACCESS: i32 = 15;
pub const YPERR_BUSY: i32 = 16;

/// `enum ypstat`.
pub const YP_TRUE: i32 = 1;
pub const YP_NOMORE: i32 = 2;
pub const YP_FALSE: i32 = 0;
pub const YP_YPERR: i32 = -6;
pub const YP_VERS: i32 = -8;

const YPPROG: u32 = 100004;
const YPVERS: u32 = 2;
const YPPROC_MATCH: u32 = 3;
const YPPROC_ALL: u32 = 8;
const YPBINDPROG: u32 = 100007;
const YPBINDVERS: u32 = 3;
const YPBINDVERS_2: u32 = 2;
const YPBINDPROC_DOMAIN: u32 = 1;
const YPBIND_SUCC_VAL: u32 = 1;
const YPBIND_FAIL_VAL: u32 = 2;
const XDRMAXNAME: u32 = 1024;
const XDRMAXRECORD: u32 = 16 * 1024 * 1024;
const BINDINGDIR: &str = "/var/yp/binding";
const NIS_MAXNAMELEN: usize = 1024;
const RPCTIMEOUT: Timeval = Timeval { sec: 25, usec: 0 };
const MAXTRIES: i32 = 2;

/// `ypbindlist_lock`: held across a whole `yp_all()`.
static YPBINDLIST_LOCK: Mutex<()> = Mutex::new(());

/// `ypdomainname`: the domain, once there is one.
static YPDOMAINNAME: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// `yp_get_default_domain()`: the domain name (kept once it's found), or
/// `YPERR_NODOM` when it's unset (`(none)`). An empty domain name isn't kept:
/// it's "found" (and asked for again next time).
pub fn yp_get_default_domain() -> Result<Vec<u8>, i32> {
    let mut d = YPDOMAINNAME.lock().unwrap_or_else(|e| e.into_inner());
    if d.is_empty() {
        let Some(mut name) = sys::getdomainname() else { return Err(YPERR_NODOM) };
        name.truncate(NIS_MAXNAMELEN);
        if name == b"(none)" {
            return Err(YPERR_NODOM);
        }
        *d = name;
    }
    Ok(d.clone())
}

/// `yperr_string()`.
pub fn yperr_string(error: i32) -> &'static str {
    match error {
        YPERR_SUCCESS => "Success",
        YPERR_BADARGS => "Request arguments bad",
        YPERR_RPC => "RPC failure on NIS operation",
        YPERR_DOMAIN => "Can't bind to server which serves this domain",
        YPERR_MAP => "No such map in server's domain",
        YPERR_KEY => "No such key in map",
        YPERR_YPERR => "Internal NIS error",
        YPERR_RESRC => "Local resource allocation failure",
        YPERR_NOMORE => "No more records in map database",
        YPERR_PMAP => "Can't communicate with portmapper",
        YPERR_YPBIND => "Can't communicate with ypbind",
        YPERR_YPSERV => "Can't communicate with ypserv",
        YPERR_NODOM => "Local domain name not set",
        YPERR_BADDB => "NIS map database is bad",
        YPERR_VERS => "NIS client/server version mismatch - can't supply service",
        YPERR_ACCESS => "Permission denied",
        YPERR_BUSY => "Database is busy",
        _ => "Unknown NIS error code",
    }
}

/// `ypprot_err()`: a server's `ypstat` as a `YPERR_` code.
pub fn ypprot_err(code: i32) -> i32 {
    match code {
        1 => YPERR_SUCCESS,
        2 => YPERR_NOMORE,
        0 => YPERR_YPERR,
        -1 => YPERR_MAP,
        -2 => YPERR_DOMAIN,
        -3 => YPERR_KEY,
        -4 => YPERR_YPERR,
        -5 => YPERR_BADDB,
        -6 => YPERR_YPERR,
        -7 => YPERR_BADARGS,
        -8 => YPERR_VERS,
        _ => YPERR_YPERR,
    }
}

/// A `dom_binding`: the server and the UDP client of its ypserv.
#[derive(Default)]
struct DomBinding {
    server: Option<Vec<u8>>,
    client: Option<Client>,
}

impl DomBinding {
    /// `__yp_unbind()`.
    fn unbind(self) {
        if let Some(c) = self.client {
            c.destroy();
        }
    }

    /// `yp_bind_client_create_v3()` and `_v2()`: a UDP client of `server`'s
    /// ypserv, with libtirpc's message on stderr if it can't be made.
    fn client_create(&mut self, server: Vec<u8>, who: &[u8]) {
        let c = with_lib(|lib: &mut Lib| {
            let c = tirpc::clnt::clnt_create(lib, &server, YPPROG, YPVERS, Some(b"udp"));
            if c.is_none() {
                tirpc::clnt::pcreateerror(lib, who);
            }
            c
        });
        self.server = Some(server);
        self.client = c;
    }
}

/// `xdr_netconfig()` decoding (the values are only checked).
fn skip_netconfig(x: &mut dyn XdrDecode) -> Option<()> {
    xdr::get_string(x, u32::MAX)?;
    xdr::get_u32(x)?;
    xdr::get_u32(x)?;
    for _ in 0..3 {
        xdr::get_string(x, u32::MAX)?;
    }
    let n = xdr::get_u32(x)?;
    if n > 100 {
        return None;
    }
    for _ in 0..n {
        xdr::get_string(x, u32::MAX)?;
    }
    for _ in 0..8 {
        xdr::get_u32(x)?;
    }
    Some(())
}

/// `xdr_ypbind3_binding()` decoding: the server name (`ypbind_servername`,
/// which decoding always makes, so `taddr2ipstr()` on the address is never
/// what names the server).
fn get_ypbind3_binding(x: &mut dyn XdrDecode) -> Option<Vec<u8>> {
    if xdr::get_bool(x)? {
        skip_netconfig(x)?;
    }
    if xdr::get_bool(x)? {
        let mut maxlen = 0;
        get_netbuf(x, &mut maxlen)?;
    }
    let name = xdr::get_string(x, u32::MAX)?;
    xdr::get_u32(x)?;
    xdr::get_u32(x)?;
    Some(name)
}

/// `inet_ntoa()`.
fn inet_ntoa(a: &[u8]) -> Vec<u8> {
    format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]).into_bytes()
}

/// `yp_bind_file()`: a binding from the binding directory, if there is one.
fn yp_bind_file(domain: &[u8], ysd: &mut DomBinding) {
    let dom = String::from_utf8_lossy(domain);
    let path3 = format!("{BINDINGDIR}/{dom}.{YPBINDVERS}");
    if let Ok(mut data) = std::fs::read(&path3) {
        let mut x = XdrMem::new(&mut data);
        if let Some(name) = get_ypbind3_binding(&mut x) {
            ysd.client_create(cstr::c(&name).to_vec(), b"yp_bind_client_create_v3");
            return;
        }
    }
    // The version 2 file: a port number (16 bits, ignored), then the
    // YPBIND_RESP record as it is in memory (12 bytes).
    let path2 = format!("{BINDINGDIR}/{dom}.2");
    if let Ok(data) = std::fs::read(&path2)
        && data.len() >= 2 + 12
    {
        // ypbind_status, then the binding: in_addr, port.
        let addr = &data[6..10];
        ysd.client_create(inet_ntoa(addr), b"yp_bind_client_create_v2");
    }
}

/// `xdr_domainname()` encoding.
fn put_domainname(x: &mut dyn XdrEncode, d: &[u8]) -> bool {
    xdr::put_string(x, d, XDRMAXNAME)
}

/// `yp_bind_ypbindprog()`: ask ypbind on localhost (version 3, then 2).
fn yp_bind_ypbindprog(domain: &[u8], ysd: &mut DomBinding) -> i32 {
    let client = with_lib(|lib| tirpc::clnt::clnt_create(lib, b"localhost", YPBINDPROG, YPBINDVERS, Some(b"tcp")));
    if let Some(mut client) = client {
        // None: the call failed; Some((status, server)).
        let mut resp: Option<(u32, Option<Vec<u8>>)> = None;
        let ret = client.call(
            YPBINDPROC_DOMAIN,
            &mut |x| put_domainname(x, domain),
            &mut |x| {
                resp = (|| {
                    let st = xdr::get_u32(x)?;
                    match st {
                        YPBIND_FAIL_VAL => {
                            xdr::get_u32(x)?;
                            Some((st, None))
                        }
                        YPBIND_SUCC_VAL => {
                            if xdr::get_bool(x)? {
                                Some((st, Some(get_ypbind3_binding(x)?)))
                            } else {
                                Some((st, None))
                            }
                        }
                        _ => None,
                    }
                })();
                resp.is_some()
            },
            RPCTIMEOUT,
        );
        client.destroy();
        if ret != RPC_SUCCESS {
            if ret != RPC_PROGVERSMISMATCH {
                return YPERR_YPBIND;
            }
        } else {
            let (st, server) = resp.unwrap_or((0, None));
            if st != YPBIND_SUCC_VAL {
                return YPERR_DOMAIN;
            }
            ysd.server = None;
            // A success with no binding: C would crash on the NULL.
            let Some(server) = server else { return YPERR_YPSERV };
            ysd.client_create(cstr::c(&server).to_vec(), b"yp_bind_client_create_v3");
            if ysd.client.is_none() {
                return YPERR_YPSERV;
            }
            return YPERR_SUCCESS;
        }
    }
    // try_v2: fall back to protocol version 2.
    let Some(mut client) =
        with_lib(|lib| tirpc::clnt::clnt_create(lib, b"localhost", YPBINDPROG, YPBINDVERS_2, Some(b"tcp")))
    else {
        return YPERR_YPBIND;
    };
    let mut resp: Option<(u32, Vec<u8>)> = None;
    let ret = client.call(
        YPBINDPROC_DOMAIN,
        &mut |x| put_domainname(x, domain),
        &mut |x| {
            resp = (|| {
                let st = xdr::get_u32(x)?;
                match st {
                    YPBIND_FAIL_VAL => {
                        xdr::get_u32(x)?;
                        Some((st, Vec::new()))
                    }
                    YPBIND_SUCC_VAL => {
                        let addr = xdr::get_opaque(x, 4)?;
                        xdr::get_opaque(x, 2)?;
                        Some((st, addr))
                    }
                    _ => None,
                }
            })();
            resp.is_some()
        },
        RPCTIMEOUT,
    );
    client.destroy();
    if ret != RPC_SUCCESS {
        return YPERR_YPBIND;
    }
    let (st, addr) = resp.unwrap_or((0, Vec::new()));
    if st != YPBIND_SUCC_VAL {
        return YPERR_DOMAIN;
    }
    ysd.server = None;
    ysd.client_create(inet_ntoa(&addr), b"yp_bind_client_create_v2");
    if ysd.client.is_none() {
        return YPERR_YPSERV;
    }
    YPERR_SUCCESS
}

/// `__yp_bind()` for a new binding.
fn yp_bind(domain: &[u8]) -> Result<DomBinding, i32> {
    if domain.is_empty() {
        return Err(YPERR_BADARGS);
    }
    let mut ysd = DomBinding::default();
    // Try the binding directory first.
    yp_bind_file(domain, &mut ysd);
    if ysd.client.is_none() {
        let r = yp_bind_ypbindprog(domain, &mut ysd);
        if r != YPERR_SUCCESS {
            return Err(r);
        }
    }
    if ysd.client.is_none() {
        return Err(YPERR_YPSERV);
    }
    Ok(ysd)
}

type Args<'a> = &'a mut dyn FnMut(&mut dyn XdrEncode) -> bool;
type Res<'a> = &'a mut dyn FnMut(&mut dyn XdrDecode) -> bool;

/// `__ypclnt_call()`.
fn ypclnt_call(proc_: u32, args: Args<'_>, res: Res<'_>, ydb: &mut DomBinding, print_error: bool) -> i32 {
    let client = ydb.client.as_mut().expect("bound client");
    let result = client.call(proc_, args, res, RPCTIMEOUT);
    if result != RPC_SUCCESS {
        if print_error {
            with_lib(|lib| tirpc::clnt::perror(lib, client, b"do_ypcall: clnt_call"));
        }
        return YPERR_RPC;
    }
    YPERR_SUCCESS
}

/// `do_ypcall()`: bind (from a file or ypbind) and call; if that fails, ask
/// ypbind and call once more.
fn do_ypcall(domain: &[u8], proc_: u32, args: Args<'_>, res: Res<'_>) -> i32 {
    let mut status = YPERR_YPERR;
    if let Ok(mut ydb) = yp_bind(domain) {
        status = ypclnt_call(proc_, args, res, &mut ydb, true);
        ydb.unbind();
    }
    if status != YPERR_SUCCESS {
        let mut ydb = DomBinding::default();
        if yp_bind_ypbindprog(domain, &mut ydb) == YPERR_SUCCESS {
            status = ypclnt_call(proc_, args, res, &mut ydb, true);
        }
        ydb.unbind();
    }
    status
}

/// `yp_match()`: the value of `key` in the map.
pub fn yp_match(domain: &[u8], map: &[u8], key: &[u8]) -> Result<Vec<u8>, i32> {
    if domain.is_empty() || map.is_empty() || key.is_empty() || key[0] == 0 {
        return Err(YPERR_BADARGS);
    }
    let mut resp: Option<(i32, Vec<u8>)> = None;
    let status = do_ypcall(
        domain,
        YPPROC_MATCH,
        &mut |x| {
            xdr::put_string(x, domain, XDRMAXNAME)
                && xdr::put_string(x, map, XDRMAXNAME)
                && xdr::put_bytes(x, key, XDRMAXRECORD)
        },
        &mut |x| {
            resp = (|| Some((xdr::get_i32(x)?, xdr::get_bytes(x, XDRMAXRECORD)?)))();
            resp.is_some()
        },
    );
    if status != YPERR_SUCCESS {
        return Err(status);
    }
    let (st, val) = resp.unwrap_or((0, Vec::new()));
    let status = ypprot_err(st);
    if status != YPERR_SUCCESS {
        return Err(status);
    }
    Ok(val)
}

/// `yp_all()`'s callback: (status, key, value) for each entry (`YP_TRUE`)
/// and once for an error status (no key or value); nonzero stops the read.
pub type Foreach<'a> = &'a mut dyn FnMut(i32, Option<&[u8]>, Option<&[u8]>) -> i32;

/// `__xdr_ypresp_all()` decoding: the entries, through the callback, and the
/// final status.
fn get_ypresp_all(x: &mut dyn XdrDecode, foreach: &mut Foreach<'_>, status: &mut i32) -> bool {
    loop {
        let more = match xdr::get_bool(x) {
            Some(m) => m,
            None => {
                *status = YP_YPERR;
                return false;
            }
        };
        if !more {
            *status = YP_NOMORE;
            return true;
        }
        let kv = (|| Some((xdr::get_i32(x)?, xdr::get_bytes(x, XDRMAXRECORD)?, xdr::get_bytes(x, XDRMAXRECORD)?)))();
        let Some((st, val, key)) = kv else {
            *status = YP_YPERR;
            return false;
        };
        if st == YP_TRUE {
            *status = YP_TRUE;
            if foreach(YP_TRUE, Some(&key), Some(&val)) != 0 {
                return true;
            }
        } else {
            *status = st;
            // Sun says the call isn't needed, but Solaris makes it.
            foreach(st, None, None);
            return true;
        }
    }
}

/// `yp_all()`: every entry of the map, over TCP.
pub fn yp_all(domain: &[u8], map: &[u8], mut foreach: Foreach<'_>) -> i32 {
    if domain.is_empty() || map.is_empty() {
        return YPERR_BADARGS;
    }
    let _g = YPBINDLIST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut res = YPERR_YPERR;
    let mut try_ = 0;
    while try_ < MAXTRIES && res != YPERR_SUCCESS {
        let ydb = match yp_bind(domain) {
            Ok(b) => b,
            Err(_) => return YPERR_DOMAIN,
        };
        let server = ydb.server.clone().unwrap_or_default();
        // The UDP client isn't needed any more.
        ydb.unbind();
        let Some(mut clnt) = with_lib(|lib| tirpc::clnt::clnt_create(lib, &server, YPPROG, YPVERS, Some(b"tcp")))
        else {
            return YPERR_PMAP;
        };
        let mut status = 0;
        let result = clnt.call(
            YPPROC_ALL,
            &mut |x| xdr::put_string(x, domain, XDRMAXNAME) && xdr::put_string(x, map, XDRMAXNAME),
            &mut |x| get_ypresp_all(x, &mut foreach, &mut status),
            RPCTIMEOUT,
        );
        if result != RPC_SUCCESS {
            // The message only on the last try.
            if try_ == MAXTRIES - 1 {
                with_lib(|lib| tirpc::clnt::perror(lib, &clnt, b"yp_all: clnt_call"));
            }
            res = YPERR_RPC;
        } else {
            res = YPERR_SUCCESS;
        }
        clnt.destroy();
        if res == YPERR_SUCCESS && status != YP_NOMORE {
            return ypprot_err(status);
        }
        try_ += 1;
    }
    res
}
