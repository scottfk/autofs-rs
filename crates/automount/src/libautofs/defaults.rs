//! `lib/defaults.c`: the configuration, from `/etc/autofs/autofs.conf` and the
//! old-style `/etc/conf.d/autofs`, kept in upstream's 128-bucket hash of
//! `(section, name, value)` options, and its getters.
//!
//! QUIRKs kept: `conf_load_amd_defaults()` tests `uname()`'s result the wrong
//! way round, so `arch`, `karch`, `os` and `osver` are set to nothing when
//! `uname()` works; `fgets()` reads at most 256 bytes, so a longer line is read
//! as several and the "was truncated" message never shows; lines that don't
//! start with a letter or `[` (indented ones too) are ignored; and the
//! "neither file changed" test can never be true (an `=`/`!=` precedence slip),
//! so every call rereads both files. Options with `CONF_ENV` are exported to
//! the environment (`setenv(name, value, 0)`) and can be overridden by it.

use std::sync::Mutex;

use crate::libautofs::cstr;
use crate::libautofs::cstr::{caseeq, ncaseeq};
use crate::libautofs::log;
use crate::sys;

pub const AUTOFS_MAP_DIR: &[u8] = b"/etc/autofs";
pub const AUTOFS_CONF_DIR: &[u8] = b"/etc/conf.d";
pub const AUTOFS_LIB_DIR: &[u8] = b"/usr/lib64/autofs";
const DEFAULT_CONFIG_FILE: &[u8] = b"/etc/autofs/autofs.conf";
const OLD_CONFIG_FILE: &[u8] = b"/etc/conf.d/autofs";
const MAX_LINE_LEN: usize = 256;

const AUTOFS_GBL_SEC: &[u8] = b"autofs";
const AMD_GBL_SEC: &[u8] = b"amd";

pub const DEFAULT_MASTER_MAP_NAME: &[u8] = b"auto.master";
const DEFAULT_OPEN_FILE_LIMIT: &[u8] = b"20480";
pub const DEFAULT_TIMEOUT: &[u8] = b"600";
const DEFAULT_MASTER_WAIT: &[u8] = b"10";
const DEFAULT_NEGATIVE_TIMEOUT: &[u8] = b"60";
const DEFAULT_POSITIVE_TIMEOUT: &[u8] = b"120";
const DEFAULT_MOUNT_VERBOSE: &[u8] = b"0";
const DEFAULT_MOUNT_WAIT: &[u8] = b"-1";
const DEFAULT_UMOUNT_WAIT: &[u8] = b"12";
const DEFAULT_BROWSE_MODE: &[u8] = b"1";
const DEFAULT_LOGGING: &[u8] = b"none";
const DEFAULT_FORCE_STD_PROG_MAP_ENV: &[u8] = b"0";
const DEFAULT_LDAP_TIMEOUT: &[u8] = b"-1";
const DEFAULT_LDAP_NETWORK_TIMEOUT: &[u8] = b"8";
const DEFAULT_MOUNT_NFS_DEFAULT_PROTOCOL: &[u8] = b"3";
const DEFAULT_APPEND_OPTIONS: &[u8] = b"1";
const DEFAULT_AUTH_CONF_FILE: &[u8] = b"/etc/autofs/autofs_ldap_auth.conf";
const DEFAULT_MAP_HASH_TABLE_SIZE: &[u8] = b"1024";
const DEFAULT_USE_HOSTNAME_FOR_MOUNTS: &[u8] = b"0";
const DEFAULT_DISABLE_NOT_FOUND_MESSAGE: &[u8] = b"0";
const DEFAULT_USE_IGNORE_MOUNT_OPTION: &[u8] = b"0";
const DEFAULT_SSS_MASTER_MAP_WAIT: &[u8] = b"0";
const DEFAULT_USE_MOUNT_REQUEST_LOG_ID: &[u8] = b"0";

const DEFAULT_AMD_AUTO_DIR: &[u8] = b"/a";
const DEFAULT_AMD_BROWSABLE_DIRS: &[u8] = b"no";
const DEFAULT_AMD_DOMAIN_STRIP: &[u8] = b"yes";
const DEFAULT_AMD_EXEC_MAP_TIMEOUT: &[u8] = b"10";
const DEFAULT_AMD_FORCED_UMOUNTS: &[u8] = b"no";
const DEFAULT_AMD_FULLY_QUALIFIED_HOSTS: &[u8] = b"no";
const DEFAULT_AMD_HESIOD_BASE: &[u8] = b"automount";
const DEFAULT_AMD_LDAP_PROTO_VERSION: &[u8] = b"2";
const DEFAULT_AMD_LOCALHOST_ADDRESS: &[u8] = b"localhost";
const DEFAULT_AMD_LOG_OPTIONS: &[u8] = b"defaults";
const DEFAULT_AMD_NORMALIZE_HOSTNAMES: &[u8] = b"no";
const DEFAULT_AMD_NORMALIZE_SLASHES: &[u8] = b"yes";
const DEFAULT_AMD_RESTART_MOUNTS: &[u8] = b"no";
const DEFAULT_AMD_SELECTORS_IN_DEFAULTS: &[u8] = b"no";
const DEFAULT_AMD_UMOUNT_ON_EXIT: &[u8] = b"yes";
const DEFAULT_AMD_VENDOR: &[u8] = b"unknown";
const DEFAULT_AMD_LINUX_UFS_MOUNT_TYPE: &[u8] = b"ext3";

pub const CONF_NONE: u64 = 0x0000_0000;
pub const CONF_ENV: u64 = 0x0000_0001;
pub const CONF_BROWSABLE_DIRS: u64 = 0x0000_0008;
pub const CONF_MOUNT_TYPE_AUTOFS: u64 = 0x0000_0010;
pub const CONF_SELECTORS_IN_DEFAULTS: u64 = 0x0000_0020;
pub const CONF_NORMALIZE_HOSTNAMES: u64 = 0x0000_0040;
pub const CONF_RESTART_EXISTING_MOUNTS: u64 = 0x0000_0100;
pub const CONF_FULLY_QUALIFIED_HOSTS: u64 = 0x0000_0400;
pub const CONF_UNMOUNT_ON_EXIT: u64 = 0x0000_0800;
pub const CONF_AUTOFS_USE_LOFS: u64 = 0x0000_1000;
pub const CONF_DOMAIN_STRIP: u64 = 0x0000_2000;
pub const CONF_NORMALIZE_SLASHES: u64 = 0x0000_4000;
pub const CONF_FORCED_UNMOUNTS: u64 = 0x0000_8000;

const CFG_TABLE_SIZE: u32 = 128;
const CFG_OK: i32 = 0;
const CFG_FAIL: i32 = 1;

const NAME_MASTER_MAP: &[u8] = b"master_map_name";
const NAME_LDAP_URI: &[u8] = b"ldap_uri";
const NAME_SEARCH_BASE: &[u8] = b"search_base";

#[derive(Debug, Clone)]
struct ConfOption {
    section: Vec<u8>,
    name: Vec<u8>,
    value: Option<Vec<u8>>,
    flags: u64,
}

#[derive(Debug)]
struct ConfCache {
    hash: Vec<Vec<ConfOption>>,
    modified: i64,
}

static CONFIG: Mutex<Option<ConfCache>> = Mutex::new(None);

/// `hash()` from `include/hash.h` (one-at-a-time), modulo `size`.
pub fn hash(key: &[u8], size: u32) -> u32 {
    let mut h: u32 = 0;
    for &b in cstr::c(key) {
        h = h.wrapping_add(b as u32);
        h = h.wrapping_add(h << 10);
        h ^= h >> 6;
    }
    h = h.wrapping_add(h << 3);
    h ^= h >> 11;
    h = h.wrapping_add(h << 15);
    h % size
}

fn get_hash(key: &[u8]) -> usize {
    let l: Vec<u8> = cstr::c(key).iter().map(|&b| cstr::tolower(b)).collect();
    hash(&l, CFG_TABLE_SIZE) as usize
}

/// `message()`.
fn message(to_syslog: bool, msg: &[u8]) {
    if to_syslog {
        sys::syslog(libc::LOG_CRIT, msg);
    } else {
        let mut m = msg.to_vec();
        m.push(b'\n');
        log::eprint(&m);
    }
}

impl ConfCache {
    fn lookup_key(&self, section: &[u8], key: &[u8]) -> Option<(usize, usize)> {
        let h = get_hash(key);
        for (i, co) in self.hash[h].iter().enumerate() {
            if !caseeq(section, &co.section) {
                continue;
            }
            if caseeq(key, &co.name) {
                return Some((h, i));
            }
        }
        None
    }

    /// `conf_lookup()`.
    fn lookup(&self, section: &[u8], key: &[u8]) -> Option<(usize, usize)> {
        if cstr::c(key).len() > libc::PATH_MAX as usize {
            return None;
        }
        let key = cstr::c(key);
        match self.lookup_key(section, key) {
            Some(p) => Some(p),
            None => {
                if key.len() > 8 && ncaseeq(b"DEFAULT_", key, 8) {
                    self.lookup_key(section, &key[8..])
                } else {
                    let mut old = b"DEFAULT_".to_vec();
                    old.extend_from_slice(key);
                    self.lookup_key(section, &old)
                }
            }
        }
    }

    fn get(&self, p: (usize, usize)) -> &ConfOption {
        &self.hash[p.0][p.1]
    }

    /// `conf_add()`.
    fn add(&mut self, section: &[u8], key: &[u8], value: Option<&[u8]>, flags: u64) -> i32 {
        let mut val = None;
        let env = if flags & CONF_ENV != 0 { sys::getenv(key) } else { None };
        if env.is_some() || value.is_some() {
            val = Some(env.unwrap_or_else(|| value.unwrap().to_vec()));
        }
        let co = ConfOption { section: cstr::c(section).to_vec(), name: cstr::c(key).to_vec(), value: val, flags };
        if flags & CONF_ENV != 0
            && let Some(v) = value
        {
            sys::setenv(key, v, false);
        }
        let h = get_hash(key);
        self.hash[h].push(co);
        CFG_OK
    }

    /// `conf_delete()`.
    fn delete(&mut self, section: &[u8], key: &[u8]) {
        let h = get_hash(key);
        let pos = self.hash[h].iter().position(|co| caseeq(section, &co.section) && caseeq(key, &co.name));
        if let Some(i) = pos {
            self.hash[h].remove(i);
        }
    }

    /// `conf_update()`.
    fn update(&mut self, section: &[u8], key: &[u8], value: Option<&[u8]>, flags: u64) -> i32 {
        match self.lookup(section, key) {
            None => self.add(section, key, value, flags),
            Some((h, i)) => {
                let env = if flags & CONF_ENV != 0 { sys::getenv(key) } else { None };
                let mut val = None;
                if env.is_some() || value.is_some() {
                    val = Some(env.unwrap_or_else(|| value.unwrap().to_vec()));
                }
                let co = &mut self.hash[h][i];
                co.value = val;
                if flags != 0 {
                    co.flags = flags;
                }
                if flags & CONF_ENV != 0
                    && let Some(v) = value
                {
                    sys::setenv(key, v, false);
                }
                CFG_OK
            }
        }
    }

    fn load_autofs_defaults(&mut self) -> bool {
        let sec = AUTOFS_GBL_SEC;
        let defaults: [(&[u8], &[u8]); 19] = [
            (b"open_file_limit", DEFAULT_OPEN_FILE_LIMIT),
            (b"timeout", DEFAULT_TIMEOUT),
            (b"master_wait", DEFAULT_MASTER_WAIT),
            (b"negative_timeout", DEFAULT_NEGATIVE_TIMEOUT),
            (b"browse_mode", DEFAULT_BROWSE_MODE),
            (b"logging", DEFAULT_LOGGING),
            (b"ldap_timeout", DEFAULT_LDAP_TIMEOUT),
            (b"ldap_network_timeout", DEFAULT_LDAP_NETWORK_TIMEOUT),
            (b"append_options", DEFAULT_APPEND_OPTIONS),
            (b"mount_verbose", DEFAULT_MOUNT_VERBOSE),
            (b"mount_wait", DEFAULT_MOUNT_WAIT),
            (b"umount_wait", DEFAULT_UMOUNT_WAIT),
            (b"auth_conf_file", DEFAULT_AUTH_CONF_FILE),
            (b"mount_nfs_default_protocol", DEFAULT_MOUNT_NFS_DEFAULT_PROTOCOL),
            (b"use_hostname_for_mounts", DEFAULT_USE_HOSTNAME_FOR_MOUNTS),
            (b"disable_not_found_message", DEFAULT_DISABLE_NOT_FOUND_MESSAGE),
            (b"use_ignore_mount_option", DEFAULT_USE_IGNORE_MOUNT_OPTION),
            (b"sss_master_map_wait", DEFAULT_SSS_MASTER_MAP_WAIT),
            (b"use_mount_request_log_id", DEFAULT_USE_MOUNT_REQUEST_LOG_ID),
        ];
        for (name, val) in defaults {
            if self.update(sec, name, Some(val), CONF_ENV) == CFG_FAIL {
                return false;
            }
        }
        // LDAP_URI and SEARCH_BASE can occur multiple times.
        while let Some(p) = self.lookup(sec, NAME_LDAP_URI) {
            let co = self.get(p).clone();
            self.delete(&co.section, &co.name);
        }
        while let Some(p) = self.lookup(sec, NAME_SEARCH_BASE) {
            let co = self.get(p).clone();
            self.delete(&co.section, &co.name);
        }
        true
    }

    fn load_amd_defaults(&mut self) -> bool {
        let sec = AMD_GBL_SEC;
        let (r, uts) = sys::uname();
        // QUIRK: the test is inverted, so these are all NULL when uname() works.
        let (os, osver, arch) = if r != 0 {
            (Some(uts.sysname.clone()), Some(uts.release.clone()), Some(uts.machine.clone()))
        } else {
            (None, None, None)
        };
        let os = os.as_deref();
        let osver = osver.as_deref();
        let arch = arch.as_deref();
        let list: [(&[u8], Option<&[u8]>); 30] = [
            (b"arch", arch),
            (b"karch", arch),
            (b"os", os),
            (b"osver", osver),
            (b"auto_dir", Some(DEFAULT_AMD_AUTO_DIR)),
            // QUIRK: autofs_use_lofs gets auto_dir's default.
            (b"autofs_use_lofs", Some(DEFAULT_AMD_AUTO_DIR)),
            (b"browsable_dirs", Some(DEFAULT_AMD_BROWSABLE_DIRS)),
            (b"cluster", None),
            (b"domain_strip", Some(DEFAULT_AMD_DOMAIN_STRIP)),
            (b"exec_map_timeout", Some(DEFAULT_AMD_EXEC_MAP_TIMEOUT)),
            (b"forced_unmounts", Some(DEFAULT_AMD_FORCED_UMOUNTS)),
            (b"fully_qualified_hosts", Some(DEFAULT_AMD_FULLY_QUALIFIED_HOSTS)),
            (b"full_os", None),
            (b"hesiod_base", Some(DEFAULT_AMD_HESIOD_BASE)),
            (b"karch", arch),
            (b"ldap_base", None),
            (b"ldap_hostports", None),
            (b"local_domain", None),
            (b"localhost_address", Some(DEFAULT_AMD_LOCALHOST_ADDRESS)),
            (b"log_options", Some(DEFAULT_AMD_LOG_OPTIONS)),
            (b"map_defaults", None),
            (b"map_options", None),
            (b"map_type", None),
            (b"nis_domain", None),
            (b"normalize_hostnames", Some(DEFAULT_AMD_NORMALIZE_HOSTNAMES)),
            (b"normalize_slashes", Some(DEFAULT_AMD_NORMALIZE_SLASHES)),
            (b"os", os),
            (b"restart_mounts", Some(DEFAULT_AMD_RESTART_MOUNTS)),
            (b"search_path", None),
            // selectors_on_default is deprecated, use selectors_in_defaults
            (b"selectors_on_default", Some(DEFAULT_AMD_SELECTORS_IN_DEFAULTS)),
        ];
        for (name, val) in list {
            if self.update(sec, name, val, CONF_NONE) == CFG_FAIL {
                return false;
            }
        }
        let rest: [(&[u8], Option<&[u8]>); 4] = [
            (b"selectors_in_defaults", Some(DEFAULT_AMD_SELECTORS_IN_DEFAULTS)),
            (b"unmount_on_exit", Some(DEFAULT_AMD_UMOUNT_ON_EXIT)),
            (b"vendor", Some(DEFAULT_AMD_VENDOR)),
            (b"linux_ufs_mount_type", Some(DEFAULT_AMD_LINUX_UFS_MOUNT_TYPE)),
        ];
        for (name, val) in rest {
            if self.update(sec, name, val, CONF_NONE) == CFG_FAIL {
                return false;
            }
        }
        true
    }

    fn reset_defaults(&mut self, to_syslog: bool) -> bool {
        if !self.load_autofs_defaults() {
            message(to_syslog, b"failed to reset autofs default config");
            return false;
        }
        if !self.load_amd_defaults() {
            message(to_syslog, b"failed to reset amd default config");
            return false;
        }
        true
    }

    /// `check_set_config_value()`.
    fn check_set_config_value(&mut self, section: Option<&[u8]>, res: &[u8], value: &[u8]) {
        let sec = section.unwrap_or(AUTOFS_GBL_SEC);
        if caseeq(res, NAME_LDAP_URI) || caseeq(res, NAME_SEARCH_BASE) {
            self.add(sec, res, Some(value), 0);
        } else {
            self.update(sec, res, Some(value), 0);
        }
    }

    /// `read_config()`.
    fn read_config(&mut self, to_syslog: bool, data: &[u8]) {
        let mut new_sec: Option<Vec<u8>> = None;
        for raw in fgets_chunks(data, MAX_LINE_LEN + 1) {
            let mut line = raw.clone();
            line.push(0);
            let Some(parsed) = parse_line(&mut line) else { continue };
            match parsed {
                Parsed::Section(sec) => {
                    new_sec = Some(sec.clone());
                    self.update(&sec, &sec, None, 0);
                    continue;
                }
                Parsed::Value(key, value) => {
                    let res = &key;
                    if caseeq(res, b"mount_type") {
                        message(to_syslog, &bfmt!("{} is always autofs, ignored", res));
                        continue;
                    }
                    if caseeq(res, b"pid_file") {
                        message(to_syslog, &bfmt!("{} must be specified as a command line option, ignored", res));
                        continue;
                    }
                    if caseeq(res, b"restart_mounts") {
                        message(to_syslog, &bfmt!("{} is always done by autofs, ignored", res));
                        continue;
                    }
                    const UNUSED: [&[u8]; 32] = [
                        b"use_tcpwrappers",
                        b"auto_attrcache",
                        b"print_pid",
                        b"print_version",
                        b"log_file",
                        b"preferred_amq_port",
                        b"truncate_log",
                        b"debug_mtab_file",
                        b"debug_options",
                        b"sun_map_syntax",
                        b"portmap_program",
                        b"nfs_vers",
                        b"nfs_vers_ping",
                        b"nfs_proto",
                        b"nfs_allow_any_interface",
                        b"nfs_allow_insecure_port",
                        b"nfs_retransmit_counter",
                        b"nfs_retransmit_counter_udp",
                        b"nfs_retransmit_counter_tcp",
                        b"nfs_retransmit_counter_toplvl",
                        b"nfs_retry_interval",
                        b"nfs_retry_interval_udp",
                        b"nfs_retry_interval_tcp",
                        b"nfs_retry_interval_toplvl",
                        b"ldap_cache_maxmem",
                        b"ldap_cache_seconds",
                        b"ldap_proto_version",
                        b"show_statfs_entries",
                        b"cache_duration",
                        b"map_reload_interval",
                        b"map_options",
                        b"plock",
                    ];
                    if UNUSED.iter().any(|n| caseeq(res, n)) {
                        message(to_syslog, &bfmt!("{} is not used by autofs, ignored", res));
                        continue;
                    }
                    self.check_set_config_value(new_sec.as_deref(), &key, &value);
                }
            }
        }
    }

    /// `save_ldap_option_list()`: take the autofs section's `key` options out of
    /// their bucket, in order.
    fn save_ldap_option_list(&mut self, key: &[u8]) -> Vec<ConfOption> {
        let h = get_hash(key);
        let mut saved = Vec::new();
        let mut i = 0;
        while i < self.hash[h].len() {
            let co = &self.hash[h][i];
            if caseeq(AUTOFS_GBL_SEC, &co.section) && caseeq(&co.name, key) {
                saved.push(self.hash[h].remove(i));
                continue;
            }
            i += 1;
        }
        saved
    }

    /// `restore_ldap_option_list()`: put them back at the head of the bucket.
    fn restore_ldap_option_list(&mut self, list: Vec<ConfOption>) {
        if list.is_empty() {
            return;
        }
        let h = get_hash(&list[0].name);
        let rest = std::mem::take(&mut self.hash[h]);
        self.hash[h] = list;
        self.hash[h].extend(rest);
    }

    fn clean_ldap_multi_option(&mut self, key: &[u8]) {
        while let Some(p) = self.lookup(AUTOFS_GBL_SEC, key) {
            let co = self.get(p).clone();
            self.delete(&co.section, &co.name);
        }
    }
}

/// What `fgets(buf, size, f)` returns, call after call, over `data`.
fn fgets_chunks(data: &[u8], size: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut j = i;
        while j < data.len() && j - i < size - 1 {
            j += 1;
            if data[j - 1] == b'\n' {
                break;
            }
        }
        out.push(data[i..j].to_vec());
        i = j;
    }
    out
}

enum Parsed {
    Section(Vec<u8>),
    Value(Vec<u8>, Vec<u8>),
}

/// `parse_line()`, on a NUL-terminated copy of the line (it edits it in place
/// as C does, and reads back C strings from it).
fn parse_line(line: &mut [u8]) -> Option<Parsed> {
    let at = |l: &[u8], i: usize| -> u8 { l.get(i).copied().unwrap_or(0) };
    let mut key = 0usize;
    if line[0] == b'#' || (line[0] != b'[' && !cstr::isalpha(line[0])) {
        return None;
    }
    while at(line, key) != 0 && cstr::isblank(at(line, key)) {
        key += 1;
    }
    if at(line, key) == 0 {
        return None;
    }
    if at(line, key) == b'[' {
        while at(line, key) != 0 && (at(line, key) == b'[' || cstr::isblank(at(line, key))) {
            key += 1;
        }
        let mut tmp = key + cstr::strchr(&line[key..], b']')?;
        line[tmp] = b' ';
        while at(line, tmp) != 0 && cstr::isblank(at(line, tmp)) {
            line[tmp] = 0;
            if tmp == 0 {
                break;
            }
            tmp -= 1;
        }
        return Some(Parsed::Section(cstr::c(&line[key..]).to_vec()));
    }
    let mut val = key + cstr::strchr(&line[key..], b'=')?;
    let mut tmp = val;
    line[val] = 0;
    val += 1;
    loop {
        tmp -= 1;
        if !cstr::isblank(line[tmp]) {
            break;
        }
        line[tmp] = 0;
    }
    while at(line, val) != 0 && (at(line, val) == b'"' || cstr::isblank(at(line, val))) {
        val += 1;
    }
    let mut len = cstr::c(&line[val..]).len();
    if len > 0 && line[val + len - 1] == b'\n' {
        line[val + len - 1] = 0;
        len -= 1;
    }
    // trailer = strchr(val, '#'), else val + len - 1; one before the '#'.
    let mut trailer: isize = match cstr::strchr(&line[val..], b'#') {
        None => val as isize + len as isize - 1,
        Some(p) => (val + p) as isize - 1,
    };
    while trailer >= 0 {
        let ch = line[trailer as usize];
        if ch == 0 || !(ch == b'"' || cstr::isblank(ch)) {
            break;
        }
        line[trailer as usize] = 0;
        trailer -= 1;
    }
    Some(Parsed::Value(cstr::c(&line[key..]).to_vec(), cstr::c(&line[val..]).to_vec()))
}

/// `open_fopen_r()` and read the whole file, logging as it does on failure.
fn open_read(path: &[u8]) -> Option<Vec<u8>> {
    match sys::read_file(path) {
        Ok(d) => Some(d),
        Err(e) => {
            logerr!("open_fopen_r", "211", "failed to open file: {}", sys::strerror(e));
            None
        }
    }
}

/// `defaults_read_config()`.
pub fn defaults_read_config(to_syslog: bool) -> bool {
    let mut g = CONFIG.lock().unwrap();
    if g.is_none() {
        *g = Some(ConfCache { hash: vec![Vec::new(); CFG_TABLE_SIZE as usize], modified: 0 });
    }
    let config = g.as_mut().unwrap();
    let conf = open_read(DEFAULT_CONFIG_FILE);
    if conf.is_none() {
        message(to_syslog, &bfmt!("failed to open config {}", DEFAULT_CONFIG_FILE));
    }
    let oldconf = open_read(OLD_CONFIG_FILE);
    if oldconf.is_none() && conf.is_none() {
        message(to_syslog, &bfmt!("failed to open old config {}", OLD_CONFIG_FILE));
    }
    // QUIRK: "neither config has been updated" is never true (see the module
    // docs), so both files are always reread.
    if (conf.is_some() || oldconf.is_some()) && !config.reset_defaults(to_syslog) {
        return false;
    }
    let _ = config.modified;
    if let Some(c) = &conf {
        config.read_config(to_syslog, c);
    }
    if let Some(o) = &oldconf {
        let search_base = config.save_ldap_option_list(NAME_SEARCH_BASE);
        if !search_base.is_empty() {
            config.clean_ldap_multi_option(NAME_SEARCH_BASE);
        }
        let uris = config.save_ldap_option_list(NAME_LDAP_URI);
        if !uris.is_empty() {
            config.clean_ldap_multi_option(NAME_LDAP_URI);
        }
        config.read_config(to_syslog, o);
        if !search_base.is_empty() && config.lookup(AMD_GBL_SEC, NAME_SEARCH_BASE).is_none() {
            config.restore_ldap_option_list(search_base);
        }
        if !uris.is_empty() && config.lookup(AMD_GBL_SEC, NAME_LDAP_URI).is_none() {
            config.restore_ldap_option_list(uris);
        }
    }
    true
}

/// `defaults_conf_release()`.
pub fn defaults_conf_release() {
    *CONFIG.lock().unwrap() = None;
}

fn with<R>(f: impl FnOnce(&mut ConfCache) -> R) -> Option<R> {
    let mut g = CONFIG.lock().unwrap();
    g.as_mut().map(f)
}

/// `conf_get_string()`.
fn conf_get_string(section: &[u8], name: &[u8]) -> Option<Vec<u8>> {
    with(|c| c.lookup(section, name).and_then(|p| c.get(p).value.clone())).flatten()
}

/// `conf_get_number()`.
fn conf_get_number(section: &[u8], name: &[u8]) -> i64 {
    conf_get_string(section, name).map_or(-1, |v| cstr::atol(&v))
}

/// `conf_get_yesno()`.
fn conf_get_yesno(section: &[u8], name: &[u8]) -> i32 {
    match conf_get_string(section, name) {
        Some(v) => {
            if cstr::isdigit(v.first().copied().unwrap_or(0)) {
                cstr::atoi(&v)
            } else if caseeq(&v, b"yes") {
                1
            } else if caseeq(&v, b"no") {
                0
            } else {
                -1
            }
        }
        None => -1,
    }
}

pub fn defaults_get_master_map() -> Vec<u8> {
    conf_get_string(AUTOFS_GBL_SEC, NAME_MASTER_MAP).unwrap_or_else(|| DEFAULT_MASTER_MAP_NAME.to_vec())
}

pub fn defaults_master_set() -> bool {
    with(|c| c.lookup(AUTOFS_GBL_SEC, NAME_MASTER_MAP).is_some()).unwrap_or(false)
}

pub fn defaults_get_open_file_limit() -> u64 {
    let l = conf_get_number(AUTOFS_GBL_SEC, b"open_file_limit");
    (if l < 0 { cstr::atol(DEFAULT_OPEN_FILE_LIMIT) } else { l }) as u64
}

pub fn defaults_get_timeout() -> u32 {
    let t = conf_get_number(AUTOFS_GBL_SEC, b"timeout");
    (if t < 0 { cstr::atol(DEFAULT_TIMEOUT) } else { t }) as u32
}

pub fn defaults_get_master_wait() -> i32 {
    let w = conf_get_number(AUTOFS_GBL_SEC, b"master_wait");
    (if w < 0 { cstr::atol(DEFAULT_MASTER_WAIT) } else { w }) as i32
}

pub fn defaults_get_negative_timeout() -> u32 {
    let n = conf_get_number(AUTOFS_GBL_SEC, b"negative_timeout");
    (if n <= 0 { cstr::atol(DEFAULT_NEGATIVE_TIMEOUT) } else { n }) as u32
}

pub fn defaults_get_positive_timeout() -> u32 {
    let p = conf_get_number(AUTOFS_GBL_SEC, b"positive_timeout");
    (if p <= 0 { cstr::atol(DEFAULT_POSITIVE_TIMEOUT) } else { p }) as u32
}

fn yesno_or(name: &[u8], default: &[u8]) -> u32 {
    let r = conf_get_yesno(AUTOFS_GBL_SEC, name);
    (if r < 0 { cstr::atoi(default) } else { r }) as u32
}

pub fn defaults_get_browse_mode() -> u32 {
    yesno_or(b"browse_mode", DEFAULT_BROWSE_MODE)
}

pub fn defaults_get_logging() -> u32 {
    let Some(res) = conf_get_string(AUTOFS_GBL_SEC, b"logging") else { return log::LOGOPT_NONE };
    let mut logging = log::LOGOPT_NONE;
    if !caseeq(&res, b"none") {
        if caseeq(&res, b"verbose") {
            logging |= log::LOGOPT_VERBOSE;
        }
        if caseeq(&res, b"debug") {
            logging |= log::LOGOPT_DEBUG;
        }
    }
    logging
}

pub fn defaults_force_std_prog_map_env() -> u32 {
    yesno_or(b"force_standard_program_map_env", DEFAULT_FORCE_STD_PROG_MAP_ENV)
}

pub fn defaults_get_mount_nfs_default_proto() -> u32 {
    let p = conf_get_number(AUTOFS_GBL_SEC, b"mount_nfs_default_protocol") as i32;
    (if !(2..=4).contains(&p) { cstr::atoi(DEFAULT_MOUNT_NFS_DEFAULT_PROTOCOL) } else { p }) as u32
}

pub fn defaults_get_append_options() -> u32 {
    yesno_or(b"append_options", DEFAULT_APPEND_OPTIONS)
}

pub fn defaults_get_mount_verbose() -> u32 {
    yesno_or(b"mount_verbose", DEFAULT_MOUNT_VERBOSE)
}

pub fn defaults_get_mount_wait() -> u32 {
    let w = conf_get_number(AUTOFS_GBL_SEC, b"mount_wait");
    (if w < 0 { cstr::atoi(DEFAULT_MOUNT_WAIT) as i64 } else { w }) as u32
}

pub fn defaults_get_umount_wait() -> u32 {
    let w = conf_get_number(AUTOFS_GBL_SEC, b"umount_wait");
    (if w < 0 { cstr::atoi(DEFAULT_UMOUNT_WAIT) as i64 } else { w }) as u32
}

pub fn defaults_get_map_hash_table_size() -> u32 {
    let s = conf_get_number(AUTOFS_GBL_SEC, b"map_hash_table_size");
    (if s < 0 { cstr::atoi(DEFAULT_MAP_HASH_TABLE_SIZE) as i64 } else { s }) as u32
}

pub fn defaults_use_hostname_for_mounts() -> u32 {
    yesno_or(b"use_hostname_for_mounts", DEFAULT_USE_HOSTNAME_FOR_MOUNTS)
}

pub fn defaults_disable_not_found_message() -> u32 {
    yesno_or(b"disable_not_found_message", DEFAULT_DISABLE_NOT_FOUND_MESSAGE)
}

pub fn defaults_get_use_ignore_mount_option() -> u32 {
    yesno_or(b"use_ignore_mount_option", DEFAULT_USE_IGNORE_MOUNT_OPTION)
}

pub fn defaults_get_use_mount_request_log_id() -> u32 {
    yesno_or(b"use_mount_request_log_id", DEFAULT_USE_MOUNT_REQUEST_LOG_ID)
}

pub fn conf_amd_mount_section_exists(section: &[u8]) -> bool {
    with(|c| c.lookup(section, section).is_some()).unwrap_or(false)
}

/// `conf_amd_get_mount_paths()`: the amd mount sections (names starting with
/// `/`), in bucket order, runs of the same section counted once.
pub fn conf_amd_get_mount_paths() -> Vec<Vec<u8>> {
    with(|c| {
        let mut out: Vec<Vec<u8>> = Vec::new();
        let mut last: Option<Vec<u8>> = None;
        for bucket in &c.hash {
            for co in bucket {
                if co.section.first() != Some(&b'/') {
                    continue;
                }
                if last.as_deref() != Some(&co.section[..]) {
                    out.push(co.section.clone());
                }
                last = Some(co.section.clone());
            }
        }
        out
    })
    .unwrap_or_default()
}

pub fn conf_amd_get_arch() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"arch")
}

pub fn conf_amd_get_karch() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"karch").or_else(conf_amd_get_arch)
}

pub fn conf_amd_get_os() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"os")
}

pub fn conf_amd_get_os_ver() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"osver")
}

pub fn conf_amd_get_vendor() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"vendor")
}

pub fn conf_amd_get_full_os() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"full_os")
}

pub fn conf_amd_get_auto_dir() -> Vec<u8> {
    conf_get_string(AMD_GBL_SEC, b"auto_dir").unwrap_or_else(|| DEFAULT_AMD_AUTO_DIR.to_vec())
}

pub fn conf_amd_get_cluster() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"cluster")
}

pub fn conf_amd_get_exec_map_timeout() -> u32 {
    let t = conf_get_number(AMD_GBL_SEC, b"exec_map_timeout");
    (if t == -1 { cstr::atoi(DEFAULT_AMD_EXEC_MAP_TIMEOUT) as i64 } else { t }) as u32
}

pub fn conf_amd_get_hesiod_base() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"hesiod_base")
}

pub fn conf_amd_get_ldap_proto_version() -> u32 {
    let t = conf_get_number(AMD_GBL_SEC, b"ldap_proto_version");
    (if t == -1 { cstr::atoi(DEFAULT_AMD_LDAP_PROTO_VERSION) as i64 } else { t }) as u32
}

pub fn conf_amd_get_sub_domain() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"local_domain")
}

pub fn conf_amd_get_localhost_address() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"localhost_address")
}

/// `conf_amd_get_log_options()`.
pub fn conf_amd_get_log_options() -> u32 {
    let mut log_level: i32 = -1;
    if let Some(tmp) = conf_get_string(AMD_GBL_SEC, b"log_options") {
        let has = |s: &[u8]| cstr::strstr(&tmp, s).is_some();
        if (has(b"debug") || has(b"all")) && log_level < libc::LOG_DEBUG {
            log_level = libc::LOG_DEBUG;
        }
        if (has(b"info") || has(b"user") || !cstr::eq(&tmp, b"defaults")) && log_level < libc::LOG_INFO {
            log_level = libc::LOG_INFO;
        }
        if has(b"notice") && log_level < libc::LOG_NOTICE {
            log_level = libc::LOG_NOTICE;
        }
        if (has(b"warn") || has(b"map") || has(b"stats") || has(b"warning")) && log_level < libc::LOG_WARNING {
            log_level = libc::LOG_WARNING;
        }
        if has(b"error") && log_level < libc::LOG_ERR {
            log_level = libc::LOG_ERR;
        }
        if has(b"fatal") && log_level < libc::LOG_CRIT {
            log_level = libc::LOG_CRIT;
        }
    }
    if log_level == -1 {
        log_level = libc::LOG_ERR;
    }
    log_level as u32
}

pub fn conf_amd_get_nis_domain() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"nis_domain")
}

pub fn conf_amd_set_nis_domain(domain: &[u8]) -> u32 {
    with(|c| c.update(AMD_GBL_SEC, b"nis_domain", Some(domain), CONF_NONE)).unwrap_or(CFG_FAIL) as u32
}

fn section_then_amd(section: Option<&[u8]>, name: &[u8]) -> Option<Vec<u8>> {
    section.and_then(|s| conf_get_string(s, name)).or_else(|| conf_get_string(AMD_GBL_SEC, name))
}

pub fn conf_amd_get_map_defaults(section: Option<&[u8]>) -> Option<Vec<u8>> {
    section_then_amd(section, b"map_defaults")
}

pub fn conf_amd_get_map_name(section: Option<&[u8]>) -> Option<Vec<u8>> {
    section.and_then(|s| conf_get_string(s, b"map_name"))
}

pub fn conf_amd_get_map_options(section: Option<&[u8]>) -> Option<Vec<u8>> {
    section.and_then(|s| conf_get_string(s, b"map_options"))
}

pub fn conf_amd_get_map_type(section: Option<&[u8]>) -> Option<Vec<u8>> {
    section_then_amd(section, b"map_type")
}

pub fn conf_amd_get_search_path(section: Option<&[u8]>) -> Option<Vec<u8>> {
    section_then_amd(section, b"search_path")
}

/// `conf_amd_get_dismount_interval()`.
pub fn conf_amd_get_dismount_interval(section: Option<&[u8]>) -> u32 {
    let mut tmp = -1;
    if let Some(s) = section {
        tmp = conf_get_number(s, b"dismount_interval");
    }
    if tmp == -1 {
        tmp = conf_get_number(AMD_GBL_SEC, b"dismount_interval");
    }
    if tmp == -1 {
        tmp = defaults_get_timeout() as i64;
    }
    tmp as u32
}

pub fn conf_amd_get_linux_ufs_mount_type() -> Option<Vec<u8>> {
    conf_get_string(AMD_GBL_SEC, b"linux_ufs_mount_type")
}

/// `conf_amd_get_flags()`.
pub fn conf_amd_get_flags(section: Option<&[u8]>) -> u64 {
    let amd = AMD_GBL_SEC;
    let mut flags = CONF_MOUNT_TYPE_AUTOFS;
    let sec_then = |name: &[u8]| -> i32 {
        let mut t = -1;
        if let Some(s) = section {
            t = conf_get_yesno(s, name);
        }
        if t == -1 {
            t = conf_get_yesno(amd, name);
        }
        t
    };
    if sec_then(b"browsable_dirs") != 0 {
        flags |= CONF_BROWSABLE_DIRS;
    }
    if sec_then(b"selectors_in_defaults") != 0 {
        flags |= CONF_SELECTORS_IN_DEFAULTS;
    }
    if conf_get_yesno(amd, b"normalize_hostnames") != 0 {
        flags |= CONF_NORMALIZE_HOSTNAMES;
    }
    if conf_get_yesno(amd, b"restart_mounts") != 0 {
        flags |= CONF_RESTART_EXISTING_MOUNTS;
    }
    if conf_get_yesno(amd, b"fully_qualified_hosts") != 0 {
        flags |= CONF_FULLY_QUALIFIED_HOSTS;
    }
    if conf_get_yesno(amd, b"unmount_on_exit") != 0 {
        flags |= CONF_UNMOUNT_ON_EXIT;
    }
    if sec_then(b"autofs_use_lofs") != 0 {
        flags |= CONF_AUTOFS_USE_LOFS;
    }
    if conf_get_yesno(amd, b"domain_strip") != 0 {
        flags |= CONF_DOMAIN_STRIP;
    }
    if conf_get_yesno(amd, b"normalize_slashes") != 0 {
        flags |= CONF_NORMALIZE_SLASHES;
    }
    if conf_get_yesno(amd, b"forced_unmounts") != 0 {
        flags |= CONF_FORCED_UNMOUNTS;
    }
    flags
}
