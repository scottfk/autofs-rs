//! `daemon/master.c`: the master map's entries (`struct master_mapent`), their
//! autofs mount points (`struct autofs_point`) and map sources (`struct
//! map_source`, with the instances the nsswitch lookups add), and the
//! `--dumpmaps` printing.
//!
//! The C structures are linked by pointers; here they're `Arc`s with their
//! fields behind a lock each. Lists keep C's order: map sources are appended,
//! instances go to the head of their list. Identity (C's pointer compares) is an
//! id per map source.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use crate::daemon::lookup;
use crate::daemon::module::LookupMod;
use crate::libautofs::args::{self, Argv};
use crate::libautofs::cache::Cache;
use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::libautofs::log;
use crate::sys;

pub const LKP_INDIRECT: u32 = 0x0002;
pub const LKP_DIRECT: u32 = 0x0004;

pub const MAP_FLAG_FORMAT_AMD: u32 = 0x0001;

pub const MOUNT_FLAG_GHOST: u32 = 0x0001;
pub const MOUNT_FLAG_REMOUNT: u32 = 0x0008;
pub const MOUNT_FLAG_RANDOM_SELECT: u32 = 0x0004;
pub const MOUNT_FLAG_USE_WEIGHT_ONLY: u32 = 0x0010;
pub const MOUNT_FLAG_NOBIND: u32 = 0x0020;
pub const MOUNT_FLAG_SYMLINK: u32 = 0x0040;
pub const MOUNT_FLAG_AMD_CACHE_ALL: u32 = 0x0080;
pub const MOUNT_FLAG_SHARED: u32 = 0x0100;
pub const MOUNT_FLAG_SLAVE: u32 = 0x0200;
pub const MOUNT_FLAG_PRIVATE: u32 = 0x0400;
pub const MOUNT_FLAG_STRICTEXPIRE: u32 = 0x0800;
pub const MOUNT_FLAG_IGNORE: u32 = 0x1000;

pub const DAEMON_FLAGS_FOREGROUND: u32 = 0x0001;
pub const DAEMON_FLAGS_SYSTEMD_SERVICE: u32 = 0x0002;
pub const DAEMON_FLAGS_HAVE_GLOBAL_OPTIONS: u32 = 0x0004;
pub const DAEMON_FLAGS_GHOST: u32 = 0x0008;
pub const DAEMON_FLAGS_CHECK_DAEMON: u32 = 0x0010;
pub const DAEMON_FLAGS_DUMP_MAPS: u32 = 0x0020;

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// A `struct map_source`'s fields.
#[derive(Debug)]
pub struct MapSourceData {
    pub ty: Option<Vec<u8>>,
    pub format: Option<Vec<u8>>,
    pub name: Option<Vec<u8>>,
    pub flags: u32,
    pub age: i64,
    pub master_line: u32,
    pub mc: Option<Arc<Cache>>,
    pub stale: bool,
    pub recurse: bool,
    pub depth: u32,
    pub argv: Argv,
    pub lookup: Option<Box<dyn LookupMod>>,
    /// The instances, head first.
    pub instances: Vec<Arc<MapSource>>,
    pub exp_timeout: i64,
    pub refcnt: u32,
}

/// A `struct map_source`.
#[derive(Debug)]
pub struct MapSource {
    pub id: usize,
    pub d: Mutex<MapSourceData>,
}

impl MapSource {
    fn new(d: MapSourceData) -> Arc<MapSource> {
        Arc::new(MapSource { id: NEXT_ID.fetch_add(1, Ordering::Relaxed), d: Mutex::new(d) })
    }

    pub fn lock(&self) -> MutexGuard<'_, MapSourceData> {
        self.d.lock().unwrap()
    }

    pub fn ty(&self) -> Option<Vec<u8>> {
        self.lock().ty.clone()
    }

    pub fn format(&self) -> Option<Vec<u8>> {
        self.lock().format.clone()
    }

    pub fn argv(&self) -> Argv {
        self.lock().argv.clone()
    }

    pub fn mc(&self) -> Arc<Cache> {
        self.lock().mc.clone().expect("map source without a cache")
    }

    pub fn instances(&self) -> Vec<Arc<MapSource>> {
        self.lock().instances.clone()
    }
}

/// A `struct autofs_point`'s fields.
#[derive(Debug)]
pub struct AutofsPointData {
    pub path: Vec<u8>,
    pub pref: Option<Vec<u8>>,
    pub negative_timeout: u32,
    pub positive_timeout: u32,
    pub exp_timeout: i64,
    pub exp_runfreq: i64,
    pub flags: u32,
    pub ty: u32,
    pub logopt: u32,
    pub submount: bool,
    pub mode: u64,
}

/// A `struct autofs_point`.
#[derive(Debug)]
pub struct AutofsPoint {
    pub d: Mutex<AutofsPointData>,
    pub entry: Weak<MasterMapent>,
    pub parent: Option<Arc<AutofsPoint>>,
}

impl AutofsPoint {
    pub fn lock(&self) -> MutexGuard<'_, AutofsPointData> {
        self.d.lock().unwrap()
    }

    pub fn logopt(&self) -> u32 {
        self.lock().logopt
    }

    pub fn ty(&self) -> u32 {
        self.lock().ty
    }

    pub fn path(&self) -> Vec<u8> {
        self.lock().path.clone()
    }

    pub fn entry(&self) -> Arc<MasterMapent> {
        self.entry.upgrade().expect("autofs point without its entry")
    }
}

/// A `struct master_mapent`'s fields.
#[derive(Debug)]
pub struct MasterMapentData {
    pub age: i64,
    pub maps: Vec<Arc<MapSource>>,
    pub ap: Option<Arc<AutofsPoint>>,
}

/// A `struct master_mapent`.
#[derive(Debug)]
pub struct MasterMapent {
    pub path: Vec<u8>,
    pub d: Mutex<MasterMapentData>,
}

impl MasterMapent {
    pub fn lock(&self) -> MutexGuard<'_, MasterMapentData> {
        self.d.lock().unwrap()
    }

    pub fn ap(&self) -> Arc<AutofsPoint> {
        self.lock().ap.clone().expect("entry without an autofs point")
    }

    pub fn maps(&self) -> Vec<Arc<MapSource>> {
        self.lock().maps.clone()
    }
}

/// A `struct master`'s fields.
#[derive(Debug)]
pub struct MasterData {
    pub name: Vec<u8>,
    pub nc: Option<Arc<Cache>>,
    pub recurse: bool,
    pub depth: u32,
    pub read_fail: bool,
    pub readall: bool,
    pub default_ghost: u32,
    pub default_logging: u32,
    pub default_timeout: u32,
    pub logopt: u32,
    pub mounts: Vec<Arc<MasterMapent>>,
}

/// A `struct master`.
#[derive(Debug)]
pub struct Master {
    pub d: Mutex<MasterData>,
}

impl Master {
    pub fn lock(&self) -> MutexGuard<'_, MasterData> {
        self.d.lock().unwrap()
    }

    pub fn name(&self) -> Vec<u8> {
        self.lock().name.clone()
    }

    pub fn set_name(&self, n: Vec<u8>) {
        self.lock().name = n;
    }

    pub fn logopt(&self) -> u32 {
        self.lock().logopt
    }

    pub fn mounts(&self) -> Vec<Arc<MasterMapent>> {
        self.lock().mounts.clone()
    }
}

/// `master_list`.
pub static MASTER_LIST: Mutex<Option<Arc<Master>>> = Mutex::new(None);

pub fn master_list() -> Arc<Master> {
    MASTER_LIST.lock().unwrap().clone().expect("no master list")
}

/// The daemon's globals that the master map code reads.
#[derive(Debug, Default)]
pub struct Globals {
    pub negative_timeout: i64,
    pub positive_timeout: i64,
    pub selection_options: u32,
    pub global_options: Option<Vec<u8>>,
}

pub static GLOBALS: Mutex<Globals> =
    Mutex::new(Globals { negative_timeout: -1, positive_timeout: -1, selection_options: 0, global_options: None });

/// `master_get_logopt()`.
pub fn master_get_logopt() -> u32 {
    MASTER_LIST.lock().unwrap().as_ref().map_or(log::LOGOPT_NONE, |m| m.logopt())
}

/// `master_new()`.
pub fn master_new(name: Option<&[u8]>, timeout: u32, flags: u32) -> Arc<Master> {
    let name = match name {
        None => defaults::defaults_get_master_map(),
        Some(n) => cstr::c(n).to_vec(),
    };
    let logging = defaults::defaults_get_logging();
    Arc::new(Master {
        d: Mutex::new(MasterData {
            name,
            nc: None,
            recurse: false,
            depth: 0,
            read_fail: false,
            readall: false,
            default_ghost: flags & DAEMON_FLAGS_GHOST,
            default_timeout: timeout,
            default_logging: logging,
            logopt: logging,
            mounts: Vec::new(),
        }),
    })
}

/// `master_new_mapent()`.
pub fn master_new_mapent(path: &[u8], age: i64) -> Arc<MasterMapent> {
    Arc::new(MasterMapent {
        path: cstr::c(path).to_vec(),
        d: Mutex::new(MasterMapentData { age, maps: Vec::new(), ap: None }),
    })
}

/// `master_find_mapent()`.
pub fn master_find_mapent(master: &Master, path: &[u8]) -> Option<Arc<MasterMapent>> {
    master.mounts().into_iter().find(|e| cstr::eq(&e.path, path))
}

/// `master_add_mapent()`.
pub fn master_add_mapent(master: &Master, entry: Arc<MasterMapent>) {
    master.lock().mounts.push(entry);
}

/// `master_add_autofs_point()`.
pub fn master_add_autofs_point(entry: &Arc<MasterMapent>, logopt: u32, nobind: bool, ghost: bool, submount: bool) {
    let g = GLOBALS.lock().unwrap();
    let negative_timeout =
        if g.negative_timeout <= 0 { defaults::defaults_get_negative_timeout() } else { g.negative_timeout as u32 };
    let positive_timeout =
        if g.positive_timeout < 0 { defaults::defaults_get_positive_timeout() } else { g.positive_timeout as u32 };
    drop(g);
    let mut flags = 0;
    if defaults::defaults_get_use_ignore_mount_option() != 0 {
        flags = MOUNT_FLAG_IGNORE;
    }
    if ghost {
        flags |= MOUNT_FLAG_GHOST;
    }
    if nobind {
        flags |= MOUNT_FLAG_NOBIND;
    }
    let path = entry.path.clone();
    let ty = if path.get(1) == Some(&b'-') { LKP_DIRECT } else { LKP_INDIRECT };
    let ap = Arc::new(AutofsPoint {
        d: Mutex::new(AutofsPointData {
            path,
            pref: None,
            negative_timeout,
            positive_timeout,
            exp_timeout: defaults::defaults_get_timeout() as i64,
            exp_runfreq: 0,
            flags,
            ty,
            logopt,
            submount,
            mode: 0,
        }),
        entry: Arc::downgrade(entry),
        parent: None,
    });
    entry.lock().ap = Some(ap);
}

fn compare_source_type_and_format(map: &MapSourceData, ty: Option<&[u8]>, format: Option<&[u8]>) -> bool {
    let same = |a: Option<&[u8]>, b: &Option<Vec<u8>>| match (a, b) {
        (Some(a), Some(b)) => cstr::eq(a, b),
        (None, None) => true,
        _ => false,
    };
    same(ty, &map.ty) && same(format, &map.format)
}

fn new_source_data(ty: Option<&[u8]>, format: Option<&[u8]>, age: i64, argv: &Argv) -> MapSourceData {
    let mut flags = 0;
    if format.is_some_and(|f| cstr::eq(f, b"amd")) {
        flags |= MAP_FLAG_FORMAT_AMD;
    }
    MapSourceData {
        ty: ty.map(|t| cstr::c(t).to_vec()),
        format: format.map(|f| cstr::c(f).to_vec()),
        name: None,
        flags,
        age,
        master_line: 0,
        mc: None,
        stale: true,
        recurse: false,
        depth: 0,
        argv: args::copy_argv(argv),
        lookup: None,
        instances: Vec::new(),
        exp_timeout: 0,
        refcnt: 0,
    }
}

/// `master_add_map_source()`.
pub fn master_add_map_source(
    entry: &Arc<MasterMapent>,
    ty: Option<&[u8]>,
    format: Option<&[u8]>,
    age: i64,
    argv: &Argv,
) -> Arc<MapSource> {
    let mut d = new_source_data(ty, format, age, argv);
    d.refcnt = 1;
    d.name = args::arg(&d.argv, 0).map(|a| a.to_vec());
    let maps = entry.maps();
    if !maps.is_empty()
        && let Some(this) = maps.iter().find(|m| {
            let md = m.lock();
            compare_source_type_and_format(&md, ty, format) && args::compare_argv(&md.argv, argv)
        })
    {
        let ap = entry.ap();
        debug!(ap.logopt(), "master_add_map_source", "map source used without taking reference");
        this.lock().age = age;
        return this.clone();
    }
    d.mc = Some(Arc::new(Cache::init()));
    let source = MapSource::new(d);
    entry.lock().maps.push(source.clone());
    source
}

/// `master_find_source_instance()`.
pub fn master_find_source_instance(
    source: &MapSource,
    ty: Option<&[u8]>,
    format: Option<&[u8]>,
    argv: Option<&Argv>,
) -> Option<Arc<MapSource>> {
    for map in source.instances() {
        let md = map.lock();
        if !compare_source_type_and_format(&md, ty, format) {
            continue;
        }
        match argv {
            None => return Some(map.clone()),
            Some(a) => {
                if args::compare_argv(&md.argv, a) {
                    return Some(map.clone());
                }
            }
        }
    }
    None
}

/// `master_add_source_instance()`.
pub fn master_add_source_instance(
    source: &Arc<MapSource>,
    ty: Option<&[u8]>,
    format: Option<&[u8]>,
    age: i64,
    argv: &Argv,
) -> Arc<MapSource> {
    if let Some(i) = master_find_source_instance(source, ty, format, Some(argv)) {
        return i;
    }
    let mut d = new_source_data(ty, format, age, argv);
    {
        let s = source.lock();
        d.mc = s.mc.clone();
        d.exp_timeout = s.exp_timeout;
        d.name = s.name.clone();
    }
    let new = MapSource::new(d);
    source.lock().instances.insert(0, new.clone());
    new
}

/// `check_stale_instances()`.
pub fn check_stale_instances(source: &MapSource) -> bool {
    for map in source.instances() {
        if map.lock().stale {
            return true;
        }
        if check_stale_instances(&map) {
            return true;
        }
    }
    false
}

/// `clear_stale_instances()`.
pub fn clear_stale_instances(source: &MapSource) {
    for map in source.instances() {
        clear_stale_instances(&map);
        map.lock().stale = false;
    }
}

/// `set_exp_timeout()`.
pub fn set_exp_timeout(ap: &AutofsPoint, source: Option<&MapSource>, timeout: i64) {
    ap.lock().exp_timeout = timeout;
    if let Some(s) = source {
        s.lock().exp_timeout = timeout;
    }
}

/// `get_exp_timeout()`.
pub fn get_exp_timeout(ap: &AutofsPoint, source: Option<&MapSource>) -> i64 {
    let a = ap.lock();
    match source {
        Some(s) if a.ty == LKP_DIRECT => s.lock().exp_timeout,
        _ => a.exp_timeout,
    }
}

/// Close a map source's lookup modules, its instances' first
/// (`__master_free_map_source()`'s module part).
pub fn master_free_map_source(source: &MapSource) {
    {
        let mut s = source.lock();
        if s.refcnt > 0 {
            s.refcnt -= 1;
            if s.refcnt > 0 {
                return;
            }
        }
    }
    let lookup = source.lock().lookup.take();
    if let Some(l) = lookup {
        for inst in source.instances() {
            let il = inst.lock().lookup.take();
            if let Some(il) = il {
                il.done();
            }
        }
        l.done();
    }
    for inst in source.instances() {
        master_free_map_source(&inst);
    }
    source.lock().instances.clear();
}

/// `master_free_mapent_sources()`.
pub fn master_free_mapent_sources(entry: &MasterMapent) {
    let maps = std::mem::take(&mut entry.lock().maps);
    for m in maps {
        master_free_map_source(&m);
    }
}

fn print(s: &[u8]) {
    log::print(s);
}

/// What `printf("%s")` prints for a string that may be NULL.
pub fn cstr_or_null(s: &Option<Vec<u8>>) -> Vec<u8> {
    s.clone().unwrap_or_else(|| b"(null)".to_vec())
}

/// `list_source_instances()`: the instance types, the last added first (C
/// recurses to the end of the list before printing).
fn list_source_instances(source: &MapSource, instances: &[Arc<MapSource>]) {
    if instances.is_empty() {
        print(b"none");
        return;
    }
    for inst in instances.iter().rev() {
        let ty = inst.ty().unwrap_or_default();
        if !cstr::eq(&ty, b"file") {
            print(&bfmt!("{} ", ty));
        } else {
            let argv = source.argv();
            match argv.first() {
                Some(Some(a0)) if a0.first() != Some(&b'/') => print(b"files "),
                _ => print(&bfmt!("{} ", ty)),
            }
        }
    }
}

/// `print_map_info()`.
fn print_map_info(source: &MapSource) {
    let (ty, argv) = {
        let s = source.lock();
        (s.ty.clone(), s.argv.clone())
    };
    let argc = argv.len();
    let multi = ty.as_deref().is_some_and(|t| cstr::eq(t, b"multi"));
    let mut map_num = 1;
    let mut i = 0;
    while i < argc {
        if let Some(a) = &argv[i]
            && a.first() != Some(&b'-')
        {
            if !multi {
                print(&bfmt!("  map: {}\n", a));
            } else {
                print(&bfmt!("  map[{}]: {}\n", map_num, a));
            }
            i += 1;
        }
        if i >= argc {
            return;
        }
        if argv[i].as_deref().is_some_and(|a| cstr::eq(a, b"--")) {
            i += 1;
            continue;
        }
        if argv[i].is_some() {
            let mut need_newline = false;
            if !multi {
                print(b"  arguments:");
            } else {
                print(&bfmt!("  arguments[{}]:", map_num));
            }
            let mut j = i;
            while j < argc {
                let aj = argv[j].clone().unwrap_or_default();
                if cstr::eq(&aj, b"--") {
                    break;
                }
                print(&bfmt!(" {}", aj));
                i += 1;
                need_newline = true;
                j += 1;
            }
            if need_newline {
                print(b"\n");
            }
        }
        if multi {
            map_num += 1;
        }
        i += 1;
    }
}

/// `match_type()`.
fn match_type(source: &[u8], ty: &[u8]) -> bool {
    if cstr::eq(source, ty) {
        return true;
    }
    // Sources file and files are synonymous.
    cstr::neq(source, ty, 4) && cstr::c(source).len() <= 5
}

/// `get_map_name()`.
fn get_map_name(s: &[u8]) -> Vec<u8> {
    let tmp = cstr::c(s);
    let base_start = tmp.len() - cstr::gnu_basename(tmp).len();
    let mut buf = tmp.to_vec();
    if let Some(comma) = cstr::strchr(&buf[base_start..], b',') {
        buf.truncate(base_start + comma);
    }
    let start = match cstr::strchr(&buf, b'=') {
        Some(e) => e + 1,
        None => match cstr::strrchr(&buf[base_start.min(buf.len())..], b':') {
            Some(c) => base_start + c + 1,
            None => base_start.min(buf.len()),
        },
    };
    buf[start.min(buf.len())..].to_vec()
}

/// `match_name()`.
fn match_name(source: &MapSource, name: &[u8]) -> bool {
    let argv = source.argv();
    let argc = argv.len();
    let mut i = 0;
    while i < argc {
        let is_dd = argv[i].as_deref().is_some_and(|a| cstr::eq(a, b"--"));
        if i == 0 || is_dd {
            if i != 0 {
                i += 1;
                if i >= argc {
                    break;
                }
            }
            if let Some(a) = &argv[i]
                && a.first() != Some(&b'-')
            {
                let map = get_map_name(a);
                if cstr::eq(&map, name) {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// `dump_map()`.
pub fn dump_map(master: &Master, ty: &[u8], name: &[u8]) -> i32 {
    let mounts = master.mounts();
    if mounts.is_empty() {
        print(b"no master map entries found\n");
        return 1;
    }
    for this in mounts {
        let ap = this.ap();
        let now = sys::monotonic_time();
        if ap.ty() == LKP_INDIRECT {
            ap.lock().flags |= MOUNT_FLAG_GHOST;
        }
        if lookup::lookup_nss_read_map(&ap, None, now) {
            lookup::lookup_prune_cache(&ap, now);
        } else {
            print(b"failed to read map\n");
            lookup::lookup_close_lookup(&ap);
            continue;
        }
        let maps = this.maps();
        if maps.is_empty() {
            print(&bfmt!("no map sources found for {}\n", ap.path()));
            lookup::lookup_close_lookup(&ap);
            continue;
        }
        for source in &maps {
            let instance = match source.ty() {
                Some(st) => {
                    if !match_type(&st, ty) || !match_name(source, name) {
                        continue;
                    }
                    source.clone()
                }
                None => {
                    let found = source
                        .instances()
                        .into_iter()
                        .find(|map| map.ty().is_some_and(|mt| match_type(&mt, ty)) && match_name(map, name));
                    match found {
                        Some(i) => i,
                        None => {
                            lookup::lookup_close_lookup(&ap);
                            continue;
                        }
                    }
                }
            };
            let mc = source.mc();
            let c = mc.lock();
            match c.lookup_first() {
                None => print(b"no keys found in map\n"),
                Some(mut p) => loop {
                    let me = c.get(p);
                    if me.source == instance.id {
                        print(&bfmt!("{}\t{}\n", me.key, cstr_or_null(&me.mapent)));
                    }
                    match c.lookup_next(p) {
                        Some(n) => p = n,
                        None => break,
                    }
                },
            }
            drop(c);
            lookup::lookup_close_lookup(&ap);
            return 1;
        }
        lookup::lookup_close_lookup(&ap);
    }
    0
}

/// `master_show_mounts()`.
pub fn master_show_mounts(master: &Master) -> i32 {
    print(b"\nautofs dump map information\n===========================\n\n");
    print(b"global options: ");
    let gopts = GLOBALS.lock().unwrap().global_options.clone();
    match gopts {
        None => print(b"none configured\n"),
        Some(g) => {
            print(&bfmt!("{}\n", g));
            let append = if defaults::defaults_get_append_options() != 0 { "will" } else { "will not" };
            print(&bfmt!("global options {} be appended to map entries\n", append));
        }
    }
    let mounts = master.mounts();
    if mounts.is_empty() {
        print(b"no master map entries found\n\n");
        return 1;
    }
    for this in mounts {
        let ap = this.ap();
        let now = sys::monotonic_time();
        print(&bfmt!("\nMount point: {}\n", ap.path()));
        print(b"\nsource(s):\n");
        if ap.ty() == LKP_INDIRECT {
            ap.lock().flags |= MOUNT_FLAG_GHOST;
        }
        if lookup::lookup_nss_read_map(&ap, None, now) {
            lookup::lookup_prune_cache(&ap, now);
        } else {
            print(b"  failed to read map\n\n");
            continue;
        }
        let maps = this.maps();
        if maps.is_empty() {
            print(b"  no map sources found\n\n");
            continue;
        }
        for (count, source) in maps.iter().enumerate() {
            match source.ty() {
                Some(t) => print(&bfmt!("\n  type: {}\n", t)),
                None => {
                    print(b"\n  instance type(s): ");
                    list_source_instances(source, &source.instances());
                    print(b"\n");
                }
            }
            if !source.argv().is_empty() {
                print_map_info(source);
                if count > 0 && ap.ty() == LKP_INDIRECT {
                    print(b"  duplicate indirect map entry will be ignored at run time\n");
                }
            }
            print(b"\n");
            let mc = source.mc();
            let c = mc.lock();
            match c.lookup_first() {
                None => print(b"  no keys found in map\n"),
                Some(mut p) => loop {
                    let me = c.get(p);
                    print(&bfmt!("  {} | {}\n", me.key, cstr_or_null(&me.mapent)));
                    match c.lookup_next(p) {
                        Some(n) => p = n,
                        None => break,
                    }
                },
            }
        }
        lookup::lookup_close_lookup(&ap);
        print(b"\n");
    }
    1
}
