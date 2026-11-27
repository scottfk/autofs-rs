//! `lib/cache.c`: the map entry cache, a hash of chains of entries
//! (`map_hash_table_size` buckets, 64 for the null map cache), shared by a map
//! source and its instances.
//!
//! Chains are kept as ordered lists so iteration (and with it `--dumpmaps`'
//! output) follows C's: bucket by bucket, each chain from its head; a new key
//! goes to the head of its chain.
//!
//! QUIRK: adding a second entry for a key that is already cached links it after
//! the key's last entry with `existing->next = me`, dropping whatever followed
//! that entry in the chain (other keys that hashed to the same bucket).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use crate::libautofs::cstr;
use crate::libautofs::defaults;
use crate::sys;

pub const CHE_FAIL: i32 = 0x0000;
pub const CHE_OK: i32 = 0x0001;
pub const CHE_UPDATED: i32 = 0x0002;
pub const CHE_MISSING: i32 = 0x0008;
pub const CHE_COMPLETED: i32 = 0x0010;
pub const CHE_UNAVAIL: i32 = 0x0040;
pub const CHE_DUPLICATE: i32 = 0x0020;

const NULL_MAP_HASHSIZE: u32 = 64;

/// A `struct mapent`. `source` is the owning map source's id (0 for none).
#[derive(Debug, Clone)]
pub struct Mapent {
    pub key: Vec<u8>,
    pub mapent: Option<Vec<u8>>,
    pub age: i64,
    pub status: i64,
    pub source: usize,
    /// Identity (C's pointer), unique across caches.
    pub id: u64,
    /// The multi-mount the entry belongs to (`mm_root`: its root entry's id,
    /// the entry's own for the root) and its nesting point (`mm_parent`).
    pub mm_root: Option<u64>,
    pub mm_parent: Option<u64>,
    /// The offset tree (`node.left`, `node.right`), as entry ids.
    pub left: Option<u64>,
    pub right: Option<u64>,
    /// Position in the device/inode index (`ino_index`): 0 when not in it,
    /// higher for the more recently added (C adds at the head).
    pub ino_seq: u64,
    pub ioctlfd: i32,
    pub dev: u64,
    pub ino: u64,
    pub flags: u32,
    /// The pushed-down map entries (`struct stack`), top first: (mapent, age).
    pub stack: Vec<(Option<Vec<u8>>, i64)>,
}

static NEXT_ENTRY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

impl Mapent {
    /// `IS_MM(me)`.
    pub fn is_mm(&self) -> bool {
        self.mm_root.is_some()
    }

    /// `IS_MM_ROOT(me)`.
    pub fn is_mm_root(&self) -> bool {
        self.mm_root == Some(self.id)
    }

    /// `IS_MM(me) && !IS_MM_ROOT(me)`: multi-mount entries that aren't primary.
    pub fn mm_nonroot(&self) -> bool {
        self.is_mm() && !self.is_mm_root()
    }
}

/// The cache's contents (held under its lock).
#[derive(Debug)]
pub struct CacheInner {
    pub size: u32,
    pub hash: Vec<Vec<Mapent>>,
}

/// A `struct mapent_cache`.
#[derive(Debug)]
pub struct Cache {
    pub id: usize,
    inner: Mutex<CacheInner>,
}

static NEXT_ID: AtomicUsize = AtomicUsize::new(1);

/// `hash(key, size)`; a size of 0 divides by zero as C does.
fn hash(key: &[u8], size: u32) -> usize {
    if size == 0 {
        sys::die_by_signal(libc::SIGFPE);
    }
    defaults::hash(key, size) as usize
}

impl Cache {
    fn with_size(size: u32) -> Cache {
        Cache {
            id: NEXT_ID.fetch_add(1, Ordering::Relaxed),
            inner: Mutex::new(CacheInner { size, hash: vec![Vec::new(); size as usize] }),
        }
    }

    /// `cache_init()`.
    pub fn init() -> Cache {
        Cache::with_size(defaults::defaults_get_map_hash_table_size())
    }

    /// `cache_init_null_cache()`.
    pub fn init_null() -> Cache {
        Cache::with_size(NULL_MAP_HASHSIZE)
    }

    /// The cache lock (`cache_readlock()`/`cache_writelock()`).
    pub fn lock(&self) -> MutexGuard<'_, CacheInner> {
        self.inner.lock().unwrap()
    }
}

/// A position in the cache: (bucket, index in the chain).
pub type Pos = (usize, usize);

impl CacheInner {
    pub fn get(&self, p: Pos) -> &Mapent {
        &self.hash[p.0][p.1]
    }

    pub fn get_mut(&mut self, p: Pos) -> &mut Mapent {
        &mut self.hash[p.0][p.1]
    }

    /// `cache_lookup_first()`.
    pub fn lookup_first(&self) -> Option<Pos> {
        self.next_from(0, 0)
    }

    #[allow(clippy::needless_range_loop)]
    fn next_from(&self, bucket: usize, idx: usize) -> Option<Pos> {
        for b in bucket..self.size as usize {
            let start = if b == bucket { idx } else { 0 };
            for (i, me) in self.hash[b].iter().enumerate().skip(start) {
                if me.mm_nonroot() {
                    continue;
                }
                return Some((b, i));
            }
        }
        None
    }

    /// `cache_lookup_next()`.
    pub fn lookup_next(&self, p: Pos) -> Option<Pos> {
        self.next_from(p.0, p.1 + 1)
    }

    /// `cache_enumerate()`.
    pub fn enumerate(&self, p: Option<Pos>) -> Option<Pos> {
        match p {
            None => self.lookup_first(),
            Some(p) => self.lookup_next(p),
        }
    }

    /// `cache_lookup_distinct()`.
    pub fn lookup_distinct(&self, key: &[u8]) -> Option<Pos> {
        let h = hash(key, self.size);
        self.hash[h].iter().position(|me| cstr::eq(key, &me.key)).map(|i| (h, i))
    }

    /// `cache_lookup()`: the key, or else the wildcard entry (not in a direct map).
    pub fn lookup(&self, key: &[u8]) -> Option<Pos> {
        if let Some(p) = self.lookup_distinct(key) {
            return Some(p);
        }
        let first = self.lookup_first()?;
        if self.get(first).key.first() == Some(&b'/') {
            return None;
        }
        let h = hash(b"*", self.size);
        self.hash[h].iter().position(|me| me.key == b"*").map(|i| (h, i))
    }

    /// The entry with this id.
    pub fn by_id(&self, id: u64) -> Option<Pos> {
        for (b, chain) in self.hash.iter().enumerate() {
            if let Some(i) = chain.iter().position(|m| m.id == id) {
                return Some((b, i));
            }
        }
        None
    }

    /// `cache_set_ino_index()`.
    pub fn set_ino_index(&mut self, p: Pos) {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        self.get_mut(p).ino_seq = SEQ.fetch_add(1, Ordering::Relaxed);
    }

    /// `cache_lookup_ino()`: the most recently indexed entry with this device
    /// and inode.
    pub fn lookup_ino(&self, dev: u64, ino: u64) -> Option<Pos> {
        let mut best: Option<(u64, Pos)> = None;
        for (b, chain) in self.hash.iter().enumerate() {
            for (i, me) in chain.iter().enumerate() {
                if me.ino_seq != 0 && me.dev == dev && me.ino == ino && best.is_none_or(|(s, _)| me.ino_seq > s) {
                    best = Some((me.ino_seq, (b, i)));
                }
            }
        }
        best.map(|(_, p)| p)
    }

    /// `cache_update_offset()`: add or update the offset `key` of the
    /// multi-mount `mkey` (`CHE_DUPLICATE` for one already seen in this read).
    pub fn update_offset(&mut self, logopt: u32, mkey: &[u8], key: &[u8], mapent: &[u8], age: i64) -> i32 {
        let Some(owner) = self.lookup_distinct(mkey) else { return CHE_FAIL };
        let (owner_id, owner_source) = (self.get(owner).id, self.get(owner).source);
        if let Some(p) = self.lookup_distinct(key)
            && self.get(p).age == age
            && (self.get(p).id == owner_id || cstr::eq(&self.get(p).key, key))
        {
            let k = self.get(p).key.clone();
            warn!(logopt, "duplcate offset detected for key {}", k);
            self.get_mut(p).mapent = Some(cstr::c(mapent).to_vec());
            warn!(logopt, "map entry updated with: {}", mapent);
            return CHE_DUPLICATE;
        }
        let ret = self.update(owner_source, key, Some(mapent), age);
        if ret == CHE_FAIL {
            warn!(logopt, "failed to add key {} to cache", key);
            return CHE_FAIL;
        }
        ret
    }

    /// `cache_get_offset_parent()`: the nearest offset above `key`.
    pub fn get_offset_parent(&self, key: &[u8]) -> Option<Pos> {
        let key = cstr::c(key);
        if key.last() == Some(&b'/') {
            return None;
        }
        let mut parent = key.to_vec();
        let mut tail = parent.len() as isize - 1;
        loop {
            if tail < 0 || parent[tail as usize] == 0 {
                break;
            }
            while tail >= 0 && parent[tail as usize] != b'/' {
                tail -= 1;
            }
            if tail < 0 {
                return None;
            }
            parent[tail as usize] = 0;
            tail -= 1;
            if tail <= 0 {
                break;
            }
            if let Some(p) = self.lookup_distinct(&parent[..(tail + 1) as usize]) {
                return Some(p);
            }
        }
        None
    }

    /// `cache_clean_null_cache()`: empty the cache.
    pub fn clean(&mut self) {
        for chain in self.hash.iter_mut() {
            chain.clear();
        }
    }

    /// `cache_partial_match()`: the first entry (bucket by bucket) whose key is
    /// `prefix/...`.
    pub fn partial_match(&self, prefix: &[u8]) -> Option<Pos> {
        let prefix = cstr::c(prefix);
        let len = prefix.len();
        for (b, chain) in self.hash.iter().enumerate() {
            for (i, me) in chain.iter().enumerate() {
                let k = cstr::c(&me.key);
                if len < k.len() && k.starts_with(prefix) && k[len] == b'/' {
                    return Some((b, i));
                }
            }
        }
        None
    }

    /// `cache_partial_match_wild()`: the first entry (bucket by bucket) whose
    /// key is `prefix/*...`.
    pub fn partial_match_wild(&self, prefix: &[u8]) -> Option<Pos> {
        let prefix = cstr::c(prefix);
        let len = prefix.len();
        for (b, chain) in self.hash.iter().enumerate() {
            for (i, me) in chain.iter().enumerate() {
                let k = cstr::c(&me.key);
                if len < k.len() && k.starts_with(prefix) && k[len] == b'/' && k.get(len + 1) == Some(&b'*') {
                    return Some((b, i));
                }
            }
        }
        None
    }

    /// `cache_lookup_key_next()`: the next entry in the chain with the same key.
    pub fn lookup_key_next(&self, p: Pos) -> Option<Pos> {
        let me = self.get(p);
        if me.mm_nonroot() {
            // QUIRK: C loops forever here (it tests `me`, not `next`).
            loop {
                std::thread::park();
            }
        }
        let chain = &self.hash[p.0];
        (p.1 + 1..chain.len()).find(|&i| cstr::eq(&me.key, &chain[i].key)).map(|i| (p.0, i))
    }

    /// `cache_add()`.
    pub fn add(&mut self, source: usize, key: &[u8], mapent: Option<&[u8]>, age: i64) -> i32 {
        let h = hash(key, self.size);
        let me = Mapent {
            key: cstr::c(key).to_vec(),
            mapent: mapent.map(|m| cstr::c(m).to_vec()),
            age,
            status: 0,
            source,
            id: NEXT_ENTRY.fetch_add(1, Ordering::Relaxed),
            mm_root: None,
            mm_parent: None,
            left: None,
            right: None,
            ino_seq: 0,
            ioctlfd: -1,
            dev: u64::MAX,
            ino: u64::MAX,
            flags: 0,
            stack: Vec::new(),
        };
        match self.lookup_distinct(key) {
            None => self.hash[h].insert(0, me),
            Some(mut existing) => {
                while let Some(n) = self.lookup_key_next(existing) {
                    existing = n;
                }
                // QUIRK: existing->next = me drops the rest of the chain.
                let chain = &mut self.hash[existing.0];
                chain.truncate(existing.1 + 1);
                chain.push(me);
            }
        }
        CHE_OK
    }

    /// `cache_update()`.
    pub fn update(&mut self, source: usize, key: &[u8], mapent: Option<&[u8]>, age: i64) -> i32 {
        let mut me = self.lookup(key);
        while let Some(p) = me {
            if self.get(p).source == source {
                break;
            }
            me = self.lookup_key_next(p);
        }
        match me {
            Some(p) if !(self.get(p).key == b"*" && !cstr::eq(key, b"*")) => {
                let e = self.get_mut(p);
                if e.age == age {
                    return CHE_OK;
                }
                let mut ret = CHE_OK;
                match mapent {
                    None => e.mapent = None,
                    Some(m) => {
                        if e.mapent.as_deref().is_none_or(|old| !cstr::eq(old, m)) {
                            e.mapent = Some(cstr::c(m).to_vec());
                            ret = CHE_UPDATED;
                        }
                    }
                }
                e.age = age;
                ret
            }
            _ => {
                self.add(source, key, mapent, age);
                CHE_UPDATED
            }
        }
    }

    /// `cache_push_mapent()`.
    pub fn push_mapent(&mut self, p: Pos, mapent: Option<&[u8]>) -> i32 {
        let me = self.get_mut(p);
        let Some(old) = me.mapent.take() else { return CHE_FAIL };
        me.stack.insert(0, (Some(old), me.age));
        me.mapent = mapent.map(|m| cstr::c(m).to_vec());
        CHE_OK
    }

    /// `cache_pop_mapent()`.
    pub fn pop_mapent(&mut self, p: Pos) -> i32 {
        let me = self.get_mut(p);
        match me.stack.first() {
            Some((Some(_), _)) => {}
            _ => return CHE_FAIL,
        }
        let (m, age) = me.stack.remove(0);
        if age < me.age {
            return CHE_OK;
        }
        me.mapent = m;
        CHE_OK
    }

    /// `cache_lookup_negative()`: `CHE_UNAVAIL` while the negative timeout
    /// hasn't passed; else drop an expired entry that has no map entry.
    pub fn lookup_negative(&mut self, p: Pos, key: &[u8]) -> i32 {
        if self.get(p).status >= sys::monotonic_time() {
            return CHE_UNAVAIL;
        }
        if self.get(p).mapent.is_none()
            && let Some(sp) = self.lookup_distinct(key)
            && self.get(sp).mapent.is_none()
            && self.pop_mapent(sp) == CHE_FAIL
        {
            self.delete(key);
        }
        CHE_OK
    }

    /// `cache_update_negative()`.
    pub fn update_negative(&mut self, source: usize, key: &[u8], timeout: i64) {
        let now = sys::monotonic_time();
        if key == b"*" {
            return;
        }
        let rv = match self.lookup_distinct(key) {
            Some(p) => self.push_mapent(p, None),
            None => self.update(source, key, None, now),
        };
        if rv != CHE_FAIL
            && let Some(p) = self.lookup_distinct(key)
        {
            self.get_mut(p).status = now + timeout;
        }
    }

    /// `cache_delete()`.
    pub fn delete(&mut self, key: &[u8]) -> i32 {
        let h = hash(key, self.size);
        let chain = &mut self.hash[h];
        if chain.is_empty() {
            return CHE_OK;
        }
        // Everything after the head first, then the head.
        let mut i = 1;
        while i < chain.len() {
            if cstr::eq(key, &chain[i].key) {
                if chain[i].is_mm() {
                    return CHE_FAIL;
                }
                chain.remove(i);
                continue;
            }
            i += 1;
        }
        if cstr::eq(key, &chain[0].key) {
            if chain[0].is_mm() {
                return CHE_FAIL;
            }
            chain.remove(0);
        }
        CHE_OK
    }
}
