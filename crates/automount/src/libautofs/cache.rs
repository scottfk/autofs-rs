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

const NULL_MAP_HASHSIZE: u32 = 64;

/// A `struct mapent`. `source` is the owning map source's id (0 for none).
#[derive(Debug, Clone)]
pub struct Mapent {
    pub key: Vec<u8>,
    pub mapent: Option<Vec<u8>>,
    pub age: i64,
    pub status: i64,
    pub source: usize,
    /// `IS_MM(me) && !IS_MM_ROOT(me)`: a multi-mount entry that isn't the root.
    pub mm_nonroot: bool,
    pub mm: bool,
    pub ioctlfd: i32,
    pub dev: u64,
    pub ino: u64,
    pub flags: u32,
    /// The pushed-down map entries (`struct stack`), top first: (mapent, age).
    pub stack: Vec<(Option<Vec<u8>>, i64)>,
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
                if me.mm_nonroot {
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
        if me.mm_nonroot {
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
            mm_nonroot: false,
            mm: false,
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
                if chain[i].mm {
                    return CHE_FAIL;
                }
                chain.remove(i);
                continue;
            }
            i += 1;
        }
        if cstr::eq(key, &chain[0].key) {
            if chain[0].mm {
                return CHE_FAIL;
            }
            chain.remove(0);
        }
        CHE_OK
    }
}
