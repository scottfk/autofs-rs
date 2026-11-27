//! pthread-style locks, for the daemon's C locking patterns that Rust's scoped
//! guards can't express: a mutex locked in one function and unlocked in
//! another (`master_mutex`, `st_mutex`), condition variables waited on with
//! it, and a read-write lock with `trywrlock` (`entry->source_lock`).
//!
//! Each is a flag (or counts) under a std mutex, with std condition variables
//! for the waits. They aren't recursive and don't check ownership, as the
//! default pthread types aren't and don't.

use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

#[derive(Debug, Default)]
struct MState {
    locked: bool,
}

/// A `pthread_mutex_t` (`PTHREAD_MUTEX_INITIALIZER`).
#[derive(Debug)]
pub struct CMutex {
    m: Mutex<MState>,
    cv: Condvar,
}

impl Default for CMutex {
    fn default() -> Self {
        Self::new()
    }
}

impl CMutex {
    pub const fn new() -> CMutex {
        CMutex { m: Mutex::new(MState { locked: false }), cv: Condvar::new() }
    }

    fn inner(&self) -> MutexGuard<'_, MState> {
        self.m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `pthread_mutex_lock()`.
    pub fn lock(&self) {
        let mut g = self.inner();
        while g.locked {
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        g.locked = true;
    }

    /// `pthread_mutex_trylock()`: whether it was taken.
    pub fn trylock(&self) -> bool {
        let mut g = self.inner();
        if g.locked {
            return false;
        }
        g.locked = true;
        true
    }

    /// `pthread_mutex_unlock()`.
    pub fn unlock(&self) {
        let mut g = self.inner();
        g.locked = false;
        drop(g);
        self.cv.notify_one();
    }
}

/// A `pthread_cond_t`, always used with one [`CMutex`].
#[derive(Debug, Default)]
pub struct CCond {
    cv: Condvar,
    seq: Mutex<u64>,
}

impl CCond {
    pub const fn new() -> CCond {
        CCond { cv: Condvar::new(), seq: Mutex::new(0) }
    }

    /// `pthread_cond_wait(cond, m)`: `m` (held) is released while waiting and
    /// held again on return. Like pthreads, it may return without a signal, so
    /// callers loop on their predicate.
    pub fn wait(&self, m: &CMutex) {
        self.wait_until(m, None);
    }

    /// `pthread_cond_timedwait()` for at most `d`: false if it timed out.
    pub fn timedwait(&self, m: &CMutex, d: Duration) -> bool {
        self.wait_until(m, Some(d))
    }

    fn wait_until(&self, m: &CMutex, d: Option<Duration>) -> bool {
        // Take the sequence number before letting go of the mutex: a signal
        // sent after that (by whoever takes the mutex next) bumps it.
        let mut s = self.seq.lock().unwrap_or_else(|e| e.into_inner());
        let start = *s;
        m.unlock();
        let mut signaled = true;
        match d {
            None => {
                while *s == start {
                    s = self.cv.wait(s).unwrap_or_else(|e| e.into_inner());
                }
            }
            Some(d) => {
                let (g, r) = self.cv.wait_timeout_while(s, d, |v| *v == start).unwrap_or_else(|e| e.into_inner());
                s = g;
                signaled = !r.timed_out();
            }
        }
        drop(s);
        m.lock();
        signaled
    }

    /// `pthread_cond_signal()`.
    pub fn signal(&self) {
        *self.seq.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.cv.notify_one();
    }

    /// `pthread_cond_broadcast()`.
    pub fn broadcast(&self) {
        *self.seq.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.cv.notify_all();
    }
}

#[derive(Debug, Default)]
struct RwState {
    readers: u32,
    writer: bool,
    waiting_writers: u32,
}

/// A `pthread_rwlock_t` (glibc's default prefers readers, so a waiting writer
/// doesn't hold off new readers).
#[derive(Debug, Default)]
pub struct CRwLock {
    m: Mutex<RwState>,
    cv: Condvar,
}

impl CRwLock {
    pub const fn new() -> CRwLock {
        CRwLock { m: Mutex::new(RwState { readers: 0, writer: false, waiting_writers: 0 }), cv: Condvar::new() }
    }

    fn inner(&self) -> MutexGuard<'_, RwState> {
        self.m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// `pthread_rwlock_rdlock()`.
    pub fn rdlock(&self) {
        let mut g = self.inner();
        while g.writer {
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        g.readers += 1;
    }

    /// `pthread_rwlock_wrlock()`.
    pub fn wrlock(&self) {
        let mut g = self.inner();
        g.waiting_writers += 1;
        while g.writer || g.readers > 0 {
            g = self.cv.wait(g).unwrap_or_else(|e| e.into_inner());
        }
        g.waiting_writers -= 1;
        g.writer = true;
    }

    /// `pthread_rwlock_trywrlock()`: whether it was taken.
    pub fn trywrlock(&self) -> bool {
        let mut g = self.inner();
        if g.writer || g.readers > 0 {
            return false;
        }
        g.writer = true;
        true
    }

    /// `pthread_rwlock_unlock()`.
    pub fn unlock(&self) {
        let mut g = self.inner();
        if g.writer {
            g.writer = false;
        } else if g.readers > 0 {
            g.readers -= 1;
        }
        drop(g);
        self.cv.notify_all();
    }
}
