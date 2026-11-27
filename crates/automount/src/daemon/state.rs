//! `daemon/state.c`: each autofs point's state machine and the task queue the
//! state handler thread runs (expire, prune, map reads, shutdown).
//!
//! The queue, its mutex and condition are global as in C; a point's state is
//! read and changed with the queue mutex (`st_mutex`) held.
//!
//! Where the port differs: C cancels a busy expire or map read thread with
//! `pthread_cancel()`; here the thread sees a cancel request at the points C
//! tests for one explicitly (`pthread_testcancel()`) and between steps, then
//! runs the same cleanup.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::daemon::indirect;
use crate::daemon::lookup;
use crate::daemon::master::{self, AutofsPoint, LKP_INDIRECT};
use crate::libautofs::alarm;
use crate::libautofs::csync::{CCond, CMutex};
use crate::libautofs::dev_ioctl::{self, AUTOFS_EXP_FORCE, AUTOFS_EXP_IMMEDIATE, AUTOFS_EXP_NORMAL};
use crate::sys;

pub const ST_ANY: i32 = -2;
pub const ST_INVAL: i32 = -1;
pub const ST_INIT: i32 = 0;
pub const ST_READY: i32 = 1;
pub const ST_EXPIRE: i32 = 2;
pub const ST_PRUNE: i32 = 3;
pub const ST_READMAP: i32 = 4;
pub const ST_SHUTDOWN_PENDING: i32 = 5;
pub const ST_SHUTDOWN_FORCE: i32 = 6;
pub const ST_SHUTDOWN: i32 = 7;

const CHECK_RATIO: i64 = 4;

/// A `struct state_queue` entry.
struct Task {
    id: u64,
    thid: u64,
    ap: Arc<AutofsPoint>,
    state: i32,
    busy: bool,
    done: bool,
    cancel: bool,
    /// The tasks waiting behind this one (states only; they start fresh).
    pending: Vec<i32>,
}

impl Task {
    fn new(ap: &Arc<AutofsPoint>, state: i32) -> Task {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        let id = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Task { id, thid: 0, ap: ap.clone(), state, busy: false, done: false, cancel: false, pending: Vec::new() }
    }
}

static MUTEX: CMutex = CMutex::new();
static COND: CCond = CCond::new();
static SIGNALED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The queue; only touched with `MUTEX` held.
static QUEUE: Mutex<Vec<Task>> = Mutex::new(Vec::new());
/// Threads asked to cancel (by `pthread_self()` id).
static CANCELED: Mutex<Option<HashSet<u64>>> = Mutex::new(None);

fn queue() -> std::sync::MutexGuard<'static, Vec<Task>> {
    QUEUE.lock().unwrap_or_else(|e| e.into_inner())
}

/// `st_mutex_lock()`.
pub fn st_mutex_lock() {
    MUTEX.lock();
}

/// `st_mutex_unlock()`.
pub fn st_mutex_unlock() {
    MUTEX.unlock();
}

fn state_of(ap: &AutofsPoint) -> i32 {
    ap.lock().state
}

fn set_state(ap: &AutofsPoint, s: i32) {
    ap.lock().state = s;
}

fn pthread_cancel(thid: u64) {
    CANCELED.lock().unwrap().get_or_insert_with(HashSet::new).insert(thid);
}

/// `pthread_testcancel()`: whether this thread has been asked to cancel.
pub fn testcancel() -> bool {
    let me = sys::pthread_self();
    CANCELED.lock().unwrap().as_mut().is_some_and(|s| s.remove(&me))
}

/// `struct expire_args` as the expire thread's cleanup sees it.
#[derive(Debug)]
pub struct ExpireCleanup {
    pub ap: Arc<AutofsPoint>,
    pub status: i32,
}

/// `expire_cleanup()`: the expire thread has finished; pick the next state.
pub fn expire_cleanup(ec: &ExpireCleanup) {
    let thid = sys::pthread_self();
    let ap = &ec.ap;
    let success = ec.status;
    let mut next = ST_INVAL;
    st_mutex_lock();
    let (logopt, path) = (ap.logopt(), ap.path());
    debug!(logopt, "expire_cleanup", "got thid {} path {} stat {}", thid, path, success);
    if thid == ap.lock().exp_thread {
        ap.lock().exp_thread = 0;
        let st = state_of(ap);
        let (submount, ioctlfd, shutdown, runfreq) = {
            let a = ap.lock();
            (a.submount, a.ioctlfd, a.shutdown, a.exp_runfreq)
        };
        match st {
            ST_EXPIRE | ST_PRUNE | ST_READY => {
                let mut done = false;
                if st != ST_READY {
                    if submount
                        && success == 0
                        && let Ok(idle) = dev_ioctl::askumount(logopt, ioctlfd)
                        && idle != 0
                    {
                        next = ST_SHUTDOWN_PENDING;
                        done = true;
                    }
                    if !done && st == ST_EXPIRE {
                        alarm::conditional_alarm_add(ap, runfreq);
                    }
                }
                if !done {
                    next = ST_READY;
                }
            }
            ST_SHUTDOWN_PENDING => {
                // A mount request while trying to shut down returns to ready,
                // unless this is a shutdown on a signal.
                match dev_ioctl::askumount(logopt, ioctlfd) {
                    Ok(idle) if idle == 0 && !shutdown => {
                        next = ST_READY;
                        alarm::conditional_alarm_add(ap, runfreq);
                    }
                    // ENABLE_IGNORE_BUSY_MOUNTS.
                    _ => next = ST_SHUTDOWN,
                }
            }
            ST_SHUTDOWN_FORCE => next = ST_SHUTDOWN,
            s => error!(logopt, "expire_cleanup", "bad state {}", s),
        }
        if next != ST_INVAL {
            debug!(logopt, "expire_cleanup", "sigchld: exp {} finished, switching from {} to {}", thid, st, next);
        }
    }
    st_set_done(ap);
    if next != ST_INVAL {
        st_add_task_locked(ap, next);
    }
    st_mutex_unlock();
}

/// `st_ready()`.
fn st_ready(ap: &AutofsPoint) -> bool {
    debug!(ap.logopt(), "st_ready", "st_ready(): state = {} path {}", state_of(ap), ap.path());
    let mut a = ap.lock();
    a.shutdown = false;
    a.state = ST_READY;
    true
}

const EXP_ERROR: i32 = 0;
const EXP_STARTED: i32 = 1;

/// The start-up handshake of a thread the state machine creates (`ea->mutex`,
/// `ea->cond`, `ea->signaled`): the creator holds `m` until the new thread has
/// its arguments.
#[derive(Debug)]
pub struct Handshake {
    m: CMutex,
    cond: CCond,
    signaled: std::sync::atomic::AtomicBool,
}

impl Default for Handshake {
    fn default() -> Self {
        Self::new()
    }
}

impl Handshake {
    pub fn new() -> Handshake {
        Handshake { m: CMutex::new(), cond: CCond::new(), signaled: false.into() }
    }

    /// The creator, before starting the thread.
    pub fn hold(&self) {
        self.m.lock();
    }

    /// The creator: wait until the thread has started.
    pub fn wait(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        self.signaled.store(false, SeqCst);
        while !self.signaled.load(SeqCst) {
            self.cond.wait(&self.m);
        }
        self.m.unlock();
    }

    /// The creator: wait, waking every two seconds (`pthread_cond_timedwait()`).
    pub fn wait_timed(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        self.signaled.store(false, SeqCst);
        while !self.signaled.load(SeqCst) {
            self.cond.timedwait(&self.m, Duration::from_secs(2));
        }
        self.m.unlock();
    }

    /// The new thread: it has what it needs.
    pub fn started(&self) {
        use std::sync::atomic::Ordering::SeqCst;
        self.m.lock();
        self.signaled.store(true, SeqCst);
        self.cond.signal();
        self.m.unlock();
    }
}

/// Start a detached thread running `f`; its `pthread_self()` id.
pub fn spawn_detached(name: &str, f: impl FnOnce() + Send + 'static) -> Option<u64> {
    use std::os::unix::thread::JoinHandleExt;
    let h = std::thread::Builder::new().name(name.into()).spawn(f).ok()?;
    Some(h.as_pthread_t())
}

/// `expire_proc()`: start the expire thread.
fn expire_proc(ap: &Arc<AutofsPoint>, how: u32) -> i32 {
    assert_eq!(ap.lock().exp_thread, 0);
    let hs = Arc::new(Handshake::new());
    hs.hold();
    let (ap2, hs2) = (ap.clone(), hs.clone());
    let indirect = ap.ty() == LKP_INDIRECT;
    let thid = spawn_detached("expire", move || {
        if indirect {
            indirect::expire_proc_indirect(ap2, how, &hs2);
        } else {
            panic!("direct mount expire isn't ported yet (phase 4)");
        }
    });
    let Some(thid) = thid else {
        error!(ap.logopt(), "expire_proc", "expire thread create for {} failed", ap.path());
        hs.m.unlock();
        return EXP_ERROR;
    };
    ap.lock().exp_thread = thid;
    st_set_thid(ap, thid);
    debug!(ap.logopt(), "expire_proc", "exp_proc = {} path {}", thid, ap.path());
    hs.wait();
    EXP_STARTED
}

/// `do_readmap_cleanup()`.
fn do_readmap_cleanup(ap: &Arc<AutofsPoint>) {
    st_mutex_lock();
    ap.lock().readmap_thread = 0;
    st_set_done(ap);
    st_ready(ap);
    st_mutex_unlock();
}

/// `do_readmap()`.
fn do_readmap(ap: Arc<AutofsPoint>, now: i64, hs: Arc<Handshake>) {
    hs.started();
    info!(ap.logopt(), "re-reading map for {}", ap.path());
    if !testcancel() && lookup::lookup_nss_read_map(&ap, None, now) && !testcancel() {
        if ap.ty() == LKP_INDIRECT {
            let timeout = master::get_exp_timeout(&ap, ap.entry().maps().first().map(|m| &**m));
            let ioctlfd = {
                let mut a = ap.lock();
                a.exp_runfreq = (timeout + CHECK_RATIO - 1) / CHECK_RATIO;
                a.ioctlfd
            };
            dev_ioctl::timeout(ioctlfd, timeout);
            lookup::lookup_prune_cache(&ap, now);
            lookup::lookup_ghost(&ap);
        } else {
            panic!("direct map reloads aren't ported yet (phase 4)");
        }
    }
    do_readmap_cleanup(&ap);
}

/// `st_readmap()`.
fn st_readmap(ap: &Arc<AutofsPoint>) -> bool {
    let now = sys::monotonic_time();
    debug!(ap.logopt(), "st_readmap", "state {} path {}", state_of(ap), ap.path());
    assert_eq!(state_of(ap), ST_READY);
    assert_eq!(ap.lock().readmap_thread, 0);
    set_state(ap, ST_READMAP);
    let hs = Arc::new(Handshake::new());
    hs.hold();
    let (ap2, hs2) = (ap.clone(), hs.clone());
    let Some(thid) = spawn_detached("readmap", move || do_readmap(ap2, now, hs2)) else {
        error!(ap.logopt(), "st_readmap", "readmap thread create failed");
        hs.m.unlock();
        st_ready(ap);
        let rf = ap.lock().exp_runfreq;
        alarm::conditional_alarm_add(ap, rf);
        return false;
    };
    ap.lock().readmap_thread = thid;
    st_set_thid(ap, thid);
    hs.wait();
    true
}

/// The shared part of the expire-starting states.
fn start_expire(ap: &Arc<AutofsPoint>, func: &str, from_ok: &[i32], new: i32, how: u32) -> bool {
    let m = bfmt!("{}: state {} path {}", func, state_of(ap), ap.path());
    crate::libautofs::log::log_debug(ap.logopt(), &m);
    assert!(from_ok.contains(&state_of(ap)));
    set_state(ap, new);
    if expire_proc(ap, how) == EXP_STARTED {
        return true;
    }
    let rf = ap.lock().exp_runfreq;
    alarm::conditional_alarm_add(ap, rf);
    st_ready(ap);
    false
}

/// `st_shutdown()`: wake the mount handler thread to finish the shutdown.
fn st_shutdown(ap: &Arc<AutofsPoint>) -> bool {
    debug!(ap.logopt(), "st_shutdown", "state {} path {}", state_of(ap), ap.path());
    assert!(matches!(state_of(ap), ST_SHUTDOWN_PENDING | ST_SHUTDOWN_FORCE));
    set_state(ap, ST_SHUTDOWN);
    let thid = ap.lock().thid;
    let ret = sys::pthread_kill(thid, libc::SIGCONT);
    if ret != 0 {
        error!(crate::libautofs::log::LOGOPT_ANY, "st_shutdown", "error {} sending shutdown signal", ret);
    }
    false
}

/// `__st_add_task()` (the queue mutex held).
pub fn st_add_task_locked(ap: &Arc<AutofsPoint>, state: i32) -> bool {
    use std::sync::atomic::Ordering::SeqCst;
    if state == ST_READY {
        st_ready(ap);
        SIGNALED.store(true, SeqCst);
        COND.signal();
        return true;
    }
    let cur = state_of(ap);
    if cur == ST_SHUTDOWN {
        return true;
    }
    if state == ST_SHUTDOWN {
        return st_shutdown(ap);
    }
    let shutting = cur == ST_SHUTDOWN_PENDING || cur == ST_SHUTDOWN_FORCE;
    {
        let mut q = queue();
        match q.iter_mut().find(|t| Arc::ptr_eq(&t.ap, ap)) {
            Some(task) => {
                // Don't add duplicate tasks.
                if !((task.state == state && !task.done) || shutting)
                    && !task.pending.iter().any(|&p| p == state || shutting)
                {
                    task.pending.push(state);
                }
            }
            None => q.insert(0, Task::new(ap, state)),
        }
    }
    SIGNALED.store(true, SeqCst);
    COND.signal();
    true
}

/// `st_add_task()`.
pub fn st_add_task(ap: &Arc<AutofsPoint>, state: i32) -> bool {
    st_mutex_lock();
    let r = st_add_task_locked(ap, state);
    st_mutex_unlock();
    r
}

/// `st_remove_tasks()`: cancel a running expire, prune or map read and drop
/// the waiting tasks, but not a waiting shutdown.
pub fn st_remove_tasks(ap: &Arc<AutofsPoint>) {
    use std::sync::atomic::Ordering::SeqCst;
    st_mutex_lock();
    {
        let mut q = queue();
        if q.is_empty() {
            drop(q);
            st_mutex_unlock();
            return;
        }
        for task in q.iter_mut().filter(|t| Arc::ptr_eq(&t.ap, ap)) {
            if task.busy && matches!(task.state, ST_EXPIRE | ST_PRUNE | ST_READMAP) {
                task.cancel = true;
            }
            task.pending.retain(|&s| s == ST_SHUTDOWN_PENDING || s == ST_SHUTDOWN_FORCE);
        }
    }
    SIGNALED.store(true, SeqCst);
    COND.signal();
    st_mutex_unlock();
}

/// `st_task_active()`.
fn st_task_active(ap: &Arc<AutofsPoint>, state: i32) -> bool {
    st_mutex_lock();
    let active = queue()
        .iter()
        .filter(|t| Arc::ptr_eq(&t.ap, ap))
        .any(|t| t.state == state || state == ST_ANY || t.pending.iter().any(|&p| p == state || state == ST_ANY));
    st_mutex_unlock();
    active
}

/// `st_wait_task()`: poll every 200ms until no such task is queued (or
/// `seconds` pass): whether it went.
pub fn st_wait_task(ap: &Arc<AutofsPoint>, state: i32, seconds: u32) -> bool {
    let mut wait = 0;
    let mut duration = 0;
    loop {
        sys::sleep_ns(200_000_000);
        if wait == 4 {
            wait = 0;
            duration += 1;
        } else {
            wait += 1;
        }
        if !st_task_active(ap, state) {
            return true;
        }
        if seconds != 0 && duration >= seconds {
            return false;
        }
    }
}

/// `st_wait_state()`.
pub fn st_wait_state(ap: &Arc<AutofsPoint>, state: i32) -> bool {
    loop {
        sys::sleep_ns(200_000_000);
        st_mutex_lock();
        if state_of(ap) == state {
            st_mutex_unlock();
            return true;
        }
        st_mutex_unlock();
    }
}

/// `run_state_task()`: whether a thread was started for it.
fn run_state_task(ap: &Arc<AutofsPoint>, next_state: i32) -> bool {
    let state = state_of(ap);
    if next_state == state {
        return false;
    }
    match next_state {
        ST_PRUNE => start_expire(ap, "st_prune", &[ST_READY], ST_PRUNE, AUTOFS_EXP_IMMEDIATE),
        ST_EXPIRE => start_expire(ap, "st_expire", &[ST_READY], ST_EXPIRE, AUTOFS_EXP_NORMAL),
        ST_READMAP => st_readmap(ap),
        ST_SHUTDOWN_PENDING => {
            start_expire(ap, "st_prepare_shutdown", &[ST_READY, ST_EXPIRE], ST_SHUTDOWN_PENDING, AUTOFS_EXP_IMMEDIATE)
        }
        ST_SHUTDOWN_FORCE => start_expire(
            ap,
            "st_force_shutdown",
            &[ST_READY, ST_EXPIRE],
            ST_SHUTDOWN_FORCE,
            AUTOFS_EXP_FORCE | AUTOFS_EXP_IMMEDIATE,
        ),
        s => {
            error!(ap.logopt(), "run_state_task", "bad next state {}", s);
            false
        }
    }
}

fn st_set_thid(ap: &Arc<AutofsPoint>, thid: u64) {
    if let Some(t) = queue().iter_mut().find(|t| Arc::ptr_eq(&t.ap, ap)) {
        t.thid = thid;
    }
}

/// `st_set_done()` (the queue mutex held).
fn st_set_done(ap: &Arc<AutofsPoint>) {
    if let Some(t) = queue().iter_mut().find(|t| Arc::ptr_eq(&t.ap, ap)) {
        t.done = true;
    }
}

fn pos(q: &[Task], id: u64) -> Option<usize> {
    q.iter().position(|t| t.id == id)
}

/// The id of the task after `id` (`p->next`), `None` at the end.
fn next_id(id: u64) -> Option<u64> {
    let q = queue();
    let i = pos(&q, id)?;
    q.get(i + 1).map(|t| t.id)
}

/// Mark the task busy and run it: whether a thread was started for it. The
/// queue's own lock isn't held while it runs (it may add tasks).
fn start_task(id: u64) -> bool {
    let (ap, state) = {
        let mut q = queue();
        let i = pos(&q, id).expect("queued task");
        q[i].busy = true;
        (q[i].ap.clone(), q[i].state)
    };
    run_state_task(&ap, state)
}

fn remove_task(id: u64) {
    let mut q = queue();
    if let Some(i) = pos(&q, id) {
        q.remove(i);
    }
}

/// `remove:` in the handler: drop the task, or replace it with its first
/// pending one (added at the end). Whether one was added.
fn finish_task(id: u64) -> bool {
    let mut q = queue();
    let Some(i) = pos(&q, id) else { return false };
    let mut t = q.remove(i);
    if t.pending.is_empty() {
        return false;
    }
    let s = t.pending.remove(0);
    let mut n = Task::new(&t.ap, s);
    n.pending = std::mem::take(&mut t.pending);
    q.push(n);
    true
}

fn first_id() -> Option<u64> {
    queue().first().map(|t| t.id)
}

/// `st_queue_handler()`.
fn st_queue_handler() {
    use std::sync::atomic::Ordering::SeqCst;
    st_mutex_lock();
    loop {
        while queue().is_empty() {
            COND.wait(&MUTEX);
        }
        let mut p = first_id();
        while let Some(id) = p {
            p = next_id(id);
            let cancel = queue().iter().find(|t| t.id == id).is_some_and(|t| t.cancel);
            if cancel {
                remove_task(id);
                continue;
            }
            if !start_task(id) {
                remove_task(id);
            }
        }
        loop {
            SIGNALED.store(false, SeqCst);
            while !SIGNALED.load(SeqCst) {
                COND.wait(&MUTEX);
            }
            let mut p = first_id();
            while let Some(id) = p {
                p = next_id(id);
                let Some((thid, cancel, busy, done)) =
                    queue().iter().find(|t| t.id == id).map(|t| (t.thid, t.cancel, t.busy, t.done))
                else {
                    continue;
                };
                let remove = if thid == 0 && cancel {
                    // Canceled before it started.
                    true
                } else if !busy {
                    !start_task(id)
                } else if thid == 0 {
                    // Still starting up.
                    false
                } else if cancel {
                    pthread_cancel(thid);
                    if let Some(t) = queue().iter_mut().find(|t| t.id == id) {
                        t.cancel = false;
                    }
                    false
                } else {
                    done
                };
                if remove && finish_task(id) && p.is_none() {
                    p = first_id();
                }
            }
            if queue().is_empty() {
                break;
            }
        }
    }
}

/// `st_start_handler()`.
pub fn st_start_handler() -> bool {
    std::thread::Builder::new().name("state".into()).spawn(st_queue_handler).is_ok()
}
