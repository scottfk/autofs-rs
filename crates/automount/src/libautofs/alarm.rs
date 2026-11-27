//! `lib/alarm.c`: the expire alarms, a list ordered by time, and the thread
//! that turns each into an `ST_EXPIRE` task when it's due.

use std::sync::Arc;
use std::time::Duration;

use crate::daemon::master::AutofsPoint;
use crate::daemon::state::{self, ST_EXPIRE};
use crate::libautofs::csync::{CCond, CMutex};
use crate::libautofs::mounts;
use crate::sys;

/// A `struct alarm`.
struct Alarm {
    time: i64,
    cancel: bool,
    ap: Arc<AutofsPoint>,
}

static MUTEX: CMutex = CMutex::new();
static COND: CCond = CCond::new();
/// The list; only touched with `MUTEX` held.
static ALARMS: std::sync::Mutex<Vec<Alarm>> = std::sync::Mutex::new(Vec::new());

fn alarms() -> std::sync::MutexGuard<'static, Vec<Alarm>> {
    ALARMS.lock().unwrap_or_else(|e| e.into_inner())
}

/// `__alarm_add()`: insert in time order, waking the handler when the new
/// alarm comes first.
fn alarm_add_locked(ap: &Arc<AutofsPoint>, seconds: i64) -> bool {
    if seconds == 0 {
        return true;
    }
    let now = sys::monotonic_time();
    let new = Alarm { time: now + seconds, cancel: false, ap: ap.clone() };
    let mut l = alarms();
    let (empty, next_alarm) = match l.first() {
        None => (true, 0),
        Some(a) => (false, a.time),
    };
    let t = new.time;
    let pos = l.iter().position(|a| a.time >= t).unwrap_or(l.len());
    l.insert(pos, new);
    drop(l);
    if empty || t < next_alarm {
        COND.signal();
    }
    true
}

/// `alarm_add()`.
pub fn alarm_add(ap: &Arc<AutofsPoint>, seconds: i64) -> bool {
    MUTEX.lock();
    let r = alarm_add_locked(ap, seconds);
    MUTEX.unlock();
    r
}

/// `alarm_delete()`: drop the autofs point's alarms; the one being waited on is
/// marked canceled instead.
pub fn alarm_delete(ap: &Arc<AutofsPoint>) {
    MUTEX.lock();
    let mut signal_cancel = false;
    {
        let mut l = alarms();
        if l.is_empty() {
            drop(l);
            MUTEX.unlock();
            return;
        }
        let mut i = 0;
        while i < l.len() {
            if Arc::ptr_eq(&l[i].ap, ap) {
                if i != 0 {
                    l.remove(i);
                    continue;
                }
                l[i].cancel = true;
                l[i].time = 0;
                signal_cancel = true;
            }
            i += 1;
        }
    }
    if signal_cancel {
        COND.signal();
    }
    MUTEX.unlock();
}

/// `conditional_alarm_add()`: an alarm, unless this is a submount, nothing is
/// mounted, or there's one already.
pub fn conditional_alarm_add(ap: &Arc<AutofsPoint>, seconds: i64) -> bool {
    if ap.lock().submount {
        return true;
    }
    if !mounts::mnts_has_mounted_mounts(ap) {
        return true;
    }
    MUTEX.lock();
    if alarms().iter().any(|a| Arc::ptr_eq(&a.ap, ap)) {
        MUTEX.unlock();
        return true;
    }
    let r = alarm_add_locked(ap, seconds);
    MUTEX.unlock();
    r
}

/// `alarm_handler()`.
fn alarm_handler() {
    MUTEX.lock();
    loop {
        let first = alarms().first().map(|a| (a.time, a.cancel, a.ap.clone()));
        let Some((time, cancel, ap)) = first else {
            COND.wait(&MUTEX);
            continue;
        };
        let now = sys::monotonic_time();
        if time > now {
            // pthread_cond_timedwait() until the first alarm's second (on the
            // monotonic clock, at the current sub-second).
            COND.timedwait(&MUTEX, Duration::from_secs((time - now) as u64));
        } else {
            alarms().remove(0);
            if !cancel {
                MUTEX.unlock();
                state::st_add_task(&ap, ST_EXPIRE);
                MUTEX.lock();
            }
        }
    }
}

/// `alarm_start_handler()`.
pub fn alarm_start_handler() -> bool {
    std::thread::Builder::new().name("alarm".into()).spawn(alarm_handler).is_ok()
}
