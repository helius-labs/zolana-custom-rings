//! Background work keyed by ring or registry, one task per key under a shared bound.
//!
//! A key whose last pass still runs is skipped, so a stalled ring holds one slot and never the tick
//! of another key. A cancelled or panicked task frees its key on drop.

use std::{
    collections::HashSet,
    future::Future,
    hash::Hash,
    sync::{Arc, Mutex, PoisonError},
};

use tokio::sync::Semaphore;

/// Rings and registries that run at once, the rest wait for a slot.
pub(crate) const MAX_CONCURRENT_KEYED_TASKS: usize = 8;

pub(crate) struct KeyedTasks<K> {
    running: Arc<Mutex<HashSet<K>>>,
    slots: Arc<Semaphore>,
}

/// Frees its key when its task ends by any path.
struct Running<K: Eq + Hash> {
    running: Arc<Mutex<HashSet<K>>>,
    key: K,
}

impl<K: Eq + Hash> Drop for Running<K> {
    fn drop(&mut self) {
        self.running
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.key);
    }
}

impl<K: Copy + Eq + Hash + Send + 'static> KeyedTasks<K> {
    pub(crate) fn new(max_concurrent: usize) -> Self {
        Self {
            running: Arc::default(),
            slots: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    /// Spawns one pass for each key with none running and returns at once.
    pub(crate) fn spawn_idle<F, Fut>(&self, keys: impl IntoIterator<Item = K>, work: F)
    where
        F: Fn(K) -> Fut,
        Fut: Future<Output = ()> + Send + 'static,
    {
        for key in keys {
            let idle = self
                .running
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(key);
            if !idle {
                continue;
            }
            let guard = Running {
                running: self.running.clone(),
                key,
            };
            let slots = self.slots.clone();
            let pass = work(key);
            tokio::spawn(async move {
                let _guard = guard;
                // The semaphore is never closed, an error ends the pass unrun.
                let Ok(_slot) = slots.acquire_owned().await else {
                    return;
                };
                pass.await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::sync::Notify;

    use super::*;

    /// Key 0 never finishes, key 1 runs once per tick beside it.
    #[tokio::test]
    async fn a_stalled_key_holds_neither_another_key_nor_its_own_next_tick() {
        let tasks = KeyedTasks::new(2);
        let stall = Arc::new(Notify::new());
        let started = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0)]);
        for _ in 0..3 {
            let (stall, started) = (stall.clone(), started.clone());
            tasks.spawn_idle([0usize, 1], move |key| {
                let (stall, started) = (stall.clone(), started.clone());
                async move {
                    started[key].fetch_add(1, Ordering::SeqCst);
                    if key == 0 {
                        stall.notified().await;
                    }
                }
            });
            for _ in 0..16 {
                tokio::task::yield_now().await;
            }
        }
        assert_eq!(
            started[0].load(Ordering::SeqCst),
            1,
            "a running key is skipped"
        );
        assert_eq!(
            started[1].load(Ordering::SeqCst),
            3,
            "the other key ran every tick"
        );
        stall.notify_one();
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        let rerun = started.clone();
        tasks.spawn_idle([0usize], move |key| {
            let started = rerun.clone();
            async move {
                started[key].fetch_add(1, Ordering::SeqCst);
            }
        });
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
        assert_eq!(
            started[0].load(Ordering::SeqCst),
            2,
            "a finished key runs again"
        );
    }
}
