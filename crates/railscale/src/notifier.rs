//! state change notification system for long-polling
//!
//! the [`StateNotifier`] allows the map handler to subscribe to state changes
//! and push updates to clients with streaming connections

use std::sync::Arc;

use std::sync::Mutex;
use tokio::sync::broadcast;

use crate::map_cache::MapCache;

/// event sent when state changes and subscribers should refresh
#[derive(Debug, Clone)]
pub struct StateChanged;

/// inner shared state for the notifier (shared across all clones)
struct NotifierInner {
    sender: broadcast::Sender<StateChanged>,
    /// optional map cache to invalidate on state changes
    map_cache: Mutex<Option<Arc<MapCache>>>,
}

/// notifier for broadcasting state changes to streaming map handlers
///
/// uses `tokio::sync::broadcast` for one-to-many notifications.
/// when state changes (node created/updated/deleted), call [`notify_state_changed`]
/// to wake all waiting map handlers and invalidate the map cache.
///
/// all clones share the same inner state, so attaching a map cache
/// on one clone makes it visible to all others.
#[derive(Clone)]
pub struct StateNotifier {
    inner: Arc<NotifierInner>,
}

impl StateNotifier {
    /// create a new state notifier (without map cache)
    ///
    /// the channel has a capacity of 16 messages. if a subscriber falls behind,
    /// it will receive a `RecvError::Lagged` and should re-fetch state
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(16);
        Self {
            inner: Arc::new(NotifierInner {
                sender,
                map_cache: Mutex::new(None),
            }),
        }
    }

    /// attach a map cache for automatic invalidation on state changes
    ///
    /// since all clones share inner state, this is visible to every clone
    pub fn set_map_cache(&self, cache: Arc<MapCache>) {
        *self
            .inner
            .map_cache
            .lock()
            .expect("notifier mutex poisoned") = Some(cache);
    }

    /// subscribe to state change notifications
    ///
    /// returns a receiver that will wake when [`notify_state_changed`] is called
    pub fn subscribe(&self) -> broadcast::Receiver<StateChanged> {
        self.inner.sender.subscribe()
    }

    /// notify all subscribers that state has changed
    ///
    /// also invalidates the map cache so the next read rebuilds from DB
    pub fn notify_state_changed(&self) {
        if let Some(ref cache) = *self
            .inner
            .map_cache
            .lock()
            .expect("notifier mutex poisoned")
        {
            cache.invalidate();
        }
        // ignore errors - if there are no receivers, that's fine
        let _ = self.inner.sender.send(StateChanged);
    }
}

impl Default for StateNotifier {
    fn default() -> Self {
        Self::new()
    }
}
