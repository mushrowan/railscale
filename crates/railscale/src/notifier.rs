//! state change notification system for long-polling
//!
//! the [`StateNotifier`] allows the map handler to subscribe to state changes
//! and push updates to clients with streaming connections

use tokio::sync::broadcast;

/// event sent when state changes and subscribers should refresh
#[derive(Debug, Clone)]
pub struct StateChanged;

/// notifier for broadcasting state changes to streaming map handlers
///
/// uses `tokio::sync::broadcast` for one-to-many notifications
/// when state changes (node created/updated/deleted), call [`notify_state_changed`]
/// to wake all waiting map handlers
#[derive(Clone)]
pub struct StateNotifier {
    sender: broadcast::Sender<StateChanged>,
}

impl StateNotifier {
    /// create a new state notifier
    ///
    /// the channel has a capacity of 16 messages. If a subscriber falls behind,
    /// it will receive a `RecvError::Lagged` and should re-fetch state
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(16);
        Self { sender }
    }

    /// subscribe to state change notifications
    ///
    /// returns a receiver that will wake when [`notify_state_changed`] is called
    pub fn subscribe(&self) -> broadcast::Receiver<StateChanged> {
        self.sender.subscribe()
    }

    /// notify all subscribers that state has changed
    ///
    /// subscribers should re-fetch state and push an update to their clients
    pub fn notify_state_changed(&self) {
        // ignore errors - if there are no receivers, that's fine
        let _ = self.sender.send(StateChanged);
    }
}

impl Default for StateNotifier {
    fn default() -> Self {
        Self::new()
    }
}
