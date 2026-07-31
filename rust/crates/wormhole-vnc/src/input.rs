//! Pointer / keyboard input toward the RFB server, plus a bounded outbound queue.

use std::collections::VecDeque;
use std::ops::BitOr;

use crate::VncError;

/// Default cap on queued pointer/key events awaiting the engine drain.
pub const DEFAULT_INPUT_QUEUE_CAPACITY: usize = 256;

/// RFB pointer button mask bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PointerButtons(pub u8);

impl PointerButtons {
    pub const LEFT: Self = Self(1 << 0);
    pub const MIDDLE: Self = Self(1 << 1);
    pub const RIGHT: Self = Self(1 << 2);
    pub const WHEEL_UP: Self = Self(1 << 3);
    pub const WHEEL_DOWN: Self = Self(1 << 4);

    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl BitOr for PointerButtons {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PointerEvent {
    pub x: u16,
    pub y: u16,
    pub buttons: PointerButtons,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// X11 keysym (RFB uses keysyms).
    pub keysym: u32,
    pub down: bool,
}

/// Unified outbound input event for the queue / engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputEvent {
    Pointer(PointerEvent),
    Key(KeyEvent),
}

/// Outbound input toward the VNC server (session / engine implements this).
pub trait VncInputSink: Send {
    fn pointer(&mut self, event: PointerEvent) -> crate::Result<()>;
    fn key(&mut self, event: KeyEvent) -> crate::Result<()>;
}

/// Bounded FIFO of pointer/key events awaiting RFB send.
///
/// UI threads enqueue; the session/engine drains with [`InputEventQueue::dequeue`].
///
/// **Drop policy:** when full, enqueue returns [`VncError::InputQueueFull`] and
/// leaves the queue unchanged (no silent drop, no unbounded growth). Callers must
/// drain or surface the error.
#[derive(Debug, Clone)]
pub struct InputEventQueue {
    capacity: usize,
    events: VecDeque<InputEvent>,
}

impl Default for InputEventQueue {
    fn default() -> Self {
        Self::new(DEFAULT_INPUT_QUEUE_CAPACITY)
    }
}

impl InputEventQueue {
    /// Create a queue with the given capacity.
    ///
    /// A requested capacity of `0` is treated as `1` so construction never panics.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            events: VecDeque::with_capacity(capacity),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn is_full(&self) -> bool {
        self.events.len() >= self.capacity
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }

    pub fn enqueue(&mut self, event: InputEvent) -> Result<(), VncError> {
        if self.is_full() {
            return Err(VncError::InputQueueFull {
                capacity: self.capacity,
            });
        }
        self.events.push_back(event);
        Ok(())
    }

    pub fn enqueue_pointer(&mut self, event: PointerEvent) -> Result<(), VncError> {
        self.enqueue(InputEvent::Pointer(event))
    }

    pub fn enqueue_key(&mut self, event: KeyEvent) -> Result<(), VncError> {
        self.enqueue(InputEvent::Key(event))
    }

    pub fn dequeue(&mut self) -> Option<InputEvent> {
        self.events.pop_front()
    }

    /// Drain up to `max` events (engine batch send).
    pub fn drain(&mut self, max: usize) -> Vec<InputEvent> {
        let n = max.min(self.events.len());
        self.events.drain(..n).collect()
    }
}

impl VncInputSink for InputEventQueue {
    fn pointer(&mut self, event: PointerEvent) -> crate::Result<()> {
        self.enqueue_pointer(event)
    }

    fn key(&mut self, event: KeyEvent) -> crate::Result<()> {
        self.enqueue_key(event)
    }
}

/// Records input for tests (unbounded).
#[derive(Debug, Default)]
pub struct RecordingInput {
    pub pointers: Vec<PointerEvent>,
    pub keys: Vec<KeyEvent>,
}

impl VncInputSink for RecordingInput {
    fn pointer(&mut self, event: PointerEvent) -> crate::Result<()> {
        self.pointers.push(event);
        Ok(())
    }

    fn key(&mut self, event: KeyEvent) -> crate::Result<()> {
        self.keys.push(event);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn button_mask_or() {
        let b = PointerButtons::LEFT | PointerButtons::RIGHT;
        assert!(b.contains(PointerButtons::LEFT));
        assert!(b.contains(PointerButtons::RIGHT));
        assert!(!b.contains(PointerButtons::MIDDLE));
    }

    #[test]
    fn queue_enqueue_dequeue_fifo() {
        let mut q = InputEventQueue::new(4);
        q.enqueue_pointer(PointerEvent {
            x: 1,
            y: 2,
            buttons: PointerButtons::LEFT,
        })
        .unwrap();
        q.enqueue_key(KeyEvent {
            keysym: 0xff0d,
            down: true,
        })
        .unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Pointer(PointerEvent {
                x: 1,
                y: 2,
                buttons: PointerButtons::LEFT,
            }))
        );
        assert_eq!(
            q.dequeue(),
            Some(InputEvent::Key(KeyEvent {
                keysym: 0xff0d,
                down: true,
            }))
        );
        assert!(q.dequeue().is_none());
    }

    #[test]
    fn queue_rejects_when_full() {
        let mut q = InputEventQueue::new(2);
        let ptr = PointerEvent {
            x: 0,
            y: 0,
            buttons: PointerButtons::empty(),
        };
        q.enqueue_pointer(ptr).unwrap();
        q.enqueue_pointer(ptr).unwrap();
        assert!(q.is_full());
        assert_eq!(
            q.enqueue_pointer(ptr),
            Err(VncError::InputQueueFull { capacity: 2 })
        );
        assert_eq!(
            q.enqueue_key(KeyEvent {
                keysym: 1,
                down: false
            }),
            Err(VncError::InputQueueFull { capacity: 2 })
        );
        // Queue unchanged after reject (still 2 events; no silent drop).
        assert_eq!(q.len(), 2);
        // Dequeue frees a slot.
        assert!(q.dequeue().is_some());
        q.enqueue_key(KeyEvent {
            keysym: 2,
            down: true,
        })
        .unwrap();
        assert_eq!(q.len(), 2);
    }

    #[test]
    fn queue_capacity_zero_becomes_one() {
        let mut q = InputEventQueue::new(0);
        assert_eq!(q.capacity(), 1);
        q.enqueue_key(KeyEvent {
            keysym: 1,
            down: true,
        })
        .unwrap();
        assert!(q.is_full());
        assert_eq!(
            q.enqueue_key(KeyEvent {
                keysym: 2,
                down: false
            }),
            Err(VncError::InputQueueFull { capacity: 1 })
        );
    }

    #[test]
    fn queue_drain_and_clear() {
        let mut q = InputEventQueue::new(8);
        for i in 0..5u16 {
            q.enqueue_pointer(PointerEvent {
                x: i,
                y: 0,
                buttons: PointerButtons::empty(),
            })
            .unwrap();
        }
        let batch = q.drain(3);
        assert_eq!(batch.len(), 3);
        assert_eq!(q.len(), 2);
        q.clear();
        assert!(q.is_empty());
    }

    #[test]
    fn sink_impl_enqueues() {
        let mut q = InputEventQueue::new(4);
        VncInputSink::pointer(
            &mut q,
            PointerEvent {
                x: 9,
                y: 8,
                buttons: PointerButtons::RIGHT,
            },
        )
        .unwrap();
        VncInputSink::key(
            &mut q,
            KeyEvent {
                keysym: 65,
                down: true,
            },
        )
        .unwrap();
        assert_eq!(q.len(), 2);
    }
}
