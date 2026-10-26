//! Progress, warnings and cancellation, without printing.
//!
//! A library operation never writes to stdout or stderr. It delivers typed
//! events to an [`Observer`] and polls the observer for cancellation. An
//! operation names its own event enum. A caller that wants silence passes
//! [`NoopObserver`]. A caller that only needs to cancel can pass an
//! [`AtomicBool`].

use std::sync::atomic::{AtomicBool, Ordering};

/// Receives events of type `E` and can cancel an operation at its checkpoints.
///
/// Both methods have a default body, so an observer implements only what it
/// needs.
pub trait Observer<E: ?Sized> {
    /// Called synchronously, on the calling thread, as events happen. Some
    /// events fire while a repository lock is held, so keep this cheap.
    fn event(&self, _event: &E) {}

    /// Polled at every checkpoint between network or disk steps. Returning
    /// `true` makes the operation stop with its interrupted error.
    fn cancelled(&self) -> bool {
        false
    }
}

/// An observer that ignores every event and never cancels.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoopObserver;

impl<E: ?Sized> Observer<E> for NoopObserver {}

/// A cancel flag. It ignores events. It cancels once another thread, or a
/// signal handler, sets the flag.
impl<E: ?Sized> Observer<E> for AtomicBool {
    fn cancelled(&self) -> bool {
        self.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Tick {
        Started,
        Item(u32),
        Warned(&'static str),
    }

    #[derive(Default)]
    struct Recorder {
        events: RefCell<Vec<Tick>>,
    }

    impl Observer<Tick> for Recorder {
        fn event(&self, event: &Tick) {
            self.events.borrow_mut().push(event.clone());
        }
    }

    /// Emits every item, and stops at the first checkpoint that is cancelled.
    fn run(items: u32, observer: &dyn Observer<Tick>) -> u32 {
        observer.event(&Tick::Started);
        let mut done = 0;
        for item in 0..items {
            if observer.cancelled() {
                observer.event(&Tick::Warned("cancelled"));
                break;
            }
            observer.event(&Tick::Item(item));
            done += 1;
        }
        done
    }

    #[test]
    fn events_arrive_in_the_order_they_happen() {
        let recorder = Recorder::default();
        assert_eq!(run(3, &recorder), 3);
        assert_eq!(
            *recorder.events.borrow(),
            [Tick::Started, Tick::Item(0), Tick::Item(1), Tick::Item(2)]
        );
    }

    #[test]
    fn a_noop_observer_ignores_events_and_never_cancels() {
        assert_eq!(run(5, &NoopObserver), 5);
        assert!(!Observer::<Tick>::cancelled(&NoopObserver));
    }

    #[test]
    fn the_default_methods_do_nothing() {
        struct Bare;
        impl Observer<Tick> for Bare {}
        assert_eq!(run(2, &Bare), 2);
    }

    #[test]
    fn a_set_flag_stops_the_operation_at_the_next_checkpoint() {
        let flag = AtomicBool::new(true);
        assert_eq!(run(5, &flag), 0);
    }

    #[test]
    fn an_unset_flag_lets_the_operation_finish() {
        let flag = AtomicBool::new(false);
        assert_eq!(run(5, &flag), 5);
        flag.store(true, Ordering::Relaxed);
        assert_eq!(run(5, &flag), 0);
    }

    #[test]
    fn cancellation_after_some_work_keeps_the_events_in_order() {
        struct StopAfter {
            recorder: Recorder,
            limit: usize,
        }
        impl Observer<Tick> for StopAfter {
            fn event(&self, event: &Tick) {
                self.recorder.event(event);
            }
            fn cancelled(&self) -> bool {
                self.recorder.events.borrow().len() > self.limit
            }
        }
        let observer = StopAfter {
            recorder: Recorder::default(),
            limit: 2,
        };
        assert_eq!(run(10, &observer), 2);
        assert_eq!(
            *observer.recorder.events.borrow(),
            [
                Tick::Started,
                Tick::Item(0),
                Tick::Item(1),
                Tick::Warned("cancelled")
            ]
        );
    }
}
