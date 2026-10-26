//! The observer that every long operation takes: typed events in order, a
//! cancel flag, and a no-op default.
#![allow(clippy::unwrap_used)] // unwrap is the assertion in tests

use std::cell::RefCell;
use std::sync::atomic::{AtomicBool, Ordering};

use libkit::{NoopObserver, Observer};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Step {
    Began,
    Done(u32),
}

#[derive(Default)]
struct Recorder(RefCell<Vec<Step>>);

impl Observer<Step> for Recorder {
    fn event(&self, event: &Step) {
        self.0.borrow_mut().push(event.clone());
    }
}

/// Stops at the first checkpoint that reports a cancel.
fn work(count: u32, observer: &dyn Observer<Step>) -> u32 {
    observer.event(&Step::Began);
    let mut finished = 0;
    for index in 0..count {
        if observer.cancelled() {
            break;
        }
        observer.event(&Step::Done(index));
        finished += 1;
    }
    finished
}

#[test]
fn events_arrive_in_order() {
    let recorder = Recorder::default();
    assert_eq!(work(2, &recorder), 2);
    assert_eq!(
        *recorder.0.borrow(),
        [Step::Began, Step::Done(0), Step::Done(1)]
    );
}

#[test]
fn a_flag_cancels_the_operation() {
    let flag = AtomicBool::new(false);
    assert_eq!(work(3, &flag), 3);
    flag.store(true, Ordering::Relaxed);
    assert_eq!(work(3, &flag), 0);
}

#[test]
fn the_no_op_observer_is_the_default_choice() {
    assert_eq!(work(4, &NoopObserver), 4);
    assert!(!Observer::<Step>::cancelled(&NoopObserver));
}
