//! Blocking [`std::io`] frame adapters: the length-prefixed framing of
//! `mkit-rpc` over a reader and a writer.
//!
//! They have no read deadline, so they never return
//! [`FrameIoError::Timeout`]. `write_frame` flushes after every frame.

use std::io::{Read, Write};

use mkit_rpc::mkit::rpc::v1::ssh::SshFrame;

use crate::session::{FrameIoError, FrameSink, FrameSource};

/// A [`FrameSource`] over a blocking reader.
#[derive(Debug)]
pub struct ReadFrames<R>(pub R);

impl<R: Read> FrameSource for ReadFrames<R> {
    fn next_frame(&mut self) -> Result<SshFrame, FrameIoError> {
        mkit_rpc::read_frame(&mut self.0).map_err(FrameIoError::from)
    }
}

/// A [`FrameSink`] over a blocking writer. Each frame is flushed.
#[derive(Debug)]
pub struct WriteFrames<W>(pub W);

impl<W: Write> FrameSink for WriteFrames<W> {
    fn send(&mut self, frame: &SshFrame) -> Result<(), FrameIoError> {
        mkit_rpc::write_frame(&mut self.0, frame).map_err(FrameIoError::from)
    }
}
