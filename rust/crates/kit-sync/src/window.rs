//! Receiving the window of a shallow fetch (SPEC-SHALLOW §8.2).
//!
//! [`receive_window`] asks a remote for the window of some tips, writes each
//! pack it sends into the store, and then checks what arrived: the window it
//! computes from the received objects must have the boundary the server
//! listed, and every window commit must have its full snapshot closure. Only
//! a window that passes is returned, and only then may a caller write the
//! record and the refs (SH8).

use kit_core::pack::{PackError, PackReader, PackSpool};
use kit_core::protocol::{
    PACK_BODY_LIMIT, PackKey, PackSink, SHALLOW_UNSUPPORTED, Transport, TransportError,
    TransportResult, WindowRequest, WindowSink,
};
use kit_core::shallow::{ReceivedError, Window, check_received};
use kit_core::store::ObjectStore;

/// Why a shallow fetch could not receive its window.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WindowFetchError {
    /// The remote refused or failed, or the request broke a limit.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// A received pack could not be unpacked.
    #[error("unpack a window pack: {0}")]
    Pack(#[from] PackError),
    /// The received objects do not make the window the server claimed.
    #[error("refused the window: {0}")]
    Received(#[from] ReceivedError),
}

/// Receive the window `request` names from `transport` into `store`, and
/// check it. The objects stay in the store even when the check fails: no
/// ref names them, and `kit gc` drops them.
///
/// # Errors
/// [`WindowFetchError::Transport`] for a refused or failed request, among
/// them a remote that cannot serve a shallow fetch;
/// [`WindowFetchError::Pack`] for a pack that does not unpack; and
/// [`WindowFetchError::Received`] for a window that fails the checks.
pub fn receive_window(
    transport: &dyn Transport,
    store: &ObjectStore,
    request: &WindowRequest,
) -> Result<Window, WindowFetchError> {
    request.validate()?;
    if !transport.supports_download_window() {
        return Err(TransportError::Unsupported(SHALLOW_UNSUPPORTED).into());
    }
    let mut sink = StoreSink {
        store,
        open: None,
        failure: None,
    };
    let listed = transport.download_window(request, &mut sink);
    if let Some(failure) = sink.failure {
        return Err(failure);
    }
    let listed = listed?;
    Ok(check_received(
        store,
        &request.tips,
        request.depth,
        &listed,
    )?)
}

/// Spools each pack of a window, checks it against its key and unpacks it
/// into the store.
struct StoreSink<'a> {
    store: &'a ObjectStore,
    open: Option<(PackKey, PackSpool)>,
    /// A local failure, reported in place of the transport error it caused.
    failure: Option<WindowFetchError>,
}

impl StoreSink<'_> {
    fn fail(&mut self, error: impl Into<WindowFetchError>) -> TransportError {
        self.failure.get_or_insert(error.into());
        TransportError::ProtocolError
    }
}

impl WindowSink for StoreSink<'_> {
    fn begin_pack(&mut self, key: &PackKey, len: u64) -> TransportResult<&mut dyn PackSink> {
        if self.open.is_some() {
            return Err(TransportError::InvalidResponse);
        }
        if len > PACK_BODY_LIMIT {
            return Err(TransportError::PayloadTooLarge(usize::MAX));
        }
        let spool = match PackSpool::create(&self.store.spool_dir(), len) {
            Ok(spool) => spool,
            Err(e) => return Err(self.fail(e)),
        };
        let (_, spool) = self.open.insert((*key, spool));
        Ok(spool)
    }

    fn end_pack(&mut self) -> TransportResult<()> {
        let Some((key, spool)) = self.open.take() else {
            return Err(TransportError::InvalidResponse);
        };
        // A pack whose bytes do not hash to its key is the remote's fault.
        let pack = spool
            .finish(&key)
            .map_err(|_| TransportError::InvalidResponse)?;
        match PackReader::read_verified(&pack, self.store) {
            Ok(_) => Ok(()),
            Err(e) => Err(self.fail(e)),
        }
    }
}
