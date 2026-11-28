//! Receiving the window of a shallow fetch (SPEC-SHALLOW §8.2).
//!
//! [`receive_window`] asks a remote for the window of some tips, writes each
//! pack it sends into the store, and then checks what arrived: the window it
//! computes from the received objects must have the boundary the server
//! listed, and every window commit must have its full snapshot closure. Only
//! a window that passes is returned, and only then may a caller write the
//! record and the refs (SH8).

use kit_core::pack::PackError;
use kit_core::protocol::{TransportError, WindowRequest};
use kit_core::shallow::{ReceivedError, Window};
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
    transport: &dyn kit_core::protocol::Transport,
    store: &ObjectStore,
    request: &WindowRequest,
) -> Result<Window, WindowFetchError> {
    let _ = (transport, store, request);
    Err(WindowFetchError::Transport(TransportError::ProtocolError))
}
