//! Host-owned credentials, retry scheduling, admission and progress policy.
use crate::{
    ConnectTransport, EnvelopeSigner, GrantOperation, GrantRef, GrantRequest, PendingEvent,
    UploadEvent,
};
use http::HeaderMap;
use kit_client::{
    Clock, RequestContext, RequestHeaders, RequestPolicy, Signer, UnsignedRequestContext, Veto,
};
use kit_core::hash::Hash;
use kit_core::protocol::{AdvanceOutcome, BackoffIterator, CommitOutcome, TransportError};
use kit_sync::{RemoteSource, SourceError};
use kit_sync::{UploadEvent as SourceUploadEvent, WriteRecovery};
use std::cell::{Cell, RefCell};
use std::time::{Duration, Instant};

pub(crate) struct HostSigner<'a> {
    signer: Option<&'a dyn EnvelopeSigner>,
    key: Hash,
}
fn decode<const N: usize>(text: &str) -> Result<[u8; N], String> {
    if text.len() != N * 2 || !text.is_ascii() {
        return Err("invalid signer hex length".into());
    }
    let mut value = [0; N];
    for (index, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|_| "invalid signer hex".to_owned())?;
    }
    Ok(value)
}
impl<'a> HostSigner<'a> {
    pub(crate) fn new(signer: Option<&'a dyn EnvelopeSigner>) -> Result<Self, TransportError> {
        Ok(Self {
            key: signer
                .map(|s| decode(&s.public_key_hex()))
                .transpose()
                .map_err(TransportError::RemoteError)?
                .unwrap_or_default(),
            signer,
        })
    }
}
impl Signer for HostSigner<'_> {
    fn public_key(&self) -> Hash {
        self.key
    }
    async fn sign(&self, digest: &Hash) -> Result<[u8; 64], String> {
        decode(&self.signer.ok_or("signer unavailable")?.sign_hex(digest)?)
    }
}
pub(crate) struct HostClock(pub(crate) fn() -> i64);
impl Clock for HostClock {
    fn now_ms(&self) -> i64 {
        (self.0)()
    }
    fn nonce(&self) -> Result<Hash, String> {
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|e| e.to_string())?;
        Ok(nonce)
    }
    async fn wait(&self, duration: Duration) {
        tokio::time::sleep(duration).await;
    }
}
pub(crate) fn select_grant(
    host: &ConnectTransport,
    operation: GrantOperation<'_>,
) -> Option<String> {
    if matches!(operation, GrantOperation::Part) {
        return None;
    }
    let (Some(source), Some(key), Some(identity)) =
        (&host.grant_source, &host.signer_key, &host.repository)
    else {
        return None;
    };
    let namespace = identity.namespace()?;
    if namespace.to_string() == format!("ed25519-{key}") {
        return None;
    }
    source.select(&GrantRequest::new(
        &host.origin,
        &host.repository_text,
        key,
        operation,
    ))
}
pub(crate) struct HostPolicy<'a> {
    host: &'a ConnectTransport,
    headers: RefCell<HeaderMap>,
    receipt_headers: RefCell<Option<HeaderMap>>,
    advance_margin: Cell<Duration>,
    advance_ticketed: Cell<bool>,
    helper_ran: Cell<bool>,
    ladder: RefCell<BackoffIterator>,
    lag_since: Cell<Option<i64>>,
    pending_since: Cell<Option<i64>>,
    saw_pending: Cell<bool>,
    deadline: Cell<i64>,
    base_deadline: Cell<i64>,
    attempt_deadline: Cell<Option<Instant>>,
    saved: Cell<(u64, u32, u32)>,
}
impl<'a> HostPolicy<'a> {
    pub(crate) fn new(host: &'a ConnectTransport) -> Self {
        Self {
            host,
            headers: RefCell::new(HeaderMap::new()),
            receipt_headers: RefCell::new(None),
            advance_margin: Cell::new(Duration::from_secs(30)),
            advance_ticketed: Cell::new(false),
            helper_ran: Cell::new(false),
            ladder: RefCell::new(BackoffIterator::with(Duration::ZERO, Duration::ZERO, 0)),
            lag_since: Cell::new(None),
            pending_since: Cell::new(None),
            saw_pending: Cell::new(false),
            deadline: Cell::new((host.now)().saturating_add(7 * 24 * 60 * 60 * 1000)),
            base_deadline: Cell::new((host.now)().saturating_add(7 * 24 * 60 * 60 * 1000)),
            attempt_deadline: Cell::new(None),
            saved: Cell::new((0, 0, 0)),
        }
    }
    pub(crate) fn set_deadline(&self, deadline: Option<i64>) {
        if let Some(deadline) = deadline {
            self.deadline.set(deadline);
            self.base_deadline.set(deadline);
        }
    }
    fn remaining(&self) -> Duration {
        let now = (self.host.now)();
        let mut millis = self.deadline.get().saturating_sub(now);
        if let Some(start) = self.lag_since.get() {
            millis = millis.min(60_000_i64.saturating_sub(now.saturating_sub(start)));
        }
        Duration::from_millis(u64::try_from(millis).unwrap_or(0))
    }
    fn check_deadline(&self) -> Result<(), SourceError> {
        if (self.host.now)() >= self.deadline.get() {
            Err(SourceError::RemoteError(
                if self.pending_since.get().is_some() {
                    "pending verification ticket deadline expired"
                } else {
                    "advance deadline expired"
                }
                .into(),
            ))
        } else {
            Ok(())
        }
    }
    fn credentials(&self) -> RequestHeaders {
        let mut headers = RequestHeaders::new();
        if let Some(token) = &self.host.token
            && http::HeaderValue::from_str(&format!("Bearer {token}")).is_ok()
        {
            headers = headers.with_authorization(format!("Bearer {token}"));
        }
        for (name, value) in self.headers.borrow().iter() {
            if let Ok(value) = value.to_str() {
                headers = if name == http::header::AUTHORIZATION {
                    headers.with_authorization(value)
                } else {
                    headers.with(name.as_str(), value)
                };
            }
        }
        headers
    }
    pub(crate) fn map_failure(&self, error: SourceError) -> TransportError {
        if matches!(error, SourceError::Deadline) && self.attempt_expired() {
            TransportError::RemoteError("client-side deadline exceeded".into())
        } else if matches!(error, SourceError::Deadline) && self.saw_pending.get() {
            TransportError::RemoteError("pending verification ticket deadline expired".into())
        } else {
            map_source(error, false)
        }
    }
    pub(crate) fn finished(&self, succeeded: bool) {
        if let (Some(start), Some(observer)) =
            (self.pending_since.take(), &self.host.pending_observer)
        {
            observer(PendingEvent::Finished {
                elapsed: Duration::from_millis(
                    u64::try_from((self.host.now)().saturating_sub(start)).unwrap_or(0),
                ),
                succeeded,
            });
        }
    }
    fn wait_pending(&self, duration: Duration) -> Result<(), SourceError> {
        self.saw_pending.set(true);
        let start = self.pending_since.get().unwrap_or_else(|| {
            let now = (self.host.now)();
            self.pending_since.set(Some(now));
            now
        });
        let mut left = duration;
        while !left.is_zero() {
            self.check_deadline()?;
            if self
                .lag_since
                .get()
                .is_some_and(|start| (self.host.now)().saturating_sub(start) >= 60_000)
            {
                return Err(SourceError::RemoteError(
                    "repository membership not yet visible after 60 seconds".into(),
                ));
            }
            let next = left.min(Duration::from_secs(1)).min(self.remaining());
            let elapsed = Duration::from_millis(
                u64::try_from((self.host.now)().saturating_sub(start)).unwrap_or(0),
            );
            if self
                .host
                .pending_observer
                .as_ref()
                .is_some_and(|observer| !observer(PendingEvent::Waiting { elapsed, next }))
            {
                return Err(SourceError::RemoteError(
                    crate::PENDING_INTERRUPTED_MESSAGE.into(),
                ));
            }
            (self.host.sleep)(next);
            left = left.saturating_sub(next);
        }
        Ok(())
    }
    fn attempt_budget(&self, procedure: &str) -> Duration {
        if matches!(
            procedure,
            kit_client::procedures::UPLOAD_PACK
                | kit_client::procedures::UPLOAD_PART
                | "/kit.transport.v1.TransportService/DownloadPack"
        ) {
            self.host.pack_transfer_timeout
        } else {
            self.host.unary_timeout
        }
    }
    fn begin_attempt(&self, procedure: &str) {
        self.attempt_deadline
            .set(Instant::now().checked_add(self.attempt_budget(procedure)));
    }
    fn attempt_expired(&self) -> bool {
        self.attempt_deadline
            .get()
            .is_some_and(|deadline| Instant::now() >= deadline)
    }
    pub(crate) fn map_client_failure(&self, error: kit_client::Error) -> TransportError {
        if matches!(error, kit_client::Error::Deadline) && self.attempt_expired() {
            TransportError::RemoteError("client-side deadline exceeded".into())
        } else {
            map_client(error, false)
        }
    }
    fn observe_intent(&self, intent: Option<kit_client::WriteIntent<'_>>) {
        if let Some(intent) = intent
            && intent.procedure == kit_client::procedures::ADVANCE_REFS
        {
            self.advance_ticketed.set(intent.ticketed);
        }
    }
    fn observe(&self, procedure: &str, headers: &HeaderMap) {
        if matches!(
            procedure,
            kit_client::procedures::BEGIN_UPLOAD
                | kit_client::procedures::UPDATE_REF
                | kit_client::procedures::ADVANCE_REFS
        ) {
            self.receipt_headers.replace(Some(headers.clone()));
        }
    }
    fn finish_receipts(&self, procedure: &'static str, succeeded: bool) {
        let headers = self.receipt_headers.borrow_mut().take();
        if succeeded && let Some(headers) = headers {
            crate::receipt::observe_receipts(&headers, procedure, &self.host.receipt_observer);
        }
    }
    fn configured_advance_margin(&self) -> Duration {
        let (attempts, delays) =
            (self.host.backoff)().fold((1_i64, 0_i64), |(attempts, delays), delay| {
                (
                    attempts.saturating_add(1),
                    delays.saturating_add(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX)),
                )
            });
        let millis = i64::try_from(self.host.unary_timeout.as_millis())
            .unwrap_or(i64::MAX)
            .saturating_mul(attempts)
            .saturating_add(delays)
            .max(30_000);
        Duration::from_millis(u64::try_from(millis).unwrap_or(u64::MAX))
    }
}
impl RequestPolicy for HostPolicy<'_> {
    fn request_timeout(&self, procedure: &str) -> Option<Duration> {
        if self.attempt_deadline.get().is_none() {
            self.begin_attempt(procedure);
        }
        Some(
            self.remaining().min(
                self.attempt_deadline
                    .get()
                    .map_or(Duration::MAX, |deadline| {
                        deadline.saturating_duration_since(Instant::now())
                    }),
            ),
        )
    }
    fn advertise_request_timeout(&self, _procedure: &str) -> bool {
        true
    }
    fn headers(&self, request: &RequestContext<'_>) -> Result<RequestHeaders, Veto> {
        if self.attempt_deadline.get().is_none() {
            self.begin_attempt(request.signing.procedure);
        }
        self.observe_intent(request.intent);
        let mut headers = self.credentials();
        let refs: Vec<_> = request
            .intent
            .map(|intent| {
                intent
                    .ref_moves
                    .iter()
                    .map(|movement| {
                        GrantRef::new(&movement.name, crate::client::grant_condition(movement.old))
                    })
                    .collect()
            })
            .unwrap_or_default();
        let operation = match request.intent {
            None if request.signing.procedure.ends_with("/SetRepoVisibility") => {
                GrantOperation::Part
            }
            None => GrantOperation::Read,
            Some(intent) if intent.procedure == kit_client::procedures::BEGIN_UPLOAD => {
                GrantOperation::BeginUpload {
                    ref_name: intent.target_ref.unwrap_or(""),
                }
            }
            Some(intent)
                if matches!(
                    intent.procedure,
                    kit_client::procedures::UPLOAD_PART | kit_client::procedures::COMPLETE_UPLOAD
                ) || (intent.procedure == kit_client::procedures::UPLOAD_PACK
                    && intent.ticketed) =>
            {
                GrantOperation::Part
            }
            Some(_) => GrantOperation::Write { refs: &refs },
        };
        if let Some(grant) = select_grant(self.host, operation) {
            headers = headers.with_write_grant(grant);
        }
        Ok(headers)
    }
    fn unsigned_headers(
        &self,
        request: &UnsignedRequestContext<'_>,
    ) -> Result<RequestHeaders, Veto> {
        if self.attempt_deadline.get().is_none() {
            self.begin_attempt(request.procedure);
        }
        self.observe_intent(request.intent);
        Ok(self.credentials())
    }
    fn after_response(&self, request: &RequestContext<'_>, headers: &HeaderMap) {
        self.observe(request.signing.procedure, headers)
    }
    fn after_unsigned_response(&self, request: &UnsignedRequestContext<'_>, headers: &HeaderMap) {
        self.observe(request.procedure, headers)
    }
}
impl WriteRecovery for HostPolicy<'_> {
    fn before_attempt(&self, procedure: &str, deadline: Option<i64>) -> Result<(), SourceError> {
        self.begin_attempt(procedure);
        self.deadline
            .set(deadline.map_or(self.base_deadline.get(), |deadline| {
                deadline.min(self.base_deadline.get())
            }));
        self.check_deadline()?;
        if self
            .lag_since
            .get()
            .is_some_and(|start| (self.host.now)().saturating_sub(start) >= 60_000)
        {
            return Err(SourceError::RemoteError(
                "repository membership not yet visible after 60 seconds".into(),
            ));
        }
        Ok(())
    }
    fn after_call(&self, procedure: &str, succeeded: bool) {
        let procedure = match procedure {
            kit_client::procedures::BEGIN_UPLOAD => kit_client::procedures::BEGIN_UPLOAD,
            kit_client::procedures::UPDATE_REF => kit_client::procedures::UPDATE_REF,
            _ => return,
        };
        self.finish_receipts(procedure, succeeded);
    }
    fn after_advance(&self, outcome: Option<CommitOutcome>) {
        self.finish_receipts(
            kit_client::procedures::ADVANCE_REFS,
            matches!(
                outcome,
                Some(CommitOutcome::Advanced(AdvanceOutcome::Committed))
            ),
        );
        self.finished(outcome.is_some());
    }
    fn renewal_margin(&self, procedure: &str) -> Duration {
        if procedure == kit_client::procedures::ADVANCE_REFS {
            self.advance_margin.get()
        } else {
            Duration::from_secs(30)
        }
    }
    fn before_call(&self, procedure: &str) -> Result<(), SourceError> {
        self.attempt_deadline.set(None);
        self.deadline.set(self.base_deadline.get());
        self.check_deadline()?;
        self.saw_pending.set(false);
        self.advance_ticketed.set(false);
        self.headers.borrow_mut().clear();
        self.receipt_headers.borrow_mut().take();
        self.helper_ran.set(false);
        self.ladder.replace((self.host.backoff)());
        self.lag_since.set(None);
        if procedure == kit_client::procedures::ADVANCE_REFS {
            self.advance_margin.set(self.configured_advance_margin());
        }
        Ok(())
    }
    fn recover(&self, procedure: &str, error: &SourceError, _: u32) -> Result<bool, SourceError> {
        self.check_deadline()?;
        if !matches!(error, SourceError::MembershipNotVisible) {
            self.lag_since.set(None);
        }
        if (matches!(
            error,
            SourceError::PendingVerification { .. } | SourceError::MembershipNotVisible
        ) && !procedure.ends_with("/AdvanceRefs"))
            || (matches!(error, SourceError::MembershipNotVisible) && !self.advance_ticketed.get())
            || matches!(error, SourceError::RetryAfter { .. })
        {
            let Some(delay) = self.ladder.borrow_mut().next() else {
                return Ok(false);
            };
            (self.host.sleep)(delay);
            return Ok(true);
        }
        match error {
            SourceError::AdmissionRequired { challenges } => {
                if self.helper_ran.replace(true) {
                    return Err(SourceError::AdmissionRequired {
                        challenges: Box::new(
                            (**challenges).clone().with_reason(
                                "remote challenged again after the admission helper ran",
                            ),
                        ),
                    });
                }
                let Some(policy) = self.host.admission_policy.as_ref() else {
                    return Ok(false);
                };
                let full = match procedure.rsplit('/').next() {
                    Some("BeginUpload") => kit_client::procedures::BEGIN_UPLOAD,
                    Some("UpdateRef") => kit_client::procedures::UPDATE_REF,
                    Some("AdvanceRefs") => kit_client::procedures::ADVANCE_REFS,
                    _ => return Ok(false),
                };
                let mut carried = HeaderMap::new();
                if self.host.token.is_some() {
                    carried.insert("authorization", "present".parse().unwrap());
                }
                let headers = crate::admission::respond_to_challenge(
                    policy,
                    &self.host.admission_runs,
                    (&self.host.origin, &self.host.repository_text, full),
                    &carried,
                    self.host.token.is_some(),
                    (**challenges).clone(),
                )
                .map_err(SourceError::from)?;
                self.headers.replace(headers);
                self.ladder.replace((self.host.backoff)());
                Ok(true)
            }
            SourceError::PendingVerification { retry_after } => {
                self.ladder.replace((self.host.backoff)());
                self.wait_pending(*retry_after)?;
                Ok(true)
            }
            SourceError::MembershipNotVisible => {
                let now = (self.host.now)();
                let start = self.lag_since.get().unwrap_or_else(|| {
                    self.lag_since.set(Some(now));
                    now
                });
                if now.saturating_sub(start) >= 60_000 {
                    return Err(SourceError::RemoteError(
                        "repository membership not yet visible after 60 seconds".into(),
                    ));
                }
                self.ladder.replace((self.host.backoff)());
                self.wait_pending(Duration::from_secs(2))?;
                Ok(true)
            }
            _ => {
                let mapped = map_source_ref(
                    error,
                    procedure.ends_with("UploadPack")
                        || procedure.ends_with("UploadPart")
                        || procedure.ends_with("CompleteUpload"),
                );
                if !kit_core::protocol::is_retryable(&mapped) {
                    return Ok(false);
                };
                let Some(delay) = self.ladder.borrow_mut().next() else {
                    return Ok(false);
                };
                (self.host.sleep)(delay);
                Ok(true)
            }
        }
    }
    fn upload_event(&self, event: SourceUploadEvent) -> Result<(), SourceError> {
        let event = match event {
            SourceUploadEvent::PartsPlanned {
                parts,
                resumed,
                saved_bytes,
                bytes,
            } => {
                self.saved.set((saved_bytes, parts, resumed));
                UploadEvent::PartsPlanned {
                    parts,
                    resumed,
                    saved_bytes,
                    bytes,
                }
            }
            SourceUploadEvent::PartSent {
                index,
                parts,
                saved_bytes,
                bytes,
                resumed,
            } => {
                let saved = self.saved.get().2.saturating_add(1);
                self.saved.set((saved_bytes, parts, saved));
                UploadEvent::PartSent {
                    index,
                    parts,
                    saved_bytes,
                    bytes,
                    resumed,
                }
            }
            SourceUploadEvent::BeforePart => UploadEvent::BeforePart,
            SourceUploadEvent::Completing => UploadEvent::Completing,
            SourceUploadEvent::Finished => UploadEvent::Finished,
            _ => return Ok(()),
        };
        if self
            .host
            .upload_observer
            .as_ref()
            .is_some_and(|observer| !observer(event))
        {
            let (_, total, saved) = self.saved.get();
            return Err(SourceError::RemoteError(format!(
                "upload interrupted; {saved} of {total} parts saved, run `kit push` again to resume"
            )));
        }
        Ok(())
    }
}
fn raw_error(remote: &kit_sync::RemoteFailure) -> connectrpc::ConnectError {
    let code = match remote.code.as_str() {
        "not_found" => connectrpc::ErrorCode::NotFound,
        "unauthenticated" => connectrpc::ErrorCode::Unauthenticated,
        "permission_denied" => connectrpc::ErrorCode::PermissionDenied,
        "failed_precondition" => connectrpc::ErrorCode::FailedPrecondition,
        "invalid_argument" => connectrpc::ErrorCode::InvalidArgument,
        "resource_exhausted" => connectrpc::ErrorCode::ResourceExhausted,
        "unavailable" => connectrpc::ErrorCode::Unavailable,
        "aborted" => connectrpc::ErrorCode::Aborted,
        "unimplemented" => connectrpc::ErrorCode::Unimplemented,
        "deadline_exceeded" => connectrpc::ErrorCode::DeadlineExceeded,
        _ => connectrpc::ErrorCode::Unknown,
    };
    let mut headers = HeaderMap::new();
    for (name, value) in &remote.headers {
        if let (Ok(name), Ok(value)) = (
            http::HeaderName::from_bytes(name.as_bytes()),
            http::HeaderValue::from_bytes(value),
        ) {
            headers.append(name, value);
        }
    }
    headers.remove(crate::status::STATUS_MARKER);
    if remote.status == 402 {
        headers.insert(
            crate::status::STATUS_MARKER,
            http::HeaderValue::from_static("402"),
        );
    }
    let mut error = connectrpc::ConnectError::new(code, &remote.message).with_headers(headers);
    for detail in &remote.details {
        error = error.with_detail(connectrpc::ErrorDetail {
            type_url: detail.type_url.clone(),
            value: detail.value.clone(),
            debug: None,
        });
    }
    error
}
fn map_source_ref(error: &SourceError, upload: bool) -> TransportError {
    if let SourceError::Remote(remote) = error {
        return crate::error::map_connect_error(
            raw_error(remote),
            if upload {
                crate::error::ErrorContext::Upload
            } else {
                crate::error::ErrorContext::Ref
            },
        );
    }
    match error {
        SourceError::ServerError { status } => TransportError::ServerError { status: *status },
        SourceError::ConnectionFailed => TransportError::ConnectionFailed,
        SourceError::RefConflict => TransportError::RefConflict,
        SourceError::PackNotFound => TransportError::PackNotFound,
        SourceError::AccessDenied => TransportError::AccessDenied,
        _ => TransportError::RemoteError(error.to_string()),
    }
}
pub(crate) fn map_source(error: SourceError, upload: bool) -> TransportError {
    match error {
        SourceError::Remote(remote) => crate::error::map_connect_error(
            raw_error(&remote),
            if upload {
                crate::error::ErrorContext::Upload
            } else {
                crate::error::ErrorContext::Ref
            },
        ),
        SourceError::PackNotFound => TransportError::PackNotFound,
        SourceError::AccessDenied => TransportError::AccessDenied,
        SourceError::AdmissionConfiguration(s) => TransportError::AdmissionConfiguration(s),
        SourceError::AdmissionHelperFailed(s) => TransportError::AdmissionHelperFailed(s),
        SourceError::TlsConfiguration(s) => TransportError::TlsConfiguration(s),
        SourceError::RemoteError(s) if s == "server requires signed uploads" => {
            TransportError::RemoteError(
                "server requires signed uploads; set `transport_auth = envelope`".into(),
            )
        }
        SourceError::RemoteError(s) => TransportError::RemoteError(s),
        SourceError::RefConflict => TransportError::RefConflict,
        SourceError::InvalidRef(s) => TransportError::InvalidRef(s),
        SourceError::ConnectionFailed => TransportError::ConnectionFailed,
        SourceError::ServerError { status } => TransportError::ServerError { status },
        SourceError::InvalidResponse => TransportError::InvalidResponse,
        SourceError::ProtocolError => TransportError::ProtocolError,
        SourceError::PayloadTooLarge(n) => TransportError::PayloadTooLarge(n),
        SourceError::InsecureScheme => TransportError::InsecureScheme,
        SourceError::AdmissionRequired { challenges } => {
            TransportError::AdmissionRequired(challenges)
        }
        SourceError::PendingVerification { .. }
        | SourceError::MembershipNotVisible
        | SourceError::RetryAfter { .. } => TransportError::ServerError { status: 503 },
        SourceError::Deadline => TransportError::RemoteError("advance deadline expired".into()),
        SourceError::Signing(s) => TransportError::RemoteError(s),
        other => TransportError::RemoteError(other.to_string()),
    }
}
pub(crate) fn upload_error(error: TransportError) -> TransportError {
    match error {
        TransportError::InvalidRef(_) => TransportError::ProtocolError,
        other => other,
    }
}
pub(crate) fn map_client(error: kit_client::Error, upload: bool) -> TransportError {
    match error {
        kit_client::Error::Remote(remote) => map_source(
            SourceError::Remote(Box::new(kit_sync::RemoteFailure {
                code: remote.code,
                message: remote.message,
                details: remote
                    .details
                    .into_iter()
                    .map(|d| kit_sync::RemoteDetail {
                        type_url: d.type_url,
                        value: d.value,
                    })
                    .collect(),
                status: remote.status,
                headers: remote
                    .headers
                    .iter()
                    .map(|(n, v)| (n.to_string(), v.as_bytes().to_vec()))
                    .collect(),
            })),
            upload,
        ),
        kit_client::Error::AdmissionRequired(challenges) => {
            TransportError::AdmissionRequired(challenges)
        }
        kit_client::Error::Connection(_) => TransportError::ServerError { status: 503 },
        kit_client::Error::RequestTimeout(cause) => TransportError::RemoteError(cause),
        kit_client::Error::Invalid(_) | kit_client::Error::Limit(_) => {
            TransportError::InvalidResponse
        }
        other => TransportError::RemoteError(other.to_string()),
    }
}
/// Translate source failures at the transport boundary, per operation.
pub(crate) struct HostSource<'a>(
    pub(crate) &'a dyn RemoteSource,
    pub(crate) &'a HostPolicy<'a>,
);
impl HostSource<'_> {
    fn failure(&self, error: SourceError, upload: bool) -> SourceError {
        if matches!(error, SourceError::Deadline) {
            self.1.map_failure(error).into()
        } else {
            map_source(error, upload).into()
        }
    }
}
impl RemoteSource for HostSource<'_> {
    fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, SourceError> {
        self.0.list_branches().map_err(|e| self.failure(e, false))
    }
    fn read_ref(&self, name: &str) -> Result<Option<Hash>, SourceError> {
        self.0.read_ref(name).map_err(|e| self.failure(e, false))
    }
    fn download_blob_via_ref(
        &self,
        key: &kit_core::protocol::PackKey,
        name: &str,
    ) -> Result<Vec<u8>, SourceError> {
        self.0
            .download_pack_via_ref(key, name)
            .map_err(|e| self.failure(e, false))
    }
    fn download_pack_via_ref(
        &self,
        key: &kit_core::protocol::PackKey,
        name: &str,
    ) -> Result<Vec<u8>, SourceError> {
        self.0
            .download_pack_via_ref(key, name)
            .map_err(|e| self.failure(e, false))
    }
    fn supports_push(&self) -> bool {
        self.0.supports_push()
    }
    fn upload_pack_via_ref(
        &self,
        bytes: &[u8],
        key: &kit_core::protocol::PackKey,
        name: &str,
    ) -> Result<(), SourceError> {
        self.0
            .upload_pack_via_ref(bytes, key, name)
            .map_err(|e| self.failure(e, true))
    }
    fn upload_blob_via_ref(
        &self,
        bytes: &[u8],
        key: &kit_core::protocol::PackKey,
        name: &str,
    ) -> Result<(), SourceError> {
        self.0
            .upload_blob_via_ref(bytes, key, name)
            .map_err(|e| self.failure(e, true))
    }
    fn update_ref(
        &self,
        name: &str,
        condition: kit_core::refs::RefWriteCondition,
        tip: &Hash,
    ) -> Result<(), SourceError> {
        self.0
            .update_ref(name, condition, tip)
            .map_err(|e| self.failure(e, false))
    }
    fn advance_refs_committing(
        &self,
        head: &str,
        hc: kit_core::refs::RefWriteCondition,
        tip: &Hash,
        packmap: &str,
        pc: kit_core::refs::RefWriteCondition,
        node: &Hash,
        keys: &[kit_core::protocol::PackKey],
    ) -> Result<kit_core::protocol::CommitOutcome, SourceError> {
        self.0
            .advance_refs_committing(head, hc, tip, packmap, pc, node, keys)
            .map_err(|e| self.failure(e, false))
    }
    fn upload_limits(&self) -> kit_core::protocol::UploadLimits {
        self.0.upload_limits()
    }
    fn supports_atomic_advance(&self) -> bool {
        self.0.supports_atomic_advance()
    }
    fn atomic_advance_status(&self) -> Option<bool> {
        self.0.atomic_advance_status()
    }
    fn repository_address(&self) -> Option<(String, String)> {
        self.0.repository_address()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_classification_uses_http_status_and_ignores_spoofed_markers() {
        for status in [403, 402] {
            for marker in [None, Some("402"), Some("403")] {
                let headers = marker
                    .into_iter()
                    .map(|value| {
                        (
                            crate::status::STATUS_MARKER.into(),
                            value.as_bytes().to_vec(),
                        )
                    })
                    .collect();
                let error = SourceError::Remote(Box::new(kit_sync::RemoteFailure {
                    code: "permission_denied".into(),
                    message: "denied".into(),
                    details: Vec::new(),
                    status,
                    headers,
                }));
                let mapped = map_source(error, false);
                if status == 402 {
                    assert!(matches!(mapped, TransportError::AdmissionRequired(_)));
                } else {
                    assert!(matches!(mapped, TransportError::AccessDenied));
                }
            }
        }
    }
    fn one_retry() -> BackoffIterator {
        BackoffIterator::with(Duration::ZERO, Duration::ZERO, 1)
    }
    #[test]
    fn unticketed_membership_and_nonadvance_pending_use_the_ordinary_ladder() {
        for (procedure, error) in [
            (
                kit_client::procedures::ADVANCE_REFS,
                SourceError::MembershipNotVisible,
            ),
            (
                "/kit.transport.v1.TransportService/ReadRef",
                SourceError::PendingVerification {
                    retry_after: Duration::from_secs(2),
                },
            ),
            (
                kit_client::procedures::BEGIN_UPLOAD,
                SourceError::PendingVerification {
                    retry_after: Duration::from_secs(2),
                },
            ),
        ] {
            let waits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let events = waits.clone();
            let host =
                ConnectTransport::connect_for_test("http://127.0.0.1:9".parse().expect("test URI"))
                    .with_retry_hooks_for_test(one_retry, |_| {})
                    .with_pending_observer(move |event| {
                        if matches!(event, PendingEvent::Waiting { .. }) {
                            events.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                        true
                    });
            let policy = HostPolicy::new(&host);
            assert!(policy.before_call(procedure).is_ok());
            assert!(matches!(policy.recover(procedure, &error, 1), Ok(true)));
            assert_eq!(
                waits.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "{procedure}"
            );
            assert!(matches!(policy.recover(procedure, &error, 2), Ok(false)));
            assert!(policy.pending_since.get().is_none());
        }
    }
}
