// Shared operation counter; wrappers retain each backend's repository identity.
struct CountingSource<'a> {
    inner: &'a dyn kit_sync::RemoteSource,
    calls: std::cell::RefCell<Vec<String>>,
    address: Option<(String, String)>,
    before_pack: Option<&'a std::sync::Barrier>,
}

impl<'a> CountingSource<'a> {
    fn new(inner: &'a dyn kit_sync::RemoteSource) -> Self {
        Self {
            inner,
            calls: std::cell::RefCell::default(),
            address: inner.repository_address(),
            before_pack: None,
        }
    }
    fn take(&self) -> Vec<String> {
        std::mem::take(&mut *self.calls.borrow_mut())
    }
}

impl kit_sync::RemoteSource for CountingSource<'_> {
    fn list_branches(&self) -> Result<Vec<kit_core::refs::Ref>, kit_sync::SourceError> {
        self.calls.borrow_mut().push("ListRefs".into());
        self.inner.list_branches()
    }
    fn read_ref(
        &self,
        name: &str,
    ) -> Result<Option<kit_core::hash::Hash>, kit_sync::SourceError> {
        self.calls.borrow_mut().push(format!("ReadRef {name}"));
        self.inner.read_ref(name)
    }
    fn download_blob_via_ref(
        &self,
        key: &kit_core::protocol::PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.calls.borrow_mut().push(format!(
            "Node {}",
            kit_core::hash::to_hex(&key.into_hash())
        ));
        self.inner.download_blob_via_ref(key, name)
    }
    fn download_pack_via_ref(
        &self,
        key: &kit_core::protocol::PackKey,
        name: &str,
    ) -> Result<Vec<u8>, kit_sync::SourceError> {
        self.calls.borrow_mut().push(format!(
            "Pack {}",
            kit_core::hash::to_hex(&key.into_hash())
        ));
        if let Some(barrier) = self.before_pack {
            barrier.wait();
        }
        self.inner.download_pack_via_ref(key, name)
    }
    fn repository_address(&self) -> Option<(String, String)> {
        self.address.clone()
    }
}
