//! Private fetch windows. Only complete, checked wire packs enter a window.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use kit_core::hash::{Hash, to_hex};
use kit_core::object::{EntryMode, Object, ObjectType};
use kit_core::pack::{ObjectSpool, PackError};
use kit_core::protocol::PackKey;
use kit_core::serialize;
use kit_core::store::{
    ClosureSource, LocalPackWriter, ObjectSource, ObjectStore, PruneGuard, StoreError, StoreResult,
};

use crate::applied_packs::AppliedPacks;
use crate::observer::{Observer, SyncEvent};

const WINDOW_BYTES: usize = 64 << 20;
// A minimum-size blob is ten bytes. The byte limit alone would allow more
// than six million tiny objects. Stop at 65,536 entries, which bounds the
// locators, batch paths and pack index workspace to the same entry count as
// the decoder's normal window.
const WINDOW_ENTRIES: usize = 1 << 16;
const PACK_OBJECT_BYTES: usize = 16 << 10;
// One file-role entry is a 32-byte id, a boolean and hash-table overhead.
// 262,144 roles cover a 100,000-file snapshot with room for changes and
// bound the table to about 17 MiB. At the cap, new ids stay unclassified.
const FILE_ROLES: usize = 1 << 18;

pub(crate) struct Publication<'a> {
    store: &'a ObjectStore,
    guard: &'a PruneGuard,
    pack: bool,
    window: Option<Window>,
    roles: HashMap<Hash, bool>,
}

struct Window {
    spool: ObjectSpool,
    bytes: usize,
    entries: usize,
    completed: Vec<PackKey>,
    completed_set: HashSet<PackKey>,
}

impl<'a> Publication<'a> {
    pub(crate) fn new(store: &'a ObjectStore, guard: &'a PruneGuard) -> StoreResult<Self> {
        Ok(Self {
            store,
            guard,
            pack: store.local_packs_active(guard)?,
            window: None,
            roles: HashMap::new(),
        })
    }

    pub(crate) fn pending(&self) -> Option<&ObjectSpool> {
        self.window.as_ref().map(|window| &window.spool)
    }

    pub(crate) fn view(&self) -> PendingView<'_> {
        PendingView::new(self.store, self.pending())
    }

    pub(crate) fn completed(&self, key: &PackKey) -> bool {
        self.window
            .as_ref()
            .is_some_and(|window| window.completed_set.contains(key))
    }

    pub(crate) fn accept(
        &mut self,
        spool: &ObjectSpool,
        key: PackKey,
        observer: &dyn Observer<SyncEvent>,
        remote: &str,
        applied: &mut AppliedPacks,
    ) -> Result<(), PackError> {
        let order = spool.take_order();
        if order.is_empty() {
            record(key, observer, remote, applied);
            return Ok(());
        }
        if self.pack {
            self.note_file_roles(spool, &order)?;
        }
        for (_, id, len, ty) in order {
            let len = len as usize;
            if self.window.as_ref().is_some_and(|window| {
                window.bytes + len > WINDOW_BYTES || window.entries == WINDOW_ENTRIES
            }) {
                self.seal(observer, remote, applied, &HashSet::new())?;
            }
            let bytes = staged(spool, &id)?;
            let window = self.window()?;
            window.spool.append(window.entries, id, ty, &bytes)?;
            window.bytes += len;
            window.entries += 1;
        }
        let packed = self.pack;
        let window = self.window()?;
        window.completed.push(key);
        window.completed_set.insert(key);
        if !packed || window.bytes >= WINDOW_BYTES || window.entries == WINDOW_ENTRIES {
            self.seal(observer, remote, applied, &HashSet::new())?;
        }
        Ok(())
    }

    fn window(&mut self) -> Result<&mut Window, PackError> {
        if self.window.is_none() {
            self.window = Some(Window {
                spool: ObjectSpool::new(&self.store.spool_dir())?,
                bytes: 0,
                entries: 0,
                completed: Vec::new(),
                completed_set: HashSet::new(),
            });
        }
        Ok(self.window.as_mut().expect("created publication window"))
    }

    fn note_file_roles(
        &mut self,
        spool: &ObjectSpool,
        order: &[(usize, Hash, u32, ObjectType)],
    ) -> Result<(), PackError> {
        let roles = &mut self.roles;
        for &(_, id, _, ty) in order {
            match ty {
                ObjectType::Tree => {
                    let Object::Tree(tree) = serialize::deserialize_owned(staged(spool, &id)?)
                        .map_err(PackError::InvalidObject)?
                    else {
                        unreachable!("object id and tree type were checked by the decoder");
                    };
                    for entry in tree
                        .entries
                        .into_iter()
                        .filter(|entry| entry.mode != EntryMode::Tree)
                    {
                        remember_role(roles, entry.object_hash, true);
                    }
                }
                ObjectType::ChunkedBlob => {
                    let Object::ChunkedBlob(manifest) =
                        serialize::deserialize_owned(staged(spool, &id)?)
                            .map_err(PackError::InvalidObject)?
                    else {
                        unreachable!("object id and manifest type were checked by the decoder");
                    };
                    let mut start = 0;
                    for (chunk, end) in manifest.entries() {
                        if end - start < PACK_OBJECT_BYTES as u64 {
                            remember_role(roles, chunk, false);
                        }
                        start = end;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(crate) fn seal(
        &mut self,
        observer: &dyn Observer<SyncEvent>,
        remote: &str,
        applied: &mut AppliedPacks,
        chunks: &HashSet<Hash>,
    ) -> Result<(), PackError> {
        let Some(window) = self.window.take() else {
            return Ok(());
        };
        let loose = self.store.batch();
        let mut pack = None;
        for (_, id, len, ty) in window.spool.take_order() {
            let bytes = staged(&window.spool, &id)?;
            let eligible = self.pack
                && (len as usize) < PACK_OBJECT_BYTES
                && (ty != ObjectType::Blob
                    || (self.roles.get(&id) == Some(&true) && !chunks.contains(&id)));
            if eligible {
                if pack.is_none() {
                    pack = Some(LocalPackWriter::new(self.store, self.guard)?);
                }
                pack.as_mut().expect("created local pack").write(&bytes)?;
            } else {
                loose.write_fetched(&bytes)?;
            }
        }
        if let Some(pack) = pack {
            pack.publish()?;
        }
        loose.commit()?;
        for key in window.completed {
            record(key, observer, remote, applied);
        }
        crate::fetch::persist_record(applied, observer, remote);
        Ok(())
    }
}

fn staged(spool: &ObjectSpool, id: &Hash) -> StoreResult<Vec<u8>> {
    spool
        .read(id)?
        .ok_or_else(|| StoreError::ObjectNotFound(to_hex(id)))
}

fn remember_role(roles: &mut HashMap<Hash, bool>, id: Hash, file: bool) {
    // Known chunk use wins within the pending window. A blob with no
    // whole-file evidence always stays loose.
    if let Some(existing) = roles.get_mut(&id) {
        *existing &= file;
    } else if roles.len() < FILE_ROLES {
        roles.insert(id, file);
    }
}

fn record(
    key: PackKey,
    observer: &dyn Observer<SyncEvent>,
    remote: &str,
    applied: &mut AppliedPacks,
) {
    if let Err(e) = applied.record_applied(&key) {
        observer.event(&SyncEvent::AppliedPacksPersistFailed {
            remote: remote.to_owned(),
            error: e.to_string(),
        });
    }
}

/// Hash-check private reads and fall through to the durable store on a miss.
pub(crate) struct PendingView<'a> {
    store: &'a ObjectStore,
    spool: Option<&'a ObjectSpool>,
    chunks: Mutex<HashSet<Hash>>,
}

impl<'a> PendingView<'a> {
    pub(crate) fn new(store: &'a ObjectStore, spool: Option<&'a ObjectSpool>) -> Self {
        Self {
            store,
            spool,
            chunks: Mutex::new(HashSet::new()),
        }
    }

    fn pending(&self, id: &Hash) -> StoreResult<Option<Vec<u8>>> {
        self.spool.map_or(Ok(None), |spool| spool.read(id))
    }

    pub(crate) fn chunks(self) -> HashSet<Hash> {
        self.chunks.into_inner().expect("pending chunk mutex")
    }

    pub(crate) fn contains(&self, id: &Hash) -> bool {
        self.spool.is_some_and(|spool| spool.contains(id)) || self.store.contains(id)
    }
}

impl ObjectSource for PendingView<'_> {
    fn read(&self, id: &Hash) -> StoreResult<Vec<u8>> {
        self.pending(id)?.map_or_else(|| self.store.read(id), Ok)
    }

    fn read_object(&self, id: &Hash) -> StoreResult<Object> {
        if let Some(bytes) = self.pending(id)? {
            Ok(serialize::deserialize_owned(bytes)?)
        } else {
            self.store.read_object(id)
        }
    }
}
impl ClosureSource for PendingView<'_> {
    fn object_type(&self, id: &Hash) -> StoreResult<ObjectType> {
        if let Some(bytes) = self.pending(id)? {
            Ok(serialize::deserialize_owned(bytes)?.object_type())
        } else {
            self.store.object_type(id)
        }
    }

    fn object_head(&self, id: &Hash) -> StoreResult<(ObjectType, Option<u64>)> {
        if let Some(bytes) = self.pending(id)? {
            let object = serialize::deserialize_owned(bytes)?;
            let len = match &object {
                Object::Blob(blob) => {
                    if bytes_fit_pack(blob.data.len()) {
                        self.chunks.lock().expect("pending chunk mutex").insert(*id);
                    }
                    Some(blob.data.len() as u64)
                }
                _ => None,
            };
            Ok((object.object_type(), len))
        } else {
            self.store.object_head(id)
        }
    }
}

fn bytes_fit_pack(blob_len: usize) -> bool {
    blob_len + 10 < PACK_OBJECT_BYTES
}
