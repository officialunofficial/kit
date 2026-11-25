use std::sync::Arc;

use tempfile::TempDir;

use super::*;
use crate::batch::testing::{Ev, RecordingSyncer};

fn recording() -> (Arc<RecordingSyncer>, Group) {
    let rec = Arc::new(RecordingSyncer::default());
    let group = Group::with_syncer(Arc::clone(&rec) as Arc<dyn Syncer>);
    (rec, group)
}

/// The anchors of the full flushes, in order.
fn flushes(rec: &RecordingSyncer) -> Vec<PathBuf> {
    rec.events()
        .into_iter()
        .filter_map(|event| match event {
            Ev::Full(path) => Some(path),
            _ => None,
        })
        .collect()
}

fn renames(rec: &RecordingSyncer) -> usize {
    rec.events()
        .iter()
        .filter(|event| matches!(event, Ev::Rename { .. }))
        .count()
}

/// The temp files left in `dir`.
fn temps_in(dir: &Path) -> usize {
    fs::read_dir(dir)
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".kit.tmp.")
        })
        .count()
}

#[test]
fn temp_prefixes_are_short_hidden_and_unique() {
    let (a, b) = (temp_prefix(), temp_prefix());
    assert_ne!(a, b);
    for name in [&a, &b] {
        let rest = name.strip_prefix(".kit.tmp.").expect("fixed hidden prefix");
        let (pid, seq) = rest.split_once('.').expect("pid and sequence");
        assert_eq!(pid, process::id().to_string());
        assert!(seq.bytes().all(|c| c.is_ascii_digit()) && !seq.is_empty());
    }
}

#[test]
fn the_batch_syncer_flushes_directories_through_flush_dir() {
    let dir = tempfile::tempdir().unwrap();
    testing::reset_dir_sync_calls();
    RealSyncer.dir_sync(dir.path()).unwrap();
    assert_eq!(testing::dir_sync_calls(), 1);
    // Where the writeout is the directory flush itself, it counts too.
    #[cfg(not(any(target_os = "macos", target_os = "ios")))]
    {
        RealSyncer.dir_writeout(dir.path()).unwrap();
        assert_eq!(testing::dir_sync_calls(), 2);
    }
}

#[test]
fn the_real_syncer_needs_a_flush_only_where_a_writeout_is_not_durable() {
    assert_eq!(
        RealSyncer.writeouts_need_flush(),
        cfg!(any(target_os = "macos", target_os = "ios"))
    );
}

#[cfg(unix)]
#[test]
fn a_directory_that_cannot_be_inspected_is_not_a_gone_one() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("file");
    fs::write(&file, b"x").unwrap();
    // A path below a file fails with ENOTDIR, not NotFound: it stays in the
    // flush, on device zero, where the flush fails for it.
    assert_eq!(RealSyncer.device_of(&file.join("below")), Some(0));
}

#[test]
fn a_missing_directory_has_no_device() {
    let dir = tempfile::tempdir().unwrap();
    assert!(RealSyncer.device_of(dir.path()).is_some());
    assert!(RealSyncer.device_of(&dir.path().join("gone")).is_none());
}

#[test]
fn a_pointer_replaces_the_file_and_leaves_no_temp() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("ptr");
    write_pointer(&dest, b"old", Parents::Existing).unwrap();
    write_pointer(&dest, b"new", Parents::Existing).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"new");
    assert_eq!(temps_in(dir.path()), 0);
}

#[test]
fn a_write_makes_missing_directories_only_when_asked() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("a/b/ptr");
    assert!(write_pointer(&dest, b"x", Parents::Existing).is_err());
    assert!(write_pointer_new(&dest, b"x", Parents::Existing).is_err());
    assert!(write_cache(&dest, b"x", Parents::Existing).is_err());
    assert!(!dir.path().join("a").exists());

    write_pointer(&dest, b"x", Parents::Create).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"x");
    write_pointer_new(&dir.path().join("c/d/ptr"), b"y", Parents::Create).unwrap();
    write_cache(&dir.path().join("e/f/rec"), b"z", Parents::Create).unwrap();
    assert_eq!(fs::read(dir.path().join("e/f/rec")).unwrap(), b"z");
}

#[test]
fn a_destination_without_a_directory_is_an_error_not_a_panic() {
    for dest in [Path::new("/"), Path::new("bare")] {
        let error = write_pointer(dest, b"x", Parents::Existing).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }
}

#[test]
fn a_new_pointer_keeps_the_file_that_is_there() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("ref");
    assert!(write_pointer_new(&dest, b"first", Parents::Existing).unwrap());
    assert!(!write_pointer_new(&dest, b"second", Parents::Existing).unwrap());
    assert_eq!(fs::read(&dest).unwrap(), b"first");
    assert_eq!(temps_in(dir.path()), 0);
}

#[test]
fn a_pointer_from_a_reader_copies_exactly_the_length() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("pack");
    let mut source: &[u8] = b"abcdef";
    write_pointer_from(&dest, &mut source, 4, Parents::Existing).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"abcd");
    assert_eq!(source, b"ef");
}

#[test]
fn a_copy_writes_whole_chunks_then_the_rest() {
    let dir = TempDir::new().unwrap();
    for (len, chunk) in [(10u64, 4usize), (8, 4), (3, 4), (0, 4), (5, 1), (4, 4)] {
        let source: Vec<u8> = (0..16).collect();
        let path = dir.path().join(format!("copy-{len}-{chunk}"));
        let mut file = File::create(&path).unwrap();
        let mut reader = &source[..];
        copy_exact_in(&mut file, &mut reader, len, chunk).unwrap();
        let want = &source[..usize::try_from(len).unwrap()];
        assert_eq!(fs::read(&path).unwrap(), want, "len {len} chunk {chunk}");
        assert_eq!(reader.len(), source.len() - want.len());
    }
    let mut file = File::create(dir.path().join("short")).unwrap();
    let error = copy_exact_in(&mut file, &mut &b"abcdef"[..], 9, 4).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
}

#[cfg(unix)]
#[test]
fn flushing_a_missing_directory_succeeds_and_any_other_failure_is_an_error() {
    let dir = TempDir::new().unwrap();
    assert!(flush_dir(dir.path()).is_ok());
    assert!(flush_dir(&dir.path().join("gone")).is_ok());
    // A path below a file is not "missing": the open fails with ENOTDIR.
    let file = dir.path().join("file");
    fs::write(&file, b"x").unwrap();
    assert!(flush_dir(&file.join("below")).is_err());
}

#[test]
fn a_rename_that_may_not_replace_fails_for_a_missing_directory_and_reports_a_taken_name() {
    let dir = TempDir::new().unwrap();
    let tmp = || temp_file_in(dir.path()).unwrap().into_temp_path();
    let missing = dir.path().join("no/such/dir/file");
    assert!(RealSyncer.rename_new(tmp(), &missing).is_err());

    let dest = dir.path().join("dest");
    assert!(RealSyncer.rename_new(tmp(), &dest).unwrap());
    assert!(!RealSyncer.rename_new(tmp(), &dest).unwrap());
}

#[test]
fn a_short_reader_writes_nothing_and_leaves_no_temp() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("pack");
    let error = write_pointer_from(&dest, &mut &b"abc"[..], 4, Parents::Existing).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert!(!dest.exists());
    assert_eq!(temps_in(dir.path()), 0);
}

#[test]
fn a_cache_record_replaces_the_file_and_leaves_no_temp() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("rec");
    write_cache(&dest, b"old", Parents::Existing).unwrap();
    write_cache(&dest, b"new", Parents::Existing).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"new");
    assert_eq!(temps_in(dir.path()), 0);
}

#[test]
fn content_synced_writes_the_file_and_leaves_no_temp() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("obj");
    write_content_synced(&dest, b"bytes").unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"bytes");
    assert_eq!(temps_in(dir.path()), 0);
}

#[test]
fn a_pointer_flushes_its_bytes_then_renames_then_flushes_its_directory() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("ptr");
    let rec = RecordingSyncer::default();
    pointer_via(&rec, &dest, Parents::Existing, |file| {
        file.write_all(b"bytes")
    })
    .unwrap();
    let events = rec.events();
    assert_eq!(events.len(), 3, "{events:?}");
    let (Ev::Full(temp), Ev::Rename { tmp, dst }, Ev::DirSync(synced)) =
        (&events[0], &events[1], &events[2])
    else {
        panic!("wrong order: {events:?}");
    };
    assert_eq!(temp, tmp);
    assert_eq!(dst, &dest);
    assert_eq!(synced, dir.path());
    assert_eq!(fs::read(&dest).unwrap(), b"bytes");
}

#[test]
fn a_failed_fill_leaves_the_destination_and_no_temp() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("ptr");
    write_pointer(&dest, b"old", Parents::Existing).unwrap();
    let rec = RecordingSyncer::default();
    let result = pointer_via(&rec, &dest, Parents::Existing, |_| {
        Err(io::Error::other("no bytes"))
    });
    assert!(result.is_err());
    assert!(rec.events().is_empty());
    assert_eq!(fs::read(&dest).unwrap(), b"old");
    assert_eq!(temps_in(dir.path()), 0);
}

#[cfg(feature = "fault-injection")]
mod counted {
    use super::*;
    use crate::fault;

    /// The full flushes `work` made on this thread.
    fn flushes_of(work: impl FnOnce()) -> u64 {
        let before = fault::flushes();
        work();
        fault::flushes() - before
    }

    #[test]
    fn a_pointer_costs_two_full_flushes_and_a_cache_record_none() {
        let dir = TempDir::new().unwrap();
        let path = |name: &str| dir.path().join(name);
        assert_eq!(
            flushes_of(|| write_pointer(&path("a"), b"x", Parents::Existing).unwrap()),
            2
        );
        assert_eq!(
            flushes_of(|| {
                write_pointer_from(&path("b"), &mut &b"x"[..], 1, Parents::Existing).unwrap();
            }),
            2
        );
        assert_eq!(
            flushes_of(|| assert!(write_pointer_new(&path("c"), b"x", Parents::Existing).unwrap())),
            2
        );
        // A new pointer that finds the file there flushes its bytes only.
        assert_eq!(
            flushes_of(|| assert!(
                !write_pointer_new(&path("c"), b"y", Parents::Existing).unwrap()
            )),
            1
        );
        assert_eq!(
            flushes_of(|| write_cache(&path("d"), b"x", Parents::Existing).unwrap()),
            0
        );
    }

    #[test]
    fn a_group_on_the_real_device_calls_shares_one_flush() {
        let dir = TempDir::new().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        let mut group = Group::default();
        // Apple: one flush covers both files, and the rename's directory is
        // only written out. Elsewhere a writeout is durable, so the group
        // flushes nothing, and the one full flush is the directory fsync of
        // the rename.
        let flushed = flushes_of(|| {
            let first = group.stage(&a, b"1", Parents::Existing).unwrap();
            let _second = group.stage(&b, b"2", Parents::Existing).unwrap();
            let token = group.flush().unwrap();
            group.publish(first, &token).unwrap();
        });
        assert_eq!(flushed, 1);
        assert_eq!(fs::read(&a).unwrap(), b"1");
        assert!(!b.exists());
        // The last flush makes the rename's directory durable on Apple.
        let finished = flushes_of(|| group.finish().unwrap());
        assert_eq!(
            finished,
            u64::from(cfg!(any(target_os = "macos", target_os = "ios")))
        );
    }

    #[test]
    fn each_flush_appends_one_line_to_the_log() {
        let dir = TempDir::new().unwrap();
        let log = dir.path().join("flushes");
        append_flush_line(&log);
        append_flush_line(&log);
        assert_eq!(fs::read_to_string(&log).unwrap(), "full\nfull\n");
    }

    #[test]
    fn the_hook_counts_the_flushes_and_writeouts_under_a_directory() {
        let (inside, outside) = (TempDir::new().unwrap(), TempDir::new().unwrap());
        let counter = fault::count_flushes(inside.path());
        let file = File::create(inside.path().join("f")).unwrap();
        flush_file(&file, &inside.path().join("f")).unwrap();
        flush_file(&file, &inside.path().join("f")).unwrap();
        flush_file(&file, &outside.path().join("f")).unwrap();
        note_writeout(&inside.path().join("f"));
        note_writeout(&outside.path().join("f"));
        assert_eq!(counter.flushes(), 2);
        assert_eq!(counter.writeouts(), 1);
    }

    #[test]
    fn a_real_writeout_and_a_real_flush_each_report_their_step() {
        let dir = TempDir::new().unwrap();
        let counter = fault::count_flushes(dir.path());
        let mut group = Group::default();
        let staged = group
            .stage(&dir.path().join("a"), b"x", Parents::Existing)
            .unwrap();
        assert_eq!((counter.writeouts(), counter.flushes()), (1, 0));
        let token = group.flush().unwrap();
        let apple = usize::from(cfg!(any(target_os = "macos", target_os = "ios")));
        assert_eq!(counter.flushes(), apple);
        group.publish(staged, &token).unwrap();
        // The directory's writeout. Where a writeout is the directory fsync
        // itself, it is a full flush as well.
        assert_eq!(counter.writeouts(), 2);
    }
}

#[test]
fn an_empty_group_flushes_nothing() {
    let (rec, mut group) = recording();
    let _token = group.flush().unwrap();
    group.finish().unwrap();
    assert!(rec.events().is_empty());
}

#[test]
fn a_staged_file_is_invisible_until_it_is_published() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("a");
    let (rec, mut group) = recording();
    let staged = group.stage(&dest, b"one", Parents::Existing).unwrap();
    assert!(!dest.exists());
    assert!(matches!(rec.events().as_slice(), [Ev::Barrier(_)]));

    let token = group.flush().unwrap();
    assert_eq!(flushes(&rec), [dir.path().to_path_buf()]);
    group.publish(staged, &token).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"one");
    assert_eq!(temps_in(dir.path()), 0);
    // The rename's directory is written out; the last flush makes it durable.
    assert_eq!(
        rec.events().last(),
        Some(&Ev::DirBarrier(dir.path().to_path_buf()))
    );
    group.finish().unwrap();
    assert_eq!(flushes(&rec).len(), 2);
}

#[test]
fn a_dropped_staged_file_unlinks_its_temp() {
    let dir = TempDir::new().unwrap();
    let (_rec, mut group) = recording();
    let staged = group
        .stage(&dir.path().join("a"), b"one", Parents::Existing)
        .unwrap();
    assert_eq!(temps_in(dir.path()), 1);
    drop(staged);
    assert_eq!(temps_in(dir.path()), 0);
}

#[test]
fn a_streamed_file_is_staged_with_its_length() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("a");
    let (_rec, mut group) = recording();
    let staged = group
        .stage_from(&dest, &mut &b"hello world"[..], 5, Parents::Existing)
        .unwrap();
    let token = group.flush().unwrap();
    group.publish(staged, &token).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"hello");

    let short = group.stage_from(&dest, &mut &b"hi"[..], 5, Parents::Existing);
    assert_eq!(short.unwrap_err().kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(temps_in(dir.path()), 0);
}

#[test]
fn a_staged_file_may_make_its_directory() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("x/y/a");
    let (_rec, mut group) = recording();
    assert!(group.stage(&dest, b"1", Parents::Existing).is_err());
    let staged = group.stage(&dest, b"1", Parents::Create).unwrap();
    let token = group.flush().unwrap();
    group.publish(staged, &token).unwrap();
    assert_eq!(fs::read(&dest).unwrap(), b"1");
}

#[test]
fn a_file_staged_after_a_flush_cannot_use_its_token() {
    let dir = TempDir::new().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let (rec, mut group) = recording();
    let first = group.stage(&a, b"1", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    let late = group.stage(&b, b"2", Parents::Existing).unwrap();

    let error = group.publish(late, &token).unwrap_err();
    assert!(error.to_string().contains("no flush since"), "{error}");
    assert!(!b.exists());
    assert_eq!(renames(&rec), 0);
    assert_eq!(temps_in(dir.path()), 1, "only the first temp is left");

    group.publish(first, &token).unwrap();
    assert_eq!(fs::read(&a).unwrap(), b"1");
}

#[test]
fn a_rename_needs_a_flush_after_every_earlier_rename() {
    let dir = TempDir::new().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let (rec, mut group) = recording();
    let first = group.stage(&a, b"1", Parents::Existing).unwrap();
    let second = group.stage(&b, b"2", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    group.publish(first, &token).unwrap();

    // The token covers the second file's bytes but not the first rename.
    assert!(group.publish(second, &token).is_err());
    assert!(!b.exists());
    assert_eq!(renames(&rec), 1);

    let again = group.stage(&b, b"3", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    group.publish(again, &token).unwrap();
    assert_eq!(fs::read(&b).unwrap(), b"3");
}

#[test]
fn a_new_file_rename_also_needs_a_flush_before_the_next_rename() {
    let dir = TempDir::new().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let (_rec, mut group) = recording();
    let first = group.stage(&a, b"1", Parents::Existing).unwrap();
    let second = group.stage(&b, b"2", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    assert!(group.publish_new(first, &token).unwrap());

    // The token predates the rename of `a`.
    assert!(group.publish(second, &token).is_err());
    assert!(!b.exists());
}

#[test]
fn a_flush_right_after_a_failed_rename_covers_the_files_staged_before() {
    let dir = TempDir::new().unwrap();
    let (held, spare) = (dir.path().join("held"), dir.path().join("spare"));
    let (_rec, mut group) = recording();
    let blocked = group.stage(&held, b"1", Parents::Existing).unwrap();
    let waiting = group.stage(&spare, b"2", Parents::Existing).unwrap();
    // A non-empty directory at the name makes the rename fail.
    fs::create_dir_all(held.join("inside")).unwrap();
    let token = group.flush().unwrap();
    assert!(group.publish(blocked, &token).is_err());

    // No write came after the failed rename, so the new token is equal to it:
    // that is a flush after it.
    let token = group.flush().unwrap();
    group.publish(waiting, &token).unwrap();
    assert_eq!(fs::read(&spare).unwrap(), b"2");
}

#[test]
fn a_token_of_another_group_is_refused() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("a");
    let (rec, mut group) = recording();
    let (_other_rec, mut other) = recording();
    let staged = group.stage(&dest, b"1", Parents::Existing).unwrap();
    let foreign = other.flush().unwrap();
    assert!(group.publish(staged, &foreign).is_err());
    assert!(!dest.exists());

    // A token whose clock would cover the file is still refused: the other
    // group has made two writes, so its token is newer than the file's.
    let staged = group.stage(&dest, b"3", Parents::Existing).unwrap();
    let _one = other
        .stage(&dir.path().join("o1"), b"x", Parents::Existing)
        .unwrap();
    let _two = other
        .stage(&dir.path().join("o2"), b"x", Parents::Existing)
        .unwrap();
    let newer = other.flush().unwrap();
    assert!(group.publish(staged, &newer).is_err());
    assert!(!dest.exists());

    // A file staged by another group is refused too, whatever the token.
    let theirs = other.stage(&dest, b"2", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    assert!(group.publish(theirs, &token).is_err());
    assert!(!dest.exists());
    assert_eq!(renames(&rec), 0);
}

#[test]
fn a_new_file_is_published_only_when_the_name_is_free() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("ref");
    let (rec, mut group) = recording();
    let first = group.stage(&dest, b"first", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    assert!(group.publish_new(first, &token).unwrap());
    assert_eq!(fs::read(&dest).unwrap(), b"first");

    let second = group.stage(&dest, b"second", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    let dir_writeouts = rec
        .events()
        .iter()
        .filter(|event| matches!(event, Ev::DirBarrier(_)))
        .count();
    assert!(!group.publish_new(second, &token).unwrap());
    assert_eq!(fs::read(&dest).unwrap(), b"first");
    assert_eq!(temps_in(dir.path()), 0);
    // A name that was taken renamed nothing, so its directory is not written
    // out again.
    let after = rec
        .events()
        .iter()
        .filter(|event| matches!(event, Ev::DirBarrier(_)))
        .count();
    assert_eq!(after, dir_writeouts);
}

#[test]
fn publish_new_refuses_a_stale_token_too() {
    let dir = TempDir::new().unwrap();
    let (_rec, mut group) = recording();
    let token = group.flush().unwrap();
    let late = group
        .stage(&dir.path().join("a"), b"1", Parents::Existing)
        .unwrap();
    assert!(group.publish_new(late, &token).is_err());
    assert!(!dir.path().join("a").exists());
}

#[test]
fn a_flush_covers_each_device_once() {
    let dir = TempDir::new().unwrap();
    let (x, y) = (dir.path().join("x"), dir.path().join("y"));
    fs::create_dir_all(&x).unwrap();
    fs::create_dir_all(&y).unwrap();
    let (rec, mut group) = recording();
    rec.set_device(&x, 1);
    rec.set_device(&y, 2);

    let _a = group.stage(&x.join("a"), b"1", Parents::Existing).unwrap();
    let _b = group.stage(&x.join("b"), b"2", Parents::Existing).unwrap();
    let _c = group.stage(&y.join("c"), b"3", Parents::Existing).unwrap();
    let _first = group.flush().unwrap();
    assert_eq!(flushes(&rec), [x.clone(), y.clone()]);

    // The flush emptied the pending set: a flush with no new write is free.
    let _second = group.flush().unwrap();
    assert_eq!(flushes(&rec).len(), 2);
}

#[test]
fn files_and_directories_that_other_code_wrote_are_written_out_and_flushed() {
    let dir = TempDir::new().unwrap();
    let file = dir.path().join("log");
    fs::write(&file, b"line\n").unwrap();
    let (rec, mut group) = recording();
    group.note_file(&file).unwrap();
    group.note_dir(dir.path()).unwrap();
    assert_eq!(
        rec.events(),
        [Ev::Barrier(file), Ev::DirBarrier(dir.path().to_path_buf())]
    );
    let _token = group.flush().unwrap();
    assert_eq!(flushes(&rec), [dir.path().to_path_buf()]);
    assert!(group.note_file(&dir.path().join("missing")).is_err());
}

#[test]
fn a_flush_is_anchored_at_a_directory_that_is_still_there() {
    let dir = TempDir::new().unwrap();
    let (gone, kept) = (dir.path().join("gone"), dir.path().join("kept"));
    fs::create_dir_all(&gone).unwrap();
    fs::create_dir_all(&kept).unwrap();
    let (rec, mut group) = recording();
    group.note_dir(&gone).unwrap();
    let staged = group
        .stage(&kept.join("y"), b"1", Parents::Existing)
        .unwrap();
    fs::remove_dir(&gone).unwrap();

    let token = group.flush().unwrap();
    assert_eq!(flushes(&rec), [kept]);
    group.publish(staged, &token).unwrap();
}

#[test]
fn a_flush_with_no_directory_left_on_a_device_fails_and_poisons_the_group() {
    let dir = TempDir::new().unwrap();
    let (staging, done) = (dir.path().join("staging"), dir.path().join("done"));
    fs::create_dir_all(&staging).unwrap();
    let (rec, mut group) = recording();
    group.note_dir(&staging).unwrap();
    // The writeout is still on the device, under another name: the flush has
    // no directory to anchor at, and a token for it would be a false one.
    fs::rename(&staging, &done).unwrap();

    assert!(group.flush().is_err());
    assert!(flushes(&rec).is_empty());
    assert!(group.note_dir(dir.path()).is_err());
}

#[test]
fn a_directory_that_moves_after_its_writeout_still_fails_the_flush() {
    let dir = TempDir::new().unwrap();
    let (staging, done) = (dir.path().join("staging"), dir.path().join("done"));
    fs::create_dir_all(&staging).unwrap();
    fs::write(staging.join("log"), b"x").unwrap();
    let (rec, mut group) = recording();
    rec.move_after_writeout(&staging, &done);
    // The writeout succeeds and the directory is gone before it is recorded.
    group.note_file(&staging.join("log")).unwrap();

    assert!(group.flush().is_err());
    assert!(flushes(&rec).is_empty());
}

#[test]
fn an_anchor_that_is_gone_when_the_flush_returns_is_not_an_anchor() {
    let dir = TempDir::new().unwrap();
    let (first, second) = (dir.path().join("first"), dir.path().join("second"));
    fs::create_dir_all(&first).unwrap();
    fs::create_dir_all(&second).unwrap();
    let (rec, mut group) = recording();
    group.note_dir(&first).unwrap();
    group.note_dir(&second).unwrap();
    rec.remove_anchor_in_next_flush();

    // The first flush returns for a directory that vanished: the second one
    // makes the flush.
    let _token = group.flush().unwrap();
    assert_eq!(flushes(&rec), [first, second]);
}

#[test]
fn a_lone_anchor_that_is_gone_when_the_flush_returns_fails_the_group() {
    let dir = TempDir::new().unwrap();
    let only = dir.path().join("only");
    fs::create_dir_all(&only).unwrap();
    let (rec, mut group) = recording();
    group.note_dir(&only).unwrap();
    rec.remove_anchor_in_next_flush();

    assert!(group.flush().is_err());
    assert!(group.note_dir(dir.path()).is_err());
}

#[cfg(unix)]
#[test]
fn an_open_file_is_on_the_device_of_its_directory() {
    let dir = TempDir::new().unwrap();
    let file = File::create(dir.path().join("f")).unwrap();
    assert_eq!(
        RealSyncer.device_of_file(&file, dir.path()),
        RealSyncer.device_of(dir.path())
    );
}

#[test]
fn a_bare_file_name_is_flushed_in_the_current_directory() {
    // Cargo runs a test with the package directory as its current one.
    let (rec, mut group) = recording();
    group.note_file(Path::new("Cargo.toml")).unwrap();
    let _token = group.flush().unwrap();
    assert_eq!(flushes(&rec), [PathBuf::from(".")]);
}

#[cfg(unix)]
#[test]
fn a_shared_pointer_gets_the_mode_of_a_created_file_and_a_pointer_is_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let dir = TempDir::new().unwrap();
    let created = dir.path().join("created");
    File::create(&created).unwrap();

    let private = dir.path().join("private");
    write_pointer(&private, b"x", Parents::Existing).unwrap();
    assert_eq!(mode(&private), 0o600);

    let shared = dir.path().join("shared");
    write_pointer_shared(&shared, b"x", Parents::Existing).unwrap();
    assert_eq!(mode(&shared), mode(&created));
    let from = dir.path().join("from");
    write_pointer_from_shared(&from, &mut &b"abc"[..], 3, Parents::Existing).unwrap();
    assert_eq!(mode(&from), mode(&created));
    let new = dir.path().join("new");
    assert!(write_pointer_new_shared(&new, b"x", Parents::Existing).unwrap());
    assert_eq!(mode(&new), mode(&created));
    assert_eq!(temps_in(dir.path()), 0);
}

#[test]
fn a_directory_that_is_gone_has_nothing_to_flush() {
    let dir = TempDir::new().unwrap();
    let (rec, mut group) = recording();
    group.note_dir(&dir.path().join("gone")).unwrap();
    let _token = group.flush().unwrap();
    assert!(flushes(&rec).is_empty());
}

#[test]
fn where_writeouts_are_durable_a_flush_makes_no_call_and_still_gives_a_token() {
    let dir = TempDir::new().unwrap();
    let dest = dir.path().join("a");
    let (rec, mut group) = recording();
    rec.durable_writeouts();
    let staged = group.stage(&dest, b"1", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    group.publish(staged, &token).unwrap();
    group.finish().unwrap();
    assert!(flushes(&rec).is_empty());
    assert_eq!(fs::read(&dest).unwrap(), b"1");
}

#[test]
fn a_failed_writeout_poisons_the_group() {
    let dir = TempDir::new().unwrap();
    let (rec, mut group) = recording();
    let staged = group
        .stage(&dir.path().join("a"), b"1", Parents::Existing)
        .unwrap();
    let token = group.flush().unwrap();

    rec.fail_barriers();
    assert!(
        group
            .stage(&dir.path().join("b"), b"2", Parents::Existing)
            .is_err()
    );
    // Every later call fails, though the calls themselves would succeed.
    assert!(group.note_dir(dir.path()).is_err());
    assert!(group.flush().is_err());
    assert!(group.publish(staged, &token).is_err());
    assert!(!dir.path().join("a").exists());
    assert_eq!(renames(&rec), 0);
    assert!(group.finish().is_err());
}

#[test]
fn a_failed_flush_poisons_the_group_and_is_not_retried() {
    let dir = TempDir::new().unwrap();
    let (rec, mut group) = recording();
    let staged = group
        .stage(&dir.path().join("a"), b"1", Parents::Existing)
        .unwrap();
    let token = group.flush().unwrap();
    let _more = group
        .stage(&dir.path().join("b"), b"2", Parents::Existing)
        .unwrap();
    let log = dir.path().join("log");
    fs::write(&log, b"line\n").unwrap();

    rec.fail_flushes();
    assert!(group.flush().is_err());
    assert_eq!(flushes(&rec).len(), 2);
    assert!(group.flush().is_err());
    assert!(group.note_file(&log).is_err());
    assert!(group.publish(staged, &token).is_err());
    assert!(!dir.path().join("a").exists());
    assert!(group.finish().is_err());
    assert_eq!(flushes(&rec).len(), 2, "a failed flush is never retried");
}

#[test]
fn a_failed_rename_does_not_poison_the_group() {
    let dir = TempDir::new().unwrap();
    let (rec, mut group) = recording();
    let first = group
        .stage(&dir.path().join("a"), b"1", Parents::Existing)
        .unwrap();
    let token = group.flush().unwrap();
    rec.fail_renames_after(0);
    assert!(group.publish(first, &token).is_err());
    assert_eq!(temps_in(dir.path()), 0);
    assert!(group.flush().is_ok());
}

#[test]
fn files_published_as_siblings_share_the_flush_that_follows_them() {
    let dir = TempDir::new().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let (rec, mut group) = recording();
    let first = group.stage(&a, b"1", Parents::Existing).unwrap();
    let second = group.stage(&b, b"2", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    group.publish_sibling(first, &token).unwrap();
    // The same token licenses a file that does not depend on the first.
    group.publish_sibling(second, &token).unwrap();
    assert_eq!(fs::read(&a).unwrap(), b"1");
    assert_eq!(fs::read(&b).unwrap(), b"2");
    assert_eq!(renames(&rec), 2);

    // One flush after both renames makes them durable.
    let _named = group.flush().unwrap();
    assert_eq!(flushes(&rec).len(), 2);
}

#[test]
fn a_sibling_still_needs_a_flush_after_every_rename_before_its_run() {
    let dir = TempDir::new().unwrap();
    let (a, b, c) = (
        dir.path().join("a"),
        dir.path().join("b"),
        dir.path().join("c"),
    );
    let (_rec, mut group) = recording();
    let first = group.stage(&a, b"1", Parents::Existing).unwrap();
    let second = group.stage(&b, b"2", Parents::Existing).unwrap();
    let third = group.stage(&c, b"3", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    group.publish(first, &token).unwrap();

    // A rename that is not a sibling came first, and this token predates it.
    assert!(group.publish_sibling(second, &token).is_err());
    assert!(!b.exists());
    assert!(group.publish_sibling(third, &token).is_err());
    assert!(!c.exists());
}

#[test]
fn a_plain_publish_ends_a_run_of_siblings() {
    let dir = TempDir::new().unwrap();
    let (a, b, c) = (
        dir.path().join("a"),
        dir.path().join("b"),
        dir.path().join("c"),
    );
    let (_rec, mut group) = recording();
    let first = group.stage(&a, b"1", Parents::Existing).unwrap();
    let second = group.stage(&b, b"2", Parents::Existing).unwrap();
    let third = group.stage(&c, b"3", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    group.publish_sibling(first, &token).unwrap();
    group.publish_sibling(second, &token).unwrap();
    // A strict publish follows both renames, which this token predates.
    assert!(group.publish(third, &token).is_err());
    assert!(!c.exists());
}

#[test]
fn a_rename_outside_the_group_ends_a_run_of_siblings() {
    let dir = TempDir::new().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let (_rec, mut group) = recording();
    let first = group.stage(&a, b"1", Parents::Existing).unwrap();
    let second = group.stage(&b, b"2", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    group.publish_sibling(first, &token).unwrap();
    // Objects are renamed by code outside the group after the first sibling.
    group.note_renamed();
    assert!(group.publish_sibling(second, &token).is_err());
    assert!(!b.exists());
}

#[test]
fn a_new_token_starts_a_new_run_of_siblings() {
    let dir = TempDir::new().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let (_rec, mut group) = recording();
    let first = group.stage(&a, b"1", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    group.publish_sibling(first, &token).unwrap();

    let second = group.stage(&b, b"2", Parents::Existing).unwrap();
    let again = group.flush().unwrap();
    group.publish_sibling(second, &again).unwrap();
    assert_eq!(fs::read(&b).unwrap(), b"2");
}

#[test]
fn a_sibling_of_another_group_or_a_stale_token_is_refused() {
    let dir = TempDir::new().unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    let (_rec, mut group) = recording();
    let early = group.flush().unwrap();
    let staged = group.stage(&a, b"1", Parents::Existing).unwrap();
    assert!(group.publish_sibling(staged, &early).is_err());
    assert!(!a.exists());

    let (_rec, mut other) = recording();
    let foreign = other.stage(&b, b"2", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    assert!(group.publish_sibling(foreign, &token).is_err());
    assert!(!b.exists());
}

#[test]
fn a_new_sibling_leaves_a_taken_name_and_shares_the_flush() {
    let dir = TempDir::new().unwrap();
    let (a, b, taken) = (
        dir.path().join("a"),
        dir.path().join("b"),
        dir.path().join("taken"),
    );
    fs::write(&taken, b"old").unwrap();
    let (_rec, mut group) = recording();
    let first = group.stage(&a, b"1", Parents::Existing).unwrap();
    let second = group.stage(&b, b"2", Parents::Existing).unwrap();
    let third = group.stage(&taken, b"3", Parents::Existing).unwrap();
    let flushed = group.flush().unwrap();
    assert!(group.publish_new_sibling(first, &flushed).unwrap());
    assert!(group.publish_new_sibling(second, &flushed).unwrap());
    assert!(!group.publish_new_sibling(third, &flushed).unwrap());
    assert_eq!(fs::read(&taken).unwrap(), b"old");
    assert_eq!(fs::read(&b).unwrap(), b"2");

    let early = group.flush().unwrap();
    let stale = group
        .stage(&dir.path().join("c"), b"4", Parents::Existing)
        .unwrap();
    assert!(group.publish_new_sibling(stale, &flushed).is_err());
    drop(early);
}

#[test]
fn a_write_made_elsewhere_is_flushed_with_the_group() {
    let dir = TempDir::new().unwrap();
    let (rec, mut group) = recording();
    // No flush is due before any write is recorded.
    let _token = group.flush().unwrap();
    assert!(flushes(&rec).is_empty());

    group.note_written(dir.path());
    // Recording makes no device call, but the next flush runs.
    assert!(rec.events().is_empty());
    let _token = group.flush().unwrap();
    assert_eq!(flushes(&rec), [dir.path().to_path_buf()]);
}

#[test]
fn a_rename_made_elsewhere_must_be_flushed_before_a_publish() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a");
    let (_rec, mut group) = recording();
    let staged = group.stage(&a, b"1", Parents::Existing).unwrap();
    let token = group.flush().unwrap();
    group.note_renamed();
    assert!(group.publish(staged, &token).is_err());
    assert!(!a.exists());

    let staged = group.stage(&a, b"2", Parents::Existing).unwrap();
    group.note_renamed();
    let token = group.flush().unwrap();
    group.publish(staged, &token).unwrap();
    assert_eq!(fs::read(&a).unwrap(), b"2");
}

#[test]
fn a_staged_file_names_its_temp_and_its_destination() {
    let dir = TempDir::new().unwrap();
    let a = dir.path().join("a");
    let (_rec, mut group) = recording();
    let staged = group.stage(&a, b"1", Parents::Existing).unwrap();
    assert_eq!(staged.dest(), a);
    assert_eq!(staged.temp_path().parent(), Some(dir.path()));
    assert!(
        staged
            .temp_path()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(".kit.tmp.")
    );
    assert_eq!(fs::read(staged.temp_path()).unwrap(), b"1");
}
