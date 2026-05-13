use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};

use zip::read::ZipFile;
use zip::result::{ZipError, ZipResult};
use zip::unstable::stream::{ZipStreamFileMetadata, ZipStreamReader, ZipStreamVisitor};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

#[derive(Debug)]
struct ReadOnlyCursor {
    inner: Cursor<Vec<u8>>,
}

impl ReadOnlyCursor {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            inner: Cursor::new(bytes),
        }
    }
}

impl Read for ReadOnlyCursor {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

#[derive(Default, Debug)]
struct WriteOnlySink {
    bytes: Vec<u8>,
}

impl WriteOnlySink {
    fn into_inner(self) -> Vec<u8> {
        self.bytes
    }
}

impl Write for WriteOnlySink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[derive(Default, Debug)]
struct EventVisitor {
    events: Vec<String>,
    file_bodies: BTreeMap<String, Vec<u8>>,
}

impl ZipStreamVisitor for EventVisitor {
    fn visit_file<R: Read>(&mut self, file: &mut ZipFile<'_, R>) -> ZipResult<()> {
        let name = file.name().to_owned();
        self.events.push(format!("file:{name}"));

        if file.is_file() {
            let mut body = Vec::new();
            file.read_to_end(&mut body)?;
            self.file_bodies.insert(name, body);
        }

        Ok(())
    }

    fn visit_additional_metadata(&mut self, metadata: &ZipStreamFileMetadata) -> ZipResult<()> {
        self.events.push(format!("metadata:{}", metadata.name()));
        Ok(())
    }
}

#[derive(Debug, Eq, PartialEq)]
enum ProofError {
    UnsafePath(PathBuf),
    DuplicatePath(PathBuf),
    PrefixCollision(PathBuf),
    MetadataMismatch {
        local: Vec<PathBuf>,
        central: Vec<PathBuf>,
    },
    Io(String),
    Zip(String),
}

impl From<io::Error> for ProofError {
    fn from(error: io::Error) -> Self {
        Self::Io(error.to_string())
    }
}

impl From<ZipError> for ProofError {
    fn from(error: ZipError) -> Self {
        Self::Zip(error.to_string())
    }
}

type ProofResult<T> = Result<T, ProofError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProofEntryKind {
    Directory,
    File,
}

#[derive(Default, Debug)]
struct ProofPathTree {
    root: ProofPathNode,
}

#[derive(Default, Debug)]
struct ProofPathNode {
    kind: Option<ProofEntryKind>,
    children: BTreeMap<OsString, ProofPathNode>,
}

impl ProofPathTree {
    fn insert(&mut self, path: &Path, kind: ProofEntryKind) -> ProofResult<()> {
        let mut node = &mut self.root;

        for component in path.components() {
            let Component::Normal(part) = component else {
                return Err(ProofError::UnsafePath(path.to_path_buf()));
            };

            if matches!(node.kind, Some(ProofEntryKind::File)) {
                return Err(ProofError::PrefixCollision(path.to_path_buf()));
            }

            node = node.children.entry(part.to_os_string()).or_default();
        }

        if node.kind.is_some() {
            return Err(ProofError::DuplicatePath(path.to_path_buf()));
        }

        if kind == ProofEntryKind::File && !node.children.is_empty() {
            return Err(ProofError::PrefixCollision(path.to_path_buf()));
        }

        node.kind = Some(kind);
        Ok(())
    }
}

struct ProofVisitor {
    selected: Box<dyn Fn(&Path) -> bool>,
    path_tree: ProofPathTree,
    local_names: Vec<PathBuf>,
    central_names: Vec<PathBuf>,
    staged_outputs: BTreeMap<PathBuf, Vec<u8>>,
    committed_outputs: BTreeMap<PathBuf, Vec<u8>>,
    failure: Option<ProofError>,
}

impl std::fmt::Debug for ProofVisitor {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProofVisitor")
            .field("path_tree", &self.path_tree)
            .field("local_names", &self.local_names)
            .field("central_names", &self.central_names)
            .field(
                "staged_outputs",
                &self.staged_outputs.keys().collect::<Vec<_>>(),
            )
            .field(
                "committed_outputs",
                &self.committed_outputs.keys().collect::<Vec<_>>(),
            )
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

impl ProofVisitor {
    fn new<F>(selected: F) -> Self
    where
        F: Fn(&Path) -> bool + 'static,
    {
        Self {
            selected: Box::new(selected),
            path_tree: ProofPathTree::default(),
            local_names: Vec::new(),
            central_names: Vec::new(),
            staged_outputs: BTreeMap::new(),
            committed_outputs: BTreeMap::new(),
            failure: None,
        }
    }

    fn staged_outputs(&self) -> &BTreeMap<PathBuf, Vec<u8>> {
        &self.staged_outputs
    }

    fn committed_outputs(&self) -> &BTreeMap<PathBuf, Vec<u8>> {
        &self.committed_outputs
    }

    fn finalize_after_auth(&mut self) -> ProofResult<()> {
        if !self.central_names.is_empty() && self.central_names != self.local_names {
            return Err(ProofError::MetadataMismatch {
                local: self.local_names.clone(),
                central: self.central_names.clone(),
            });
        }

        self.committed_outputs = self.staged_outputs.clone();
        Ok(())
    }

    fn override_metadata_names_for_test(&mut self, central_names: Vec<PathBuf>) {
        self.central_names = central_names;
    }

    fn fail<T>(&mut self, error: ProofError) -> ZipResult<T> {
        if self.failure.is_none() {
            self.failure = Some(error);
        }

        Err(ZipError::InvalidArchive(
            "dexios proof rejected archive".into(),
        ))
    }

    fn record_path(
        &mut self,
        raw_name: &str,
        enclosed_name: Option<PathBuf>,
    ) -> ZipResult<PathBuf> {
        let Some(path) = enclosed_name else {
            return self.fail(ProofError::UnsafePath(PathBuf::from(raw_name)));
        };

        match normalize_proof_path(&path) {
            Ok(path) => Ok(path),
            Err(error) => self.fail(error),
        }
    }
}

impl ZipStreamVisitor for ProofVisitor {
    fn visit_file<R: Read>(&mut self, file: &mut ZipFile<'_, R>) -> ZipResult<()> {
        let path = self.record_path(file.name(), file.enclosed_name())?;
        let kind = if file.is_dir() {
            ProofEntryKind::Directory
        } else {
            ProofEntryKind::File
        };

        if let Err(error) = self.path_tree.insert(&path, kind) {
            return self.fail(error);
        }

        self.local_names.push(path.clone());

        if file.is_file() && (self.selected)(&path) {
            let mut body = Vec::new();
            file.read_to_end(&mut body).map_err(|error| {
                if self.failure.is_none() {
                    self.failure = Some(ProofError::from(io::Error::new(
                        error.kind(),
                        error.to_string(),
                    )));
                }
                ZipError::Io(error)
            })?;
            self.staged_outputs.insert(path, body);
        } else if file.is_file() {
            io::copy(file, &mut io::sink()).map_err(|error| {
                if self.failure.is_none() {
                    self.failure = Some(ProofError::from(io::Error::new(
                        error.kind(),
                        error.to_string(),
                    )));
                }
                ZipError::Io(error)
            })?;
        }

        Ok(())
    }

    fn visit_additional_metadata(&mut self, metadata: &ZipStreamFileMetadata) -> ZipResult<()> {
        let path = self.record_path(metadata.name(), metadata.enclosed_name())?;
        self.central_names.push(path);
        Ok(())
    }
}

fn normalize_proof_path(path: &Path) -> ProofResult<PathBuf> {
    let mut normalized = PathBuf::new();

    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::Normal(part) => normalized.push(part),
            Component::ParentDir => {
                if !normalized.pop() {
                    return Err(ProofError::UnsafePath(path.to_path_buf()));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(ProofError::UnsafePath(path.to_path_buf()));
            }
        }
    }

    if normalized.as_os_str().is_empty() {
        return Err(ProofError::UnsafePath(path.to_path_buf()));
    }

    Ok(normalized)
}

fn visit_zip_with_proof<F>(zip_bytes: &[u8], selected: F) -> ProofResult<ProofVisitor>
where
    F: Fn(&Path) -> bool + 'static,
{
    let (proof, result) = run_zip_with_proof(zip_bytes, selected);
    result?;
    Ok(proof)
}

fn run_zip_with_proof<F>(zip_bytes: &[u8], selected: F) -> (ProofVisitor, ProofResult<()>)
where
    F: Fn(&Path) -> bool + 'static,
{
    let mut proof = ProofVisitor::new(selected);
    let visit_result =
        ZipStreamReader::new(ReadOnlyCursor::new(zip_bytes.to_vec())).visit(&mut proof);

    if let Some(error) = proof.failure.take() {
        return (proof, Err(error));
    }

    (proof, visit_result.map_err(ProofError::from))
}

fn make_zip(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
    let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    for (name, body) in entries {
        match body {
            Some(body) => {
                writer.start_file(*name, options).unwrap();
                writer.write_all(body).unwrap();
            }
            None => writer.add_directory(*name, options).unwrap(),
        }
    }

    writer.finish().unwrap().into_inner()
}

#[test]
fn zip_stream_reader_visits_files_from_non_seek_reader() {
    let zip_bytes = make_zip(&[("dir/", None), ("dir/file.txt", Some(b"streamed"))]);
    let reader = ReadOnlyCursor::new(zip_bytes);
    let mut visitor = EventVisitor::default();

    ZipStreamReader::new(reader).visit(&mut visitor).unwrap();

    assert_eq!(
        visitor.file_bodies.get("dir/file.txt").unwrap(),
        b"streamed"
    );
}

#[test]
fn zip_stream_reader_does_not_provide_central_metadata_before_file_data() {
    let zip_bytes = make_zip(&[("file.txt", Some(b"body"))]);
    let reader = ReadOnlyCursor::new(zip_bytes);
    let mut visitor = EventVisitor::default();

    ZipStreamReader::new(reader).visit(&mut visitor).unwrap();

    let file_position = visitor
        .events
        .iter()
        .position(|event| event == "file:file.txt");
    let metadata_position = visitor
        .events
        .iter()
        .position(|event| event == "metadata:file.txt");
    assert!(file_position.is_some());
    if let Some(metadata_position) = metadata_position {
        assert!(file_position.unwrap() < metadata_position);
    }
}

#[test]
fn zip_writer_new_stream_writes_readable_zip_to_non_seek_writer() {
    let sink = WriteOnlySink::default();
    let mut writer = ZipWriter::new_stream(sink);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    writer.start_file("file.txt", options).unwrap();
    writer.write_all(b"streamed").unwrap();
    let sink = writer.finish().unwrap().into_inner();

    let mut archive = ZipArchive::new(Cursor::new(sink.into_inner())).unwrap();
    assert_eq!(archive.len(), 1);
    assert_eq!(archive.by_index(0).unwrap().name(), "file.txt");
}

#[test]
fn zip_streaming_proof_stages_without_committing_before_finalize() {
    let zip_bytes = make_zip(&[("keep.txt", Some(b"body"))]);

    let mut proof = visit_zip_with_proof(&zip_bytes, |_| true).unwrap();

    assert_eq!(
        proof.staged_outputs().get(Path::new("keep.txt")).unwrap(),
        b"body"
    );
    assert!(proof.committed_outputs().is_empty());
    proof.finalize_after_auth().unwrap();
    assert_eq!(
        proof
            .committed_outputs()
            .get(Path::new("keep.txt"))
            .unwrap(),
        b"body"
    );
}

#[test]
fn zip_streaming_proof_rejects_parent_traversal() {
    let zip_bytes = make_zip(&[("../escape.txt", Some(b"body"))]);

    let (proof, result) = run_zip_with_proof(&zip_bytes, |_| true);
    let err = result.unwrap_err();

    assert!(matches!(
        err,
        ProofError::UnsafePath(path) if path.as_path() == Path::new("../escape.txt")
    ));
    assert!(proof.committed_outputs().is_empty());
}

#[test]
fn zip_streaming_proof_rejects_duplicate_normalized_paths() {
    let zip_bytes = make_zip(&[
        ("same.txt", Some(b"first")),
        ("./same.txt", Some(b"second")),
    ]);

    let (proof, result) = run_zip_with_proof(&zip_bytes, |_| true);
    let err = result.unwrap_err();

    assert!(matches!(
        err,
        ProofError::DuplicatePath(path) if path.as_path() == Path::new("same.txt")
    ));
    assert!(proof.committed_outputs().is_empty());
}

#[test]
fn zip_streaming_proof_rejects_file_directory_prefix_collision() {
    let zip_bytes = make_zip(&[("a", Some(b"file")), ("a/b.txt", Some(b"child"))]);

    let (proof, result) = run_zip_with_proof(&zip_bytes, |_| true);
    let err = result.unwrap_err();

    assert!(matches!(
        err,
        ProofError::PrefixCollision(path) if path.as_path() == Path::new("a/b.txt")
    ));
    assert!(proof.committed_outputs().is_empty());
}

#[test]
fn zip_streaming_proof_keeps_selected_outputs_staged_until_finalize() {
    let zip_bytes = make_zip(&[
        ("keep.txt", Some(b"selected")),
        ("skip.txt", Some(b"ignored")),
    ]);

    let mut proof = visit_zip_with_proof(&zip_bytes, |path| path == Path::new("keep.txt")).unwrap();

    assert_eq!(
        proof.staged_outputs().get(Path::new("keep.txt")).unwrap(),
        b"selected"
    );
    assert!(!proof.staged_outputs().contains_key(Path::new("skip.txt")));
    assert!(proof.committed_outputs().is_empty());
    proof.finalize_after_auth().unwrap();
    assert_eq!(proof.committed_outputs().len(), 1);
    assert_eq!(
        proof
            .committed_outputs()
            .get(Path::new("keep.txt"))
            .unwrap(),
        b"selected"
    );
}

#[test]
fn zip_streaming_proof_rejects_finalize_when_metadata_is_missing_or_mismatched() {
    let zip_bytes = make_zip(&[("file.txt", Some(b"body"))]);
    let mut proof = visit_zip_with_proof(&zip_bytes, |_| true).unwrap();

    proof.override_metadata_names_for_test(vec![PathBuf::from("different.txt")]);
    let err = proof.finalize_after_auth().unwrap_err();

    assert!(matches!(err, ProofError::MetadataMismatch { .. }));
    assert!(proof.committed_outputs().is_empty());
}
