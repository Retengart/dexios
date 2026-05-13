use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};

use zip::read::ZipFile;
use zip::result::ZipResult;
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

    assert_eq!(visitor.file_bodies.get("dir/file.txt").unwrap(), b"streamed");
}

#[test]
fn zip_stream_reader_does_not_provide_central_metadata_before_file_data() {
    let zip_bytes = make_zip(&[("file.txt", Some(b"body"))]);
    let reader = ReadOnlyCursor::new(zip_bytes);
    let mut visitor = EventVisitor::default();

    ZipStreamReader::new(reader).visit(&mut visitor).unwrap();

    let file_position = visitor.events.iter().position(|event| event == "file:file.txt");
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
