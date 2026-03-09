use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use core::header::{HEADER_VERSION, HeaderType};
use core::primitives::{Algorithm, Mode};

use crate::global::states::{HashMode, HeaderLocation, PasswordState};
use crate::{
    global::states::EraseSourceDir,
    global::{
        states::Compression,
        structs::{CryptoParams, PackParams},
    },
};
use domain::storage::Storage;

use crate::cli::prompt::overwrite_check;

fn should_continue_after_overwrite_checks<F>(output_ok: bool, header_check: F) -> Result<bool>
where
    F: FnOnce() -> Result<Option<bool>>,
{
    if !output_ok {
        return Ok(false);
    }

    Ok(header_check()?.unwrap_or(true))
}

pub struct Request<'a> {
    pub input_file: &'a Vec<String>,
    pub output_file: &'a str,
    pub pack_params: PackParams,
    pub crypto_params: CryptoParams,
    pub algorithm: Algorithm,
}

#[cfg(windows)]
fn prefix_label(prefix: std::path::PrefixComponent<'_>) -> OsString {
    use std::path::Prefix;

    match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => {
            OsString::from(format!("drive-{}", char::from(drive).to_ascii_uppercase()))
        }
        Prefix::UNC(server, share) | Prefix::VerbatimUNC(server, share) => {
            let mut label = OsString::from("unc-");
            label.push(server);
            label.push("-");
            label.push(share);
            label
        }
        Prefix::DeviceNS(device) => {
            let mut label = OsString::from("device-");
            label.push(device);
            label
        }
        Prefix::Verbatim(name) => {
            let mut label = OsString::from("verbatim-");
            label.push(name);
            label
        }
    }
}

fn normalized_absolute_components(path: &Path) -> Vec<OsString> {
    let mut components = Vec::new();

    for component in path.components() {
        match component {
            #[cfg(windows)]
            Component::Prefix(prefix) => components.push(prefix_label(prefix)),
            #[cfg(not(windows))]
            Component::Prefix(_) => {}
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                components.pop();
            }
            Component::Normal(part) => components.push(part.to_os_string()),
        }
    }

    components
}

fn normalized_path_components(path: &Path) -> Result<Vec<OsString>> {
    let current_dir = std::env::current_dir().context("Unable to read current directory")?;
    let current_dir_components = normalized_absolute_components(&current_dir);
    let resolved = if path.is_absolute() {
        path.to_path_buf()
    } else {
        current_dir.join(path)
    };
    let mut components = normalized_absolute_components(&resolved);

    if components.starts_with(&current_dir_components) {
        let relative = components.split_off(current_dir_components.len());
        if relative.is_empty() {
            let fallback = current_dir
                .file_name()
                .map(|name| name.to_os_string())
                .unwrap_or_else(|| OsString::from("root"));
            return Ok(vec![fallback]);
        }
        return Ok(relative);
    }

    if components.is_empty() {
        return Err(anyhow::anyhow!(
            "Unable to derive archive root name from input path"
        ));
    }

    Ok(components)
}

fn suffix_path(components: &[OsString], suffix_len: usize) -> PathBuf {
    let start = components.len().saturating_sub(suffix_len);
    let mut path = PathBuf::new();
    for component in &components[start..] {
        path.push(component);
    }
    path
}

fn archive_root_names(inputs: &[String]) -> Result<Vec<PathBuf>> {
    let components = inputs
        .iter()
        .map(|input| normalized_path_components(Path::new(input)))
        .collect::<Result<Vec<_>>>()?;

    let mut suffix_lengths = vec![1usize; components.len()];

    loop {
        let roots = components
            .iter()
            .zip(&suffix_lengths)
            .map(|(parts, suffix_len)| suffix_path(parts, *suffix_len))
            .collect::<Vec<_>>();

        let mut collisions = std::collections::HashMap::<PathBuf, Vec<usize>>::new();
        for (index, root) in roots.iter().enumerate() {
            collisions.entry(root.clone()).or_default().push(index);
        }

        let mut progressed = false;
        let mut has_collision = false;

        for indexes in collisions.into_values() {
            if indexes.len() == 1 {
                continue;
            }

            has_collision = true;
            for index in indexes {
                if suffix_lengths[index] < components[index].len() {
                    suffix_lengths[index] += 1;
                    progressed = true;
                }
            }
        }

        if !has_collision {
            return Ok(roots);
        }

        if !progressed {
            return Err(anyhow::anyhow!(
                "Input paths must resolve to unique archive roots"
            ));
        }
    }
}

fn excluded_pack_paths(req: &Request) -> Result<HashSet<PathBuf>> {
    let mut paths = HashSet::new();
    paths.insert(
        fs::canonicalize(req.output_file)
            .with_context(|| format!("Unable to resolve output path {}", req.output_file))?,
    );

    if let HeaderLocation::Detached(path) = &req.crypto_params.header_location {
        paths.insert(
            fs::canonicalize(path)
                .with_context(|| format!("Unable to resolve detached header path {path}"))?,
        );
    }

    Ok(paths)
}

// this first indexes the input directory
// once it has the total number of files/folders, it creates a temporary zip file
// it compresses all of the files into the temporary archive
// once compressed, it encrypts the zip file
// it erases the temporary archive afterwards, to stop any residual data from remaining
pub fn execute(req: &Request) -> Result<()> {
    // TODO: It is necessary to raise it to a higher level
    let stor = Arc::new(domain::storage::FileStorage);

    // 1. validate and prepare options
    if req.input_file.iter().any(|f| f == req.output_file) {
        return Err(anyhow::anyhow!(
            "Input and output files cannot have the same name."
        ));
    }

    if req.input_file.iter().any(|f| PathBuf::from(f).is_file()) {
        return Err(anyhow::anyhow!("Input path cannot be a file."));
    }

    let output_ok = overwrite_check(req.output_file, req.crypto_params.force)?;

    if !should_continue_after_overwrite_checks(output_ok, || {
        match &req.crypto_params.header_location {
            HeaderLocation::Embedded => Ok(None),
            HeaderLocation::Detached(path) => {
                overwrite_check(path, req.crypto_params.force).map(Some)
            }
        }
    })? {
        return Ok(());
    }

    let input_files = req
        .input_file
        .iter()
        .map(|file_name| stor.read_file(file_name))
        .collect::<Result<Vec<_>, _>>()?;
    let raw_key = req.crypto_params.key.get_secret(&PasswordState::Validate)?;
    let output_file = stor
        .create_file(req.output_file)
        .or_else(|_| stor.write_file(req.output_file))?;

    let header_file = match &req.crypto_params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => {
            Some(stor.create_file(path).or_else(|_| stor.write_file(path))?)
        }
    };

    let archive_root_names = archive_root_names(req.input_file)?;
    let excluded_paths = excluded_pack_paths(req)?;

    let mut entries = Vec::new();
    for (file, archive_root_name) in input_files.into_iter().zip(archive_root_names.into_iter()) {
        let root_path = file.path().to_path_buf();

        if file.is_dir() {
            let files = stor.read_dir(&file)?;
            for source in files {
                let canonical_source_path = fs::canonicalize(source.path())
                    .map_err(|_| domain::storage::Error::DirEntries)?;
                if excluded_paths.contains(&canonical_source_path) {
                    continue;
                }

                let relative = source
                    .path()
                    .strip_prefix(&root_path)
                    .map_err(|_| domain::storage::Error::DirEntries)?;
                let archive_path = if relative.as_os_str().is_empty() {
                    archive_root_name.clone()
                } else {
                    archive_root_name.join(relative)
                };

                entries.push(domain::pack::ArchiveSourceEntry {
                    source,
                    archive_path,
                });
            }
        } else {
            entries.push(domain::pack::ArchiveSourceEntry {
                source: file,
                archive_path: archive_root_name,
            });
        }
    }

    let compression_method = match req.pack_params.compression {
        Compression::None => zip::CompressionMethod::Stored,
        Compression::Zstd => zip::CompressionMethod::Zstd,
    };

    // 2. compress and encrypt files
    domain::pack::execute(
        stor.clone(),
        domain::pack::Request {
            entries,
            compression_method,
            writer: output_file.try_writer()?,
            header_writer: header_file.as_ref().and_then(|f| f.try_writer().ok()),
            raw_key,
            header_type: HeaderType {
                version: HEADER_VERSION,
                mode: Mode::StreamMode,
                algorithm: req.algorithm,
            },
            hashing_algorithm: req.crypto_params.hashing_algorithm,
        },
    )?;

    // 3. flush result
    if let Some(header_file) = header_file {
        stor.flush_file(&header_file)?;
    }
    stor.flush_file(&output_file)?;

    if req.crypto_params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[req.output_file.to_string()])?;
    }

    if req.pack_params.erase_source == EraseSourceDir::Erase {
        req.input_file.iter().try_for_each(|file_name| {
            super::erase::secure_erase(file_name, 1, req.crypto_params.force)
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    #[test]
    fn archive_root_names_expand_to_minimal_unique_suffixes() {
        let roots =
            super::archive_root_names(&["parent1/foo".to_string(), "parent2/foo".to_string()])
                .unwrap();

        assert_eq!(
            roots,
            vec![PathBuf::from("parent1/foo"), PathBuf::from("parent2/foo")]
        );
    }

    #[test]
    fn archive_root_names_keep_shorter_visible_path_when_sibling_is_more_specific() {
        let roots = super::archive_root_names(&["foo".to_string(), "bar/foo".to_string()]).unwrap();

        assert_eq!(roots, vec![PathBuf::from("foo"), PathBuf::from("bar/foo")]);
    }

    #[cfg(windows)]
    #[test]
    fn archive_root_names_distinguish_drive_prefixes_when_needed() {
        let roots =
            super::archive_root_names(&[r"C:\foo".to_string(), r"D:\foo".to_string()]).unwrap();

        assert_eq!(
            roots,
            vec![
                PathBuf::from("drive-C").join("foo"),
                PathBuf::from("drive-D").join("foo"),
            ]
        );
    }

    #[test]
    fn detached_header_decline_returns_false_before_work_starts() {
        assert!(!super::should_continue_after_overwrite_checks(true, || Ok(Some(false))).unwrap());
    }

    #[test]
    fn approve_all_overwrite_checks_returns_true() {
        assert!(super::should_continue_after_overwrite_checks(true, || Ok(Some(true))).unwrap());
        assert!(super::should_continue_after_overwrite_checks(true, || Ok(None)).unwrap());
    }

    #[test]
    fn main_output_decline_short_circuits_header_check() {
        let mut called = false;

        let result = super::should_continue_after_overwrite_checks(false, || {
            called = true;
            Ok(Some(true))
        })
        .unwrap();

        assert!(!result);
        assert!(!called);
    }
}
