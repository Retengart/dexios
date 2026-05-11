use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};

use crate::global::states::{
    DeleteSource, DirectoryMode, HashMode, HeaderLocation, PasswordState, PrintMode,
};
use crate::global::{
    states::Compression,
    structs::{CryptoParams, PackParams},
};
use crate::info;
use domain::storage::Storage;
use domain::storage::identity::OverwritePolicy;

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

fn overwrite_policy_for(path: &Path) -> OverwritePolicy {
    if fs::symlink_metadata(path).is_ok() {
        OverwritePolicy::ReplaceAtCommit
    } else {
        OverwritePolicy::CreateNew
    }
}

// this first indexes the input directory
// once it has the total number of files/folders, it creates a temporary zip file
// it compresses all of the files into the temporary archive
// once compressed, it encrypts the zip file
// it drops/deletes the temporary archive afterwards; this is cleanup only, not a secure-erase guarantee
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

    let output_path = PathBuf::from(req.output_file);
    let output_overwrite_policy = overwrite_policy_for(&output_path);
    let detached_header_path = match &req.crypto_params.header_location {
        HeaderLocation::Embedded => None,
        HeaderLocation::Detached(path) => Some(PathBuf::from(path)),
    };
    let detached_header_overwrite_policy = detached_header_path
        .as_ref()
        .map_or(OverwritePolicy::CreateNew, |path| {
            overwrite_policy_for(path)
        });

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

    let archive_root_names = archive_root_names(req.input_file)?;

    let mut entries = Vec::new();
    for (file, archive_root_name) in input_files.into_iter().zip(archive_root_names) {
        let root_path = file.path().to_path_buf();

        if file.is_dir() {
            let files = stor.read_dir(&file)?;
            for source in files {
                let relative = source
                    .path()
                    .strip_prefix(&root_path)
                    .map_err(|_| domain::storage::Error::DirEntries)?;
                let archive_path = if relative.as_os_str().is_empty() {
                    archive_root_name.clone()
                } else {
                    archive_root_name.join(relative)
                };

                if req.pack_params.print_mode == PrintMode::Verbose {
                    info!("Packing {}", archive_path.display());
                }

                entries.push(domain::pack::ArchiveSourceEntry {
                    source,
                    archive_path,
                });
            }
        } else {
            if req.pack_params.print_mode == PrintMode::Verbose {
                info!("Packing {}", archive_root_name.display());
            }
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
    let _commit_receipt =
        domain::pack::execute_transactional(domain::pack::TransactionalPackRequest {
            source_paths: req.input_file.iter().map(PathBuf::from).collect(),
            entries,
            output_path,
            detached_header_path,
            output_overwrite_policy,
            detached_header_overwrite_policy,
            raw_key,
            kdf: req.crypto_params.kdf,
            compression_method,
            recursive: req.pack_params.dir_mode == DirectoryMode::Recursive,
        })?;

    if req.crypto_params.hash_mode == HashMode::CalculateHash {
        super::hashing::hash_stream(&[req.output_file.to_string()])?;
    }

    if req.pack_params.delete_source == DeleteSource::Delete {
        req.input_file
            .iter()
            .try_for_each(|file_name| super::delete_path(file_name))?;
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
