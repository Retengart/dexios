use std::fs;
use std::path::Path;
use std::process::Command;

fn has_any_keyfile_arg(args: &[&str]) -> bool {
    args.iter()
        .any(|arg| matches!(*arg, "-k" | "--keyfile" | "--keyfile-old"))
}

fn has_new_key_source(args: &[&str]) -> bool {
    args.iter()
        .any(|arg| matches!(*arg, "-n" | "--keyfile-new") || arg.starts_with("--auto"))
}

fn has_auto_arg(args: &[&str]) -> bool {
    args.iter().any(|arg| arg.starts_with("--auto"))
}

fn is_help_request(args: &[&str]) -> bool {
    args.iter().any(|arg| matches!(*arg, "-h" | "--help"))
}

fn pack_reads_current_directory(args: &[&str]) -> bool {
    matches!(args.first(), Some(&"pack")) && args.contains(&".")
}

fn write_keyfile(current_dir: &Path, key: &str, args: &[&str]) -> std::path::PathBuf {
    let keyfile_dir = if pack_reads_current_directory(args) {
        current_dir
            .parent()
            .expect("pack . test directory should have a parent")
    } else {
        current_dir
    };
    let path = keyfile_dir.join(".dexios-test-key");
    fs::write(&path, key).expect("test keyfile should be writable");
    path
}

pub(crate) fn append_keyed_args(
    command: &mut Command,
    current_dir: &Path,
    key: &str,
    args: &[&str],
) {
    if args.is_empty() || is_help_request(args) || has_any_keyfile_arg(args) {
        command.args(args);
        return;
    }

    let keyfile = write_keyfile(current_dir, key, args);
    match args {
        ["encrypt" | "pack", rest @ ..] if has_auto_arg(rest) => {
            command.args(args);
        }
        ["encrypt" | "decrypt" | "pack" | "unpack", rest @ ..] => {
            command
                .arg(args[0])
                .arg("--keyfile")
                .arg(keyfile)
                .args(rest);
        }
        ["key", "add" | "change", rest @ ..] if has_new_key_source(rest) => {
            command
                .arg("key")
                .arg(args[1])
                .arg("--keyfile-old")
                .arg(keyfile)
                .args(rest);
        }
        ["key", "del" | "verify", rest @ ..] => {
            command
                .arg("key")
                .arg(args[1])
                .arg("--keyfile")
                .arg(keyfile)
                .args(rest);
        }
        _ => {
            command.args(args);
        }
    }
}
