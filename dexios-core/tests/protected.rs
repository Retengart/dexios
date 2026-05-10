use dexios_core::protected::Protected;

#[test]
fn debug_output_is_redacted() {
    let secret = Protected::new(b"secret debug bytes".to_vec());

    assert_eq!(format!("{secret:?}"), "[REDACTED]");
}

#[test]
fn with_exposed_scopes_secret_access_to_closure() {
    let secret = Protected::new(vec![1, 2, 3, 4]);

    let observed_len = secret.with_exposed(|bytes| {
        assert_eq!(bytes.as_slice(), &[1, 2, 3, 4]);
        bytes.len()
    });

    assert_eq!(observed_len, 4);
}

#[test]
fn protected_source_has_no_blanket_clone_public_expose_or_deref() {
    let source = include_str!("../src/protected.rs");

    assert!(
        !source.contains("#[derive(Clone)]"),
        "Protected<T> must not derive blanket Clone"
    );
    assert!(
        !source.contains("impl<T> Clone for Protected<T>"),
        "Protected<T> must not provide blanket Clone"
    );
    assert!(
        !source.contains("pub fn expose("),
        "Protected<T> must not expose secrets through a public direct accessor"
    );
    assert!(
        !source.contains("impl<T> std::ops::Deref for Protected<T>"),
        "Protected<T> must not implement Deref"
    );
}
