use anyhow::{Context, Result, anyhow};
use std::fs;
use std::path::{Path, PathBuf};
use syn::punctuated::Punctuated;
use syn::{Attribute, Meta, Token};

pub(crate) fn workspace_root() -> Result<PathBuf> {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| anyhow!("failed to resolve workspace root"))
}

pub(crate) fn rust_files_under(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_rust_files(root, &mut files)?;
    files.sort();
    Ok(files)
}

fn collect_rust_files(path: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    if path.is_file() {
        if path.extension().and_then(|value| value.to_str()) == Some("rs") {
            files.push(path.to_path_buf());
        }
        return Ok(());
    }
    for entry in fs::read_dir(path).with_context(|| format!("failed to read {}", path.display()))? {
        let entry = entry.with_context(|| format!("failed to read entry in {}", path.display()))?;
        collect_rust_files(&entry.path(), files)?;
    }
    Ok(())
}

pub(crate) fn is_test_file(path: &Path) -> bool {
    path.components()
        .any(|component| component.as_os_str() == "tests")
        || path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| {
                name.ends_with("_test.rs")
                    || name.ends_with("_tests.rs")
                    || name == "tests.rs"
                    || name == "test_util.rs"
            })
}

/// Whether every `cfg` attribute on the item can only hold when `test` is on.
///
/// A single `test` or `all(test, ...)` predicate is test-only. `any(feature,
/// ..., test)` is production because a feature can enable it, and `not(...)`
/// is production because its negation can hold outside tests. Multiple `cfg`
/// attributes combine with logical AND, so one test-only conjunct makes the
/// whole item test-only.
pub(crate) fn has_cfg_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("cfg") {
            return false;
        }
        let Meta::List(list) = &attr.meta else {
            return false;
        };
        let Ok(predicate) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
        else {
            return false;
        };
        predicate.len() == 1 && meta_is_test_only(&predicate[0])
    })
}

fn meta_is_test_only(meta: &Meta) -> bool {
    match meta {
        Meta::Path(path) => path.is_ident("test"),
        Meta::List(list) if list.path.is_ident("all") => {
            let Ok(args) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            else {
                return false;
            };
            !args.is_empty() && args.iter().any(meta_is_test_only)
        }
        Meta::List(list) if list.path.is_ident("any") => {
            let Ok(args) = list.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)
            else {
                return false;
            };
            !args.is_empty() && args.iter().all(meta_is_test_only)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::has_cfg_test;
    use syn::ItemFn;

    fn attrs(source: &str) -> Vec<syn::Attribute> {
        syn::parse_str::<ItemFn>(source)
            .expect("test item parses")
            .attrs
    }

    #[test]
    fn cfg_test_is_test_only() {
        assert!(has_cfg_test(&attrs("#[cfg(test)] fn f() {}")));
        assert!(has_cfg_test(&attrs(
            "#[cfg(all(test, feature = \"http3\"))] fn f() {}"
        )));
        assert!(has_cfg_test(&attrs("#[cfg(any(test))] fn f() {}")));
    }

    #[test]
    fn feature_enabled_and_negated_cfg_are_production() {
        assert!(!has_cfg_test(&attrs(
            "#[cfg(any(feature = \"http3\", test))] fn f() {}"
        )));
        assert!(!has_cfg_test(&attrs("#[cfg(not(test))] fn f() {}")));
        assert!(!has_cfg_test(&attrs("fn f() {}")));
    }

    #[test]
    fn multiple_cfg_attributes_are_anded() {
        assert!(has_cfg_test(&attrs(
            "#[cfg(test)] #[cfg(all(test, feature = \"http3\"))] fn f() {}"
        )));
    }
}
