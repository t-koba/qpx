use super::*;
use crate::envsubst::expand_env_with;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("qpx-core should live below the workspace root")
        .to_path_buf()
}

fn collect_yaml_files(dir: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|err| {
        panic!(
            "failed to read sample config directory {}: {err}",
            dir.display()
        )
    }) {
        let path = entry
            .unwrap_or_else(|err| panic!("failed to read sample config entry: {err}"))
            .path();
        if path.is_dir() {
            collect_yaml_files(&path, files);
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("yaml") {
            files.push(path);
        }
    }
}

fn is_qpxd_sample_config(path: &Path) -> bool {
    let path = path.to_string_lossy();
    !path.contains("/fragments/")
        && !path.ends_with("/qpxf.yaml")
        && !path.ends_with("/qpxf-tcp.yaml")
        && !path.ends_with("/qpxf-fastcgi.yaml")
        && !path.contains("-native-")
}

fn load_sample_config(path: &Path) -> Result<crate::config::Config, ConfigLoadError> {
    let raw = fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed to read sample config {}: {err}", path.display()));
    let expanded = expand_sample_env(&raw)
        .unwrap_or_else(|err| panic!("env expansion failed for {}: {err}", path.display()));
    let _: serde_yaml::Value = serde_yaml::from_str(&expanded)
        .unwrap_or_else(|err| panic!("yaml parse failed for {}: {err}", path.display()));
    let dir = unique_tmp_dir();
    let root = workspace_root();
    let relative = path
        .strip_prefix(&root)
        .unwrap_or_else(|_| panic!("sample config should be below {}", root.display()));
    let config = dir.join(relative);
    fs::create_dir_all(config.parent().expect("config parent")).expect("mkdir");
    copy_sample_fragments(&root, &dir);
    fs::write(&config, expanded).expect("write canonical sample config");
    let loaded = load_config(&config);
    fs::remove_dir_all(&dir).ok();
    loaded
}

fn expand_sample_env(raw: &str) -> Result<String, crate::envsubst::EnvSubstError> {
    expand_env_with(raw, |key| match key {
        "QPXF_UNIX_LISTEN" => Some("unix:///tmp/qpx-config-test-qpxf.sock".to_string()),
        _ => None,
    })
}

fn copy_sample_fragments(root: &Path, dir: &Path) {
    let fragments = root.join("config/fragments");
    let target = dir.join("config/fragments");
    fs::create_dir_all(&target).expect("mkdir fragments");
    for entry in fs::read_dir(&fragments).unwrap_or_else(|err| {
        panic!(
            "failed to read sample fragments directory {}: {err}",
            fragments.display()
        )
    }) {
        let path = entry
            .unwrap_or_else(|err| panic!("failed to read sample fragment entry: {err}"))
            .path();
        if path.is_file() {
            let raw = fs::read_to_string(&path).unwrap_or_else(|err| {
                panic!("failed to read sample fragment {}: {err}", path.display())
            });
            let expanded = expand_sample_env(&raw).unwrap_or_else(|err| {
                panic!(
                    "env expansion failed for sample fragment {}: {err}",
                    path.display()
                )
            });
            fs::write(
                target.join(path.file_name().expect("fragment file name")),
                expanded,
            )
            .unwrap_or_else(|err| {
                panic!("failed to write sample fragment {}: {err}", path.display())
            });
        }
    }
}

#[test]
fn sample_qpxd_configs_load() {
    let root = workspace_root();
    let mut files = vec![root.join("config/qpx.example.yaml")];
    collect_yaml_files(&root.join("config/usecases"), &mut files);
    files.retain(|path| is_qpxd_sample_config(path));
    files.sort();

    assert!(!files.is_empty(), "no qpxd sample configs found");
    for path in files {
        if let Err(err) = load_sample_config(&path) {
            let chain = err
                .chain()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n");
            panic!("sample config failed to load: {}\n{chain}", path.display());
        }
    }
}
