#[cfg(not(unix))]
use super::ensure_private_dir;
use super::temp_path;
use anyhow::{Context, Result, anyhow};
use std::fs::File;
use std::path::{Path, PathBuf};

pub(super) struct CachePublication {
    destination: PathBuf,
    temporary: PathBuf,
    #[cfg(unix)]
    directory: super::nofollow::Directory,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn publication_and_cleanup_remain_in_the_verified_parent() {
        let root = super::super::tests::temp_dir("anchored-publication");
        let outside = super::super::tests::temp_dir("outside-publication");
        let parent = root.join("objects");
        let destination = parent.join("object.qpxc");
        let publication = CachePublication::new(&destination).expect("open publication parent");
        let saved = root.join("saved");
        std::fs::rename(&parent, &saved).expect("move verified directory");
        std::os::unix::fs::symlink(&outside, &parent).expect("replace parent with symlink");
        let protected = outside.join("object.qpxc");
        std::fs::write(&protected, b"outside").expect("write outside sentinel");
        let mut file = publication.create().expect("create in verified directory");
        file.write_all(b"published").expect("write publication");
        drop(file);
        publication.commit().expect("publish in verified directory");
        assert_eq!(
            std::fs::read(saved.join("object.qpxc")).expect("read publication"),
            b"published"
        );
        assert_eq!(
            std::fs::read(&protected).expect("read outside sentinel"),
            b"outside"
        );
        drop(
            publication
                .create()
                .expect("create failed publication fixture"),
        );
        let error = publication
            .finish::<()>(Err(anyhow!("write failed")))
            .expect_err("retain write failure");
        assert_eq!(error.to_string(), "write failed");
        assert_eq!(
            std::fs::read_dir(&saved)
                .expect("list verified directory")
                .count(),
            1
        );
        assert_eq!(
            std::fs::read_dir(&outside)
                .expect("list outside directory")
                .count(),
            1
        );
        assert!(CachePublication::new(&destination).is_err());
        assert!(CachePublication::new(&parent.join("new/object.qpxc")).is_err());
        assert!(!outside.join("new").exists());
        std::fs::remove_dir_all(root).expect("remove publication fixture");
        std::fs::remove_dir_all(outside).expect("remove outside fixture");
    }
}

impl CachePublication {
    pub(super) fn new(path: &Path) -> Result<Self> {
        let parent = path
            .parent()
            .ok_or_else(|| anyhow!("disk cache path missing parent"))?;
        if path.file_name().is_none() {
            return Err(anyhow!("disk cache path missing file name"));
        }
        #[cfg(unix)]
        let directory = match super::nofollow::Directory::open(parent) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                super::nofollow::Directory::create_all(parent)?
            }
            Err(error) => {
                return Err(error).context("failed to open disk cache publication directory");
            }
        };
        #[cfg(not(unix))]
        ensure_private_dir(parent)?;
        Ok(Self {
            destination: path.to_path_buf(),
            temporary: temp_path(parent),
            #[cfg(unix)]
            directory,
        })
    }

    pub(super) fn create(&self) -> Result<File> {
        #[cfg(unix)]
        let result = self.directory.create(
            self.temporary
                .file_name()
                .expect("validated temporary name"),
        );
        #[cfg(not(unix))]
        let result = super::create_secure_new_file(&self.temporary);
        result.with_context(|| {
            format!(
                "failed to create disk cache file {}",
                self.temporary.display()
            )
        })
    }

    pub(super) fn commit(&self) -> Result<()> {
        #[cfg(unix)]
        let result = self.directory.rename(
            self.temporary
                .file_name()
                .expect("validated temporary name"),
            self.destination
                .file_name()
                .expect("validated destination name"),
        );
        #[cfg(not(unix))]
        let result = std::fs::rename(&self.temporary, &self.destination);
        result.with_context(|| {
            format!(
                "failed to commit disk cache object {}",
                self.destination.display()
            )
        })
    }

    pub(super) fn finish<T>(&self, result: Result<T>) -> Result<T> {
        let Err(error) = result else {
            return result;
        };
        #[cfg(unix)]
        let cleanup = self.directory.remove(
            self.temporary
                .file_name()
                .expect("validated temporary name"),
        );
        #[cfg(not(unix))]
        let cleanup = std::fs::remove_file(&self.temporary);
        match cleanup {
            Ok(()) => Err(error),
            Err(cleanup) if cleanup.kind() == std::io::ErrorKind::NotFound => Err(error),
            Err(cleanup) => Err(error.context(format!(
                "failed to clean disk cache temporary file: {cleanup}"
            ))),
        }
    }
}
