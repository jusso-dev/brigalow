//! Crash-safe, no-replace publication of a complete local output directory.
//!
//! Files are staged in a new private (0700) sibling directory on the same filesystem,
//! created exclusively relative to that directory's descriptor (no symlink following),
//! fsynced, sealed by a caller-built completion marker and published as a whole with the
//! platform's no-replace rename. A staged directory is never treated as published output.
//! Platforms without a no-replace rename fail closed; there is no existence-check emulation.
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("atomic no-replace directory publication is unsupported here")]
    Unsupported,
    #[error("output already exists")]
    Exists,
    #[error("existing output differs")]
    Mismatch,
    #[error("invalid output path")]
    Path,
    #[error("output I/O failed")]
    Io,
}

/// Behaviour when the destination already exists at publication time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Never replace or accept an existing destination.
    Refuse,
    /// Accept only a destination whose entries are byte-for-byte identical to the stage.
    RequireIdentical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Published {
    Created,
    Identical,
}

/// Digests (lowercase hex SHA-256) of every finished staged file, keyed by name.
pub type Digests = BTreeMap<&'static str, String>;

pub use imp::{Stage, Staged};

fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name != "."
        && name != ".."
        && !name.contains(['/', '\0'])
}

#[cfg(unix)]
mod imp {
    use super::{valid_name, Digests, Error, Existing, Published};
    use rustix::fs::{self, AtFlags, Mode, OFlags};
    use rustix::io::Errno;
    use sha2::{Digest, Sha256};
    use std::{
        ffi::OsString,
        fs::File,
        io::{self, BufWriter, Read, Write},
        os::fd::OwnedFd,
        path::{Component, Path, PathBuf},
    };

    const DIR_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    /// A private staging directory. Dropping an unpublished stage removes what it created.
    pub struct Stage {
        parent: OwnedFd,
        dir: OwnedFd,
        stage_name: String,
        target_name: OsString,
        created: Vec<&'static str>,
        digests: Digests,
        done: bool,
    }

    /// A create-new staged file; SHA-256 is computed over exactly the bytes written.
    pub struct Staged {
        name: &'static str,
        file: BufWriter<File>,
        hasher: Sha256,
    }

    impl Write for Staged {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let written = self.file.write(bytes)?;
            self.hasher.update(&bytes[..written]);
            Ok(written)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }

    fn split(target: &Path) -> Result<(PathBuf, OsString), Error> {
        let mut components: Vec<Component<'_>> = target.components().collect();
        let name = match components.pop() {
            Some(Component::Normal(name)) => name.to_owned(),
            _ => return Err(Error::Path),
        };
        if name.as_encoded_bytes().len() > 255 {
            return Err(Error::Path);
        }
        let parent: PathBuf = components.into_iter().collect();
        if parent.as_os_str().is_empty() {
            Ok((PathBuf::from("."), name))
        } else {
            Ok((parent, name))
        }
    }

    fn supported() -> bool {
        cfg!(any(target_os = "linux", target_os = "macos"))
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn rename_noreplace(parent: &OwnedFd, from: &str, to: &OsString) -> Result<(), Errno> {
        // Linux renameat2(RENAME_NOREPLACE); macOS renameatx_np(RENAME_EXCL).
        fs::renameat_with(parent, from, parent, to, fs::RenameFlags::NOREPLACE)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    fn rename_noreplace(_: &OwnedFd, _: &str, _: &OsString) -> Result<(), Errno> {
        Err(Errno::NOSYS)
    }

    impl Stage {
        /// Create a private staging directory beside `target`. Fails closed on platforms
        /// without a no-replace rename, before the caller performs any irreversible step.
        pub fn create(target: &Path) -> Result<Self, Error> {
            if !supported() {
                return Err(Error::Unsupported);
            }
            let (parent_path, target_name) = split(target)?;
            let parent = fs::open(
                &parent_path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| Error::Io)?;
            let stage_name = format!(".brigalow-stage-{}", uuid::Uuid::new_v4().simple());
            fs::mkdirat(&parent, stage_name.as_str(), Mode::RWXU).map_err(|_| Error::Io)?;
            let opened = (|| {
                let dir = fs::openat(&parent, stage_name.as_str(), DIR_FLAGS, Mode::empty())?;
                fs::fchmod(&dir, Mode::RWXU)?;
                let stat = fs::fstat(&dir)?;
                if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::Directory
                    || stat.st_uid != rustix::process::geteuid().as_raw()
                    || stat.st_mode & 0o7777 != 0o700
                {
                    return Err(Errno::PERM);
                }
                Ok(dir)
            })();
            match opened {
                Ok(dir) => Ok(Self {
                    parent,
                    dir,
                    stage_name,
                    target_name,
                    created: vec![],
                    digests: Digests::new(),
                    done: false,
                }),
                Err(_) => {
                    let _ = fs::unlinkat(&parent, stage_name.as_str(), AtFlags::REMOVEDIR);
                    Err(Error::Io)
                }
            }
        }

        /// Early refusal before irreversible work. Only the publication rename is authoritative.
        pub fn ensure_absent(&self) -> Result<(), Error> {
            match fs::statat(&self.parent, &self.target_name, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(_) => Err(Error::Exists),
                Err(Errno::NOENT) => Ok(()),
                Err(_) => Err(Error::Io),
            }
        }

        pub fn file(&mut self, name: &'static str) -> Result<Staged, Error> {
            if !valid_name(name) || self.created.contains(&name) {
                return Err(Error::Path);
            }
            let fd = fs::openat(
                &self.dir,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::RUSR,
            )
            .map_err(|_| Error::Io)?;
            self.created.push(name);
            Ok(Staged {
                name,
                file: BufWriter::new(File::from(fd)),
                hasher: Sha256::new(),
            })
        }

        /// Flush and fsync a staged file, then record its digest.
        pub fn finish(&mut self, staged: Staged) -> Result<(), Error> {
            let Staged { name, file, hasher } = staged;
            let file = file.into_inner().map_err(|_| Error::Io)?;
            file.sync_all().map_err(|_| Error::Io)?;
            self.digests
                .insert(name, format!("{:x}", hasher.finalize()));
            Ok(())
        }

        pub fn write(&mut self, name: &'static str, bytes: &[u8]) -> Result<(), Error> {
            let mut staged = self.file(name)?;
            staged.write_all(bytes).map_err(|_| Error::Io)?;
            self.finish(staged)
        }

        pub fn digests(&self) -> &Digests {
            &self.digests
        }

        /// Write and fsync the completion marker last, then publish the whole directory
        /// without replacement and fsync the parent.
        pub fn publish(
            mut self,
            marker_name: &'static str,
            marker: &[u8],
            existing: Existing,
        ) -> Result<Published, Error> {
            if self.created.len() != self.digests.len() {
                return Err(Error::Io);
            }
            self.write(marker_name, marker)?;
            fs::fsync(&self.dir).map_err(|_| Error::Io)?;
            match rename_noreplace(&self.parent, &self.stage_name, &self.target_name) {
                Ok(()) => {
                    // Published: never clean up the destination, even if the parent fsync fails.
                    self.done = true;
                    fs::fsync(&self.parent).map_err(|_| Error::Io)?;
                    Ok(Published::Created)
                }
                Err(Errno::EXIST | Errno::NOTEMPTY) => match existing {
                    Existing::Refuse => Err(Error::Exists),
                    Existing::RequireIdentical => {
                        self.matches_existing()?;
                        Ok(Published::Identical)
                    }
                },
                Err(Errno::NOSYS | Errno::INVAL | Errno::NOTSUP) => Err(Error::Unsupported),
                Err(_) => Err(Error::Io),
            }
        }

        fn matches_existing(&self) -> Result<(), Error> {
            let target = fs::openat(&self.parent, &self.target_name, DIR_FLAGS, Mode::empty())
                .map_err(|_| Error::Mismatch)?;
            let mut names = vec![];
            for entry in fs::Dir::read_from(&target).map_err(|_| Error::Mismatch)? {
                let entry = entry.map_err(|_| Error::Mismatch)?;
                let name = entry.file_name().to_bytes();
                if name != b"." && name != b".." {
                    names.push(name.to_vec());
                }
            }
            let mut expected: Vec<Vec<u8>> = self
                .created
                .iter()
                .map(|name| name.as_bytes().to_vec())
                .collect();
            names.sort();
            expected.sort();
            if names != expected {
                return Err(Error::Mismatch);
            }
            let read = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
            for name in &self.created {
                let existing =
                    fs::openat(&target, *name, read, Mode::empty()).map_err(|_| Error::Mismatch)?;
                let stat = fs::fstat(&existing).map_err(|_| Error::Mismatch)?;
                if fs::FileType::from_raw_mode(stat.st_mode) != fs::FileType::RegularFile {
                    return Err(Error::Mismatch);
                }
                let staged =
                    fs::openat(&self.dir, *name, read, Mode::empty()).map_err(|_| Error::Io)?;
                if !identical(File::from(staged), File::from(existing))? {
                    return Err(Error::Mismatch);
                }
            }
            Ok(())
        }
    }

    fn identical(mut a: File, mut b: File) -> Result<bool, Error> {
        let (mut left, mut right) = (vec![0; 65536], vec![0; 65536]);
        loop {
            let n = fill(&mut a, &mut left).map_err(|_| Error::Io)?;
            let m = fill(&mut b, &mut right).map_err(|_| Error::Mismatch)?;
            if n != m || left[..n] != right[..m] {
                return Ok(false);
            }
            if n == 0 {
                return Ok(true);
            }
        }
    }

    fn fill(file: &mut File, buffer: &mut [u8]) -> io::Result<usize> {
        let mut filled = 0;
        while filled < buffer.len() {
            match file.read(&mut buffer[filled..])? {
                0 => break,
                n => filled += n,
            }
        }
        Ok(filled)
    }

    impl Drop for Stage {
        fn drop(&mut self) {
            if self.done {
                return;
            }
            for name in &self.created {
                let _ = fs::unlinkat(&self.dir, *name, AtFlags::empty());
            }
            let _ = fs::unlinkat(&self.parent, self.stage_name.as_str(), AtFlags::REMOVEDIR);
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::{Digests, Error, Existing, Published};
    /// Never constructed: publication requires a Unix no-replace rename.
    pub struct Stage {
        digests: Digests,
    }
    pub struct Staged;
    impl std::io::Write for Staged {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::Unsupported.into())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::ErrorKind::Unsupported.into())
        }
    }
    impl Stage {
        pub fn create(_: &std::path::Path) -> Result<Self, Error> {
            Err(Error::Unsupported)
        }
        pub fn ensure_absent(&self) -> Result<(), Error> {
            Err(Error::Unsupported)
        }
        pub fn file(&mut self, _: &'static str) -> Result<Staged, Error> {
            Err(Error::Unsupported)
        }
        pub fn finish(&mut self, _: Staged) -> Result<(), Error> {
            Err(Error::Unsupported)
        }
        pub fn write(&mut self, _: &'static str, _: &[u8]) -> Result<(), Error> {
            Err(Error::Unsupported)
        }
        pub fn digests(&self) -> &Digests {
            &self.digests
        }
        pub fn publish(self, _: &'static str, _: &[u8], _: Existing) -> Result<Published, Error> {
            Err(Error::Unsupported)
        }
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn stage(target: &Path, body: &[u8]) -> Stage {
        let mut stage = Stage::create(target).unwrap();
        stage.write("a.txt", body).unwrap();
        stage.write("b.txt", b"second").unwrap();
        stage
    }
    fn marker(stage: &Stage) -> Vec<u8> {
        serde_json::to_vec(stage.digests()).unwrap()
    }
    fn leftovers(parent: &Path) -> Vec<String> {
        std::fs::read_dir(parent)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(".brigalow-stage-"))
            .collect()
    }

    #[test]
    fn publishes_private_complete_directory_with_marker_digests() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("out");
        let stage = stage(&target, b"first");
        let m = marker(&stage);
        assert_eq!(
            stage
                .publish("COMPLETE.json", &m, Existing::Refuse)
                .unwrap(),
            Published::Created
        );
        let mode = std::fs::metadata(&target).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700);
        for name in ["a.txt", "b.txt", "COMPLETE.json"] {
            let meta = std::fs::symlink_metadata(target.join(name)).unwrap();
            assert!(meta.is_file());
            assert_eq!(meta.permissions().mode() & 0o7777, 0o400);
        }
        let digests: BTreeMap<String, String> =
            serde_json::from_slice(&std::fs::read(target.join("COMPLETE.json")).unwrap()).unwrap();
        use sha2::Digest;
        assert_eq!(
            digests["a.txt"],
            format!("{:x}", sha2::Sha256::digest(b"first"))
        );
        assert!(leftovers(temp.path()).is_empty());
    }

    #[test]
    fn collision_never_replaces_and_unpublished_stage_is_removed() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("out");
        std::fs::create_dir(&target).unwrap();
        std::fs::write(target.join("keep"), b"operator data").unwrap();
        let stage = stage(&target, b"first");
        assert!(matches!(stage.ensure_absent(), Err(Error::Exists)));
        let m = marker(&stage);
        assert!(matches!(
            stage.publish("COMPLETE.json", &m, Existing::Refuse),
            Err(Error::Exists)
        ));
        assert_eq!(
            std::fs::read(target.join("keep")).unwrap(),
            b"operator data"
        );
        assert!(!target.join("a.txt").exists());
        assert!(leftovers(temp.path()).is_empty());
        // An abandoned (crashed) stage is never the published destination.
        let other = temp.path().join("other");
        let mut partial = Stage::create(&other).unwrap();
        partial.write("a.txt", b"half").unwrap();
        drop(partial);
        assert!(!other.exists());
        assert!(leftovers(temp.path()).is_empty());
    }

    #[test]
    fn rejects_symlink_destination_and_escaping_names() {
        let temp = tempfile::tempdir().unwrap();
        let real = temp.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let first = stage(&real, b"first");
        let m = marker(&first);
        first
            .publish("COMPLETE.json", &m, Existing::Refuse)
            .unwrap_err();
        std::fs::remove_dir(&real).unwrap();
        let published = stage(&real, b"first");
        let m = marker(&published);
        published
            .publish("COMPLETE.json", &m, Existing::Refuse)
            .unwrap();
        // A symlink to an identical directory is not accepted as existing output.
        let again = stage(&link, b"first");
        let m = marker(&again);
        assert!(matches!(
            again.publish("COMPLETE.json", &m, Existing::RequireIdentical),
            Err(Error::Mismatch)
        ));
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let mut names = Stage::create(&temp.path().join("names")).unwrap();
        for bad in ["../escape", "a/b", "..", ".", ""] {
            assert!(matches!(names.file(bad), Err(Error::Path)));
        }
        names.write("ok", b"1").unwrap();
        assert!(matches!(names.file("ok"), Err(Error::Path)));
        drop(names);
        assert!(!temp.path().join("escape").exists());
        for bad in ["..", "/", "x/.."] {
            assert!(matches!(Stage::create(Path::new(bad)), Err(Error::Path)));
        }
        assert!(leftovers(temp.path()).is_empty());
    }

    #[test]
    fn identical_existing_output_is_accepted_and_any_difference_fails() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("out");
        let first = stage(&target, b"first");
        let m = marker(&first);
        first
            .publish("COMPLETE.json", &m, Existing::Refuse)
            .unwrap();
        let same = stage(&target, b"first");
        let m = marker(&same);
        assert_eq!(
            same.publish("COMPLETE.json", &m, Existing::RequireIdentical)
                .unwrap(),
            Published::Identical
        );
        let changed = stage(&target, b"firsT");
        let m = marker(&changed);
        assert!(matches!(
            changed.publish("COMPLETE.json", &m, Existing::RequireIdentical),
            Err(Error::Mismatch)
        ));
        // Partial (truncated) marker in the existing output fails verification.
        let marker_path = target.join("COMPLETE.json");
        let original = std::fs::read(&marker_path).unwrap();
        std::fs::set_permissions(&marker_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&marker_path, &original[..original.len() / 2]).unwrap();
        let check = stage(&target, b"first");
        let m = marker(&check);
        assert!(matches!(
            check.publish("COMPLETE.json", &m, Existing::RequireIdentical),
            Err(Error::Mismatch)
        ));
        // Missing marker and an extra file also fail.
        std::fs::remove_file(&marker_path).unwrap();
        let check = stage(&target, b"first");
        let m = marker(&check);
        assert!(check
            .publish("COMPLETE.json", &m, Existing::RequireIdentical)
            .is_err());
        std::fs::write(&marker_path, &original).unwrap();
        std::fs::write(target.join("extra"), b"x").unwrap();
        let check = stage(&target, b"first");
        let m = marker(&check);
        assert!(check
            .publish("COMPLETE.json", &m, Existing::RequireIdentical)
            .is_err());
        assert!(leftovers(temp.path()).is_empty());
    }

    #[test]
    fn concurrent_publishers_yield_exactly_one_complete_directory() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("out");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let target = target.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    let body = format!("publisher {i}");
                    let stage = stage(&target, body.as_bytes());
                    let m = marker(&stage);
                    barrier.wait();
                    (body, stage.publish("COMPLETE.json", &m, Existing::Refuse))
                })
            })
            .collect();
        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        let winners: Vec<_> = results
            .iter()
            .filter(|(_, r)| matches!(r, Ok(Published::Created)))
            .collect();
        assert_eq!(winners.len(), 1);
        assert!(results
            .iter()
            .filter(|(_, r)| r.is_err())
            .all(|(_, r)| matches!(r, Err(Error::Exists))));
        assert_eq!(
            std::fs::read(target.join("a.txt")).unwrap(),
            winners[0].0.as_bytes()
        );
        assert!(leftovers(temp.path()).is_empty());
    }
}
