//! Access project-owned files without interpreting a checkout's symbolic links
//! as authorization to touch another location. Not for explicit operator paths.

use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Component, Path};

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "expected a repository-relative regular file without linked components",
    )
}

fn parts(path: &Path) -> io::Result<Vec<&OsStr>> {
    let parts = path
        .components()
        .filter(|part| *part != Component::CurDir)
        .map(|part| match part {
            Component::Normal(name) => Ok(name),
            _ => Err(invalid()),
        })
        .collect::<io::Result<Vec<_>>>()?;
    if parts.is_empty() {
        return Err(invalid());
    }
    Ok(parts)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Access {
    Read,
    Write,
    CreateNew,
}

pub(crate) fn exists(root: &Path, path: &Path) -> io::Result<bool> {
    match platform::open_file(root, &parts(path)?, Access::Read) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

pub(crate) fn write_if_absent(root: &Path, path: &Path, bytes: &[u8]) -> io::Result<bool> {
    match platform::open_file(root, &parts(path)?, Access::CreateNew) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            Ok(true)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            // An ordinary pre-existing file (also one racing creation) is
            // preserved. Links and non-regular objects are not accepted.
            if exists(root, path)? {
                Ok(false)
            } else {
                Err(err)
            }
        }
        Err(err) => Err(err),
    }
}

pub(crate) fn write_executable(root: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    let file = replace(root, path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o755))?;
    }
    #[cfg(not(unix))]
    drop(file); // Git for Windows invokes hook scripts through its shell.
    Ok(())
}

pub(crate) fn remove_if_exists(root: &Path, path: &Path) -> io::Result<()> {
    match platform::remove_file(root, &parts(path)?) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

pub(crate) fn read(root: &Path, path: &Path) -> io::Result<Option<Vec<u8>>> {
    match platform::open_file(root, &parts(path)?, Access::Read) {
        Ok(mut file) => {
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer)?;
            Ok(Some(buffer))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(crate) fn read_text(root: &Path, path: &Path) -> io::Result<Option<String>> {
    read(root, path)?
        .map(String::from_utf8)
        .transpose()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

pub(crate) fn write(root: &Path, path: &Path, bytes: &[u8]) -> io::Result<()> {
    replace(root, path, bytes).map(drop)
}

fn replace(root: &Path, path: &Path, bytes: &[u8]) -> io::Result<File> {
    let mut file = platform::open_file(root, &parts(path)?, Access::Write)?;
    // Never request truncation until the actual opened object has been checked.
    file.set_len(0)?;
    file.write_all(bytes)?;
    Ok(file)
}

#[cfg(unix)]
mod platform {
    use super::*;
    use rustix::fd::OwnedFd;
    use rustix::fs::{mkdirat, open, openat, unlinkat, AtFlags, Mode, OFlags};
    use rustix::io::Errno;
    use std::os::unix::fs::MetadataExt;

    fn open_parent(root: &Path, parents: &[&OsStr], create: bool) -> io::Result<OwnedFd> {
        let directory_flags =
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut fd = open(root, directory_flags, Mode::empty())?;
        for parent in parents {
            fd = match openat(&fd, *parent, directory_flags, Mode::empty()) {
                Err(Errno::NOENT) if create => {
                    match mkdirat(&fd, *parent, Mode::from_raw_mode(0o777)) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(err) => return Err(err.into()),
                    }
                    openat(&fd, *parent, directory_flags, Mode::empty())?
                }
                next => next?,
            };
        }
        Ok(fd)
    }

    pub(super) fn open_file(root: &Path, parts: &[&OsStr], access: Access) -> io::Result<File> {
        let (leaf, parents) = parts.split_last().ok_or_else(invalid)?;
        let fd = open_parent(root, parents, access != Access::Read)?;
        open_leaf(&fd, leaf, access)
    }

    fn open_leaf(fd: &OwnedFd, leaf: &OsStr, access: Access) -> io::Result<File> {
        let access = match access {
            Access::Read => OFlags::RDONLY,
            Access::Write => OFlags::WRONLY | OFlags::CREATE,
            Access::CreateNew => OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL,
        };
        let flags = access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let file = File::from(openat(fd, leaf, flags, Mode::from_raw_mode(0o666))?);
        let metadata = file.metadata()?;
        // Both reads and writes are restricted. Multiple directory entries
        // make it impossible to infer repository ownership from the path.
        if !metadata.is_file() || metadata.nlink() != 1 {
            return Err(invalid());
        }
        Ok(file)
    }

    pub(super) fn remove_file(root: &Path, parts: &[&OsStr]) -> io::Result<()> {
        let (leaf, parents) = parts.split_last().ok_or_else(invalid)?;
        let fd = open_parent(root, parents, false)?;
        // A link is rejected at open. Even if the leaf were swapped later,
        // unlinkat removes the name, never a symbolic link's referent.
        let _file = open_leaf(&fd, leaf, Access::Read)?;
        unlinkat(&fd, *leaf, AtFlags::empty()).map_err(Into::into)
    }
}

#[cfg(not(unix))]
mod platform {
    use super::*;
    use std::fs::{self, Metadata, OpenOptions};

    fn is_link(metadata: &Metadata) -> bool {
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
            metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
        }
        #[cfg(not(windows))]
        {
            metadata.is_symlink()
        }
    }

    // Rust's portable API does not provide descriptor-relative directory
    // traversal. Reject links and Windows junctions at every existing
    // component. This does not claim resistance to concurrent replacements on
    // non-Unix systems.
    fn checked_path(root: &Path, parts: &[&OsStr], write: bool) -> io::Result<std::path::PathBuf> {
        let (leaf, parents) = parts.split_last().ok_or_else(invalid)?;
        let mut path = root.to_path_buf();
        for part in parents {
            path.push(part);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_dir() && !is_link(&meta) => {}
                Ok(_) => return Err(invalid()),
                Err(err) if err.kind() == io::ErrorKind::NotFound && write => {
                    fs::create_dir(&path)?;
                }
                Err(err) => return Err(err),
            }
        }
        path.push(leaf);
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.is_file() && !is_link(&meta) => {}
            Ok(_) => return Err(invalid()),
            Err(err) if err.kind() == io::ErrorKind::NotFound && write => {}
            Err(err) => return Err(err),
        }
        Ok(path)
    }

    pub(super) fn open_file(root: &Path, parts: &[&OsStr], access: Access) -> io::Result<File> {
        let write = access != Access::Read;
        let path = checked_path(root, parts, write)?;
        let mut options = OpenOptions::new();
        options.read(!write).write(write);
        match access {
            Access::Read => {}
            Access::Write => {
                options.create(true);
            }
            Access::CreateNew => {
                options.create_new(true);
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x00200000;
            options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let file = options.open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || is_link(&metadata) {
            return Err(invalid());
        }
        Ok(file)
    }

    pub(super) fn remove_file(root: &Path, parts: &[&OsStr]) -> io::Result<()> {
        std::fs::remove_file(checked_path(root, parts, false)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_relative_file_components_pass() {
        let root = tempfile::tempdir().unwrap();
        for bad in ["", ".", "../outside", "nested/../file", "/outside"] {
            assert_eq!(
                read(root.path(), Path::new(bad)).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn repo_data_round_trips_and_absence_remains_absence() {
        let root = tempfile::tempdir().unwrap();
        let path = Path::new("nested/state.toml");
        assert_eq!(read(root.path(), path).unwrap(), None);
        write(root.path(), path, b"first value").unwrap();
        write(root.path(), path, b"second").unwrap();
        assert_eq!(read(root.path(), path).unwrap().unwrap(), b"second");
    }

    #[test]
    fn exclusive_install_preserves_existing_file_and_can_remove_it() {
        let root = tempfile::tempdir().unwrap();
        let rel = Path::new("nested/state.toml");
        assert!(!exists(root.path(), rel).unwrap());
        assert!(write_if_absent(root.path(), rel, b"one").unwrap());
        assert!(!write_if_absent(root.path(), rel, b"two").unwrap());
        assert_eq!(read(root.path(), rel).unwrap().unwrap(), b"one");
        remove_if_exists(root.path(), rel).unwrap();
        remove_if_exists(root.path(), rel).unwrap();
        assert!(!exists(root.path(), rel).unwrap());
    }

    #[test]
    #[cfg(unix)]
    fn multiply_linked_file_is_not_treated_as_project_owned() {
        let root = tempfile::tempdir().unwrap();
        let fixture = root.path().join("fixture");
        std::fs::write(&fixture, b"inert fixture").unwrap();
        let alias = Path::new("alias.toml");
        std::fs::hard_link(&fixture, root.path().join(alias)).unwrap();
        assert_eq!(
            read(root.path(), alias).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(
            write(root.path(), alias, b"replacement")
                .unwrap_err()
                .kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(std::fs::read(fixture).unwrap(), b"inert fixture");
    }

    #[test]
    #[cfg(unix)]
    fn link_components_are_rejected_and_benign_target_is_untouched() {
        use std::os::unix::fs::symlink;
        let root = tempfile::tempdir().unwrap();
        let inert = root.path().join("inert");
        std::fs::create_dir(&inert).unwrap();
        std::fs::write(inert.join("fixture"), b"inert sentinel").unwrap();
        symlink(&inert, root.path().join("linked-parent")).unwrap();
        symlink(inert.join("fixture"), root.path().join("linked-leaf")).unwrap();
        for name in ["linked-parent/fixture", "linked-leaf"] {
            let path = Path::new(name);
            assert!(read(root.path(), path).is_err());
            assert!(write(root.path(), path, b"replacement").is_err());
            assert!(write_if_absent(root.path(), path, b"replacement").is_err());
            assert!(write_executable(root.path(), path, b"replacement").is_err());
            assert!(remove_if_exists(root.path(), path).is_err());
        }
        assert_eq!(
            std::fs::read(inert.join("fixture")).unwrap(),
            b"inert sentinel"
        );
    }
}
