//! Unix domain socket transport.
//!
//! On Unix, servers listen on a Unix domain socket next to the
//! rendezvous file.  Access is controlled by the file system
//! permissions of the socket, and by checking the peer's credentials,
//! hence no cookie is needed.

use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

use crate::Listener;

/// The prefix of the temporary directory used by [`bind`].
const TMP_PREFIX: &str = ".sock";

/// The number of random characters in the temporary directory's name.
const TMP_RAND: usize = 6;

/// The name of the socket in the temporary directory.
const TMP_NAME: &str = "s";

/// Returns the size of `sockaddr_un.sun_path`.
fn sun_path_len() -> usize {
    // Safety: sockaddr_un is plain old data.
    let addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    addr.sun_path.len()
}

/// Returns the directory containing `path`.
fn parent(path: &Path) -> &Path {
    match path.parent() {
        Some(p) if ! p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    }
}

/// Returns the path of the socket for the given rendezvous point.
///
/// Returns an error if the path does not fit into a `sockaddr_un`.
/// We deliberately do not fall back to TCP in that case.
pub(crate) fn socket_path(rendezvous: &Path) -> crate::Result<PathBuf> {
    let path = rendezvous.with_extension("sock");

    // `bind` first creates the socket in a temporary directory, which
    // has to fit too.
    let tmp_len = parent(&path).as_os_str().len()
        + 1 + TMP_PREFIX.len() + TMP_RAND + 1 + TMP_NAME.len();
    // sun_path must be NUL-terminated.
    if path.as_os_str().len().max(tmp_len) < sun_path_len() {
        Ok(path)
    } else {
        Err(anyhow::anyhow!(
            "The path of the socket {} is too long, use a shorter home \
             directory or explicitly select the TCP transport",
            path.display()))
    }
}

/// Locks the socket at `path`.
///
/// This serializes starting servers, so that a client does not
/// replace the socket of a server just started by another client.
/// The lock is held until the returned file is dropped.
pub(crate) fn lock(path: &Path) -> crate::Result<fs::File> {
    use anyhow::Context;
    use fs2::FileExt;

    let parent = parent(path);
    fs::create_dir_all(parent)
        .with_context(|| format!("Creating {}", parent.display()))?;

    let mut lock = path.as_os_str().to_owned();
    lock.push(".lock");
    let lock = PathBuf::from(lock);

    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&lock)
        .with_context(|| format!("Opening {}", lock.display()))?;
    file.lock_exclusive()
        .with_context(|| format!("Locking {}", lock.display()))?;
    Ok(file)
}

/// Binds a listener to `path`, replacing any stale socket.
///
/// The socket is created in a private directory, restricted to the
/// owner, and then atomically moved into place.  This way, the socket
/// is never accessible to other users, and we don't need to change
/// the process-wide umask.
pub(crate) fn bind(path: &Path) -> io::Result<UnixListener> {
    let tmp = tempfile::Builder::new()
        .prefix(TMP_PREFIX)
        .rand_bytes(TMP_RAND)
        .tempdir_in(parent(path))?;
    let tmp_path = tmp.path().join(TMP_NAME);

    let listener = UnixListener::bind(&tmp_path)?;
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
    fs::rename(&tmp_path, path)?;
    Ok(listener)
}

/// Binds a listener in a new private directory.
///
/// This is used for servers that are not supposed to be discovered by
/// other processes.  The returned directory should be dropped as soon
/// as the client has connected.
pub(crate) fn bind_private() -> io::Result<(UnixListener, PathBuf, tempfile::TempDir)> {
    let tmp = tempfile::Builder::new()
        .prefix(TMP_PREFIX)
        .rand_bytes(TMP_RAND)
        .tempdir()?;
    let path = tmp.path().join(TMP_NAME);
    let listener = UnixListener::bind(&path)?;
    Ok((listener, path, tmp))
}

/// Returns whether the peer runs under our effective user ID.
pub(crate) fn peer_is_us(stream: &tokio::net::UnixStream) -> bool {
    stream.peer_cred()
        // Safety: geteuid cannot fail.
        .map(|c| c.uid() == unsafe { libc::geteuid() })
        .unwrap_or(false)
}

impl Listener {
    /// Returns the listener for the given socket, detecting its
    /// address family.
    pub(crate) fn from_fd(fd: OwnedFd) -> io::Result<Self> {
        let socket = socket2::Socket::from(fd);
        if socket.local_addr()?.domain() == socket2::Domain::UNIX {
            Ok(Listener::Unix(socket.into()))
        } else {
            Ok(Listener::Tcp(socket.into()))
        }
    }
}

impl From<Listener> for OwnedFd {
    fn from(l: Listener) -> Self {
        match l {
            Listener::Tcp(l) => l.into(),
            Listener::Unix(l) => l.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_path_length() {
        assert_eq!(socket_path(Path::new("/run/user/1000/sequoia/x.cookie"))
                   .unwrap(),
                   PathBuf::from("/run/user/1000/sequoia/x.sock"));
        let long = format!("/{}/x.cookie", "a".repeat(sun_path_len()));
        assert!(socket_path(Path::new(&long)).is_err());
    }

    #[test]
    fn bind_replaces_stale_socket() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("x.sock");

        let first = bind(&path)?;
        drop(first);
        // The stale socket is still there; binding again replaces it.
        let listener = bind(&path)?;
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);

        std::os::unix::net::UnixStream::connect(&path)?;
        listener.accept()?;

        // Only the socket is left behind.
        assert_eq!(fs::read_dir(dir.path())?.count(), 1);
        Ok(())
    }

    #[test]
    fn listener_from_fd() -> io::Result<()> {
        let (l, _path, _dir) = bind_private()?;
        assert!(matches!(Listener::from_fd(l.into())?, Listener::Unix(_)));
        let l = std::net::TcpListener::bind("127.0.0.1:0")?;
        assert!(matches!(Listener::from_fd(l.into())?, Listener::Tcp(_)));
        Ok(())
    }
}
