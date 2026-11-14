//! Helpers for spawning subprocesses.

#[cfg(unix)]
use std::env;
#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::ffi::OsString;
use std::io;
#[cfg(unix)]
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::Child;
use std::process::Command;

/// Spawns `command`.
///
/// This is [`Command::spawn`], except that a missing executable is
/// [`io::ErrorKind::NotFound`] instead of exit status 127.  `qemu-user`,
/// OpenBSD, and HPPA surface a successful spawn and an exit code of 127
/// instead.
pub(crate) fn command_spawn(command: &mut Command) -> io::Result<Child> {
    if let Some(err) = missing_executable_error(command) {
        return Err(err);
    }
    command.spawn()
}

/// Returns `ENOENT` when `command`'s executable does not resolve.
///
/// Rust's [`Command`] uses `posix_spawn` on Unix.  When `execve` fails
/// after `posix_spawn` has already returned, POSIX requires the child to
/// exit with code 127 rather than reporting `errno` to the parent.
/// glibc usually copies that failure back through a `CLONE_VM|CLONE_VFORK`
/// shared-stack channel, but not every implementation preserves it.
/// `qemu-user`, OpenBSD, and HPPA surface a successful spawn and an exit
/// code of 127 instead.
///
/// Callers such as [`crate::Descriptor::connect_with_policy`] rely on
/// `fork` failing when the external server executable does not exist so
/// [`crate::IPCPolicy::Robust`] can fall back to the internal server.
/// Returning `ENOENT` before the spawn keeps the glibc error on every
/// platform.  A program that does exist and exits 127 is left alone:
/// waiting on the [`Child`] still reports that status.
fn missing_executable_error(command: &Command) -> Option<io::Error> {
    #[cfg(unix)]
    if ! executable_resolves(command) {
        return Some(io::Error::from_raw_os_error(libc::ENOENT));
    }
    #[cfg(not(unix))]
    let _ = command;
    None
}

/// Whether `execvp` would find `command`'s program.
///
/// A path containing a slash is used as-is, relative to the child's
/// working directory.  Anything else is searched in the child's `PATH`,
/// matching `posix_spawnp` / `execvp`.  An empty `PATH` entry means the
/// working directory.  When `PATH` is unset, glibc uses
/// `confstr(_CS_PATH)`, which is `/bin:/usr/bin`.
#[cfg(unix)]
fn executable_resolves(command: &Command) -> bool {
    use std::os::unix::ffi::OsStrExt as _;

    let program = command.get_program();
    if program.is_empty() {
        return false;
    }
    if program.as_bytes().contains(&b'/') {
        return path_exists(&resolve_dir(command, PathBuf::from(program)));
    }
    let path = command_search_path(command);
    env::split_paths(&path)
        .any(|dir| path_exists(&candidate_path(command, &dir, program)))
}

#[cfg(unix)]
fn command_search_path(command: &Command) -> OsString {
    for (key, value) in command.get_envs() {
        if key == "PATH" {
            return match value {
                Some(path) => path.to_os_string(),
                // Removed.  `execvp` then uses the `confstr(_CS_PATH)`
                // default.
                None => OsString::from("/bin:/usr/bin"),
            };
        }
    }
    env::var_os("PATH").unwrap_or_else(|| OsString::from("/bin:/usr/bin"))
}

#[cfg(unix)]
fn resolve_dir(command: &Command, path: PathBuf) -> PathBuf {
    if path.is_absolute() {
        path
    } else if let Some(cwd) = command.get_current_dir() {
        cwd.join(path)
    } else {
        path
    }
}

#[cfg(unix)]
fn candidate_path(command: &Command, dir: &Path, program: &OsStr) -> PathBuf {
    let joined = if dir.as_os_str().is_empty() {
        PathBuf::from(program)
    } else {
        dir.join(program)
    };
    resolve_dir(command, joined)
}

/// `true` when the path exists, or when we could not tell.
///
/// Only a definite "not found" is treated as a missing executable.  A
/// directory, a non-executable file, or a permission error is left for
/// `execve`, which reports `EACCES` rather than `ENOENT` when it finds
/// something it cannot run.
#[cfg(unix)]
fn path_exists(path: &Path) -> bool {
    match path.metadata() {
        Ok(_) => true,
        Err(err) if err.kind() == io::ErrorKind::NotFound => false,
        Err(_) => true,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::fs;
    use std::io;
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt as _;
    use std::process::Command;

    use super::command_spawn;
    use super::missing_executable_error;

    fn assert_not_found(err: io::Error) {
        assert_eq!(err.kind(), ErrorKind::NotFound);
        assert_eq!(err.raw_os_error(), Some(libc::ENOENT));
    }

    #[test]
    fn missing_program_is_not_found() {
        let mut command =
            Command::new("sequoia-ipc-test-missing-program-subprocess");
        assert_not_found(command_spawn(&mut command).unwrap_err());

        let mut command = Command::new(
            "/no/such/sequoia-ipc-test-missing-program-subprocess");
        assert_not_found(command_spawn(&mut command).unwrap_err());

        let mut command = Command::new("");
        assert_not_found(command_spawn(&mut command).unwrap_err());
    }

    #[test]
    fn existing_program_exit_127_is_preserved() {
        let mut command = Command::new("sh");
        command.args(["-c", "exit 127"]);
        let status = command_spawn(&mut command).unwrap().wait().unwrap();
        assert_eq!(status.code(), Some(127));
    }

    #[test]
    fn path_override_hides_an_existing_program() {
        let mut command = Command::new("sh");
        command.env("PATH", "/sequoia-ipc-test-empty-path-subprocess");
        command.args(["-c", "exit 0"]);
        assert_not_found(command_spawn(&mut command).unwrap_err());
    }

    #[test]
    fn empty_path_entry_uses_current_dir() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("tool");
        fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755))
            .unwrap();

        let mut command = Command::new("tool");
        command.current_dir(dir.path()).env("PATH", "");
        let status = command_spawn(&mut command).unwrap().wait().unwrap();
        assert!(status.success());
    }

    #[test]
    fn relative_program_uses_current_dir() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("tool");
        fs::write(&program, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o755))
            .unwrap();

        let mut command = Command::new("./tool");
        command.current_dir(dir.path());
        let status = command_spawn(&mut command).unwrap().wait().unwrap();
        assert!(status.success());

        let mut command = Command::new("./tool");
        command.current_dir("/");
        assert_not_found(command_spawn(&mut command).unwrap_err());
    }

    #[test]
    fn non_executable_file_is_left_to_spawn() {
        let dir = tempfile::tempdir().unwrap();
        let program = dir.path().join("not-exec");
        fs::write(&program, "not a script\n").unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o644))
            .unwrap();

        let command = Command::new(&program);
        assert!(missing_executable_error(&command).is_none());
    }
}
