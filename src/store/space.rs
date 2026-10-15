//! Free-space reserve for the data directory.
//!
//! The metadata database must always be able to commit: a commit that fails for lack of space
//! leaves redb unusable until it is reopened, and then even deletes (the way out of a full disk)
//! fail. So uploads are refused, before and while their data is written, once the filesystem's
//! free space would drop below a reserve. Deletes and other metadata-only writes are always
//! allowed.

use crate::error::{S3Error, S3Result};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering::Relaxed};
use std::time::Instant;

/// How long a free-space reading is reused.
const REFRESH_MS: u64 = 200;

pub struct Space {
    root: PathBuf,
    reserve: u64,
    started: Instant,
    /// Free bytes at the last reading, and when that was (ms since `started`, +1 so 0 = never).
    free: AtomicU64,
    read_at: AtomicU64,
    pub ballast: Ballast,
}

/// The reserve used when none is configured: 2% of the filesystem, between 16 MiB and 256 MiB.
pub fn default_reserve(total: u64) -> u64 {
    (total / 50).clamp(16 << 20, 256 << 20)
}

impl Space {
    /// `reserve` None picks `default_reserve` for the filesystem holding `root`.
    pub fn new(root: &Path, reserve: Option<u64>) -> Space {
        let total = statvfs(root).map(|(_, total)| total);
        let reserve = reserve.unwrap_or_else(|| total.map(default_reserve).unwrap_or(16 << 20));
        Space {
            root: root.to_path_buf(),
            reserve,
            started: Instant::now(),
            free: AtomicU64::new(u64::MAX),
            read_at: AtomicU64::new(0),
            ballast: Ballast::new(root, total.map(ballast_size).unwrap_or(8 << 20)),
        }
    }

    pub fn reserve(&self) -> u64 {
        self.reserve
    }

    /// Free bytes on the data filesystem (u64::MAX when unknown).
    pub fn free(&self) -> u64 {
        let now = self.started.elapsed().as_millis() as u64 + 1;
        let at = self.read_at.load(Relaxed);
        if at == 0 || now.saturating_sub(at) >= REFRESH_MS {
            self.read_at.store(now, Relaxed);
            let free = statvfs(&self.root).map(|(free, _)| free).unwrap_or(u64::MAX);
            self.free.store(free, Relaxed);
            return free;
        }
        self.free.load(Relaxed)
    }

    /// Refuse a write of `incoming` more bytes if it would eat into the reserve. After the
    /// ballast was given up, the space it freed is kept for metadata (deletes) until there is
    /// enough room to recreate it.
    pub fn check(&self, incoming: u64) -> S3Result<()> {
        let mut need = self.reserve.saturating_add(incoming);
        // Even with the reserve turned off (0): the ballast is what lets deletes commit on a
        // disk that filled up anyway, so uploads wait until it can be recreated.
        if !self.ballast.present() {
            need = need.saturating_add(2 * self.ballast.size);
        }
        if self.free() < need {
            return Err(storage_full());
        }
        Ok(())
    }

    /// Recreate the ballast if it is missing and there is room. Returns whether it was created.
    pub fn restore_ballast(&self) -> std::io::Result<bool> {
        self.ballast.restore(self)
    }
}

/// Size of the ballast file: 0.5% of the filesystem, between 8 MiB and 64 MiB.
pub fn ballast_size(total: u64) -> u64 {
    (total / 200).clamp(8 << 20, 64 << 20) & !((1 << 20) - 1)
}

/// A file of zeros kept in the data directory as a last line of defence: if the disk fills up
/// anyway (another process, or uploads racing past the reserve), the writer deletes it so pending
/// metadata commits, and the deletes that free space, can still succeed. It is recreated once
/// there is room again.
pub struct Ballast {
    path: PathBuf,
    pub size: u64,
    present: AtomicBool,
}

impl Ballast {
    fn new(root: &Path, size: u64) -> Ballast {
        let path = root.join("ballast");
        // A ballast of another size (the disk was resized) is replaced on the next restore.
        let present = path.metadata().is_ok_and(|m| m.len() == size);
        Ballast { path, size, present: AtomicBool::new(present) }
    }

    pub fn present(&self) -> bool {
        self.present.load(Relaxed)
    }

    /// Delete the ballast. Returns whether there was one to delete.
    pub fn release(&self) -> bool {
        if self.present.swap(false, Relaxed) {
            return std::fs::remove_file(&self.path).is_ok();
        }
        false
    }

    /// Create the ballast if it is missing and the disk has comfortably more room than the
    /// reserve plus the ballast itself.
    pub fn restore(&self, space: &Space) -> std::io::Result<bool> {
        if self.present() || space.free() < space.reserve().saturating_add(2 * self.size) {
            return Ok(false);
        }
        let tmp = self.path.with_extension("tmp");
        let res = (|| {
            let mut f = std::fs::File::create(&tmp)?;
            let zeros = vec![0u8; 1 << 20];
            for _ in 0..self.size / zeros.len() as u64 {
                f.write_all(&zeros)?;
            }
            f.sync_all()?;
            std::fs::rename(&tmp, &self.path)
        })();
        if res.is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
        res?;
        self.present.store(true, Relaxed);
        Ok(true)
    }
}

pub fn storage_full() -> S3Error {
    S3Error::new(
        "StorageFull",
        hyper::StatusCode::INSUFFICIENT_STORAGE,
        "The server is out of disk space. Delete data or add space and retry.",
    )
}

/// (available bytes for unprivileged users, total bytes) of the filesystem holding `path`.
#[cfg(unix)]
fn statvfs(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c` is a valid NUL-terminated path and `st` is a properly sized out-parameter.
    if unsafe { libc::statvfs(c.as_ptr(), &mut st) } != 0 {
        return None;
    }
    let frsize = st.f_frsize as u64;
    Some((st.f_bavail as u64 * frsize, st.f_blocks as u64 * frsize))
}

#[cfg(not(unix))]
fn statvfs(_path: &Path) -> Option<(u64, u64)> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_bounds_and_checks() {
        assert_eq!(default_reserve(100 << 20), 16 << 20);
        assert_eq!(default_reserve(1 << 40), 256 << 20);
        assert_eq!(default_reserve(5 << 30), (5u64 << 30) / 50);
        assert_eq!(ballast_size(100 << 20), 8 << 20);
        assert_eq!(ballast_size(10 << 30), 51 << 20);
        assert_eq!(ballast_size(1 << 40), 64 << 20);
        let dir = std::env::temp_dir();
        let s = Space::new(&dir, Some(0));
        assert!(s.free() > 0 && s.check(0).is_ok());
        let s = Space::new(&dir, Some(u64::MAX / 2));
        assert_eq!(s.check(0).unwrap_err().code, "StorageFull");
    }
}
