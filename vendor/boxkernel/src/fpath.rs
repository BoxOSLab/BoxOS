//! Fixed-capacity, NUL-terminated path buffer with `char[PATH_MAX]` semantics.
//!
//! The C implementation relies on fixed-size stack buffers everywhere; this
//! type reproduces that contract (bounded length, `ENAMETOOLONG` on overflow)
//! without copying cost and without UTF-8 assumptions — Linux paths are bytes.

use std::fmt;
use std::ops::{Deref, DerefMut};

use crate::PATH_MAX;

#[derive(Clone)]
pub struct FixedPath {
    buf: [u8; PATH_MAX],
    len: usize,
}

impl FixedPath {
    pub const fn new() -> Self {
        FixedPath {
            buf: [0; PATH_MAX],
            len: 0,
        }
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let mut p = FixedPath::new();
        p.set(bytes);
        p
    }

    /// Replace the content; truncates at the first NUL byte, like strcpy().
    /// Silently truncates over-long input — callers that care use `try_set`.
    pub fn set(&mut self, bytes: &[u8]) {
        let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let len = nul.min(PATH_MAX - 1);
        self.buf[..len].copy_from_slice(&bytes[..len]);
        self.buf[len] = 0;
        self.len = len;
    }

    /// Fallible variant: `-ENAMETOOLONG` if the (NUL-truncated) input does not
    /// fit, including its terminator.
    pub fn try_set(&mut self, bytes: &[u8]) -> Result<(), i32> {
        let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        if nul + 1 > PATH_MAX {
            return Err(-libc::ENAMETOOLONG);
        }
        self.buf[..nul].copy_from_slice(&bytes[..nul]);
        self.buf[nul] = 0;
        self.len = nul;
        Ok(())
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mutable view of the *whole* buffer (capacity PATH_MAX) — for
    /// kernel writes like `read_string` that fill it in place.
    /// Afterwards call [`FixedPath::set_len_terminated`] or
    /// [`FixedPath::sync_len_from_nul`].
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.buf[..]
    }

    /// Set the logical length after writing `len` bytes through
    /// `as_mut_bytes`, and write the NUL terminator (readlink-style I/O
    /// that reports a byte count without appending one).
    pub fn set_len_terminated(&mut self, len: usize) {
        let len = len.min(self.buf.len() - 1);
        self.buf[len] = 0;
        self.len = len;
    }

    /// Recover the length of a NUL-terminated string written through
    /// `as_mut_bytes` (C callers rely on implicit `strlen`).
    pub fn sync_len_from_nul(&mut self) {
        let nul = self
            .buf
            .iter()
            .position(|b| *b == 0)
            .unwrap_or(self.buf.len() - 1);
        self.buf[nul] = 0;
        self.len = nul;
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Raw NUL-terminated view (as C string bytes).
    #[inline]
    pub fn as_c_bytes(&self) -> &[u8] {
        &self.buf[..self.len + 1]
    }

    /// Borrowed [`CStr`](std::ffi::CStr) view — zero-copy; use instead of
    /// `CString::new(path.as_bytes())` when calling `sys::` wrappers.
    #[inline]
    pub fn as_c_str(&self) -> &std::ffi::CStr {
        // `buf[self.len]` is NUL by invariant; from_bytes_until_nul also
        // tolerates (never sees) interior NULs by truncating at the first.
        std::ffi::CStr::from_bytes_until_nul(&self.buf[..=self.len]).unwrap_or_default()
    }

    /// `strlen` bound check used at the top of canonicalize().
    pub fn would_overflow(&self, extra: usize) -> bool {
        self.len + extra + 1 > PATH_MAX
    }

    /// Truncate to `new_len` (must be <= current len).
    pub fn truncate(&mut self, new_len: usize) {
        if new_len < self.len {
            self.len = new_len;
            self.buf[new_len] = 0;
        }
    }

    /// Append raw bytes with no separator handling (strcat semantics).
    pub fn extend(&mut self, bytes: &[u8]) -> Result<(), i32> {
        if self.len + bytes.len() + 1 > PATH_MAX {
            return Err(-libc::ENAMETOOLONG);
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        self.buf[self.len] = 0;
        Ok(())
    }

    /// Append a component, inserting a '/' separator when needed
    /// (join_paths() semantics for a single pair).
    pub fn push_component(&mut self, component: &[u8]) -> Result<(), i32> {
        let need_sep =
            self.len > 0 && self.buf[self.len - 1] != b'/' && component.first() != Some(&b'/');
        let skip_first =
            self.len > 0 && self.buf[self.len - 1] == b'/' && component.first() == Some(&b'/');
        let add = component.len() + usize::from(need_sep) - usize::from(skip_first);
        if self.len + add + 1 >= PATH_MAX {
            return Err(-libc::ENAMETOOLONG);
        }
        if need_sep {
            self.buf[self.len] = b'/';
            self.len += 1;
        }
        let src = if skip_first {
            &component[1..]
        } else {
            component
        };
        self.buf[self.len..self.len + src.len()].copy_from_slice(src);
        self.len += src.len();
        self.buf[self.len] = 0;
        Ok(())
    }

    /// Remove the last path component (`pop_component()` semantics).
    pub fn pop_component(&mut self) {
        if self.len <= 1 {
            return;
        }
        let mut off = self.len - 1;
        while off > 1 && self.buf[off] == b'/' {
            off -= 1;
        }
        while off > 1 && self.buf[off] != b'/' {
            off -= 1;
        }
        self.truncate(off);
    }

    /// Remove a trailing "/" or "/." (`chop_finality()`).
    pub fn chop_finality(&mut self) {
        if self.len == 0 {
            return;
        }
        let last = self.buf[self.len - 1];
        if last == b'.' {
            if self.len == 2 {
                self.truncate(1);
            } else {
                self.truncate(self.len - 2);
            }
        } else if last == b'/' && self.len > 1 {
            self.truncate(self.len - 1);
        }
    }

    /// Replace the first `old_prefix_len` bytes by `new_prefix`
    /// (`substitute_path_prefix()` semantics).
    pub fn substitute_prefix(
        &mut self,
        old_prefix_len: usize,
        new_prefix: &[u8],
    ) -> Result<usize, i32> {
        let path_len = self.len;
        let mut new_len: usize;
        if new_prefix.len() == 1 {
            // "/foo" -> "/" ; "/foo/bin" -> "/bin".
            let tail = path_len - old_prefix_len;
            if tail != 0 {
                self.buf.copy_within(old_prefix_len..path_len, 0);
                new_len = tail;
            } else {
                self.buf[0] = b'/';
                new_len = 1;
            }
        } else if old_prefix_len == 1 {
            // "/" -> "/foo" ; "/bin" -> "/foo/bin".
            new_len = new_prefix.len() + path_len;
            if new_len >= PATH_MAX {
                return Err(-libc::ENAMETOOLONG);
            }
            if path_len > 1 {
                self.buf.copy_within(0..path_len, new_prefix.len());
                self.buf[..new_prefix.len()].copy_from_slice(new_prefix);
            } else {
                self.buf[..new_prefix.len()].copy_from_slice(new_prefix);
                new_len = new_prefix.len();
            }
        } else {
            new_len = path_len - old_prefix_len + new_prefix.len();
            if new_len >= PATH_MAX {
                return Err(-libc::ENAMETOOLONG);
            }
            self.buf
                .copy_within(old_prefix_len..path_len, new_prefix.len());
            self.buf[..new_prefix.len()].copy_from_slice(new_prefix);
        }
        self.len = new_len;
        self.buf[new_len] = 0;
        Ok(new_len)
    }

    /// Drop the first `n` bytes, shifting the remainder to the front
    /// (strip a known prefix — e.g. the root-binding path).
    pub fn strip_prefix(&mut self, n: usize) {
        if n >= self.len {
            self.set(b"");
            return;
        }
        self.buf.copy_within(n..self.len, 0);
        self.len -= n;
        self.buf[self.len] = 0;
    }
}

impl Default for FixedPath {
    fn default() -> Self {
        Self::new()
    }
}

// ------------------------------------------------------------------
// Scratch-buffer pool
// ------------------------------------------------------------------
//
// `FixedPath::new()` memsets PATH_MAX bytes; the canonicalizer needs
// several of them per translated syscall.  A small thread-local pool of
// spent buffers keeps the zeroing a warm-up cost — `set()`-family writes
// overwrite whatever they need, so a dirty buffer is as good as a fresh
// one.  The event loop is single-threaded, so a thread_local Vec is all
// the synchronization this needs.

thread_local! {
    static PATH_POOL: std::cell::RefCell<Vec<FixedPath>> =
        const { std::cell::RefCell::new(Vec::new()) };
}
const PATH_POOL_MAX: usize = 16;

/// A pooled [`FixedPath`]: checks out a recycled buffer and returns it to
/// the pool on drop.  Derefs to `FixedPath`, so method calls just work;
/// pass `&mut *guard` / `&*guard` where a `&mut FixedPath`/`&FixedPath`
/// is required.
pub struct PathGuard {
    inner: Option<FixedPath>,
}

impl PathGuard {
    pub fn new() -> Self {
        let inner = PATH_POOL.with(|p| p.borrow_mut().pop()).unwrap_or_default();
        PathGuard { inner: Some(inner) }
    }
}

impl Default for PathGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for PathGuard {
    type Target = FixedPath;
    fn deref(&self) -> &FixedPath {
        self.inner.as_ref().unwrap()
    }
}

impl DerefMut for PathGuard {
    fn deref_mut(&mut self) -> &mut FixedPath {
        self.inner.as_mut().unwrap()
    }
}

impl Drop for PathGuard {
    fn drop(&mut self) {
        let Some(path) = self.inner.take() else {
            return;
        };
        // try_with: during TLS teardown the pool may already be gone —
        // the buffer is simply freed with it.
        let _ = PATH_POOL.try_with(|p| {
            let mut pool = p.borrow_mut();
            if pool.len() < PATH_POOL_MAX {
                pool.push(path);
            }
        });
    }
}

impl Deref for FixedPath {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl DerefMut for FixedPath {
    fn deref_mut(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.buf[..len]
    }
}

impl fmt::Display for FixedPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.as_bytes()))
    }
}

impl fmt::Debug for FixedPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl AsRef<[u8]> for FixedPath {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_empty_and_terminated() {
        let p = FixedPath::new();
        assert_eq!(p.len(), 0);
        assert!(p.is_empty());
        assert_eq!(p.as_bytes(), b"");
        assert_eq!(p.as_c_bytes(), b"\0");
        assert_eq!(p.as_c_str().to_bytes(), b"");
    }

    #[test]
    fn default_matches_new() {
        assert_eq!(FixedPath::default().as_bytes(), FixedPath::new().as_bytes());
    }

    #[test]
    fn from_bytes_sets_content() {
        let p = FixedPath::from_bytes(b"/a/b");
        assert_eq!(p.len(), 4);
        assert_eq!(p.as_bytes(), b"/a/b");
        assert!(!p.is_empty());
    }

    #[test]
    fn from_bytes_truncates_at_nul_and_overlong() {
        let p = FixedPath::from_bytes(b"/ab\0cd");
        assert_eq!(p.as_bytes(), b"/ab");
        // Overlong input silently truncates like strcpy into a bounded buf.
        let big = vec![b'x'; PATH_MAX + 64];
        let p = FixedPath::from_bytes(&big);
        assert_eq!(p.len(), PATH_MAX - 1);
        assert_eq!(p.as_c_bytes()[PATH_MAX - 1], 0);
    }

    #[test]
    fn set_truncates_at_nul() {
        let mut p = FixedPath::new();
        p.set(b"/abc\0def");
        assert_eq!(p.as_bytes(), b"/abc");
        assert_eq!(p.as_c_bytes(), b"/abc\0");
        // set() clears previous content.
        p.set(b"/");
        assert_eq!(p.as_bytes(), b"/");
    }

    #[test]
    fn set_from_empty_slice_terminates() {
        let mut p = FixedPath::from_bytes(b"/x");
        p.set(b"");
        assert!(p.is_empty());
        assert_eq!(p.as_c_bytes(), b"\0");
    }

    #[test]
    fn try_set_reports_overflow() {
        let mut p = FixedPath::new();
        assert_eq!(p.try_set(&vec![b'x'; PATH_MAX]), Err(-libc::ENAMETOOLONG));
        assert!(p.try_set(&vec![b'x'; PATH_MAX - 1]).is_ok());
        assert_eq!(p.len(), PATH_MAX - 1);
        // NUL inside the input is honored before the length check.
        let mut q = FixedPath::new();
        let mut src = vec![b'y'; PATH_MAX + 10];
        src[3] = 0;
        assert!(q.try_set(&src).is_ok());
        assert_eq!(q.as_bytes(), b"yyy");
    }

    #[test]
    fn as_mut_bytes_exposes_capacity() {
        let mut p = FixedPath::from_bytes(b"/x");
        assert_eq!(p.as_mut_bytes().len(), PATH_MAX);
    }

    #[test]
    fn set_len_terminated_marks_read_result() {
        let mut p = FixedPath::from_bytes(b"/tmp");
        let buf = p.as_mut_bytes();
        buf[..5].copy_from_slice(b"abcde");
        p.set_len_terminated(5);
        assert_eq!(p.as_bytes(), b"abcde");
        assert_eq!(p.as_c_bytes(), b"abcde\0");
        // Clamps beyond PATH_MAX-1 so the terminator always fits.
        p.set_len_terminated(usize::MAX);
        assert_eq!(p.len(), PATH_MAX - 1);
        assert_eq!(p.as_bytes().len(), PATH_MAX - 1);
        assert_eq!(p.as_c_bytes()[PATH_MAX - 1], 0);
    }

    #[test]
    fn set_len_terminated_zero() {
        let mut p = FixedPath::from_bytes(b"/x");
        p.set_len_terminated(0);
        assert!(p.is_empty());
    }

    #[test]
    fn sync_len_from_nul_clamps_when_unterminated() {
        // Buffer full of non-NUL bytes (cannot happen via the public API —
        // written through as_mut_bytes like a kernel caller would).
        let mut p = FixedPath::new();
        p.as_mut_bytes().fill(b'x');
        p.sync_len_from_nul();
        assert_eq!(p.len(), PATH_MAX - 1);
        assert_eq!(p.as_c_bytes()[PATH_MAX - 1], 0);
        // Normal case: recovers strlen.
        let mut p = FixedPath::from_bytes(b"/abc");
        p.sync_len_from_nul();
        assert_eq!(p.len(), 4);
        // A stale tail doesn't confuse it.
        let mut p = FixedPath::from_bytes(b"/abcdef");
        p.as_mut_bytes()[2] = 0;
        p.sync_len_from_nul();
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn as_c_str_is_zero_copy() {
        let p = FixedPath::from_bytes(b"/usr/bin");
        let c = p.as_c_str();
        assert_eq!(c.to_bytes(), b"/usr/bin");
        // Borrowed, not a copy: the pointer addresses the same storage.
        assert_eq!(c.as_ptr(), p.as_bytes().as_ptr() as *const _);
    }

    #[test]
    fn would_overflow_counts_terminator() {
        let p = FixedPath::from_bytes(b"/abc");
        assert!(p.would_overflow(PATH_MAX));
        assert!(p.would_overflow(PATH_MAX - 4)); // 4 + extra + NUL > 4096
        assert!(!p.would_overflow(PATH_MAX - 5));
        assert!(!p.would_overflow(0));
    }

    #[test]
    fn truncate_shrinks_only() {
        let mut p = FixedPath::from_bytes(b"/abcdef");
        p.truncate(3);
        assert_eq!(p.as_bytes(), b"/ab");
        assert_eq!(p.as_c_bytes(), b"/ab\0");
        // No-op for >= len.
        p.truncate(3);
        p.truncate(99);
        assert_eq!(p.as_bytes(), b"/ab");
    }

    #[test]
    fn extend_appends_raw() {
        let mut p = FixedPath::from_bytes(b"/a");
        p.extend(b"b/c").unwrap();
        assert_eq!(p.as_bytes(), b"/ab/c");
        assert_eq!(p.as_c_bytes(), b"/ab/c\0");
        // Overflow is rejected and leaves the buffer unchanged.
        let mut p = FixedPath::from_bytes(b"/a");
        assert_eq!(p.extend(&vec![b'x'; PATH_MAX]), Err(-libc::ENAMETOOLONG));
        assert_eq!(p.as_bytes(), b"/a");
        // Boundary: exactly PATH_MAX-1 total fits.
        let mut p = FixedPath::from_bytes(b"/a");
        p.extend(&vec![b'x'; PATH_MAX - 3]).unwrap();
        assert_eq!(p.len(), PATH_MAX - 1);
        // One more would overflow.
        assert_eq!(p.extend(b"x"), Err(-libc::ENAMETOOLONG));
    }

    #[test]
    fn push_component_manages_separator() {
        let mut p = FixedPath::from_bytes(b"/a");
        p.push_component(b"b").unwrap();
        assert_eq!(p.as_bytes(), b"/a/b");
        // Double slash collapses.
        p.push_component(b"/c").unwrap();
        assert_eq!(p.as_bytes(), b"/a/b/c");
        // No separator added after a trailing '/'.
        let mut p = FixedPath::from_bytes(b"/a/");
        p.push_component(b"b").unwrap();
        assert_eq!(p.as_bytes(), b"/a/b");
    }

    #[test]
    fn push_component_edge_cases() {
        // Empty path + plain component.
        let mut p = FixedPath::new();
        p.push_component(b"a").unwrap();
        assert_eq!(p.as_bytes(), b"a");
        // Empty component is a no-op length-wise.
        let mut p = FixedPath::from_bytes(b"/a");
        p.push_component(b"").unwrap();
        assert_eq!(p.as_bytes(), b"/a/");
        // Component on empty path.
        let mut p = FixedPath::new();
        p.push_component(b"/abs").unwrap();
        assert_eq!(p.as_bytes(), b"/abs");
        // Root path + component.
        let mut p = FixedPath::from_bytes(b"/");
        p.push_component(b"x").unwrap();
        assert_eq!(p.as_bytes(), b"/x");
        // Overflow rejected.
        let mut p = FixedPath::from_bytes(&vec![b'x'; PATH_MAX - 3]);
        assert_eq!(p.push_component(b"yy"), Err(-libc::ENAMETOOLONG));
    }

    #[test]
    fn pop_component_drops_last() {
        let mut p = FixedPath::from_bytes(b"/a/b/c");
        p.pop_component();
        assert_eq!(p.as_bytes(), b"/a/b");
        p.pop_component();
        assert_eq!(p.as_bytes(), b"/a");
        p.pop_component();
        assert_eq!(p.as_bytes(), b"/");
        // Root has no component to pop.
        p.pop_component();
        assert_eq!(p.as_bytes(), b"/");
        // Empty stays empty.
        let mut p = FixedPath::new();
        p.pop_component();
        assert!(p.is_empty());
    }

    #[test]
    fn pop_component_trailing_slashes() {
        let mut p = FixedPath::from_bytes(b"/a/b//");
        p.pop_component();
        assert_eq!(p.as_bytes(), b"/a");
        let mut p = FixedPath::from_bytes(b"/a/");
        p.pop_component();
        assert_eq!(p.as_bytes(), b"/");
    }

    #[test]
    fn chop_finality_strips_dot_and_slash() {
        let mut p = FixedPath::from_bytes(b"/a/b/.");
        p.chop_finality();
        assert_eq!(p.as_bytes(), b"/a/b");
        let mut p = FixedPath::from_bytes(b"/a/b/");
        p.chop_finality();
        assert_eq!(p.as_bytes(), b"/a/b");
        let mut p = FixedPath::from_bytes(b"/a/b");
        p.chop_finality();
        assert_eq!(p.as_bytes(), b"/a/b");
        // Root and empty are stable.
        let mut p = FixedPath::from_bytes(b"/");
        p.chop_finality();
        assert_eq!(p.as_bytes(), b"/");
        let mut p = FixedPath::new();
        p.chop_finality();
        assert!(p.is_empty());
        // "/." alone collapses to "/".
        let mut p = FixedPath::from_bytes(b"/.");
        p.chop_finality();
        assert_eq!(p.as_bytes(), b"/");
        // A lone trailing '.' on a 2-byte path.
        let mut p = FixedPath::from_bytes(b"a.");
        p.chop_finality();
        assert_eq!(p.as_bytes(), b"a");
    }

    #[test]
    fn substitute_prefix_variants() {
        // Non-root old prefix, longer new prefix.
        let mut p = FixedPath::from_bytes(b"/old/dir/file");
        p.substitute_prefix(4, b"/new").unwrap();
        assert_eq!(p.as_bytes(), b"/new/dir/file");
        // Old prefix "/" -> insert.
        let mut p = FixedPath::from_bytes(b"/bin");
        p.substitute_prefix(1, b"/pre").unwrap();
        assert_eq!(p.as_bytes(), b"/pre/bin");
        // New prefix "/" -> strip.
        let mut p = FixedPath::from_bytes(b"/old/dir");
        p.substitute_prefix(4, b"/").unwrap();
        assert_eq!(p.as_bytes(), b"/dir");
        // Strip everything -> root.
        let mut p = FixedPath::from_bytes(b"/old");
        p.substitute_prefix(4, b"/").unwrap();
        assert_eq!(p.as_bytes(), b"/");
    }

    #[test]
    fn substitute_prefix_boundaries() {
        // Equal-length substitution is pure overwrite.
        let mut p = FixedPath::from_bytes(b"/aaa/x");
        p.substitute_prefix(4, b"/bbb").unwrap();
        assert_eq!(p.as_bytes(), b"/bbb/x");
        // Substitution past the end is reported, buffer untouched.
        let mut p = FixedPath::from_bytes(b"/old");
        let newlen = p.substitute_prefix(4, b"/longer/prefix");
        assert_eq!(newlen.unwrap(), "/longer/prefix".len());
        assert_eq!(p.as_bytes(), b"/longer/prefix");
        // Overflow -> ENAMETOOLONG.
        let mut p = FixedPath::from_bytes(&vec![b'x'; PATH_MAX - 2]);
        assert_eq!(
            p.substitute_prefix(1, b"/aaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            Err(-libc::ENAMETOOLONG)
        );
    }

    #[test]
    fn strip_prefix_shifts_in_place() {
        let mut p = FixedPath::from_bytes(b"/root/sub");
        p.strip_prefix(5);
        assert_eq!(p.as_bytes(), b"/sub");
        assert_eq!(p.as_c_bytes(), b"/sub\0");
        let mut p = FixedPath::from_bytes(b"ab");
        p.strip_prefix(2);
        assert_eq!(p.as_bytes(), b"");
        p.strip_prefix(0);
        assert_eq!(p.as_bytes(), b"");
        // n > len empties.
        let mut p = FixedPath::from_bytes(b"ab");
        p.strip_prefix(99);
        assert!(p.is_empty());
        assert_eq!(p.as_c_bytes(), b"\0");
    }

    #[test]
    fn display_and_debug_show_lossy() {
        let p = FixedPath::from_bytes(b"/a/b");
        assert_eq!(format!("{}", p), "/a/b");
        assert_eq!(format!("{:?}", p), "/a/b");
        // Non-UTF8 renders lossy, not a panic.
        let p = FixedPath::from_bytes(b"/a\xffb");
        assert!(format!("{}", p).contains('\u{FFFD}'));
    }

    #[test]
    fn deref_traits() {
        let p = FixedPath::from_bytes(b"/abc");
        let s: &[u8] = &p;
        assert_eq!(s, b"/abc");
        let s2: &[u8] = p.as_ref();
        assert_eq!(s2, b"/abc");
        let mut p = FixedPath::from_bytes(b"/abc");
        p[1] = b'X'; // DerefMut to [u8]
        assert_eq!(p.as_bytes(), b"/Xbc");
        p[..2].fill(b'z');
        assert_eq!(p.as_bytes(), b"zzbc");
    }

    #[test]
    fn clone_is_independent() {
        let p = FixedPath::from_bytes(b"/a");
        let mut q = p.clone();
        q.set(b"/b");
        assert_eq!(p.as_bytes(), b"/a");
        assert_eq!(q.as_bytes(), b"/b");
    }

    #[test]
    fn path_guard_recycles() {
        // Exercise the pool across drop/re-acquire; buffers must be
        // usable regardless of previous contents.
        {
            let mut g = PathGuard::new();
            g.set(b"/recycled");
            assert_eq!(g.as_bytes(), b"/recycled");
        }
        let mut g = PathGuard::new();
        g.set(b"/again");
        assert_eq!(g.as_bytes(), b"/again");
        assert_eq!(g.as_c_bytes(), b"/again\0");
        // Many guards can coexist (pool is bounded, extras just alloc).
        let mut gs = Vec::new();
        for i in 0..32usize {
            let mut g = PathGuard::new();
            g.set(format!("/p{i}").as_bytes());
            gs.push(g);
        }
        for (i, g) in gs.iter().enumerate() {
            assert_eq!(g.as_bytes(), format!("/p{i}").as_bytes());
        }
        drop(gs);
        let mut g = PathGuard::new();
        g.set(b"/ok");
        assert_eq!(g.as_bytes(), b"/ok");
    }

    #[test]
    fn path_guard_derefs_both_ways() {
        let mut g = PathGuard::new();
        g.push_component(b"x").unwrap();
        let fp: &FixedPath = &g;
        assert_eq!(fp.as_bytes(), b"x");
        let fm: &mut FixedPath = &mut g;
        fm.set(b"/y");
        assert_eq!(g.as_bytes(), b"/y");
    }
}
