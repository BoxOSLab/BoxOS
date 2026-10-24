//! Arrays of pointers in the tracee's memory (argv[], envp[]) —
//! port of execve/aoxp.c.
//!
//! Each entry caches a local copy on first access; `push_array_of_xpointers`
//! writes back the pointer table plus every modified pointee into a fresh
//! tracer-allocated block.

use crate::Word;
use crate::tracee::Tracee;
use crate::tracee::mem::{alloc_mem, peek_word, read_string, writev_data};
use crate::tracee::reg::{Reg, RegVersion, is_32on64_mode, peek_reg, poke_reg, sizeof_word};

/// `ARG_MAX`.
const ARG_MAX: usize = 131072;

/// One pointer slot: `remote` is the tracee-side address, `local` the
/// cached/rewritten payload (string including NUL) once read or replaced.
#[derive(Clone)]
pub struct XPointer {
    pub remote: Word,
    pub local: Option<Vec<u8>>,
}

/// `ArrayOfXPointers`.
#[derive(Default)]
pub struct XPointerArray {
    pub entries: Vec<XPointer>,
}

/// `fetch_array_of_xpointers()` — copy the NULL-terminated pointer array
/// stored in tracee memory at `reg`'s value (or exactly `nb_entries` when
/// nonzero).
pub fn fetch_array_of_xpointers(
    tracee: &Tracee,
    reg: Reg,
    nb_entries: usize,
) -> Result<XPointerArray, i32> {
    let address = peek_reg(tracee, RegVersion::Current, reg);
    let w = sizeof_word(tracee) as Word;
    let mut array = XPointerArray::default();

    let mut i = 0usize;
    loop {
        if nb_entries != 0 && i >= nb_entries {
            break;
        }
        crate::sys::clear_errno();
        let pointer = peek_word(tracee, address + i as Word * w);
        let e = crate::sys::errno();
        if e != 0 {
            return Err(-e);
        }
        // The C loop pushes the NULL terminator before stopping.
        array.entries.push(XPointer {
            remote: pointer,
            local: None,
        });
        i += 1;
        if nb_entries == 0 && pointer == 0 {
            break;
        }
    }
    Ok(array)
}

/// `read_xpointee_as_string()` — fetch+cache entry @index as a
/// NUL-terminated string.  Returns `Ok(None)` for a NULL remote.
pub fn read_xpointee_as_string(
    tracee: &Tracee,
    array: &mut XPointerArray,
    index: usize,
) -> Result<Option<Vec<u8>>, i32> {
    debug_assert!(index < array.entries.len());
    if let Some(local) = &array.entries[index].local {
        return Ok(Some(local.clone()));
    }
    if array.entries[index].remote == 0 {
        return Ok(None);
    }
    let mut tmp = vec![0u8; ARG_MAX];
    let status = read_string(tracee, &mut tmp, array.entries[index].remote);
    if status < 0 {
        return Err(status);
    }
    if status as usize >= ARG_MAX {
        return Err(-libc::ENOMEM);
    }
    let s = tmp[..status as usize].to_vec();
    array.entries[index].local = Some(s.clone());
    Ok(Some(s))
}

/// `sizeof_xpointee_as_string()` — byte length including NUL.
pub fn sizeof_xpointee_as_string(
    tracee: &Tracee,
    array: &mut XPointerArray,
    index: usize,
) -> Result<usize, i32> {
    match read_xpointee_as_string(tracee, array, index)? {
        Some(s) => Ok(s.len()),
        None => Ok(0),
    }
}

/// `is_env_name()` — "NAME=" prefix match (`variable` is NUL-terminated).
pub fn is_env_name(variable: &[u8], name: &str) -> bool {
    let name = name.as_bytes();
    let len = name.len();
    variable.first() == name.first()
        && variable.len() > len
        && variable[len] == b'='
        && &variable[..len] == name
}

/// `compare_xpointee_env()` from ldso.c: does entry @index's string start
/// with `reference` followed by '='?
pub fn compare_xpointee_env(
    tracee: &Tracee,
    array: &mut XPointerArray,
    index: usize,
    reference: &str,
) -> Result<i32, i32> {
    match read_xpointee_as_string(tracee, array, index)? {
        None => Ok(0),
        Some(v) => Ok(is_env_name(&v, reference) as i32),
    }
}

/// `find_xpointee()` over env entries; returns the index of the first
/// match or `entries.len()`.
pub fn find_xpointee_env(
    tracee: &Tracee,
    array: &mut XPointerArray,
    reference: &str,
) -> Result<usize, i32> {
    for i in 0..array.entries.len() {
        if compare_xpointee_env(tracee, array, i, reference)? != 0 {
            return Ok(i);
        }
    }
    Ok(array.entries.len())
}

/// `write_xpointee_as_string()` — mark entry @index as replaced by a
/// local copy of @string (materialized into the tracee on push).
pub fn write_xpointee_string(array: &mut XPointerArray, index: usize, string: &[u8]) {
    debug_assert!(index < array.entries.len());
    let mut v = string.to_vec();
    if !v.ends_with(b"\0") {
        v.push(0);
    }
    array.entries[index].local = Some(v);
}

/// `write_xpointees()` — variadic sugar.
pub fn write_xpointees(array: &mut XPointerArray, index: usize, strings: &[&[u8]]) {
    for (i, s) in strings.iter().enumerate() {
        write_xpointee_string(array, index + i, s);
    }
}

/// `resize_array_of_xpointers()` — insert (`delta` > 0) or remove
/// (`delta` < 0) slots at `index`.
pub fn resize_array_of_xpointers(array: &mut XPointerArray, index: usize, delta: isize) -> i32 {
    debug_assert!(index <= array.entries.len());
    if delta > 0 {
        for _ in 0..delta {
            array.entries.insert(
                index,
                XPointer {
                    remote: 0,
                    local: None,
                },
            );
        }
    } else if delta < 0 {
        let n = (-delta) as usize;
        debug_assert!(index + n <= array.entries.len());
        array.entries.drain(index..index + n);
    }
    0
}

/// `push_array_of_xpointers()` — write the pointer table + modified
/// pointees to a fresh tracer-allocated block and update `reg`.
pub fn push_array_of_xpointers(tracee: &mut Tracee, array: &mut XPointerArray, reg: Reg) -> i32 {
    let w = sizeof_word(tracee);
    let n = array.entries.len();

    // Sizes: pointer table first, then each modified pointee.
    let mut total_size = n * w;
    for i in 0..n {
        if array.entries[i].local.is_some() {
            match sizeof_xpointee_as_string(tracee, array, i) {
                Ok(s) => total_size += s,
                Err(e) => return e,
            }
        }
    }
    if array.entries.iter().all(|e| e.local.is_none()) {
        return 0;
    }

    let base = alloc_mem(tracee, total_size as i64);
    if base == 0 {
        return -libc::E2BIG;
    }

    let mut pod = vec![0u8; n * w];
    let mut blob = Vec::with_capacity(total_size - n * w);
    let mut off = n * w;
    for (i, entry) in array.entries.iter_mut().enumerate() {
        if let Some(local) = entry.local.take() {
            entry.remote = base + off as Word;
            off += local.len();
            blob.extend_from_slice(&local);
            entry.local = Some(local);
        }
        let r = entry.remote;
        if is_32on64_mode(tracee) {
            pod[i * 4..i * 4 + 4].copy_from_slice(&(r as u32).to_ne_bytes());
        } else {
            pod[i * 8..i * 8 + 8].copy_from_slice(&r.to_ne_bytes());
        }
    }
    let st = writev_data(tracee, base, &[&pod, &blob]);
    if st < 0 {
        return st;
    }
    poke_reg(tracee, reg, base);
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_env_name_matches_prefix_with_eq() {
        assert!(is_env_name(b"PATH=/bin\0", "PATH"));
        assert!(is_env_name(b"HOME=/u\0", "HOME"));
        assert!(!is_env_name(b"PATHS=/x\0", "PATH")); // longer name
        assert!(!is_env_name(b"PAT=/x\0", "PATH"));
        assert!(!is_env_name(b"PATH\0", "PATH")); // no '='
        assert!(!is_env_name(b"\0", "PATH"));
        assert!(!is_env_name(b"", "PATH"));
        assert!(is_env_name(b"A=\0", "A")); // minimal
        assert!(!is_env_name(b"A\0", "A")); // '=' required
    }

    #[test]
    fn write_xpointee_ensures_nul() {
        let mut a = XPointerArray::default();
        a.entries.push(XPointer {
            remote: 9,
            local: None,
        });
        write_xpointee_string(&mut a, 0, b"hi");
        assert_eq!(a.entries[0].local.as_deref(), Some(b"hi\0".as_slice()));
        // Already-terminated input isn't double-terminated.
        write_xpointee_string(&mut a, 0, b"bye\0");
        assert_eq!(a.entries[0].local.as_deref(), Some(b"bye\0".as_slice()));
    }

    #[test]
    fn write_xpointees_writes_consecutive() {
        let mut a = XPointerArray::default();
        for _ in 0..3 {
            a.entries.push(XPointer {
                remote: 0,
                local: None,
            });
        }
        write_xpointees(&mut a, 1, &[b"x", b"y\0"]);
        assert!(a.entries[0].local.is_none());
        assert_eq!(a.entries[1].local.as_deref(), Some(b"x\0".as_slice()));
        assert_eq!(a.entries[2].local.as_deref(), Some(b"y\0".as_slice()));
    }

    #[test]
    fn resize_inserts_and_removes() {
        let mut a = XPointerArray::default();
        for i in 0..3u64 {
            a.entries.push(XPointer {
                remote: i + 1,
                local: None,
            });
        }
        // Insert two slots at index 1.
        assert_eq!(resize_array_of_xpointers(&mut a, 1, 2), 0);
        assert_eq!(a.entries.len(), 5);
        assert_eq!(a.entries[1].remote, 0);
        assert_eq!(a.entries[2].remote, 0);
        assert_eq!(a.entries[3].remote, 2);
        // Remove them back.
        assert_eq!(resize_array_of_xpointers(&mut a, 1, -2), 0);
        assert_eq!(a.entries.len(), 3);
        assert_eq!(a.entries[1].remote, 2);
        // Removing zero is fine.
        assert_eq!(resize_array_of_xpointers(&mut a, 0, 0), 0);
    }

    // ---- remote-memory paths (forked child) ----

    use crate::testutil::{Arena, fork_child};

    /// Build a remote argv-like table: `words` pointer values written at
    /// `addr` in the child's arena.
    fn write_remote_table(arena: &mut Arena, addr: u64, words: &[u64]) {
        let base = (addr - arena.addr()) as usize;
        for (i, w) in words.iter().enumerate() {
            arena.local()[base + i * 8..base + i * 8 + 8].copy_from_slice(&w.to_ne_bytes());
        }
    }

    fn put_str(arena: &mut Arena, off: usize, s: &[u8]) -> u64 {
        arena.local()[off..off + s.len()].copy_from_slice(s);
        arena.local()[off + s.len()] = 0;
        arena.addr() + off as u64
    }

    #[test]
    fn fetch_array_reads_until_null() {
        let mut arena = Arena::new(2);
        let s1 = put_str(&mut arena, 0x800, b"one");
        let s2 = put_str(&mut arena, 0x900, b"two");
        let table = arena.addr();
        write_remote_table(&mut arena, table, &[s1, s2, 0]);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = child.tracee();
        poke_reg(&mut t, Reg::Sysarg1, table);
        let a = fetch_array_of_xpointers(&t, Reg::Sysarg1, 0).unwrap();
        assert_eq!(a.entries.len(), 3); // includes the NULL terminator
        assert_eq!(a.entries[0].remote, s1);
        assert_eq!(a.entries[1].remote, s2);
        assert_eq!(a.entries[2].remote, 0);
    }

    #[test]
    fn fetch_array_bounded_count() {
        let mut arena = Arena::new(2);
        let table = arena.addr();
        write_remote_table(&mut arena, table, &[0x11, 0x22, 0x33, 0]);
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = child.tracee();
        poke_reg(&mut t, Reg::Sysarg1, table);
        let a = fetch_array_of_xpointers(&t, Reg::Sysarg1, 2).unwrap();
        assert_eq!(a.entries.len(), 2);
        assert_eq!(a.entries[1].remote, 0x22);
    }

    #[test]
    fn fetch_array_fails_on_unreadable() {
        let mut arena = Arena::new(2);
        let table = arena.addr() + 4096; // page 1
        write_remote_table(&mut arena, table, &[0x11, 0]);
        let Some(mut child) = fork_child(&arena) else {
            return;
        };
        let mut t = child.tracee();
        poke_reg(&mut t, Reg::Sysarg1, table);
        child.protect_page(1);
        assert!(fetch_array_of_xpointers(&t, Reg::Sysarg1, 0).is_err());
        child.unprotect_page(1);
    }

    #[test]
    fn read_xpointee_caches_local_copy() {
        let mut arena = Arena::new(2);
        let s = put_str(&mut arena, 0x800, b"payload");
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        let mut a = XPointerArray::default();
        a.entries.push(XPointer {
            remote: s,
            local: None,
        });
        a.entries.push(XPointer {
            remote: 0,
            local: None,
        });
        let v = read_xpointee_as_string(&t, &mut a, 0).unwrap().unwrap();
        assert_eq!(v, b"payload\0");
        // Second read hits the cache (make remote unreadable — cached).
        assert_eq!(
            read_xpointee_as_string(&t, &mut a, 0).unwrap().as_deref(),
            Some(b"payload\0".as_slice())
        );
        // NULL remote -> Ok(None).
        assert_eq!(read_xpointee_as_string(&t, &mut a, 1).unwrap(), None);
        // sizeof counts the NUL.
        assert_eq!(sizeof_xpointee_as_string(&t, &mut a, 0).unwrap(), 8);
        assert_eq!(sizeof_xpointee_as_string(&t, &mut a, 1).unwrap(), 0);
    }

    #[test]
    fn find_xpointee_env_searches() {
        let mut arena = Arena::new(2);
        let s1 = put_str(&mut arena, 0x700, b"PATH=/bin");
        let s2 = put_str(&mut arena, 0x800, b"HOME=/u");
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let t = child.tracee();
        let mut a = XPointerArray::default();
        a.entries.push(XPointer {
            remote: s1,
            local: None,
        });
        a.entries.push(XPointer {
            remote: s2,
            local: None,
        });
        assert_eq!(find_xpointee_env(&t, &mut a, "HOME").unwrap(), 1);
        assert_eq!(find_xpointee_env(&t, &mut a, "PATH").unwrap(), 0);
        // Miss returns entries.len().
        assert_eq!(find_xpointee_env(&t, &mut a, "MISSING").unwrap(), 2);
        // compare directly.
        assert_eq!(compare_xpointee_env(&t, &mut a, 0, "HOME").unwrap(), 0);
        assert_eq!(compare_xpointee_env(&t, &mut a, 0, "PATH").unwrap(), 1);
    }

    #[test]
    fn push_writes_table_and_blobs() {
        let mut arena = Arena::new(2);
        let s = put_str(&mut arena, 0x800, b"orig");
        let Some(child) = fork_child(&arena) else {
            return;
        };
        let mut t = child.tracee_with_sp(&arena);
        let mut a = XPointerArray::default();
        a.entries.push(XPointer {
            remote: s,
            local: None,
        });
        a.entries.push(XPointer {
            remote: 0,
            local: None,
        });
        // Nothing modified -> no-op, reg untouched.
        poke_reg(&mut t, Reg::Sysarg2, 0xABCD);
        assert_eq!(push_array_of_xpointers(&mut t, &mut a, Reg::Sysarg2), 0);
        assert_eq!(peek_reg(&t, RegVersion::Current, Reg::Sysarg2), 0xABCD);

        // Modify entry 0; push must allocate remote memory and write back.
        write_xpointee_string(&mut a, 0, b"replaced");
        let sp0 = peek_reg(&t, RegVersion::Current, Reg::StackPointer);
        assert_eq!(push_array_of_xpointers(&mut t, &mut a, Reg::Sysarg2), 0);
        let base = peek_reg(&t, RegVersion::Current, Reg::Sysarg2);
        assert!(base != 0);
        // SP moved down by table+blob size plus the first-alloc red zone
        // (alloc_mem adds RED_ZONE_SIZE when sp == original sp).
        let sp1 = peek_reg(&t, RegVersion::Current, Reg::StackPointer);
        assert_eq!(sp0 - sp1, (2 * 8 + 9) as u64 + crate::arch::RED_ZONE_SIZE);
        // Table entry 0 points at the blob, terminator stays 0.
        let off = (base - arena.addr()) as usize;
        let p0 = u64::from_ne_bytes(arena.local()[off..off + 8].try_into().unwrap());
        let p1 = u64::from_ne_bytes(arena.local()[off + 8..off + 16].try_into().unwrap());
        assert_eq!(p1, 0);
        let boff = (p0 - arena.addr()) as usize;
        assert_eq!(&arena.local()[boff..boff + 9], b"replaced\0");
    }
}
