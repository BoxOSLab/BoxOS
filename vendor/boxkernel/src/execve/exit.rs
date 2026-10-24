//! execve(2) sysexit translation — port of execve/exit.c.
//!
//! On a successful execve the tracee is actually running the embedded
//! loader; this writes the load script onto its stack, fixes the
//! `/proc/<pid>/auxv` view for nested ptracers, and resets heap state.

use std::io::Write;
use std::rc::Rc;

use crate::Word;
use crate::execve::auxv::{ElfAuxVector, fetch_elf_aux_vectors, get_elf_aux_vectors_address};
use crate::execve::{Mapping, is_notification_ptraced_load_done};
use crate::path::binding::{get_binding, insort_binding3, remove_binding_from_all_lists};
use crate::path::{Comparison, Side, compare_paths};
use crate::sysnum::Sysnum;
use crate::tracee::Tracee;
use crate::tracee::mem::{peek_word, write_data};
use crate::tracee::reg::{
    Reg, RegVersion, is_32on64_mode, peek_reg, poke_reg, save_current_regs, set_sysnum, sizeof_word,
};

// Load actions (loader/script.h).
const LOAD_ACTION_OPEN_NEXT: u64 = 0;
const LOAD_ACTION_OPEN: u64 = 1;
const LOAD_ACTION_MMAP_FILE: u64 = 2;
const LOAD_ACTION_MMAP_ANON: u64 = 3;
const LOAD_ACTION_MAKE_STACK_EXEC: u64 = 4;
const LOAD_ACTION_START_TRACED: u64 = 5;
const LOAD_ACTION_START: u64 = 6;

/// `fill_file_with_auxv()` — serialize `vectors` to `path` at the ptracee's
/// word size.
fn fill_file_with_auxv(ptracee: &Tracee, path: &str, vectors: &[ElfAuxVector]) -> i32 {
    let w = sizeof_word(ptracee);
    let mut buf = Vec::with_capacity(vectors.len() * 2 * w);
    for v in vectors {
        if w == 8 {
            buf.extend_from_slice(&v.atype.to_ne_bytes());
            buf.extend_from_slice(&v.value.to_ne_bytes());
        } else {
            buf.extend_from_slice(&(v.atype as u32).to_ne_bytes());
            buf.extend_from_slice(&(v.value as u32).to_ne_bytes());
        }
    }
    match std::fs::File::create(path).and_then(|mut f| f.write_all(&buf)) {
        Ok(()) => 0,
        Err(_) => -1,
    }
}

/// `bind_proc_pid_auxv()` — snapshot the auxv into a temp file bound over
/// `/proc/<pid>/auxv` so nested ptracers see the guest's vectors.
fn bind_proc_pid_auxv(ptracee: &mut Tracee) -> i32 {
    let vectors_address = get_elf_aux_vectors_address(ptracee);
    if vectors_address == 0 {
        return -1;
    }
    let vectors = match fetch_elf_aux_vectors(ptracee, vectors_address) {
        Some(v) => v,
        None => return -1,
    };
    let guest_path = format!("/proc/{}/auxv", ptracee.pid);

    // Drop the previous execve's binding for this path, if any.
    if let Some(binding) = get_binding(ptracee, Side::Guest, guest_path.as_bytes()) {
        if compare_paths(binding.guest.as_bytes(), guest_path.as_bytes())
            == Comparison::PathsAreEqual
        {
            remove_binding_from_all_lists(ptracee, &binding);
        }
    }

    let host_path = match crate::path::temp::create_temp_file("auxv") {
        Some(p) => p,
        None => return -1,
    };
    if fill_file_with_auxv(ptracee, &host_path, &vectors) < 0 {
        return -1;
    }
    if insort_binding3(ptracee, host_path.as_bytes(), guest_path.as_bytes()).is_none() {
        return -1;
    }
    0
}

/// `transcript_mappings()` — append mmap statements for `mappings` to `script`.
fn transcript_mappings(script: &mut Vec<u64>, mappings: &[Mapping]) {
    for m in mappings {
        let is_anon = (m.flags as i32) & libc::MAP_ANONYMOUS != 0;
        script.push(if is_anon {
            LOAD_ACTION_MMAP_ANON
        } else {
            LOAD_ACTION_MMAP_FILE
        });
        script.extend_from_slice(&[m.addr, m.length, m.prot, m.offset, m.clear_length]);
    }
}

/// `transfer_load_script()` — serialize `tracee.load_info` into a load
/// script and push it (plus its path strings) onto the tracee's stack.
fn transfer_load_script(tracee: &mut Tracee) -> i32 {
    let stack_pointer = peek_reg(tracee, RegVersion::Current, Reg::StackPointer);
    let w = sizeof_word(tracee) as Word;
    let page_mask = !(crate::sys::page_size() - 1);

    // argv[0]'s address on the initial stack — the true AT_EXECFN.
    tracee.execfn_addr = peek_word(tracee, stack_pointer + w);

    let load_info = match tracee.load_info.as_ref() {
        Some(l) => l,
        None => return 0,
    };
    if load_info.mappings.is_empty() {
        return -libc::ENOEXEC;
    }

    let needs_executable_stack = load_info.needs_executable_stack
        || load_info
            .interp
            .as_ref()
            .is_some_and(|i| i.needs_executable_stack);

    let string1 = load_info.user_path.clone() + "\0";
    let string2 = match &load_info.interp {
        Some(i) => i.user_path.clone() + "\0",
        None => String::new(),
    };
    let string3 = if load_info.raw_path == load_info.user_path {
        String::new()
    } else {
        load_info.raw_path.clone() + "\0"
    };

    let string1_size = string1.len() as Word;
    let string2_size = string2.len() as Word;
    let string3_size = string3.len() as Word;

    // Align the strings block to a word boundary, or to the stricter stack
    // alignment the host ABI demands (16 bytes on aarch64).
    let align = w.max(crate::arch::STACK_ALIGNMENT);
    let padding_size = (stack_pointer - string1_size - string2_size - string3_size) % align;
    let strings_size = string1_size + string2_size + string3_size + padding_size;

    let string1_address = stack_pointer - strings_size;
    let string2_address = string1_address + string1_size;
    let string3_address = if string3_size == 0 {
        string1_address
    } else {
        string1_address + string1_size + string2_size
    };

    // ---- build the script as a sequence of 64-bit words ----
    let mut script: Vec<u64> = Vec::new();

    // open the executable
    script.push(LOAD_ACTION_OPEN);
    script.push(string1_address);
    transcript_mappings(&mut script, &load_info.mappings);

    let entry_point = if let Some(interp) = &load_info.interp {
        script.push(LOAD_ACTION_OPEN_NEXT);
        script.push(string2_address);
        transcript_mappings(&mut script, &interp.mappings);
        interp.elf_header.e_entry()
    } else {
        load_info.elf_header.e_entry()
    };

    if needs_executable_stack {
        script.push(LOAD_ACTION_MAKE_STACK_EXEC);
        script.push(stack_pointer & page_mask);
    }

    script.push(if tracee.as_ptracee.ptracer != 0 {
        LOAD_ACTION_START_TRACED
    } else {
        LOAD_ACTION_START
    });
    script.push(stack_pointer);
    script.push(entry_point);
    script.push(load_info.mappings[0].addr + load_info.elf_header.e_phoff());
    script.push(load_info.elf_header.e_phentsize() as u64);
    script.push(load_info.elf_header.e_phnum() as u64);
    script.push(load_info.elf_header.e_entry());
    script.push(string3_address);

    // ---- serialize (u32 words when the tracee is a 32-bit process) ----
    let use32 = is_32on64_mode(tracee);
    let mut buffer = Vec::with_capacity(script.len() * 8 + strings_size as usize);
    for word in &script {
        if use32 {
            buffer.extend_from_slice(&(*word as u32).to_ne_bytes());
        } else {
            buffer.extend_from_slice(&word.to_ne_bytes());
        }
    }
    buffer.extend_from_slice(string1.as_bytes());
    buffer.extend_from_slice(string2.as_bytes());
    buffer.extend_from_slice(string3.as_bytes());
    buffer.extend(std::iter::repeat_n(0, padding_size as usize));

    let buffer_size = buffer.len() as Word;
    let script_address = stack_pointer - buffer_size;
    // The script itself is word-aligned; the loader's stack must also meet
    // the ABI alignment, so start it just below the script.
    poke_reg(tracee, Reg::StackPointer, script_address & !(align - 1));
    poke_reg(tracee, Reg::Userarg1, script_address);

    let status = write_data(tracee, script_address, &buffer);
    if status < 0 {
        return status;
    }

    // In sysexit: current regs must be used as-is.
    save_current_regs(tracee, RegVersion::Original);
    tracee.regs_were_changed = true;
    0
}

/// `translate_execve_exit()`.
pub fn translate_execve_exit(tracee: &mut Tracee) {
    tracee.auxv_fd = -1;

    if tracee.skip_proot_loader {
        tracee.restore_original_regs = false;
        tracee.seen_execve = true;
        return;
    }

    if is_notification_ptraced_load_done(tracee) {
        // Don't confuse the ptracer with the loader's execve result.
        poke_reg(tracee, Reg::SysargResult, 0);
        set_sysnum(tracee, Sysnum::execve);

        // Only SP, IP, rtld_fini and flags have defined values at startup.
        poke_reg(
            tracee,
            Reg::StackPointer,
            peek_reg(tracee, RegVersion::Original, Reg::Sysarg2),
        );
        poke_reg(
            tracee,
            Reg::InstrPointer,
            peek_reg(tracee, RegVersion::Original, Reg::Sysarg3),
        );
        poke_reg(tracee, Reg::RtldFini, 0);
        poke_reg(tracee, Reg::StateFlags, 0);

        save_current_regs(tracee, RegVersion::Original);
        tracee.regs_were_changed = true;

        bind_proc_pid_auxv(tracee);

        if (tracee.as_ptracee.options & crate::ptrace::ptc::PTRACE_O_TRACEEXEC as Word) == 0 {
            crate::sys::kill(tracee.pid, libc::SIGTRAP);
        }
        return;
    }

    let syscall_result = peek_reg(tracee, RegVersion::Current, Reg::SysargResult);
    if (syscall_result as i64) < 0 {
        return;
    }

    // The guest program is now running; subsequent PR_SET_NO_NEW_PRIVS are
    // the guest's own.
    tracee.seen_execve = true;

    // Commit "/proc/self/exe".
    if let Some(new_exe) = tracee.new_exe.take() {
        tracee.exe = Some(Rc::from(new_exe));
    }

    // New processes have no heap.
    if Rc::strong_count(&tracee.heap) > 1 {
        tracee.heap = Rc::new(std::cell::RefCell::new(
            crate::syscall::heap::Heap::default(),
        ));
    } else if let Ok(mut heap) = tracee.heap.try_borrow_mut() {
        *heap = crate::syscall::heap::Heap::default();
    }

    crate::tracee::mem::mem_prepare_after_execve(tracee);
    let status = transfer_load_script(tracee);
    if status < 0 {
        crate::note!(
            Some(tracee),
            crate::note::Severity::Error,
            crate::note::Origin::Internal,
            "can't transfer load script: {}",
            std::io::Error::from_raw_os_error(-status)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execve::Mapping;

    #[test]
    fn transcript_mappings_serializes_six_words_each() {
        let mappings = vec![
            Mapping {
                fd: 7,
                offset: 0x1000,
                addr: 0x400000,
                length: 0x2000,
                flags: (libc::MAP_PRIVATE | libc::MAP_FIXED) as Word,
                prot: (libc::PROT_READ | libc::PROT_EXEC) as Word,
                clear_length: 0x100,
            },
            Mapping {
                fd: Word::MAX,
                offset: 0,
                addr: 0x500000,
                length: 0x1000,
                flags: (libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED) as Word,
                prot: libc::PROT_WRITE as Word,
                clear_length: 0,
            },
        ];
        let mut script = Vec::new();
        transcript_mappings(&mut script, &mappings);
        assert_eq!(script.len(), 12);
        assert_eq!(script[0], LOAD_ACTION_MMAP_FILE);
        assert_eq!(script[1], 0x400000);
        assert_eq!(script[2], 0x2000);
        assert_eq!(script[4], 0x1000); // offset
        assert_eq!(script[5], 0x100); // clear_length
        assert_eq!(script[6], LOAD_ACTION_MMAP_ANON);
        assert_eq!(script[7], 0x500000);
    }
}
