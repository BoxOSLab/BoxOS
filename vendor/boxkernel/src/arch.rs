//! Host-architecture constants and guest-ABI handling.
//!
//! Only the pieces the generic code needs are exposed here; register layout
//! details live in `tracee::reg` and syscall-number tables in `sysnum`.

use crate::Word;

/// Syscall number PRoot substitutes when it answers a syscall itself
/// (`PR_void`).  The avoider is negative so the kernel cancels the syscall
/// outright (x86_64: `orig_rax`; aarch64: `NT_ARM_SYSTEM_CALL`) instead of
/// executing it.
pub const SYSCALL_AVOIDER: Word = (-2i64) as Word;

#[cfg(target_arch = "x86_64")]
mod host {
    /// Size in bytes of the instruction that triggers a syscall-stop
    /// (`syscall`/`sysenter` on x86).
    pub const SYSTRAP_SIZE: crate::Word = 2;

    /// Bytes below the stack pointer a leaf function may legally use; PRoot
    /// must not scribble there when allocating tracee memory during sysenter.
    pub const RED_ZONE_SIZE: crate::Word = 128;

    /// Fixed text address the loader ELF is linked at.
    pub const LOADER_ADDRESS: u64 = 0x6000_0000_0000;

    /// Load base for position-independent guest executables.
    pub const EXEC_PIC_ADDRESS: u64 = 0x5000_0000_0000;

    /// Load base for position-independent ELF interpreters.
    pub const INTERP_PIC_ADDRESS: u64 = 0x6f00_0000_0000;

    /// 32-bit counterparts used by the optional -m32 loader.
    pub const EXEC_PIC_ADDRESS_32: u64 = 0x0f00_0000;
    pub const INTERP_PIC_ADDRESS_32: u64 = 0xaf00_0000;

    /// e_machine values treated as "host" binaries under QEMU.
    pub const HOST_ELF_MACHINE: &[u16] = &[62, 3, 6];

    /// Minimum alignment of the stack pointer the loader is started with;
    /// a guest word (4 or 8 bytes) is enough on x86.
    pub const STACK_ALIGNMENT: crate::Word = 4;
}

#[cfg(target_arch = "aarch64")]
mod host {
    /// `svc #0` is one 32-bit instruction.
    pub const SYSTRAP_SIZE: crate::Word = 4;

    /// AAPCS64 has no red zone.
    pub const RED_ZONE_SIZE: crate::Word = 0;

    /// Fixed text address the loader ELF is linked at (fits a 39-bit VA
    /// space, the smallest one Android kernels ship with).
    pub const LOADER_ADDRESS: u64 = 0x20_0000_0000;

    /// Load base for position-independent guest executables.
    pub const EXEC_PIC_ADDRESS: u64 = 0x30_0000_0000;

    /// Load base for position-independent ELF interpreters.
    pub const INTERP_PIC_ADDRESS: u64 = 0x3f_0000_0000;

    /// 32-bit (AArch32) counterparts.
    pub const EXEC_PIC_ADDRESS_32: u64 = 0x0f00_0000;
    pub const INTERP_PIC_ADDRESS_32: u64 = 0x1f00_0000;

    /// e_machine values treated as "host" binaries under QEMU (EM_AARCH64).
    pub const HOST_ELF_MACHINE: &[u16] = &[183];

    /// SP must stay 16-byte aligned: Linux enables EL0 stack alignment checks.
    pub const STACK_ALIGNMENT: crate::Word = 16;
}

#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
compile_error!("BoxKernel supports x86_64 and aarch64 hosts only");

pub use host::*;

/// AUDIT_ARCH_* tokens used in the seccomp filter, paired with the ABIs each
/// section covers.
#[derive(Copy, Clone)]
pub struct SeccompArch {
    pub value: u32,
    pub abis: &'static [crate::sysnum::Abi],
}

#[cfg(target_arch = "x86_64")]
pub const SECCOMP_ARCHS: &[SeccompArch] = &[
    SeccompArch {
        value: AUDIT_ARCH_X86_64,
        abis: &[crate::sysnum::Abi::Default, crate::sysnum::Abi::Abi3],
    },
    SeccompArch {
        value: AUDIT_ARCH_I386,
        abis: &[crate::sysnum::Abi::Abi2],
    },
];

#[cfg(target_arch = "aarch64")]
pub const SECCOMP_ARCHS: &[SeccompArch] = &[
    SeccompArch {
        value: AUDIT_ARCH_AARCH64,
        abis: &[crate::sysnum::Abi::Default],
    },
    SeccompArch {
        value: AUDIT_ARCH_ARM,
        abis: &[crate::sysnum::Abi::Abi2],
    },
];

pub const AUDIT_ARCH_I386: u32 = 0x4000_0003; // EM_386 | __AUDIT_ARCH_LE
pub const AUDIT_ARCH_X86_64: u32 = 0xC000_003E; // EM_X86_64|__AUDIT_ARCH_64BIT|LE
pub const AUDIT_ARCH_ARM: u32 = 0x4000_0028; // EM_ARM | __AUDIT_ARCH_LE
pub const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7; // EM_AARCH64|__AUDIT_ARCH_64BIT|LE

/// Offsets of st_uid/st_gid inside the *32-bit* `struct stat` layout.
pub const OFFSETOF_STAT_UID_32: usize = 24;
pub const OFFSETOF_STAT_GID_32: usize = 28;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avoider_is_negative_word() {
        // The kernel cancels the syscall when orig_rax is negative.
        assert_eq!(SYSCALL_AVOIDER as i64, -2);
    }

    #[test]
    fn load_addresses_are_distinct_and_aligned() {
        assert_ne!(LOADER_ADDRESS, EXEC_PIC_ADDRESS);
        assert_ne!(EXEC_PIC_ADDRESS, INTERP_PIC_ADDRESS);
        assert_ne!(EXEC_PIC_ADDRESS_32, INTERP_PIC_ADDRESS_32);
        // Page-aligned.
        for a in [LOADER_ADDRESS, EXEC_PIC_ADDRESS, INTERP_PIC_ADDRESS] {
            assert_eq!(a % 4096, 0);
        }
        for a in [EXEC_PIC_ADDRESS_32, INTERP_PIC_ADDRESS_32] {
            assert_eq!(a % 4096, 0);
            assert!(a < 0x1_0000_0000, "32-bit address escapes 4GiB");
        }
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn audit_arch_tokens() {
        // EM_386 | __AUDIT_ARCH_LE | __AUDIT_ARCH_64BIT? i386 = LE|3.
        assert_eq!(AUDIT_ARCH_I386 & 0xFFFF, 3);
        assert_eq!(AUDIT_ARCH_X86_64 & 0xFFFF, 62);
        const { assert!(AUDIT_ARCH_X86_64 & 0x8000_0000 != 0) } // 64-bit marker
        // SECCOMP_ARCHS cover all three ABIs exactly once.
        let total: usize = SECCOMP_ARCHS.iter().map(|a| a.abis.len()).sum();
        assert_eq!(total, 3);
    }

    #[test]
    #[cfg(target_arch = "x86_64")]
    fn host_machines_include_x86() {
        // EM_X86_64=62, EM_386=3, EM_86=6 — PRoot treats these as native.
        assert!(HOST_ELF_MACHINE.contains(&62));
        assert!(HOST_ELF_MACHINE.contains(&3));
        assert!(HOST_ELF_MACHINE.contains(&6));
        assert!(!HOST_ELF_MACHINE.contains(&40)); // not ARM
    }
}
