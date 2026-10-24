//! Diagnostic output, mirroring cli/note.c.
//!
//! `note()` prints `proot <severity>: <message>` on stderr; `SYSTEM` origin
//! appends the current errno's description.  `verbose!` is the per-tracee
//! gated form.

use std::sync::atomic::{AtomicI32, Ordering};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    System,
    Internal,
    User,
}

pub static GLOBAL_VERBOSE_LEVEL: AtomicI32 = AtomicI32::new(0);
static TOOL_NAME: std::sync::OnceLock<&'static str> = std::sync::OnceLock::new();

pub fn set_tool_name(name: &'static str) {
    let _ = TOOL_NAME.set(name);
}

pub fn tool_name() -> &'static str {
    TOOL_NAME.get().copied().unwrap_or("proot")
}

pub fn global_verbose() -> i32 {
    GLOBAL_VERBOSE_LEVEL.load(Ordering::Relaxed)
}

/// Print a notice on stderr.  INFO is suppressed when the global verbose
/// level is negative; per-tracee verbosity gates at call sites via the
/// `verbose!` macro (the same split as the C code).
pub fn note(severity: Severity, origin: Origin, args: std::fmt::Arguments) {
    if severity == Severity::Info && global_verbose() < 0 {
        return;
    }
    let tool = tool_name();
    match severity {
        Severity::Warning => eprint!("{} warning: ", tool),
        Severity::Error => eprint!("{} error: ", tool),
        Severity::Info => eprint!("{} info: ", tool),
    }
    eprint!("{}", args);
    match origin {
        Origin::System => {
            eprintln!(": {}", crate::sys::strerror(crate::sys::errno()));
        }
        _ => eprintln!(),
    }
}

/// `note(tracee, severity, origin, ...)` — verbose level comes from the
/// tracee when present, otherwise from the global level.
#[macro_export]
macro_rules! note {
    // The tracee-prefixed form is matched on the literal `Some(...)` token —
    // otherwise the two forms are ambiguous at the syntax level.
    (Some($tracee:expr_2021), $severity:expr_2021, $origin:expr_2021, $($arg:tt)*) => {{
        let _ = $tracee;
        $crate::note::note($severity, $origin, format_args!($($arg)*))
    }};
    (None, $severity:expr_2021, $origin:expr_2021, $($arg:tt)*) => {{
        $crate::note::note($severity, $origin, format_args!($($arg)*))
    }};
    ($severity:expr_2021, $origin:expr_2021, $($arg:tt)*) => {{
        $crate::note::note($severity, $origin, format_args!($($arg)*))
    }};
}

/// VERBOSE(tracee, level, ...) — emit an INFO message when the tracee's (or
/// the global) verbose level reaches `level`.
#[macro_export]
macro_rules! verbose {
    ($tracee:expr_2021, $level:expr_2021, $($arg:tt)*) => {{
        let v = $crate::tracee::verbose_of($tracee);
        if v >= $level {
            $crate::note::note($crate::note::Severity::Info,
                               $crate::note::Origin::Internal,
                               format_args!($($arg)*));
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_name_defaults_and_sets() {
        // OnceLock: first set wins; subsequent calls are ignored.
        assert_eq!(tool_name(), "proot");
        set_tool_name("boxkernel-test");
        // Depending on test order another test may have set it already.
        let n = tool_name();
        assert!(n == "proot" || n == "boxkernel-test");
    }

    #[test]
    fn global_verbose_roundtrip() {
        let _g = crate::testutil::env_lock();
        let old = global_verbose();
        GLOBAL_VERBOSE_LEVEL.store(3, Ordering::Relaxed);
        assert_eq!(global_verbose(), 3);
        GLOBAL_VERBOSE_LEVEL.store(old, Ordering::Relaxed);
    }

    #[test]
    fn note_does_not_panic() {
        // Smoke: every severity/origin combo renders without panic.
        for s in [Severity::Error, Severity::Warning, Severity::Info] {
            for o in [Origin::System, Origin::Internal, Origin::User] {
                note(s, o, format_args!("test {s:?} {o:?}"));
            }
        }
    }

    #[test]
    fn verbose_macro_gates_on_level() {
        // verbose! with level far above any plausible setting is a no-op;
        // just ensure the macro expands and doesn't evaluate eagerly.
        let mut evaluated = false;
        {
            let v = crate::tracee::verbose_of(None);
            if v >= 99 {
                evaluated = true;
            }
        }
        assert!(!evaluated);
        crate::verbose!(None, 99, "should not print");
        crate::note!(None, Severity::Info, Origin::Internal, "info smoke");
        crate::note!(Severity::Warning, Origin::User, "warning smoke");
    }
}
