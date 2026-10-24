# BoxOS for Android

BoxOS is a native Android Linux client powered by [BoxKernel](https://github.com/BoxOSLab/BoxKernel) and the official [BoxRootfs](https://github.com/BoxOSLab/BoxRootfs) distribution catalog. It runs without Android root access on **Android 8.0+**, on **ARM64 and x86-64** devices.

## What is included

- Debian stable, Ubuntu LTS, and Alpine stable, resolved from BoxRootfs `latest.json` rather than hardcoded versions.
- Multiple independently named Linux environments, with architecture filtering, free-space checks, download progress, SHA-256 verification, cancellation, atomic installation, and startup recovery of abandoned staging directories.
- Up to eight interactive PTY sessions with 256-color/truecolor terminal emulation, Unicode, scrollback, selection, hardware keyboard support, paste, transcript copy, pinch zoom, font controls, and an extra-key row.
- A foreground service and notification that keep active sessions and operations running when the activity is backgrounded; a Stop all action and an optional bounded CPU wake lock.
- A file browser with directory navigation, filtering, folder/file creation, text editing (256 KB limit), recursive deletion, Android document import (2 GB limit), and export.
- Complete environment backup to `.tar.xz` and restore as a new environment. Files, normal permissions, and symbolic links are retained. Stop an environment’s terminals before backup or deletion.
- System/light/dark themes, terminal font settings, DNS resolvers, shared workspace binding, optional seccomp acceleration, setup guidance, and copyable diagnostics.
- Automated unit tests, upstream terminal-emulator tests, JVM UI snapshots, Android lint, an APK/ELF verifier, and a live BoxRootfs Linux smoke test. No manual testing is required by the build workflow.

## Build

Requirements: JDK 17, Android SDK platform 35, NDK `27.0.12077973`, Rust stable with `aarch64-linux-android` and `x86_64-linux-android`, and `cargo-ndk`. The Gradle wrapper uses Gradle 8.10.

```sh
export JAVA_HOME=/path/to/jdk17
export ANDROID_HOME=/path/to/android-sdk
export ANDROID_NDK_HOME="$ANDROID_HOME/ndk/27.0.12077973"
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk --locked
./gradlew :app:assembleDebug
```

`preBuild` compiles the vendored BoxKernel and packages both its executable and its fixed-address loader as extracted native libraries. JNI PTY code is built by the NDK. The output is `app/build/outputs/apk/debug/app-debug.apk`.

For an existing native build, `-PskipNativeBuild=true` skips Rust compilation. Do not use this for a fresh checkout. APK verification will fail if native assets are missing. Release builds are unsigned until a distribution signing identity is configured; the included debug APK is installable for development.

## Automated validation

```sh
./gradlew :app:testDebugUnitTest :terminal-emulator:testDebugUnitTest :app:lintDebug
./gradlew :app:recordPaparazziDebug
./gradlew :app:assembleDebug
python3 scripts/verify-apk.py
cargo test --manifest-path vendor/boxkernel/Cargo.toml
python3 scripts/host-smoke.py
# Exercise all three current native AMD64 images:
python3 scripts/host-smoke.py --all
```

UI snapshots are generated on the JVM without a phone or emulator. The smoke test downloads and verifies an official AMD64 Alpine image and launches it with the vendored BoxKernel and the app’s compatibility options. It tests fake root, file I/O, nested shell processes, hard links, and the package-manager executable. It requires Linux x86-64, Python 3.12+, network access, and a host that permits ptrace. These checks do not certify every device vendor’s SELinux/seccomp policy; blocked runtime launches retain their error output in the terminal.

## Runtime and storage

`files/environments/<uuid>/environment.json` records the distribution, architecture, checksum, name, and installation time; `rootfs/` holds its filesystem. Staging and deletion directories are invisible to the environment list. Runtime temporary files are under the application cache, and `files/shared` is bound to `/mnt/shared` when enabled. Files and backups are exchanged through Android’s Storage Access Framework; no broad storage permission is requested.

Launch arguments are passed as separate arguments, never interpolated through a host shell. A session uses fake root, hard-link compatibility, symlink fixups, System V IPC emulation, protected-port remapping, and explicit `/dev`, `/proc`, and `/sys` bindings. The guest DNS file is preserved instead of binding Android’s host DNS configuration. Seccomp is off by default for Android kernel compatibility.

Android 10+ restricts execution from writable application storage. BoxOS follows the [Android execution policy](https://developer.android.com/about/versions/10/behavior-changes-10#execute-permission) by packaging BoxKernel and its loader in the APK’s extracted native library directory and setting `PROOT_LOADER` explicitly. Native ELF load segments use 16 KB alignment. User-initiated work runs under the [special-use foreground service type](https://developer.android.com/develop/background-work/services/fgs/service-types#special-use).

Backups contain `environment.json` and `rootfs/`. Restore validates their structure and architecture, extracts into a staging directory, assigns a new UUID, and never overwrites an existing environment. Archive extraction rejects traversal, device nodes, invalid hard links, duplicate link paths, excessive expansion, and writing through symbolic links. Absolute *guest* symbolic links are preserved for Linux; the host file browser deliberately does not follow them.

The shared workspace and files outside the environment are not included in environment backups.

## Limits

This is a Linux **userspace**, sharing Android’s kernel. It does not provide Android root, a virtual machine, systemd boot, kernel modules, or a preinstalled graphical desktop. Distributions start as minimal command-line systems; install tools using `apt` or `apk`. Desktop/VNC packages can be managed from the terminal, but BoxOS does not include a graphical desktop viewer. Foreign-architecture QEMU execution is not exposed; only native-architecture images are installed.

Package tools are detected from the installed image. Debian and Ubuntu images include apt; Alpine includes apk. Ubuntu environments installed from BoxRootfs release `2026.10.24` contain `dpkg` but not `apt`, and BoxOS labels them in Workspace rather than presenting apt as installed. Install a new Ubuntu environment to get apt, or import compatible `.deb` files and install them using dpkg.

BoxKernel is not a security boundary. Programs can access data available to the Android application. Android can terminate background work under memory pressure or vendor power-management rules. Terminal processes are not restored after process death; installed files and settings persist. Checksums verify that an image matches the HTTPS-delivered catalog; they do not replace upstream release signing.

## Source layout and licenses

`app/` contains the Kotlin/Compose client, installer, filesystem tools, and runtime service. `vendor/boxkernel/` contains the Rust runtime. `vendor/terminal-emulator/` and `vendor/terminal-view/` contain the Termux terminal libraries. See [vendor/PROVENANCE.md](vendor/PROVENANCE.md) for exact source origins and local changes.

BoxOS is GPL-3.0, compatible with BoxKernel’s GPL-2.0-or-later license. Termux sources retain their upstream GPL-3.0 terms and Apache-2.0 exceptions. Distribution contents retain their own licenses. No rootfs image is bundled in the APK.
