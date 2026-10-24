# Vendored source provenance

## BoxKernel

- Upstream: https://github.com/BoxOSLab/BoxKernel
- Base commit: `4c278f69a6c2ddc8faefba96204658791eb132c8`
- License: GPL-2.0-or-later (`boxkernel/LICENSE`).
- Snapshot: the existing local BoxKernel working tree at the start of this task. Its uncommitted Android/aarch64 compatibility work is captured in `boxkernel-android.patch`, relative to the base commit. The original checkout was not changed.
- Additional BoxOS integration changes: `PTRACE_O_EXITKILL` on Android so guest descendants die with the tracer; 16 KB loader segment alignment. These changes live only in the vendored snapshot. `boxos-integration.patch` records them separately.

## Termux terminal libraries

- Upstream: https://github.com/termux/termux-app
- Tag: `v0.118.3`
- Commit: `5b657c6adf4304e5198951ce815fe0205dcac29c`
- Only `terminal-emulator/src` and `terminal-view/src` are included. The Termux Android app and `termux-shared` are not included.
- License notice: `TERMUX-LICENSE.md` (GPL-3.0 with Apache-2.0 exceptions), `APACHE-2.0.txt`, and the project’s GPL-3.0 `LICENSE`.
- New minimal Gradle module files and package-free Android manifests adapt the libraries to AGP 8.6.
- JNI links with 16 KB segment alignment and sets a parent-death signal so the tracer cannot outlive the application process.
- PTY I/O uses public `ParcelFileDescriptor.fromFd`/auto-close streams instead of reflective access to hidden `FileDescriptor` fields. Input and output streams own independent duplicated descriptors.
- Existing upstream emulator unit tests are retained.

## AndroidX Material vector icons

- Only the 32 extended rounded vectors used by the app are copied into `app/src/main/java/androidx/compose/material/icons/rounded/`. The small Material icons core library remains a normal Maven dependency.
- Source: Google's Maven Central distribution endpoint, `https://dl.google.com/dl/android/maven2/androidx/compose/material/material-icons-extended/1.7.6/material-icons-extended-1.7.6-sources.jar`.
- Source archive SHA-256: `9b22840d9d5ec83fca54783df66640c0e2d76bb164687d654c23bcc6c02f3a96`.
- License: Apache-2.0; original Android Open Source Project copyright and license headers are retained in each source file. License text is in `APACHE-2.0.txt`.
- The full extended icon library is deliberately omitted from the APK to avoid packaging thousands of unused vectors.

## BoxRootfs

- Catalog: https://raw.githubusercontent.com/BoxOSLab/BoxRootfs/main/latest.json
- Images: immutable releases under https://github.com/BoxOSLab/BoxRootfs/releases
- The catalog is fetched at runtime, schema-validated, restricted to official release URLs, and cached for offline display. Versions and release hashes are not hardcoded into the client.
- Image SHA-256 and exact download length must match before extraction.
- No BoxRootfs binary image or build script is redistributed in this source tree.
