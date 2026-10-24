package io.boxos.app

import io.boxos.app.data.*
import io.boxos.app.runtime.LaunchSpec
import org.junit.Assert.*
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import org.apache.commons.compress.archivers.tar.*
import org.tukaani.xz.*

class CoreTest {
    private fun image() = RootImage("alpine", "3.24.3", "arm64", "alpine-arm64.tar.xz", "ab".repeat(32), 1024,
        "https://github.com/BoxOSLab/BoxRootfs/releases/download/2026.10.24/alpine-arm64.tar.xz")
    private fun rejects(block: () -> Unit) {
        try { block(); fail("Expected rejection") } catch (_: IllegalArgumentException) {} catch (_: IllegalStateException) {}
    }
    @Test fun catalogAcceptsUpstreamSchemaAndUnknownFields() {
        val parsed = BoxJson.decodeFromString<Catalog>("""{"schema":1,"generated":"today","release":"test","repository":"upstream","images":[{"distro":"alpine","version":"3","arch":"arm64","filename":"alpine.tar.xz","sha256":"${"ab".repeat(32)}","size":10,"url":"https://github.com/BoxOSLab/BoxRootfs/releases/download/test/alpine.tar.xz","qemu":"qemu-aarch64"}]}""")
        parsed.validate(); assertEquals("alpine", parsed.images.single().distro)
    }
    @Test fun catalogRejectsUntrustedUrls() {
        listOf("http://github.com/BoxOSLab/BoxRootfs/releases/download/tag/alpine-arm64.tar.xz", "https://example.com/alpine-arm64.tar.xz", "https://github.com/attacker/root/releases/download/tag/alpine-arm64.tar.xz", "https://github.com/BoxOSLab/BoxRootfs/releases/download/tag/alpine-arm64.tar.xz?x=y").forEach { url -> rejects { image().copy(url = url).validate() } }
    }
    @Test fun catalogRejectsCorruptMetadata() {
        rejects { image().copy(sha256 = "invalid").validate() }
        rejects { image().copy(size = -1).validate() }
        rejects { image().copy(arch = "armv7").validate() }
        rejects { image().copy(filename = "../image.tar.xz").validate() }
        rejects { Catalog(2, "", "", listOf(image())).validate() }
        rejects { Catalog(1, "", "", listOf(image(), image())).validate() }
    }
    @Test fun launchUsesArgumentBoundariesAndPackagedLoader() {
        val spec = LaunchSpec.build("/native", "/data/my root;echo bad", "/cache", "/shared", Preferences(), "/bin/sh")
        assertEquals("/native/libboxkernel.so", spec.executable)
        assertTrue(spec.arguments.contains("/data/my root;echo bad"))
        assertTrue(spec.arguments.contains("--kill-on-exit"))
        assertFalse(spec.arguments.contains("-c"))
        assertTrue(spec.environment.contains("PROOT_LOADER=/native/libboxloader.so"))
        assertTrue(spec.environment.contains("PROOT_NO_SECCOMP=1"))
        assertFalse(spec.arguments.contains("-R")) // Do not replace guest DNS with Android /etc/resolv.conf.
    }
    @Test fun launchHonorsSharedFolderAndSeccompPreferences() {
        val spec = LaunchSpec.build("/n", "/r", "/t", "/shared", Preferences(seccomp = true, sharedFolder = false), "/bin/bash")
        assertFalse(spec.arguments.any { it.contains("/shared") })
        assertFalse(spec.environment.any { it.startsWith("PROOT_NO_SECCOMP") })
        assertEquals(listOf("/bin/bash", "-l"), spec.arguments.takeLast(2))
    }
    @Test fun pathValidationRejectsTraversal() {
        listOf("../escape", "/absolute", "a/../../escape", "a\\..\\x", "x\u0000y").forEach { rejects { SafeArchive.relative(it) } }
        assertEquals("etc/file", SafeArchive.relative("./etc/file").toString())
    }
    private fun archive(vararg entries: Triple<String, Byte, String>): ByteArray {
        val output = ByteArrayOutputStream()
        XZOutputStream(output, LZMA2Options(1)).use { xz -> TarArchiveOutputStream(xz).use { tar ->
            entries.forEach { (name, kind, data) ->
                val entry = TarArchiveEntry(name, kind)
                if (kind == TarConstants.LF_NORMAL) { entry.size = data.toByteArray().size.toLong(); entry.mode = 493 }
                else entry.linkName = data
                tar.putArchiveEntry(entry)
                if (kind == TarConstants.LF_NORMAL) tar.write(data.toByteArray())
                tar.closeArchiveEntry()
            }
        } }
        return output.toByteArray()
    }
    private fun fixture(block: (java.io.File) -> Unit) {
        val dir = Files.createTempDirectory("boxos-test").toFile()
        try { block(dir) } finally { SafeArchive.deleteTree(dir) }
    }
    @Test fun extractionPreservesFilesExecutabilityAndGuestLinks() = fixture { dir ->
        val data = archive(Triple("usr/bin/tool", TarConstants.LF_NORMAL, "hello"), Triple("bin", TarConstants.LF_SYMLINK, "usr/bin"), Triple("absolute", TarConstants.LF_SYMLINK, "/usr/bin/tool"))
        SafeArchive.extract(ByteArrayInputStream(data), dir)
        assertEquals("hello", java.io.File(dir, "usr/bin/tool").readText())
        assertTrue(java.io.File(dir, "usr/bin/tool").canExecute())
        assertEquals("/usr/bin/tool", Files.readSymbolicLink(java.io.File(dir, "absolute").toPath()).toString())
    }
    @Test fun extractionRejectsTraversalBeforeWritingOutsideRoot() = fixture { dir ->
        rejects { SafeArchive.extract(ByteArrayInputStream(archive(Triple("../escape", TarConstants.LF_NORMAL, "bad"))), dir) }
    }
    @Test fun extractionCannotWriteThroughArchiveSymlink() = fixture { dir ->
        val outside = Files.createTempDirectory("boxos-outside").toFile()
        try {
            rejects { SafeArchive.extract(ByteArrayInputStream(archive(Triple("link", TarConstants.LF_SYMLINK, outside.path), Triple("link/escape", TarConstants.LF_NORMAL, "bad"))), dir) }
            assertFalse(java.io.File(outside, "escape").exists())
        } finally { SafeArchive.deleteTree(outside) }
    }
    @Test fun extractionRejectsEscapingHardLinks() = fixture { dir ->
        rejects { SafeArchive.extract(ByteArrayInputStream(archive(Triple("bad", TarConstants.LF_LINK, "../escape"))), dir) }
    }
    @Test fun extractionSupportsForwardHardLinks() = fixture { dir ->
        SafeArchive.extract(ByteArrayInputStream(archive(Triple("first", TarConstants.LF_LINK, "second"), Triple("second", TarConstants.LF_NORMAL, "data"))), dir)
        assertEquals("data", java.io.File(dir, "first").readText())
        assertTrue(Files.isSameFile(java.io.File(dir, "first").toPath(), java.io.File(dir, "second").toPath()))
    }
    @Test fun extractionRejectsDeviceNodes() = fixture { dir ->
        rejects { SafeArchive.extract(ByteArrayInputStream(archive(Triple("device", TarConstants.LF_CHR, ""))), dir) }
    }
    @Test fun extractionRespondsToCancellation() = fixture { dir ->
        var cancelled = false
        try { SafeArchive.extract(ByteArrayInputStream(archive(Triple("file", TarConstants.LF_NORMAL, "hello"))), dir, { throw java.util.concurrent.CancellationException() }) }
        catch (_: java.util.concurrent.CancellationException) { cancelled = true }
        assertTrue(cancelled)
    }
    @Test fun backupRoundTripPreservesLinksAndContents() = fixture { source -> fixture { destination ->
        java.io.File(source, "rootfs/root").mkdirs()
        java.io.File(source, "rootfs/root/hello").writeText("world")
        java.io.File(source, "rootfs/root/hello").setExecutable(true)
        Files.createSymbolicLink(java.io.File(source, "rootfs/link").toPath(), java.nio.file.Paths.get("root/hello"))
        val output = ByteArrayOutputStream(); SafeArchive.pack(source, output)
        SafeArchive.extract(ByteArrayInputStream(output.toByteArray()), destination)
        assertEquals("world", java.io.File(destination, "rootfs/root/hello").readText())
        assertTrue(java.io.File(destination, "rootfs/root/hello").canExecute())
        assertTrue(Files.isSymbolicLink(java.io.File(destination, "rootfs/link").toPath()))
    } }
    @Test fun hostBrowserRejectsSymlinkAncestor() = fixture { dir ->
        Files.createSymbolicLink(java.io.File(dir, "outside").toPath(), java.nio.file.Paths.get("/tmp"))
        rejects { safeGuestPath(dir, "outside/file") }
        assertEquals(dir.canonicalFile, safeGuestPath(dir, ""))
    }
    @Test fun deletionNeverTraversesSymbolicLinks() = fixture { dir -> fixture { outside ->
        java.io.File(outside, "keep").writeText("keep")
        val link = java.io.File(dir, "link"); Files.createSymbolicLink(link.toPath(), outside.toPath())
        SafeArchive.deleteTree(link)
        assertEquals("keep", java.io.File(outside, "keep").readText())
    } }
    @Test fun atomicWriteReplacesLinkWithoutFollowingIt() = fixture { dir ->
        val target = java.io.File(dir, "target").apply { writeText("original") }
        val link = java.io.File(dir, "link"); Files.createSymbolicLink(link.toPath(), target.toPath())
        atomicWrite(link, "replacement")
        assertEquals("original", target.readText()); assertEquals("replacement", link.readText())
    }
    @Test fun minimalImagesReportTheirActualPackageTool() = fixture { dir ->
        java.io.File(dir, "usr/bin").mkdirs()
        assertEquals("none", detectPackageManager(dir))
        java.io.File(dir, "usr/bin/dpkg").writeText("")
        assertEquals("dpkg", detectPackageManager(dir))
        java.io.File(dir, "usr/bin/apt").writeText("")
        assertEquals("apt", detectPackageManager(dir))
    }
}
