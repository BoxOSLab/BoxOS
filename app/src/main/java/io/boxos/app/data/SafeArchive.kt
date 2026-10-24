package io.boxos.app.data

import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream
import org.apache.commons.compress.archivers.tar.TarArchiveEntry
import org.tukaani.xz.XZInputStream
import org.tukaani.xz.XZOutputStream
import org.tukaani.xz.LZMA2Options
import java.io.File
import java.io.InputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.FileVisitResult
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions

/** Never follow archive links while writing. Links are materialized only after regular files. */
object SafeArchive {
    private const val MAX_BYTES = 8L * 1024 * 1024 * 1024
    fun relative(name: String): Path {
        require(!name.startsWith('/') && !name.contains('\u0000') && !name.contains('\\')) { "Unsafe archive path: $name" }
        val path = java.nio.file.Paths.get(name).normalize()
        require(!path.isAbsolute && !path.startsWith("..")) { "Archive path escapes root: $name" }
        return path
    }

    fun extract(input: InputStream, root: File, check: () -> Unit = {}, progress: (Long) -> Unit = {}) {
        root.mkdirs()
        val base = root.toPath().toAbsolutePath().normalize()
        val links = mutableListOf<Pair<Path, String>>()
        val hardLinks = mutableListOf<Pair<Path, Path>>()
        val directories = linkedMapOf<Path, Int>()
        var total = 0L
        var count = 0
        XZInputStream(input, 64 * 1024).use { xz ->
            TarArchiveInputStream(xz).use { tar ->
                while (true) {
                    check()
                    val entry = tar.nextTarEntry ?: break
                    require(++count <= 500_000) { "Archive contains too many entries" }
                    require(entry.isFile || entry.size == 0L) { "Non-file entry has an unexpected body" }
                    val rel = relative(entry.name)
                    if (rel.toString().isEmpty() || rel.toString() == ".") continue
                    val path = base.resolve(rel)
                    require(path.startsWith(base))
                    Files.createDirectories(path.parent)
                    when {
                        entry.isSymbolicLink -> {
                            require(entry.linkName.isNotEmpty() && !entry.linkName.contains('\u0000')) { "Invalid symbolic link" }
                            links += path to entry.linkName
                        }
                        entry.isLink -> hardLinks += path to base.resolve(relative(entry.linkName))
                        entry.isDirectory -> { Files.createDirectories(path); directories[path] = entry.mode }
                        // commons-compress reports device and FIFO entries as files.
                        entry.isCharacterDevice || entry.isBlockDevice || entry.isFIFO -> error("Unsupported special entry: ${entry.name}")
                        entry.isFile -> {
                            require(entry.size in 0..(MAX_BYTES - total)) { "Expanded archive exceeds 8 GB" }
                            total += entry.size
                            Files.newOutputStream(path).use { out ->
                                val buffer = ByteArray(64 * 1024)
                                var copied = 0L
                                while (true) {
                                    check()
                                    val read = tar.read(buffer)
                                    if (read < 0) break
                                    out.write(buffer, 0, read); copied += read
                                }
                                require(copied == entry.size) { "Truncated archive entry" }
                            }
                            // Retain normal executable bits; never set setuid/setgid.
                            val bits = (entry.mode and 0x1ff) or 0x180
                            permissions(path, bits)
                        }
                        else -> error("Unsupported special entry: ${entry.name}")
                    }
                    if (count % 100 == 0) progress(total)
                }
            }
        }
        // Hard links may refer forward, including to another hard link.
        while (hardLinks.isNotEmpty()) {
            check()
            val ready = hardLinks.filter { Files.isRegularFile(it.second, java.nio.file.LinkOption.NOFOLLOW_LINKS) }
            require(ready.isNotEmpty()) { "Invalid hard link target" }
            ready.forEach { (path, target) ->
                try { Files.createLink(path, target) }
                catch (_: java.io.IOException) {
                    // Android SELinux can prohibit hard links even in private app storage.
                    Files.copy(target, path, java.nio.file.StandardCopyOption.COPY_ATTRIBUTES)
                }
                hardLinks.remove(path to target)
            }
        }
        links.forEach { (path, target) ->
            check()
            require(!Files.exists(path, java.nio.file.LinkOption.NOFOLLOW_LINKS)) { "Duplicate link path" }
            Files.createSymbolicLink(path, java.nio.file.Paths.get(target))
        }
        directories.entries.toList().asReversed().forEach { (path, mode) -> permissions(path, (mode and 0x1ff) or 0x1c0) }
    }

    private fun permissions(path: Path, bits: Int) {
        val perms = buildString { for (i in 8 downTo 0) append(if (bits and (1 shl i) != 0) "xwr"[i % 3] else '-') }
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(perms))
    }

    fun pack(root: File, output: OutputStream, check: () -> Unit = {}) {
        XZOutputStream(output, LZMA2Options(1)).use { xz ->
            TarArchiveOutputStream(xz).use { tar ->
                tar.setLongFileMode(TarArchiveOutputStream.LONGFILE_POSIX)
                tar.setBigNumberMode(TarArchiveOutputStream.BIGNUMBER_POSIX)
                val base = root.toPath()
                var bytes = 0L
                var entries = 0
                Files.walkFileTree(base, object : SimpleFileVisitor<Path>() {
                    fun add(path: Path, attributes: BasicFileAttributes) {
                        check()
                        val name = base.relativize(path).toString()
                        if (name.isEmpty()) return
                        require(++entries <= 500_000) { "Backup exceeds the 500,000 entry restore limit" }
                        require(attributes.isDirectory || attributes.isSymbolicLink || attributes.isRegularFile) { "Remove special file before backup: $name" }
                        if (attributes.isRegularFile) {
                            require(attributes.size() in 0..(MAX_BYTES - bytes)) { "Backup exceeds the 8 GB restore limit" }
                            bytes += attributes.size()
                        }
                        val entry = if (attributes.isSymbolicLink) {
                            TarArchiveEntry(name, org.apache.commons.compress.archivers.tar.TarConstants.LF_SYMLINK).apply { linkName = Files.readSymbolicLink(path).toString() }
                        } else TarArchiveEntry(path.toFile(), name).apply {
                            // The File constructor uses default modes; keep the real permission bits.
                            mode = (mode and 0x1ff.inv()) or Files.getPosixFilePermissions(path, java.nio.file.LinkOption.NOFOLLOW_LINKS).sumOf { 1 shl (8 - it.ordinal) }
                        }
                        tar.putArchiveEntry(entry)
                        if (attributes.isRegularFile) Files.newInputStream(path).use { input ->
                            val buffer = ByteArray(64 * 1024)
                            while (true) { check(); val n = input.read(buffer); if (n < 0) break; tar.write(buffer, 0, n) }
                        }
                        tar.closeArchiveEntry()
                    }
                    override fun preVisitDirectory(dir: Path, attrs: BasicFileAttributes): FileVisitResult { add(dir, attrs); return FileVisitResult.CONTINUE }
                    override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult { add(file, attrs); return FileVisitResult.CONTINUE }
                })
            }
        }
    }

    fun deleteTree(root: File) {
        if (!Files.exists(root.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS)) return
        if (Files.isDirectory(root.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS)) {
            Files.setPosixFilePermissions(root.toPath(), PosixFilePermissions.fromString("rwx------"))
        }
        Files.walkFileTree(root.toPath(), object : SimpleFileVisitor<Path>() {
            override fun visitFile(file: Path, attrs: BasicFileAttributes): FileVisitResult { Files.delete(file); return FileVisitResult.CONTINUE }
            override fun visitFileFailed(file: Path, error: java.io.IOException): FileVisitResult {
                if (!Files.isDirectory(file, java.nio.file.LinkOption.NOFOLLOW_LINKS)) throw error
                Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rwx------"))
                deleteTree(file.toFile())
                return FileVisitResult.CONTINUE
            }
            override fun postVisitDirectory(dir: Path, error: java.io.IOException?): FileVisitResult {
                if (error != null) throw error
                Files.delete(dir); return FileVisitResult.CONTINUE
            }
        })
    }
}
