package io.boxos.app.data

import android.content.Context
import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import kotlinx.serialization.encodeToString
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit

class BoxRepository(val context: Context) {
    val base = File(context.filesDir, "environments").apply { mkdirs() }
    val shared = File(context.filesDir, "shared").apply { mkdirs() }
    val arch = when (Build.SUPPORTED_ABIS.firstOrNull()) { "arm64-v8a" -> "arm64"; "x86_64" -> "amd64"; else -> "unsupported" }
    private val http = OkHttpClient.Builder().connectTimeout(20, TimeUnit.SECONDS).readTimeout(45, TimeUnit.SECONDS).callTimeout(20, TimeUnit.MINUTES).build()
    private val _environments = MutableStateFlow<List<Environment>>(emptyList())
    val environments = _environments.asStateFlow()
    val catalog = MutableStateFlow<Catalog?>(null)
    val catalogError = MutableStateFlow<String?>(null)
    val preferences = MutableStateFlow(readPreferences())
    private val preferenceFile get() = File(context.filesDir, "preferences.json")

    fun root(env: Environment) = File(base, "${env.id}/rootfs")
    private fun metadata(env: Environment) = File(base, "${env.id}/environment.json")
    fun refreshEnvironments() {
        _environments.value = base.listFiles().orEmpty().filter { !it.name.startsWith('.') }.mapNotNull {
            runCatching { BoxJson.decodeFromString<Environment>(File(it, "environment.json").readText()) }
                .getOrNull()?.takeIf { env -> env.id == it.name && env.id.matches(Regex("[a-f0-9-]{36}")) && File(it, "rootfs").isDirectory }
        }.sortedByDescending { it.installedAt }
    }

    suspend fun initialize() = withContext(Dispatchers.IO) {
        // Staging trees are never visible as installations; recover abandoned operations.
        base.listFiles().orEmpty().filter { it.name.startsWith(".pending-") || it.name.startsWith(".trash-") }.forEach { SafeArchive.deleteTree(it) }
        refreshEnvironments()
        val cache = File(context.filesDir, "catalog.json")
        catalog.value = runCatching { BoxJson.decodeFromString<Catalog>(cache.readText()).validate() }.getOrNull()
        refreshCatalog()
    }

    suspend fun refreshCatalog() = withContext(Dispatchers.IO) {
        try {
            http.newCall(Request.Builder().url(CATALOG_URL).build()).execute().use { response ->
                check(response.isSuccessful) { "Catalog request failed (HTTP ${response.code})" }
                val body = response.body ?: error("Empty catalog")
                require(body.contentLength() <= 2_000_000) { "Catalog too large" }
                val bytes = body.byteStream().use { it.readBytesLimited(2_000_000) }
                val text = bytes.toString(Charsets.UTF_8)
                val parsed = BoxJson.decodeFromString<Catalog>(text).validate()
                atomicWrite(File(context.filesDir, "catalog.json"), text)
                catalog.value = parsed; catalogError.value = null
            }
        } catch (e: Exception) {
            currentCoroutineContext().ensureActive()
            catalogError.value = "Couldn’t refresh BoxRootfs. ${e.message ?: "Check your connection."}"
        }
    }

    @OptIn(kotlinx.coroutines.InternalCoroutinesApi::class)
    suspend fun install(image: RootImage, name: String, report: (Operation) -> Unit) = withContext(Dispatchers.IO) {
        image.validate()
        require(image.arch == arch) { "Image architecture does not match this device" }
        require(base.usableSpace > image.size * 8 + 256L * 1024 * 1024) { "Not enough free storage. Free at least ${humanBytes(image.size * 8 + 256L * 1024 * 1024)}." }
        val id = UUID.randomUUID().toString()
        val staging = File(base, ".pending-$id").apply { mkdirs() }
        val archive = File(staging, "download.tar.xz")
        val job = currentCoroutineContext()
        try {
            report(Operation("Downloading ${image.title}", 0f, "Connecting securely…"))
            val call = http.newCall(Request.Builder().url(image.url).build())
            // Cancel socket I/O immediately even while a network read is blocked.
            val cancellation = job[kotlinx.coroutines.Job]?.invokeOnCompletion(onCancelling = true, invokeImmediately = true) { if (it != null) call.cancel() }
            try {
                call.execute().use { response ->
                    check(response.isSuccessful) { "Download failed (HTTP ${response.code})" }
                    val body = response.body ?: error("Empty image response")
                    val digest = MessageDigest.getInstance("SHA-256")
                    var downloaded = 0L
                    body.byteStream().use { input -> archive.outputStream().use { output ->
                        val buffer = ByteArray(64 * 1024)
                        var lastReport = 0L
                        while (true) {
                            job.ensureActive()
                            val read = input.read(buffer)
                            if (read < 0) break
                            downloaded += read
                            require(downloaded <= image.size) { "Image exceeds catalog size" }
                            digest.update(buffer, 0, read); output.write(buffer, 0, read)
                            if (downloaded - lastReport > 256 * 1024 || downloaded == image.size) {
                                report(Operation("Downloading ${image.title}", downloaded.toFloat() / image.size, "${humanBytes(downloaded)} of ${humanBytes(image.size)}"))
                                lastReport = downloaded
                            }
                        }
                    } }
                    report(Operation("Verifying image", null, "Checking SHA-256 integrity"))
                    require(downloaded == image.size && digest.digest().joinToString("") { "%02x".format(it) }.equals(image.sha256, true)) { "Image verification failed. Please try again." }
                }
            } finally { cancellation?.dispose() }
            report(Operation("Installing ${image.title}", null, "Unpacking your Linux environment"))
            val root = File(staging, "rootfs")
            archive.inputStream().use { SafeArchive.extract(it, root, { job.ensureActive() }) { bytes -> report(Operation("Installing ${image.title}", null, "${humanBytes(bytes)} unpacked")) } }
            prepareRoot(root)
            val env = Environment(id, name.trim().take(40).ifBlank { image.title }, image.distro, image.version, image.arch, System.currentTimeMillis(), image.sha256, detectPackageManager(root))
            File(staging, "environment.json").writeText(BoxJson.encodeToString(env))
            archive.delete()
            job.ensureActive()
            Files.move(staging.toPath(), File(base, id).toPath(), StandardCopyOption.ATOMIC_MOVE)
            refreshEnvironments()
        } finally { SafeArchive.deleteTree(staging) }
    }

    fun prepareRoot(root: File) {
        require(Files.isDirectory(root.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS)) { "Invalid root filesystem directory" }
        require(File(root, "bin/sh").exists() || File(root, "usr/bin/sh").exists() || Files.isSymbolicLink(File(root, "bin/sh").toPath())) { "Image is missing /bin/sh" }
        listOf("root", "tmp", "dev/shm", "proc", "sys", "mnt/shared").forEach {
            val directory = safeGuestPath(root, it)
            require(!Files.isSymbolicLink(directory.toPath())) { "Invalid system directory: $it" }
            directory.mkdirs()
        }
        val resolver = safeGuestPath(root, "etc/resolv.conf")
        if (Files.isSymbolicLink(resolver.toPath())) Files.delete(resolver.toPath())
        resolver.writeText(preferences.value.dns.split(',').joinToString("\n", postfix = "\n") { "nameserver ${it.trim()}" })
        val hostname = safeGuestPath(root, "etc/hostname")
        if (!Files.isSymbolicLink(hostname.toPath())) hostname.writeText("boxos\n")
    }

    fun rename(env: Environment, name: String) {
        require(name.trim().isNotEmpty()) { "Name cannot be empty" }
        atomicWrite(metadata(env), BoxJson.encodeToString(env.copy(name = name.trim().take(40))))
        refreshEnvironments()
    }
    fun remove(env: Environment) {
        val folder = File(base, env.id)
        val trash = File(base, ".trash-${env.id}")
        Files.move(folder.toPath(), trash.toPath(), StandardCopyOption.ATOMIC_MOVE)
        refreshEnvironments()
        SafeArchive.deleteTree(trash)
    }
    fun savePreferences(prefs: Preferences) {
        require(prefs.theme in listOf("system", "dark", "light"))
        require(prefs.fontSize in 10..24)
        val servers = prefs.dns.split(',').map { it.trim() }
        require(servers.size in 1..4 && servers.all { server ->
            val parts = server.split('.'); parts.size == 4 && parts.all { it.toIntOrNull() in 0..255 }
        }) { "Enter up to four IPv4 DNS addresses, separated by commas" }
        atomicWrite(preferenceFile, BoxJson.encodeToString(prefs)); preferences.value = prefs
    }
    private fun readPreferences() = runCatching { BoxJson.decodeFromString<Preferences>(preferenceFile.readText()) }.getOrDefault(Preferences())
}

fun atomicWrite(file: File, text: String) {
    val temporary = Files.createTempFile(file.parentFile!!.toPath(), ".boxos-write-", ".tmp").toFile()
    try {
        val permissions = if (Files.isRegularFile(file.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS)) Files.getPosixFilePermissions(file.toPath()) else null
        temporary.outputStream().use { it.write(text.toByteArray()); it.fd.sync() }
        if (permissions != null) Files.setPosixFilePermissions(temporary.toPath(), permissions)
        Files.move(temporary.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
    } finally { temporary.delete() }
}

/** Host-side file tools never follow links out of the private root or through absolute guest links. */
fun safeGuestPath(root: File, relative: String): File {
    val base = root.canonicalFile.toPath()
    val path = base.resolve(SafeArchive.relative(relative)).normalize()
    require(path.startsWith(base)) { "Path escapes environment" }
    if (path == base) return base.toFile()
    var parent = path.parent
    while (parent != null && parent != base) {
        require(!Files.isSymbolicLink(parent)) { "Open the real directory instead of a symbolic link" }
        parent = parent.parent
    }
    return path.toFile()
}

fun java.io.InputStream.readBytesLimited(limit: Int): ByteArray {
    val output = java.io.ByteArrayOutputStream()
    val buffer = ByteArray(8192)
    while (true) { val n = read(buffer); if (n < 0) break; require(output.size() + n <= limit) { "File is too large" }; output.write(buffer, 0, n) }
    return output.toByteArray()
}

fun detectPackageManager(root: File): String = when {
    listOf("usr/bin/apt", "bin/apt").any { File(root, it).exists() } -> "apt"
    listOf("sbin/apk", "usr/sbin/apk").any { File(root, it).exists() } -> "apk"
    listOf("usr/bin/dpkg", "bin/dpkg").any { File(root, it).exists() } -> "dpkg"
    else -> "none"
}
