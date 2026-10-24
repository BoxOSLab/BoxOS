package io.boxos.app.runtime

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.core.content.ContextCompat
import com.termux.terminal.TerminalSession
import com.termux.terminal.TerminalSessionClient
import io.boxos.app.BoxApp
import io.boxos.app.data.*
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import java.io.File
import java.nio.file.Files
import java.util.UUID

data class BoxSession(val id: String, val environment: Environment, val terminal: TerminalSession, val number: Int)

class RuntimeManager(private val app: BoxApp, val repository: BoxRepository, private val scope: CoroutineScope) : TerminalSessionClient {
    val sessions = MutableStateFlow<List<BoxSession>>(emptyList())
    val selected = MutableStateFlow<String?>(null)
    val revision = MutableStateFlow(0)
    val operation = MutableStateFlow<Operation?>(null)
    val error = MutableStateFlow<String?>(null)
    val notice = MutableStateFlow<String?>(null)
    val logs = MutableStateFlow<List<String>>(emptyList())
    private var operationJob: Job? = null
    private val handler = Handler(Looper.getMainLooper())
    private var redrawPending = false
    private var nextNumber = 1

    private fun ensureService() { ContextCompat.startForegroundService(app, Intent(app, BoxService::class.java)) }
    fun isActive(env: Environment) = sessions.value.any { it.environment.id == env.id && it.terminal.isRunning }

    fun launch(env: Environment) {
        if (operation.value != null) { error.value = "Wait for the current operation to finish."; return }
        runCatching {
            require(sessions.value.size < 8) { "Close a terminal before opening another (maximum 8)." }
            val root = repository.root(env)
            repository.prepareRoot(root)
            val nativeDir = app.applicationInfo.nativeLibraryDir
            require(File(nativeDir, "libboxkernel.so").canExecute() && File(nativeDir, "libboxloader.so").canExecute()) { "BoxKernel is missing from this APK. Rebuild with scripts/build-native.sh." }
            val temporary = File(app.cacheDir, "runtime/${env.id}").apply { mkdirs() }
            val shell = if (File(root, "bin/bash").exists() || File(root, "usr/bin/bash").exists()) "/bin/bash" else "/bin/sh"
            val spec = LaunchSpec.build(nativeDir, root.absolutePath, temporary.absolutePath, repository.shared.absolutePath, repository.preferences.value, shell)
            ensureService()
            val terminal = TerminalSession(spec.executable, root.absolutePath, spec.arguments.toTypedArray(), spec.environment.toTypedArray(), 10000, this)
            terminal.initializeEmulator(80, 24, 8, 16)
            val session = BoxSession(UUID.randomUUID().toString(), env, terminal, nextNumber++)
            sessions.value += session
            selected.value = session.id
            logInfo("BoxOS", "Opened ${env.name} · terminal ${session.number}")
        }.onFailure { error.value = it.message ?: "Could not start Linux" }
    }

    fun close(session: BoxSession) {
        session.terminal.finishIfRunning()
        sessions.value = sessions.value.filterNot { it.id == session.id }
        if (selected.value == session.id) selected.value = sessions.value.lastOrNull()?.id
    }
    fun stopAll() { sessions.value.toList().forEach(::close) }
    fun cancelOperation() { operationJob?.cancel() }

    fun task(label: String, cancellable: Boolean = true, action: suspend ((Operation) -> Unit) -> Unit) {
        if (operation.value != null) { error.value = "Another operation is already running."; return }
        operation.value = Operation(label, cancellable = cancellable)
        runCatching { ensureService() }.onFailure { operation.value = null; error.value = it.message; return }
        operationJob = scope.launch {
            try {
                action { operation.value = it }
                notice.value = "$label complete"
                logInfo("BoxOS", "$label complete")
            } catch (e: CancellationException) {
                notice.value = "$label cancelled"
            } catch (e: Exception) {
                error.value = e.message ?: "$label failed"
                logError("BoxOS", "$label: ${e.message}")
            } finally { operation.value = null; operationJob = null }
        }
    }

    fun install(image: RootImage, name: String) = task("Install ${image.title}") { report -> repository.install(image, name, report) }
    fun remove(env: Environment) {
        if (isActive(env)) { error.value = "Close this environment’s running terminals before deleting it."; return }
        task("Delete ${env.name}", false) { withContext(Dispatchers.IO) { repository.remove(env) } }
    }
    fun backup(env: Environment, uri: android.net.Uri) {
        if (isActive(env)) { error.value = "Close running terminals before backing up this environment."; return }
        task("Back up ${env.name}") { report -> withContext(Dispatchers.IO) {
            val job = currentCoroutineContext()
            report(Operation("Backing up ${env.name}", detail = "Saving files, permissions, and symbolic links"))
            try {
                app.contentResolver.openOutputStream(uri, "wt")!!.use { SafeArchive.pack(repository.root(env).parentFile!!, it) { job.ensureActive() } }
            } catch (e: Exception) {
                runCatching { android.provider.DocumentsContract.deleteDocument(app.contentResolver, uri) }
                throw e
            }
        } }
    }
    fun restore(uri: android.net.Uri) = task("Restore backup") { report -> withContext(Dispatchers.IO) {
        require(repository.base.usableSpace > 512L * 1024 * 1024) { "Free at least 512 MB before restoring" }
        val staging = File(repository.base, ".pending-${UUID.randomUUID()}").apply { mkdirs() }
        val job = currentCoroutineContext()
        try {
            report(Operation("Restoring backup", detail = "Unpacking into a new environment"))
            app.contentResolver.openInputStream(uri)!!.use { SafeArchive.extract(it, staging, { job.ensureActive() }) }
            val manifest = File(staging, "environment.json")
            require(Files.isRegularFile(manifest.toPath(), java.nio.file.LinkOption.NOFOLLOW_LINKS) && manifest.length() <= 16_384) { "Invalid backup manifest" }
            require(staging.listFiles().orEmpty().all { it.name in listOf("environment.json", "rootfs") }) { "Unexpected backup contents" }
            val old = BoxJson.decodeFromString<Environment>(manifest.readText())
            require(old.arch == repository.arch && old.distro in listOf("alpine", "debian", "ubuntu")) { "Backup is for an unsupported architecture or distribution" }
            val env = old.copy(id = UUID.randomUUID().toString(), name = "${old.name.take(30)} restored", installedAt = System.currentTimeMillis(), packageManager = detectPackageManager(File(staging, "rootfs")))
            repository.prepareRoot(File(staging, "rootfs"))
            File(staging, "environment.json").writeText(kotlinx.serialization.json.Json.encodeToString(Environment.serializer(), env))
            job.ensureActive()
            Files.move(staging.toPath(), File(repository.base, env.id).toPath(), java.nio.file.StandardCopyOption.ATOMIC_MOVE)
            repository.refreshEnvironments()
        } finally { SafeArchive.deleteTree(staging) }
    } }

    override fun onTextChanged(changedSession: TerminalSession) {
        if (!redrawPending) {
            redrawPending = true
            handler.postDelayed({ redrawPending = false; revision.value++ }, 32)
        }
    }
    override fun onTitleChanged(changedSession: TerminalSession) { revision.value++ }
    override fun onSessionFinished(finishedSession: TerminalSession) {
        revision.value++
        logInfo("Terminal", "Session exited with status ${finishedSession.exitStatus}")
    }
    override fun onCopyTextToClipboard(session: TerminalSession, text: String) { clipboard().setPrimaryClip(ClipData.newPlainText("Terminal", text)) }
    override fun onPasteTextFromClipboard(session: TerminalSession) { clipboard().primaryClip?.getItemAt(0)?.coerceToText(app)?.let { session.emulator?.paste(it.toString()) } }
    private fun clipboard() = app.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    override fun onBell(session: TerminalSession) {}
    override fun onColorsChanged(session: TerminalSession) { revision.value++ }
    override fun onTerminalCursorStateChange(state: Boolean) { revision.value++ }
    override fun getTerminalCursorStyle(): Int = 0
    override fun logError(tag: String, message: String) { log(tag, message); Log.e(tag, message) }
    override fun logWarn(tag: String, message: String) { log(tag, message); Log.w(tag, message) }
    override fun logInfo(tag: String, message: String) { log(tag, message) }
    override fun logDebug(tag: String, message: String) { Log.d(tag, message) }
    override fun logVerbose(tag: String, message: String) {}
    override fun logStackTraceWithMessage(tag: String, message: String, e: Exception) { logError(tag, "$message: ${e.message}") }
    override fun logStackTrace(tag: String, e: Exception) { logError(tag, e.toString()) }
    private fun log(tag: String, message: String) {
        handler.post { logs.value = (logs.value + "$tag · $message").takeLast(200) }
    }
}
