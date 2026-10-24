package io.boxos.app.ui

import android.provider.OpenableColumns
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.boxos.app.BoxApp
import io.boxos.app.data.*
import kotlinx.coroutines.*
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption

private data class FileItem(val name: String, val directory: Boolean, val link: Boolean, val size: Long)
@Composable
fun FilesScreen(app: BoxApp, environments: List<Environment>) {
    var selected by rememberSaveable { mutableStateOf<String?>(null) }
    var path by rememberSaveable { mutableStateOf("root") }
    var refresh by remember { mutableIntStateOf(0) }
    var entries by remember { mutableStateOf<List<FileItem>>(emptyList()) }
    var loading by remember { mutableStateOf(false) }
    var loadError by remember { mutableStateOf<String?>(null) }
    var selectedFile by remember { mutableStateOf<FileItem?>(null) }
    var exporting by rememberSaveable { mutableStateOf<String?>(null) }
    var deleting by remember { mutableStateOf<FileItem?>(null) }
    var mkdir by remember { mutableStateOf(false) }
    var newFile by remember { mutableStateOf(false) }
    var editing by remember { mutableStateOf<File?>(null) }
    var editText by remember { mutableStateOf("") }
    var editName by remember { mutableStateOf("") }
    var search by rememberSaveable { mutableStateOf("") }
    val runtime = app.runtime
    val busy by runtime.operation.collectAsStateWithLifecycle()
    val env = environments.find { it.id == selected } ?: environments.firstOrNull()
    val scope = rememberCoroutineScope()
    fun fail(e: Throwable) { runtime.error.value = e.message ?: "File operation failed" }
    fun currentDirectory(): File = safeGuestPath(app.repository.root(env ?: error("Choose an environment")), path)
    fun safeFile(name: String): File = safeGuestPath(app.repository.root(env ?: error("Choose an environment")), if (path.isBlank()) name else "$path/$name")
    fun validName(name: String) { require(name.isNotBlank() && name != "." && name != ".." && !name.contains('/') && !name.contains('\\') && name.length <= 128) { "Choose a filename without slashes" } }
    val importFile = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        if (uri != null && env != null) {
            val directory = runCatching { currentDirectory() }.getOrElse { fail(it); return@rememberLauncherForActivityResult }
            runtime.task("Import file") { withContext(Dispatchers.IO) {
                val job = currentCoroutineContext()
                val name = app.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor -> if (cursor.moveToFirst()) cursor.getString(0) else null } ?: "imported-file"
                validName(name)
                var target = safeGuestPath(app.repository.root(env), "$path/$name")
                if (Files.exists(target.toPath(), LinkOption.NOFOLLOW_LINKS)) target = safeGuestPath(app.repository.root(env), "$path/${System.currentTimeMillis()}-$name")
                val temporary = File(directory, ".boxos-import-${java.util.UUID.randomUUID()}")
                try {
                    app.contentResolver.openInputStream(uri)!!.use { input -> temporary.outputStream().use { output ->
                        val buffer = ByteArray(64 * 1024); var total = 0L
                        while (true) { job.ensureActive(); val n = input.read(buffer); if (n < 0) break; total += n; require(total <= 2L * 1024 * 1024 * 1024) { "Import limit is 2 GB" }; output.write(buffer, 0, n) }
                    } }
                    Files.move(temporary.toPath(), target.toPath(), java.nio.file.StandardCopyOption.ATOMIC_MOVE)
                } finally { temporary.delete() }
                refresh++
            } }
        }
    }
    val exportFile = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/octet-stream")) { uri ->
        val source = exporting?.let(::File)
        if (uri != null && source != null) runtime.task("Export file") { withContext(Dispatchers.IO) {
            require(!Files.isSymbolicLink(source.toPath())) { "Symbolic links cannot be exported as files" }
            val job = currentCoroutineContext()
            try { app.contentResolver.openOutputStream(uri, "wt")!!.use { output -> source.inputStream().use { input ->
                val buffer = ByteArray(64 * 1024)
                while (true) { job.ensureActive(); val n = input.read(buffer); if (n < 0) break; output.write(buffer, 0, n) }
            } } } catch (e: Exception) { runCatching { android.provider.DocumentsContract.deleteDocument(app.contentResolver, uri) }; throw e }
        } }
        exporting = null
    }
    LaunchedEffect(env?.id, path, refresh) {
        if (env == null) return@LaunchedEffect
        loading = true
        loadError = null
        try {
            entries = withContext(Dispatchers.IO) {
                currentDirectory().listFiles()?.map { file ->
                    val link = Files.isSymbolicLink(file.toPath())
                    FileItem(file.name, !link && file.isDirectory, link, if (link) 0 else file.length())
                }?.sortedWith(compareByDescending<FileItem> { it.directory }.thenBy { it.name.lowercase() }) ?: error("Could not open this directory")
            }
        } catch (e: Exception) { loadError = e.message; entries = emptyList() }
        loading = false
    }
    Column(Modifier.fillMaxSize().padding(horizontal = 20.dp)) {
        PageTitle("Inside your workspace", "Files") { IconButton({ refresh++ }) { Icon(Icons.Rounded.Refresh, "Refresh files") } }
        if (env == null) { EmptyState(Icons.Rounded.FolderOpen, "No files yet", "Install an environment to browse, edit, and exchange files."); return@Column }
        Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            environments.forEach { candidate -> FilterChip(env.id == candidate.id, { selected = candidate.id; path = "root"; search = "" }, label = { Text(candidate.name) }) }
        }
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            IconButton({ path = path.substringBeforeLast('/', ""); search = "" }, enabled = path.isNotEmpty()) { Icon(Icons.Rounded.ArrowUpward, "Parent directory") }
            Text("/$path", fontSize = 12.sp, fontFamily = FontFamily.Monospace, modifier = Modifier.weight(1f))
            IconButton({ path = ""; search = "" }) { Icon(Icons.Rounded.Home, "Root directory") }
            IconButton({ mkdir = true }, enabled = busy == null) { Icon(Icons.Rounded.CreateNewFolder, "Create folder") }
            IconButton({ newFile = true }, enabled = busy == null) { Icon(Icons.Rounded.NoteAdd, "Create text file") }
            IconButton({ importFile.launch(arrayOf("*/*")) }, enabled = busy == null) { Icon(Icons.Rounded.FileDownload, "Import from Android") }
        }
        OutlinedTextField(search, { search = it }, Modifier.fillMaxWidth().padding(bottom = 12.dp), placeholder = { Text("Filter files…") }, leadingIcon = { Icon(Icons.Rounded.Search, null) }, singleLine = true, shape = RoundedCornerShape(14.dp))
        if (loading) LinearProgressIndicator(Modifier.fillMaxWidth())
        if (loadError != null) Text(loadError!!, color = MaterialTheme.colorScheme.error, modifier = Modifier.padding(16.dp))
        LazyColumn(Modifier.weight(1f)) {
            val filtered = entries.filter { it.name.contains(search, true) }
            if (filtered.isEmpty() && !loading && loadError == null) item { EmptyState(Icons.Rounded.FolderOpen, "Nothing here", if (search.isEmpty()) "Import a file or create something new." else "No files match your filter.") }
            items(filtered, key = { it.name }) { item ->
                ListItem(
                    headlineContent = { Text(item.name, fontSize = 14.sp) },
                    supportingContent = { Text(if (item.link) "Symbolic link" else if (item.directory) "Folder" else humanBytes(item.size), fontSize = 11.sp) },
                    leadingContent = { Icon(if (item.link) Icons.Rounded.Link else if (item.directory) Icons.Rounded.Folder else Icons.Rounded.Description, null, tint = if (item.directory) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant) },
                    trailingContent = { IconButton({ selectedFile = item }, enabled = busy == null) { Icon(Icons.Rounded.MoreHoriz, "Actions for ${item.name}") } },
                    modifier = Modifier.clickable(enabled = busy == null) {
                        if (item.directory) { path = if (path.isBlank()) item.name else "$path/${item.name}"; search = "" } else selectedFile = item
                    }, colors = ListItemDefaults.colors(containerColor = MaterialTheme.colorScheme.background)
                )
                HorizontalDivider(color = MaterialTheme.colorScheme.outlineVariant)
            }
        }
        Text("Import and export use Android’s file picker. /mnt/shared is also available inside Linux when enabled.", fontSize = 10.sp, lineHeight = 15.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 12.dp))
    }
    selectedFile?.let { item -> AlertDialog({ selectedFile = null }, title = { Text(item.name) }, text = {
        Column {
            if (item.link) Text("Symbolic links are shown but aren’t followed by the file browser. Manage guest links in the terminal.")
            if (!item.directory && !item.link) {
                TextButton({ selectedFile = null; scope.launch {
                    runCatching { withContext(Dispatchers.IO) {
                        require(item.size <= 256 * 1024) { "The text editor opens files up to 256 KB" }
                        val file = safeFile(item.name)
                        require(!Files.isSymbolicLink(file.toPath()))
                        val bytes = file.inputStream().use { it.readBytesLimited(256 * 1024) }
                        require(!bytes.contains(0)) { "This looks like a binary file" }
                        editText = bytes.toString(Charsets.UTF_8); editName = item.name; editing = file
                    } }.onFailure(::fail)
                } }) { Text("Edit text") }
                TextButton({ selectedFile = null; exporting = safeFile(item.name).absolutePath; exportFile.launch(item.name) }) { Text("Export to Android") }
            }
            TextButton({ selectedFile = null; deleting = item }) { Text("Delete", color = MaterialTheme.colorScheme.error) }
        }
    }, confirmButton = { TextButton({ selectedFile = null }) { Text("Done") } }) }
    deleting?.let { item -> ConfirmDialog("Delete ${item.name}?", "This permanently removes the ${if (item.directory) "folder and its contents" else "file"} from this environment.", "Delete", { deleting = null }) {
        runtime.task("Delete file", false) { withContext(Dispatchers.IO) { SafeArchive.deleteTree(safeFile(item.name)); refresh++ } }
    } }
    if (mkdir || newFile) TextPrompt(if (mkdir) "New folder" else "New text file", label = "Name", onDismiss = { mkdir = false; newFile = false }) { name ->
        val folder = mkdir
        scope.launch { runCatching { withContext(Dispatchers.IO) { validName(name); val file = safeFile(name); if (folder) Files.createDirectory(file.toPath()) else Files.createFile(file.toPath()); refresh++ } }.onFailure(::fail) }
    }
    editing?.let { file -> AlertDialog({ editing = null }, title = { Text(editName) }, text = {
        OutlinedTextField(editText, { editText = it }, Modifier.fillMaxWidth().heightIn(min = 200.dp, max = 420.dp), textStyle = LocalTextStyle.current.copy(fontFamily = FontFamily.Monospace, fontSize = 12.sp))
    }, confirmButton = { TextButton({
        val text = editText
        runtime.task("Save file", false) { withContext(Dispatchers.IO) { require(!Files.isSymbolicLink(file.toPath())); atomicWrite(file, text); refresh++ } }
        editing = null
    }) { Text("Save") } }, dismissButton = { TextButton({ editing = null }) { Text("Cancel") } }) }
}
