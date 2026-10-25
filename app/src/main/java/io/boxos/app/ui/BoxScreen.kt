package io.boxos.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.boxos.app.BoxApp
import io.boxos.app.data.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
fun BoxScreen(app: BoxApp, requestNotifications: () -> Unit) {
    val repo = app.repository
    val runtime = app.runtime
    val environments by repo.environments.collectAsStateWithLifecycle()
    val catalog by repo.catalog.collectAsStateWithLifecycle()
    val catalogError by repo.catalogError.collectAsStateWithLifecycle()
    val sessions by runtime.sessions.collectAsStateWithLifecycle()
    val operation by runtime.operation.collectAsStateWithLifecycle()
    val error by runtime.error.collectAsStateWithLifecycle()
    val notice by runtime.notice.collectAsStateWithLifecycle()
    val prefs by repo.preferences.collectAsStateWithLifecycle()
    val revision by runtime.revision.collectAsStateWithLifecycle()
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var showCatalog by rememberSaveable { mutableStateOf(false) }
    var chooseSession by remember { mutableStateOf(false) }
    var rename by remember { mutableStateOf<Environment?>(null) }
    var remove by remember { mutableStateOf<Environment?>(null) }
    var backupId by rememberSaveable { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()
    val snackbar = remember { SnackbarHostState() }
    val restoreLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri -> if (uri != null) { requestNotifications(); runtime.restore(uri) } }
    val backupLauncher = rememberLauncherForActivityResult(ActivityResultContracts.CreateDocument("application/x-xz")) { uri ->
        environments.find { it.id == backupId }?.let { if (uri != null) { requestNotifications(); runtime.backup(it, uri) } }; backupId = null
    }
    fun openEnvironment(env: Environment) { requestNotifications(); runtime.launch(env); if (runtime.error.value == null) tab = 1; chooseSession = false }
    fun savePreferences(preferences: Preferences) { scope.launch { runCatching { withContext(Dispatchers.IO) { repo.savePreferences(preferences) } }.onFailure { runtime.error.value = it.message } } }
    LaunchedEffect(notice) { notice?.let { snackbar.showSnackbar(it); runtime.notice.value = null } }
    BackHandler(showCatalog) { showCatalog = false }
    BackHandler(!showCatalog && tab != 0) { tab = 0 }
    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            if (!showCatalog) NavigationBar(containerColor = MaterialTheme.colorScheme.surface, tonalElevation = 0.dp) {
                val names = listOf("Workspace", "Terminal", "Files", "Settings")
                val icons = listOf(Icons.Rounded.Dashboard, Icons.Rounded.Terminal, Icons.Rounded.FolderOpen, Icons.Rounded.Tune)
                names.forEachIndexed { index, name ->
                    NavigationBarItem(tab == index, { tab = index }, icon = {
                        BadgedBox(badge = { if (index == 1 && sessions.isNotEmpty()) Badge { Text(sessions.size.toString()) } }) { Icon(icons[index], name) }
                    }, label = { Text(name) })
                }
            }
        }
    ) { padding ->
        // The bottom bar padding is already applied; only the IME height beyond it remains.
        Column(Modifier.fillMaxSize().padding(padding).consumeWindowInsets(padding).imePadding(), horizontalAlignment = Alignment.CenterHorizontally) {
            operation?.let { operation ->
                Surface(Modifier.fillMaxWidth(), color = MaterialTheme.colorScheme.primaryContainer) {
                    Column(Modifier.padding(horizontal = 20.dp, vertical = 10.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Column(Modifier.weight(1f)) { Text(operation.label, style = MaterialTheme.typography.labelLarge); Text(operation.detail, style = MaterialTheme.typography.bodySmall) }
                            if (operation.cancellable) TextButton(runtime::cancelOperation) { Text("Cancel") }
                        }
                        if (operation.progress == null) LinearProgressIndicator(Modifier.fillMaxWidth()) else LinearProgressIndicator(progress = { operation.progress }, modifier = Modifier.fillMaxWidth())
                    }
                }
            }
            Box(Modifier.weight(1f).widthIn(max = if (tab == 1) 1600.dp else 900.dp).fillMaxWidth()) {
                when {
                    showCatalog -> CatalogScreen(catalog, catalogError, repo.arch, operation != null, { showCatalog = false }, { scope.launch { repo.refreshCatalog() } }) { image, name ->
                        requestNotifications(); runtime.install(image, name); showCatalog = false
                    }
                    tab == 0 -> WorkspaceScreen(environments, sessions, revision, repo.base.usableSpace, operation != null,
                        repo.arch, { showCatalog = true }, ::openEnvironment,
                        { rename = it }, { remove = it }, { env ->
                            if (runtime.isActive(env)) runtime.error.value = "Close running terminals before backing up this environment."
                            else { backupId = env.id; backupLauncher.launch("boxos-${env.distro}-${env.id.take(8)}.tar.xz") }
                        }, { restoreLauncher.launch(arrayOf("*/*")) })
                    tab == 1 -> TerminalScreen(app, prefs, { chooseSession = true }, { savePreferences(prefs.copy(fontSize = it)) })
                    tab == 2 -> FilesScreen(app, environments)
                    else -> SettingsScreen(app, prefs, ::savePreferences)
                }
            }
        }
    }
    if (chooseSession) AlertDialog({ chooseSession = false }, title = { Text("Open a terminal") }, text = {
        Column {
            if (environments.isEmpty()) Text("Install a Linux environment to get started.")
            environments.forEach { env -> TextButton({ openEnvironment(env) }, Modifier.fillMaxWidth()) { DistroMark(env.distro, 32); Spacer(Modifier.width(12.dp)); Text(env.name, Modifier.weight(1f)); Icon(Icons.Rounded.ArrowForward, null) } }
        }
    }, confirmButton = { TextButton({ chooseSession = false; showCatalog = true }) { Text("Install Linux") } }, dismissButton = { TextButton({ chooseSession = false }) { Text("Cancel") } })
    rename?.let { env -> TextPrompt("Rename environment", env.name, "Name", { rename = null }) { name ->
        scope.launch { runCatching { withContext(Dispatchers.IO) { repo.rename(env, name) } }.onFailure { runtime.error.value = it.message } }
    } }
    remove?.let { env -> ConfirmDialog("Delete ${env.name}?", "This permanently removes its Linux files and installed packages. Export a backup first if you want to keep them.", "Delete environment", { remove = null }) { runtime.remove(env) } }
    error?.let { message -> AlertDialog({ runtime.error.value = null }, title = { Text("Something needs attention") }, text = { Text(message) }, confirmButton = { TextButton({ runtime.error.value = null }) { Text("OK") } }) }
}

fun copyText(context: Context, text: String) {
    (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("BoxOS", text))
}
