package io.boxos.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import io.boxos.app.data.*
import io.boxos.app.runtime.BoxSession

@Composable
fun WorkspaceScreen(environments: List<Environment>, sessions: List<BoxSession>, revision: Int, free: Long, busy: Boolean,
    arch: String, onInstall: () -> Unit, onLaunch: (Environment) -> Unit, onRename: (Environment) -> Unit,
    onDelete: (Environment) -> Unit, onBackup: (Environment) -> Unit, onRestore: () -> Unit) {
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item {
            PageTitle("Your pocket workstation", "BoxOS") {
                Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.primaryContainer) {
                    Icon(Icons.Rounded.Terminal, null, Modifier.padding(12.dp), tint = MaterialTheme.colorScheme.primary)
                }
            }
            Surface(shape = RoundedCornerShape(24.dp), color = Lime, contentColor = Ink) {
                Column(Modifier.fillMaxWidth().padding(24.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) { Box(Modifier.size(6.dp).background(Ink, RoundedCornerShape(3.dp))); Spacer(Modifier.width(7.dp)); Text("LINUX, AT HOME ON ANDROID", fontSize = 9.sp, letterSpacing = 1.5.sp, fontWeight = FontWeight.Bold) }
                    Text(if (environments.isEmpty()) "Small device.\nBig possibilities." else "Your Linux.\nYour playground.", fontSize = 34.sp, lineHeight = 37.sp, letterSpacing = (-1.4).sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(vertical = 20.dp))
                    Text(if (environments.isEmpty()) "A real Linux userspace, wherever you are.\nChoose a distro. Make it yours." else "Build, explore, and run your favorite tools.\nYour workspace is ready when you are.", fontSize = 13.sp, lineHeight = 20.sp, color = Ink.copy(alpha = .8f))
                    Button({ if (environments.isEmpty()) onInstall() else onLaunch(environments.first()) }, enabled = !busy && arch != "unsupported", modifier = Modifier.padding(top = 20.dp), colors = ButtonDefaults.buttonColors(containerColor = Ink, contentColor = Lime)) {
                        Icon(if (environments.isEmpty()) Icons.Rounded.Add else Icons.Rounded.Terminal, null, Modifier.size(17.dp)); Spacer(Modifier.width(8.dp)); Text(if (environments.isEmpty()) "Create your workspace" else "Open terminal"); Spacer(Modifier.width(12.dp)); Icon(Icons.Rounded.ArrowOutward, null, Modifier.size(16.dp))
                    }
                }
            }
        }
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Metric("ENVIRONMENTS", environments.size.toString(), Modifier.weight(1f))
                Metric("SESSIONS", sessions.count { it.terminal.isRunning }.toString(), Modifier.weight(1f))
                Metric("FREE SPACE", humanBytes(free), Modifier.weight(1f))
            }
        }
        item {
            Row(verticalAlignment = Alignment.CenterVertically) {
                SectionLabelInline("Your environments", Modifier.weight(1f))
                TextButton(onInstall, enabled = !busy) { Icon(Icons.Rounded.Add, null, Modifier.size(16.dp)); Text(" Add new") }
            }
        }
        if (environments.isEmpty()) item {
            Surface(shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surface) {
                EmptyState(Icons.Rounded.Layers, "A fresh start", "Debian, Ubuntu, or Alpine.\nNo root access required.")
            }
        }
        items(environments, key = { it.id }) { env ->
            var menu by remember { mutableStateOf(false) }
            val running = sessions.count { it.environment.id == env.id && it.terminal.isRunning }
            Surface(shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surface) {
                Column(Modifier.padding(16.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        DistroMark(env.distro)
                        Column(Modifier.weight(1f).padding(horizontal = 12.dp)) { Text(env.name, fontWeight = FontWeight.SemiBold, fontSize = 17.sp); Text("${env.title} ${env.version} · ${env.arch}", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
                        Box {
                            IconButton({ menu = true }, enabled = !busy) { Icon(Icons.Rounded.MoreHoriz, "Manage ${env.name}") }
                            DropdownMenu(menu, { menu = false }) {
                                DropdownMenuItem({ Text("Rename") }, { menu = false; onRename(env) }, leadingIcon = { Icon(Icons.Rounded.Edit, null) })
                                DropdownMenuItem({ Text("Export backup") }, { menu = false; onBackup(env) }, leadingIcon = { Icon(Icons.Rounded.Archive, null) }, enabled = running == 0)
                                DropdownMenuItem({ Text("Delete environment") }, { menu = false; onDelete(env) }, leadingIcon = { Icon(Icons.Rounded.DeleteOutline, null) }, enabled = running == 0)
                            }
                        }
                    }
                    Spacer(Modifier.height(14.dp))
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Pill(if (running > 0) "$running running" else if (env.packageManager == "dpkg") "Ready · dpkg only" else "Ready", if (running > 0) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                        Spacer(Modifier.weight(1f))
                        FilledTonalButton({ onLaunch(env) }, enabled = !busy, contentPadding = PaddingValues(horizontal = 14.dp, vertical = 8.dp)) { Icon(Icons.Rounded.Terminal, null, Modifier.size(16.dp)); Text(" Launch", fontSize = 12.sp) }
                    }
                    if (env.packageManager == "dpkg") Text("This environment was installed from an image without apt. Install a new environment to get apt, or import .deb packages in Files.", fontSize = 11.sp, lineHeight = 17.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 10.dp))
                }
            }
        }
        item {
            TextButton(onRestore, enabled = !busy, modifier = Modifier.fillMaxWidth()) { Icon(Icons.Rounded.SettingsBackupRestore, null, Modifier.size(18.dp)); Text(" Restore a BoxOS backup") }
            Row(Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 12.dp), horizontalArrangement = Arrangement.Center, verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Rounded.Memory, null, Modifier.size(13.dp), tint = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("  BOXKERNEL  /  BOXROOTFS  /  $arch", fontSize = 9.sp, letterSpacing = 1.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
@Composable
private fun Metric(title: String, value: String, modifier: Modifier) {
    Surface(modifier, shape = RoundedCornerShape(16.dp), color = MaterialTheme.colorScheme.surface) {
        Column(Modifier.padding(14.dp)) { Text(value, fontSize = 20.sp, fontWeight = FontWeight.Medium); Spacer(Modifier.height(6.dp)); Text(title, fontSize = 8.sp, letterSpacing = .7.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    }
}
@Composable
private fun SectionLabelInline(text: String, modifier: Modifier) { Text(text, modifier, fontSize = 18.sp, fontWeight = FontWeight.SemiBold) }

@Composable
fun CatalogScreen(catalog: Catalog?, error: String?, arch: String, busy: Boolean, onBack: () -> Unit, refresh: () -> Unit, install: (RootImage, String) -> Unit) {
    var selected by remember { mutableStateOf<RootImage?>(null) }
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        item {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) { IconButton(onBack) { Icon(Icons.Rounded.ArrowBack, "Back") }; IconButton(refresh) { Icon(Icons.Rounded.Refresh, "Refresh catalog") } }
            PageTitle("Build your workspace", "Pick your Linux.")
            Text("Three distributions. One pocket.\nOfficial BoxRootfs images, verified before install.", color = MaterialTheme.colorScheme.onSurfaceVariant, lineHeight = 23.sp)
            Spacer(Modifier.height(14.dp)); Pill("NATIVE ${arch.uppercase()}")
        }
        if (error != null) item { Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.errorContainer) { Column(Modifier.padding(16.dp)) { Text(error, color = MaterialTheme.colorScheme.onErrorContainer); if (catalog != null) Text("Showing the last saved catalog.", style = MaterialTheme.typography.bodySmall); TextButton(refresh) { Text("Try again") } } } }
        if (catalog == null && error == null) item { Box(Modifier.fillMaxWidth().padding(40.dp), contentAlignment = Alignment.Center) { CircularProgressIndicator() } }
        val images = catalog?.images.orEmpty().filter { it.arch == arch }.sortedBy { listOf("debian", "ubuntu", "alpine").indexOf(it.distro) }
        if (catalog != null && images.isEmpty()) item { EmptyState(Icons.Rounded.Memory, "Architecture unavailable", "BoxOS supports ARM64 and x86-64 Android devices.") }
        items(images) { image ->
            Surface(shape = RoundedCornerShape(22.dp), color = MaterialTheme.colorScheme.surface) {
                Column(Modifier.padding(20.dp)) {
                    Row(verticalAlignment = Alignment.CenterVertically) { DistroMark(image.distro, 48); Spacer(Modifier.width(14.dp)); Column(Modifier.weight(1f)) { Text(image.title, fontSize = 23.sp, fontWeight = FontWeight.SemiBold); Text("${image.version} · ${image.codename}", fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }; if (image.distro == "debian") Pill("POPULAR") }
                    Text(when(image.distro) { "debian" -> "A dependable base for development. A huge package library and a familiar place to build."; "ubuntu" -> "A familiar developer favorite. Long-term support, great tooling, and the apt ecosystem."; else -> "Small, simple, and fast. A minimal workspace with musl, BusyBox, and the apk package manager." }, Modifier.padding(vertical = 18.dp), fontSize = 13.sp, lineHeight = 21.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    Row(verticalAlignment = Alignment.CenterVertically) { Icon(Icons.Rounded.VerifiedUser, null, Modifier.size(14.dp), tint = MaterialTheme.colorScheme.primary); Text(" SHA-256 verified  ·  ${humanBytes(image.size)}", fontSize = 11.sp, modifier = Modifier.weight(1f)); FilledTonalButton({ selected = image }, enabled = !busy) { Text("Install"); Spacer(Modifier.width(6.dp)); Icon(Icons.Rounded.ArrowDownward, null, Modifier.size(16.dp)) } }
                }
            }
        }
        item { Text("These images provide a Linux command line. Add packages with apt or apk. Desktop environments require additional setup.\n\nCatalog release: ${catalog?.release ?: "—"}", fontSize = 11.sp, lineHeight = 18.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(vertical = 10.dp)) }
    }
    selected?.let { image ->
        var name by remember(image) { mutableStateOf(image.title) }
        AlertDialog({ selected = null }, icon = { DistroMark(image.distro) }, title = { Text("Install ${image.title}") }, text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Download ${humanBytes(image.size)}. Allow additional storage for unpacking and your packages.")
                OutlinedTextField(name, { name = it.take(40) }, singleLine = true, label = { Text("Workspace name") })
                Text("Linux root inside the environment does not grant Android root access. Guest programs have access to BoxOS app data.", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }, confirmButton = { TextButton({ install(image, name); selected = null }, enabled = name.isNotBlank()) { Text("Download & install") } }, dismissButton = { TextButton({ selected = null }) { Text("Cancel") } })
    }
}
