package io.boxos.app.ui

import android.content.Intent
import android.net.Uri
import android.os.Build
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.boxos.app.BoxApp
import io.boxos.app.BuildConfig
import io.boxos.app.data.Preferences

@Composable
fun SettingsScreen(app: BoxApp, prefs: Preferences, save: (Preferences) -> Unit) {
    var dns by remember { mutableStateOf(false) }
    var guide by remember { mutableStateOf(false) }
    var diagnostics by remember { mutableStateOf(false) }
    var font by remember(prefs.fontSize) { mutableFloatStateOf(prefs.fontSize.toFloat()) }
    val logs by app.runtime.logs.collectAsStateWithLifecycle()
    val environments by app.repository.environments.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val diagnosticText = "BoxOS ${BuildConfig.VERSION_NAME}\nAndroid ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})\nABI ${Build.SUPPORTED_ABIS.joinToString()}\nBoxKernel 5.1.0\nEnvironments: ${environments.size}\nSeccomp: ${prefs.seccomp}\n\n${logs.joinToString("\n")}"
    LazyColumn(Modifier.fillMaxSize(), contentPadding = PaddingValues(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        item { PageTitle("Make yourself at home", "Settings") }
        item {
            SectionLabel("Appearance")
            SettingsCard {
                Text("Color theme", fontWeight = FontWeight.Medium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) { listOf("system", "light", "dark").forEach { theme -> FilterChip(prefs.theme == theme, { save(prefs.copy(theme = theme)) }, label = { Text(theme.replaceFirstChar { it.uppercase() }) }) } }
                Spacer(Modifier.height(16.dp))
                Row { Text("Terminal text", Modifier.weight(1f), fontWeight = FontWeight.Medium); Text("${font.toInt()} sp", color = MaterialTheme.colorScheme.primary) }
                Slider(font, { font = it }, valueRange = 10f..24f, steps = 13, onValueChangeFinished = { save(prefs.copy(fontSize = font.toInt())) })
                Text("Aa  ~/workspace $", fontFamily = FontFamily.Monospace, fontSize = font.toInt().sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        item {
            SectionLabel("Runtime")
            SettingsCard {
                ToggleRow("Keep CPU awake", "Allow background work while the screen is off. Uses more battery; limited to six hours per service run.", prefs.keepAwake) { save(prefs.copy(keepAwake = it)) }
                HorizontalDivider(Modifier.padding(vertical = 12.dp), color = MaterialTheme.colorScheme.outlineVariant)
                ToggleRow("Shared workspace", "Expose BoxOS shared storage at /mnt/shared in new sessions.", prefs.sharedFolder) { save(prefs.copy(sharedFolder = it)) }
                HorizontalDivider(Modifier.padding(vertical = 12.dp), color = MaterialTheme.colorScheme.outlineVariant)
                ToggleRow("Seccomp acceleration", "Reduce tracing overhead. Leave off if your Android kernel blocks seccomp filters. Applies to new sessions.", prefs.seccomp) { save(prefs.copy(seccomp = it)) }
                HorizontalDivider(Modifier.padding(vertical = 12.dp), color = MaterialTheme.colorScheme.outlineVariant)
                Row(verticalAlignment = Alignment.CenterVertically) { Column(Modifier.weight(1f)) { Text("DNS resolvers", fontWeight = FontWeight.Medium); Text(prefs.dns, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant) }; TextButton({ dns = true }) { Text("Edit") } }
                Text("DNS changes apply when you next launch a terminal.", fontSize = 11.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
        item {
            SectionLabel("Resources")
            SettingsCard {
                TextButton({ guide = true }, Modifier.fillMaxWidth()) { Icon(Icons.Rounded.AutoStories, null); Text(" Getting started", Modifier.weight(1f)); Icon(Icons.Rounded.ChevronRight, null) }
                TextButton({ diagnostics = true }, Modifier.fillMaxWidth()) { Icon(Icons.Rounded.MonitorHeart, null); Text(" Runtime diagnostics", Modifier.weight(1f)); Icon(Icons.Rounded.ChevronRight, null) }
                TextButton({ context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/BoxOSLab/BoxKernel"))) }, Modifier.fillMaxWidth()) { Icon(Icons.Rounded.Code, null); Text(" BoxKernel source", Modifier.weight(1f)); Icon(Icons.Rounded.OpenInNew, null, Modifier.size(16.dp)) }
                TextButton({ context.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/BoxOSLab/BoxRootfs"))) }, Modifier.fillMaxWidth()) { Icon(Icons.Rounded.Layers, null); Text(" BoxRootfs images", Modifier.weight(1f)); Icon(Icons.Rounded.OpenInNew, null, Modifier.size(16.dp)) }
            }
        }
        item {
            SettingsCard {
                Row(verticalAlignment = Alignment.CenterVertically) { Icon(Icons.Rounded.Terminal, null, tint = MaterialTheme.colorScheme.primary); Spacer(Modifier.width(12.dp)); Text("BoxOS", style = MaterialTheme.typography.titleLarge); Spacer(Modifier.weight(1f)); Pill("v${BuildConfig.VERSION_NAME}") }
                Text("A small home for big ideas.", Modifier.padding(top = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant, fontSize = 13.sp)
                Text("Built on BoxKernel and BoxRootfs. Terminal emulator and view by Termux contributors (GPL-3.0, with Apache-2.0 portions). BoxOS source is GPL-3.0; Linux packages retain their own licenses.", Modifier.padding(top = 12.dp), fontSize = 11.sp, lineHeight = 17.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text("BoxKernel virtualizes a Linux userspace; it shares Android’s kernel. Root, systemd, kernel modules, and hardware virtualization aren’t provided. Environments are not a security boundary.", Modifier.padding(top = 12.dp), fontSize = 11.sp, lineHeight = 17.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
    if (dns) TextPrompt("DNS resolvers", prefs.dns, "IPv4 addresses, comma separated", { dns = false }) { save(prefs.copy(dns = it)) }
    if (diagnostics) AlertDialog({ diagnostics = false }, title = { Text("Runtime diagnostics") }, text = {
        androidx.compose.foundation.text.selection.SelectionContainer { Text(diagnosticText.takeLast(12000), fontFamily = FontFamily.Monospace, fontSize = 10.sp, modifier = Modifier.heightIn(max = 400.dp).verticalScroll(rememberScrollState())) }
    }, confirmButton = { TextButton({ copyText(context, diagnosticText) }) { Text("Copy report") } }, dismissButton = { TextButton({ diagnostics = false }) { Text("Done") } })
    if (guide) AlertDialog({ guide = false }, title = { Text("Make it yours") }, text = {
        LazyColumn(verticalArrangement = Arrangement.spacedBy(14.dp)) {
            item { Text("1  Install a distribution", fontWeight = FontWeight.SemiBold); Text("Choose Debian or Ubuntu for apt, or Alpine for a compact base. Each workspace has its own packages and files.", fontSize = 13.sp) }
            item { Text("2  Update your packages", fontWeight = FontWeight.SemiBold); CodeBlock("apt update && apt upgrade", { copyText(context, "apt update && apt upgrade") }); Spacer(Modifier.height(6.dp)); CodeBlock("apk update && apk upgrade", { copyText(context, "apk update && apk upgrade") }); Text("Check your environment’s package tool in Workspace. Some minimal Ubuntu images provide dpkg without apt. Import compatible .deb packages with their dependencies and install them using dpkg, or use Debian for apt.", fontSize = 12.sp, modifier = Modifier.padding(top = 10.dp)) }
            item { Text("3  Build something", fontWeight = FontWeight.SemiBold); CodeBlock("apt install git curl python3 nano", { copyText(context, "apt install git curl python3 nano") }); Spacer(Modifier.height(6.dp)); CodeBlock("apk add git curl python3 nano", { copyText(context, "apk add git curl python3 nano") }) }
            item { Text("4  Bring your files", fontWeight = FontWeight.SemiBold); Text("Use Files to import, edit, or export. Use the terminal for symlinks and advanced operations. Export a backup from the workspace menu after closing its terminals.", fontSize = 13.sp) }
            item { Text("Keep working", fontWeight = FontWeight.SemiBold); Text("Sessions stay active in a foreground service when you switch apps. Android may still end background processes. Use Stop all in the notification to shut them down. An exited terminal keeps its scrollback until closed.", fontSize = 13.sp) }
        }
    }, confirmButton = { TextButton({ guide = false }) { Text("Got it") } })
}
@Composable
private fun SettingsCard(content: @Composable ColumnScope.() -> Unit) {
    Surface(shape = RoundedCornerShape(18.dp), color = MaterialTheme.colorScheme.surface) { Column(Modifier.fillMaxWidth().padding(18.dp), content = content) }
}
@Composable
private fun ToggleRow(title: String, subtitle: String, value: Boolean, change: (Boolean) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f).padding(end = 14.dp)) { Text(title, fontWeight = FontWeight.Medium); Text(subtitle, fontSize = 12.sp, lineHeight = 18.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.padding(top = 4.dp)) }
        Switch(value, change)
    }
}
