package io.boxos.app.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

@Composable
fun PageTitle(eyebrow: String, title: String, trailing: @Composable () -> Unit = {}) {
    Row(Modifier.fillMaxWidth().padding(top = 8.dp, bottom = 20.dp), verticalAlignment = Alignment.CenterVertically) {
        Column(Modifier.weight(1f)) {
            Text(eyebrow.uppercase(), fontSize = 10.sp, letterSpacing = 2.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(6.dp))
            Text(title, fontSize = 32.sp, letterSpacing = (-1).sp, fontWeight = FontWeight.SemiBold)
        }
        trailing()
    }
}
@Composable
fun Pill(text: String, color: Color = MaterialTheme.colorScheme.primary) {
    Text(text, Modifier.background(color.copy(alpha = .12f), RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 4.dp), color = color, fontSize = 10.sp, fontWeight = FontWeight.Medium)
}
@Composable
fun DistroMark(distro: String, size: Int = 44) {
    val color = when (distro) { "debian" -> Color(0xFFD87596); "ubuntu" -> Color(0xFFF6A277); else -> Color(0xFF8FC9DE) }
    Box(Modifier.size(size.dp).background(color.copy(alpha = .14f), RoundedCornerShape(14.dp)), contentAlignment = Alignment.Center) {
        Icon(when (distro) { "debian" -> Icons.Rounded.Adjust; "ubuntu" -> Icons.Rounded.BlurCircular; else -> Icons.Rounded.Landscape }, null, tint = color, modifier = Modifier.size((size * .6f).dp))
    }
}
@Composable
fun SectionLabel(label: String, detail: String = "") {
    Row(Modifier.fillMaxWidth().padding(top = 12.dp, bottom = 12.dp), verticalAlignment = Alignment.CenterVertically) {
        Text(label, fontWeight = FontWeight.SemiBold, fontSize = 17.sp, modifier = Modifier.weight(1f))
        Text(detail, fontSize = 12.sp, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}
@Composable
fun EmptyState(icon: ImageVector, title: String, text: String, action: String? = null, onAction: () -> Unit = {}) {
    Column(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 32.dp), horizontalAlignment = Alignment.CenterHorizontally) {
        Box(Modifier.size(64.dp).background(MaterialTheme.colorScheme.primaryContainer, RoundedCornerShape(20.dp)), contentAlignment = Alignment.Center) {
            Icon(icon, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(28.dp))
        }
        Spacer(Modifier.height(16.dp))
        Text(title, fontSize = 20.sp, fontWeight = FontWeight.SemiBold)
        Text(text, Modifier.padding(top = 8.dp), color = MaterialTheme.colorScheme.onSurfaceVariant, textAlign = androidx.compose.ui.text.style.TextAlign.Center)
        if (action != null) Button(onAction, Modifier.padding(top = 20.dp)) { Text(action) }
    }
}
@Composable
fun TextPrompt(title: String, initial: String = "", label: String, onDismiss: () -> Unit, onSave: (String) -> Unit) {
    var value by androidx.compose.runtime.remember { androidx.compose.runtime.mutableStateOf(initial) }
    AlertDialog(onDismiss, title = { Text(title) }, text = {
        OutlinedTextField(value, { value = it.take(80) }, label = { Text(label) }, singleLine = true)
    }, confirmButton = { TextButton({ onSave(value); onDismiss() }, enabled = value.isNotBlank()) { Text("Save") } }, dismissButton = { TextButton(onDismiss) { Text("Cancel") } })
}
@Composable
fun ConfirmDialog(title: String, text: String, confirm: String, onDismiss: () -> Unit, onConfirm: () -> Unit) {
    AlertDialog(onDismiss, title = { Text(title) }, text = { Text(text) },
        confirmButton = { TextButton({ onConfirm(); onDismiss() }) { Text(confirm) } },
        dismissButton = { TextButton(onDismiss) { Text("Cancel") } })
}
@Composable
fun CodeBlock(text: String, onCopy: () -> Unit) {
    Surface(shape = RoundedCornerShape(12.dp), color = MaterialTheme.colorScheme.surfaceVariant) {
        Row(Modifier.fillMaxWidth().padding(start = 14.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(text, Modifier.weight(1f).padding(vertical = 14.dp), fontFamily = FontFamily.Monospace, fontSize = 12.sp)
            IconButton(onCopy) { Icon(Icons.Rounded.ContentCopy, "Copy command", modifier = Modifier.size(18.dp)) }
        }
    }
}
