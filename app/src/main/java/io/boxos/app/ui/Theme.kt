package io.boxos.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

val Lime = Color(0xFFB6F36B)
val Ink = Color(0xFF19230F)
private val Dark = darkColorScheme(
    primary = Lime, onPrimary = Ink, primaryContainer = Color(0xFF2A3820), onPrimaryContainer = Lime,
    background = Color(0xFF10130F), onBackground = Color(0xFFE8EDE3),
    surface = Color(0xFF171C15), onSurface = Color(0xFFE8EDE3),
    surfaceVariant = Color(0xFF242C20), onSurfaceVariant = Color(0xFFA9B3A2),
    outline = Color(0xFF444E3D), outlineVariant = Color(0xFF2B3426)
)
private val Light = lightColorScheme(
    primary = Color(0xFF40691F), onPrimary = Color.White, primaryContainer = Color(0xFFD5F6B4), onPrimaryContainer = Ink,
    background = Color(0xFFF5F7F0), onBackground = Ink,
    surface = Color(0xFFFFFFFF), onSurface = Ink,
    surfaceVariant = Color(0xFFE9EEDF), onSurfaceVariant = Color(0xFF5F6B57),
    outlineVariant = Color(0xFFDBE2D2)
)
@Composable
fun BoxTheme(theme: String = "system", content: @Composable () -> Unit) {
    val dark = theme == "dark" || (theme == "system" && isSystemInDarkTheme())
    MaterialTheme(colorScheme = if (dark) Dark else Light) {
        Surface(color = MaterialTheme.colorScheme.background, content = content)
    }
}
