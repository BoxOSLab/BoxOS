package io.boxos.app.ui

import android.content.Context
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.inputmethod.InputMethodManager
import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.termux.terminal.TerminalSession
import com.termux.view.TerminalView
import com.termux.view.TerminalViewClient
import io.boxos.app.BoxApp
import io.boxos.app.data.Preferences
import io.boxos.app.runtime.RuntimeManager
import io.boxos.app.runtime.BoxSession

@Composable
fun TerminalScreen(app: BoxApp, preferences: Preferences, onNew: () -> Unit, fontSize: (Int) -> Unit) {
    val runtime = app.runtime
    val sessions by runtime.sessions.collectAsStateWithLifecycle()
    val selected by runtime.selected.collectAsStateWithLifecycle()
    val revision by runtime.revision.collectAsStateWithLifecycle()
    val current = sessions.find { it.id == selected } ?: sessions.lastOrNull()
    var closing by remember { mutableStateOf<BoxSession?>(null) }
    val context = LocalContext.current
    var view by remember { mutableStateOf<TerminalView?>(null) }
    var ctrl by remember { mutableStateOf(false) }
    var alt by remember { mutableStateOf(false) }
    val keys = remember { TerminalKeys() }
    keys.ctrl = ctrl; keys.alt = alt
    val sizeCallback by rememberUpdatedState(fontSize)
    val currentFont by rememberUpdatedState(preferences.fontSize)
    Column(Modifier.fillMaxSize()) {
        Row(Modifier.fillMaxWidth().padding(start = 20.dp, end = 8.dp, top = 8.dp), verticalAlignment = Alignment.CenterVertically) {
            Text("Terminal", style = MaterialTheme.typography.titleLarge, modifier = Modifier.weight(1f))
            IconButton({ view?.let { (context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).showSoftInput(it, InputMethodManager.SHOW_IMPLICIT) } }, enabled = current != null) { Icon(Icons.Rounded.Keyboard, "Show keyboard") }
            IconButton({ current?.terminal?.emulator?.screen?.transcriptText?.let { copyText(context, it) } }, enabled = current != null) { Icon(Icons.Rounded.ContentCopy, "Copy terminal transcript") }
            IconButton(onNew) { Icon(Icons.Rounded.Add, "New terminal") }
        }
        if (current == null) {
            EmptyState(Icons.Rounded.Terminal, "A shell of your own", "Open a Linux environment and start creating.", "Open terminal", onNew)
        } else {
            Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                sessions.forEach { session ->
                    InputChip(selected == session.id, { runtime.selected.value = session.id }, label = { Text("${session.environment.name} : ${session.number}", fontSize = 12.sp) }, trailingIcon = {
                        IconButton({ closing = session }, Modifier.size(28.dp)) { Icon(Icons.Rounded.Close, "Close terminal ${session.number}", Modifier.size(14.dp)) }
                    })
                }
            }
            Row(Modifier.fillMaxWidth().padding(horizontal = 20.dp, vertical = 10.dp), verticalAlignment = Alignment.CenterVertically) {
                val running = remember(revision, current) { current.terminal.isRunning }
                Pill(if (running) "LIVE" else "EXITED ${current.terminal.exitStatus}")
                Text("  ${current.environment.title} ${current.environment.version}  /  root", fontSize = 10.sp, color = MaterialTheme.colorScheme.onSurfaceVariant, modifier = Modifier.weight(1f))
                IconButton({ sizeCallback((currentFont - 1).coerceAtLeast(10)) }, Modifier.size(32.dp)) { Icon(Icons.Rounded.TextDecrease, "Smaller terminal text", Modifier.size(18.dp)) }
                IconButton({ sizeCallback((currentFont + 1).coerceAtMost(24)) }, Modifier.size(32.dp)) { Icon(Icons.Rounded.TextIncrease, "Larger terminal text", Modifier.size(18.dp)) }
            }
            key(current.id) {
                val client = remember {
                    BoxTerminalClient(runtime, keys, { ctrl = false; alt = false }, {
                        view?.let { (context.getSystemService(Context.INPUT_METHOD_SERVICE) as InputMethodManager).showSoftInput(it, InputMethodManager.SHOW_IMPLICIT) }
                    }, { scale ->
                        if (scale > 1.15f) { sizeCallback((currentFont + 1).coerceAtMost(24)); 1f }
                        else if (scale < .85f) { sizeCallback((currentFont - 1).coerceAtLeast(10)); 1f } else scale
                    })
                }
                AndroidView(
                    factory = { ctx -> TerminalView(ctx, null).apply {
                        setTerminalViewClient(client)
                        setTextSize((preferences.fontSize * resources.displayMetrics.scaledDensity).toInt())
                        tag = preferences.fontSize
                        setBackgroundColor(android.graphics.Color.rgb(16, 19, 15))
                        setPadding(12, 8, 12, 8)
                        attachSession(current.terminal)
                        isFocusableInTouchMode = true
                        requestFocus()
                        view = this
                    } },
                    modifier = Modifier.fillMaxWidth().weight(1f).background(Color(0xFF10130F)),
                    update = { terminalView ->
                        if (terminalView.tag != preferences.fontSize) {
                            terminalView.setTextSize((preferences.fontSize * terminalView.resources.displayMetrics.scaledDensity).toInt())
                            terminalView.tag = preferences.fontSize
                        }
                        @Suppress("UNUSED_VARIABLE") val tick = revision
                        terminalView.onScreenUpdated()
                    }
                )
                DisposableEffect(current.id) { onDispose { view = null } }
            }
            Row(Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 8.dp, vertical = 4.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                listOf("ESC" to "\u001b", "TAB" to "\t", "CTRL" to "", "ALT" to "", "↑" to "\u001b[A", "↓" to "\u001b[B", "←" to "\u001b[D", "→" to "\u001b[C", "PASTE" to "").forEach { (label, sequence) ->
                    val active = (label == "CTRL" && ctrl) || (label == "ALT" && alt)
                    TextButton({
                        when (label) {
                            "CTRL" -> ctrl = !ctrl
                            "ALT" -> alt = !alt
                            "PASTE" -> runtime.onPasteTextFromClipboard(current.terminal)
                            else -> { current.terminal.write(sequence); ctrl = false; alt = false }
                        }
                    }, colors = ButtonDefaults.textButtonColors(containerColor = if (active) MaterialTheme.colorScheme.primaryContainer else Color.Transparent), contentPadding = PaddingValues(horizontal = 12.dp)) { Text(label, fontSize = 11.sp) }
                }
            }
        }
    }
    closing?.let { session ->
        if (!session.terminal.isRunning) LaunchedEffect(session.id) { runtime.close(session); closing = null }
        else ConfirmDialog("Close terminal ${session.number}?", "Running commands in this terminal will be stopped. Your environment’s files will stay installed.", "Close terminal", { closing = null }) { runtime.close(session) }
    }
}

private class TerminalKeys(var ctrl: Boolean = false, var alt: Boolean = false)
private class BoxTerminalClient(
    private val runtime: RuntimeManager, private val keys: TerminalKeys, private val clear: () -> Unit,
    private val showKeyboard: () -> Unit,
    private val scale: (Float) -> Float
) : TerminalViewClient {
    override fun onScale(scale: Float) = this.scale(scale)
    override fun onSingleTapUp(e: MotionEvent) = showKeyboard()
    override fun shouldBackButtonBeMappedToEscape() = false
    override fun shouldEnforceCharBasedInput() = true
    override fun shouldUseCtrlSpaceWorkaround() = false
    override fun isTerminalViewSelected() = true
    override fun copyModeChanged(copyMode: Boolean) {}
    override fun onKeyDown(keyCode: Int, e: KeyEvent, session: TerminalSession) = false
    override fun onKeyUp(keyCode: Int, e: KeyEvent) = false
    override fun onLongPress(event: MotionEvent) = false
    override fun readControlKey() = keys.ctrl
    override fun readAltKey() = keys.alt
    override fun readShiftKey() = false
    override fun readFnKey() = false
    override fun onCodePoint(codePoint: Int, ctrlDown: Boolean, session: TerminalSession): Boolean {
        // TerminalView has already captured modifiers. Let its complete Ctrl/Alt mapping run.
        if (keys.ctrl || keys.alt) { keys.ctrl = false; keys.alt = false; clear() }
        return false
    }
    override fun onEmulatorSet() {}
    override fun logError(tag: String, message: String) = runtime.logError(tag, message)
    override fun logWarn(tag: String, message: String) = runtime.logWarn(tag, message)
    override fun logInfo(tag: String, message: String) = runtime.logInfo(tag, message)
    override fun logDebug(tag: String, message: String) = runtime.logDebug(tag, message)
    override fun logVerbose(tag: String, message: String) = runtime.logVerbose(tag, message)
    override fun logStackTraceWithMessage(tag: String, message: String, e: Exception) = runtime.logStackTraceWithMessage(tag, message, e)
    override fun logStackTrace(tag: String, e: Exception) = runtime.logStackTrace(tag, e)
}
