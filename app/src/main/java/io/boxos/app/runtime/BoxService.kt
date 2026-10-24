package io.boxos.app.runtime

import android.app.*
import android.content.Intent
import android.os.IBinder
import android.os.PowerManager
import io.boxos.app.BoxApp
import io.boxos.app.MainActivity
import io.boxos.app.R
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.distinctUntilChanged

class BoxService : Service() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private var wakeLock: PowerManager.WakeLock? = null
    private var wakePeriodStarted = false
    private var starting = true
    private var shuttingDown = false
    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(NotificationChannel("runtime", "Linux sessions", NotificationManager.IMPORTANCE_LOW))
        startForeground(10, notification("Preparing your environment"))
        val app = application as BoxApp
        scope.launch {
            delay(500)
            starting = false
            combine(app.runtime.sessions, app.runtime.operation, app.repository.preferences, app.runtime.revision) { sessions, operation, prefs, _ ->
                Triple(sessions.count { it.terminal.isRunning }, operation?.label, prefs)
            }.distinctUntilChanged().collect { (count, operationLabel, preferences) ->
                val active = count > 0 || operationLabel != null
                if (active && preferences.keepAwake) {
                    if (!wakePeriodStarted) {
                        wakePeriodStarted = true
                        wakeLock = getSystemService(PowerManager::class.java).newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "BoxOS:Linux").apply { acquire(6 * 60 * 60 * 1000L) }
                    }
                } else releaseWakeLock()
                manager.notify(10, notification(operationLabel ?: "$count Linux ${if (count == 1) "session" else "sessions"} running"))
                if (!starting && !active) { shuttingDown = true; stopSelf() }
            }
        }
    }
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "stop") {
            (application as BoxApp).runtime.apply { stopAll(); cancelOperation() }
        }
        return START_NOT_STICKY
    }
    private fun notification(text: String): Notification {
        val open = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val stop = PendingIntent.getService(this, 1, Intent(this, BoxService::class.java).setAction("stop"), PendingIntent.FLAG_IMMUTABLE)
        return Notification.Builder(this, "runtime").setSmallIcon(R.drawable.ic_notification).setContentTitle("BoxOS")
            .setContentText(text).setContentIntent(open).setOngoing(true).setOnlyAlertOnce(true)
            .addAction(Notification.Action.Builder(null, "Stop all", stop).build()).build()
    }
    private fun releaseWakeLock() { if (wakeLock?.isHeld == true) wakeLock?.release(); wakeLock = null; wakePeriodStarted = false }
    override fun onTaskRemoved(rootIntent: Intent?) { /* Sessions deliberately survive swiping the activity away. */ }
    override fun onDestroy() {
        scope.cancel(); releaseWakeLock()
        if (!shuttingDown) (application as BoxApp).runtime.apply { stopAll(); cancelOperation() }
        super.onDestroy()
    }
    override fun onBind(intent: Intent?): IBinder? = null
}
