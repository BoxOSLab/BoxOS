package io.boxos.app

import android.app.Application
import io.boxos.app.data.BoxRepository
import io.boxos.app.runtime.RuntimeManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class BoxApp : Application() {
    val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    lateinit var repository: BoxRepository
    lateinit var runtime: RuntimeManager
    override fun onCreate() {
        super.onCreate()
        repository = BoxRepository(this)
        runtime = RuntimeManager(this, repository, scope)
        scope.launch { runCatching { repository.initialize() }.onFailure { runtime.error.value = "Could not load environments: ${it.message}" } }
    }
}
