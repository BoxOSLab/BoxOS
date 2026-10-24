package io.boxos.app.runtime

import io.boxos.app.data.Preferences

data class LaunchSpec(val executable: String, val arguments: List<String>, val environment: List<String>) {
    companion object {
        fun build(nativeDir: String, root: String, temporary: String, shared: String, preferences: Preferences, shell: String): LaunchSpec {
            val executable = "$nativeDir/libboxkernel.so"
            val args = mutableListOf(executable, "--kill-on-exit", "-0", "-l", "-L", "-H", "--sysvipc", "-p", "-r", root,
                "-b", "/dev", "-b", "/proc", "-b", "/sys", "-b", "$temporary:/dev/shm", "-w", "/root")
            if (preferences.sharedFolder) args += listOf("-b", "$shared:/mnt/shared")
            args += listOf(shell, "-l")
            val env = mutableListOf(
                "HOME=/root", "USER=root", "LOGNAME=root", "SHELL=$shell", "PWD=/root",
                "TERM=xterm-256color", "COLORTERM=truecolor", "LANG=C.UTF-8",
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "TMPDIR=/tmp", "PROOT_TMP_DIR=$temporary", "PROOT_LOADER=$nativeDir/libboxloader.so",
                "BOXOS=1", "ANDROID_ROOT=/system", "ANDROID_DATA=/data"
            )
            if (!preferences.seccomp) env += "PROOT_NO_SECCOMP=1"
            return LaunchSpec(executable, args, env)
        }
    }
}
