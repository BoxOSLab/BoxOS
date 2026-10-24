package io.boxos.app.data

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.net.URI

val BoxJson = Json { ignoreUnknownKeys = true; prettyPrint = true }
const val CATALOG_URL = "https://raw.githubusercontent.com/BoxOSLab/BoxRootfs/main/latest.json"

@Serializable
data class Catalog(val schema: Int, val generated: String, val release: String, val images: List<RootImage>) {
    fun validate(): Catalog = apply {
        require(schema == 1) { "Unsupported BoxRootfs catalog schema: $schema" }
        require(images.isNotEmpty()) { "The catalog has no images" }
        require(images.map { it.distro to it.arch }.distinct().size == images.size) { "Duplicate images" }
        images.forEach { it.validate() }
    }
}

@Serializable
data class RootImage(
    val distro: String, val version: String, val arch: String, val filename: String,
    val sha256: String, val size: Long, val url: String, val channel: String = "stable",
    val codename: String = ""
) {
    val title get() = distro.replaceFirstChar { it.uppercase() }
    fun validate() {
        require(distro in listOf("debian", "ubuntu", "alpine")) { "Unknown distribution" }
        require(arch in listOf("arm64", "amd64")) { "Unsupported architecture" }
        require(size in 1..2_147_483_648L) { "Invalid image size" }
        require(sha256.matches(Regex("[a-fA-F0-9]{64}"))) { "Invalid SHA-256" }
        require(filename.matches(Regex("[a-zA-Z0-9._-]+\\.tar\\.xz"))) { "Invalid archive filename" }
        val uri = URI(url)
        require(uri.scheme == "https" && uri.host == "github.com" && uri.userInfo == null && uri.port == -1 &&
            uri.path.startsWith("/BoxOSLab/BoxRootfs/releases/download/") && uri.path.endsWith("/$filename") &&
            uri.query == null && uri.fragment == null && !uri.path.contains("/../")) { "Untrusted image URL" }
    }
}

@Serializable
data class Environment(
    val id: String, val name: String, val distro: String, val version: String,
    val arch: String, val installedAt: Long, val archiveSha256: String, val packageManager: String = ""
) {
    val title get() = distro.replaceFirstChar { it.uppercase() }
}

@Serializable
data class Preferences(
    val theme: String = "system", val fontSize: Int = 14, val keepAwake: Boolean = false,
    val seccomp: Boolean = false, val sharedFolder: Boolean = true,
    val dns: String = "1.1.1.1,8.8.8.8"
)

data class Operation(val label: String, val progress: Float? = null, val detail: String = "", val cancellable: Boolean = true)
fun humanBytes(value: Long): String = when {
    value >= 1_073_741_824 -> "%.1f GB".format(value / 1_073_741_824.0)
    value >= 1_048_576 -> "%.1f MB".format(value / 1_048_576.0)
    value >= 1024 -> "%.1f KB".format(value / 1024.0)
    else -> "$value B"
}
