package io.boxos.app

import app.cash.paparazzi.Paparazzi
import io.boxos.app.ui.*
import io.boxos.app.data.*
import org.junit.Rule
import org.junit.Test

class UiShots {
    @get:Rule val paparazzi = Paparazzi()
    @Test fun emptyWorkspaceDark() { paparazzi.snapshot { BoxTheme("dark") {
        WorkspaceScreen(emptyList(), emptyList(), 0, 12_000_000_000, false, "arm64", {}, {}, {}, {}, {}, {})
    } } }
    @Test fun installedWorkspaceLight() { paparazzi.snapshot { BoxTheme("light") {
        WorkspaceScreen(listOf(Environment("test", "Development", "debian", "13", "arm64", 0, "")), emptyList(), 0, 12_000_000_000, false, "arm64", {}, {}, {}, {}, {}, {})
    } } }
    @Test fun catalogDark() {
        val image = RootImage("debian", "13", "arm64", "debian.tar.xz", "ab".repeat(32), 32_000_000, "")
        paparazzi.snapshot { BoxTheme("dark") { CatalogScreen(Catalog(1, "", "test", listOf(image)), null, "arm64", false, {}, {}, { _, _ -> }) } }
    }
}
