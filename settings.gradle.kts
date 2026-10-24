pluginManagement { repositories { google(); mavenCentral(); gradlePluginPortal() } }
dependencyResolutionManagement { repositories { google(); mavenCentral() } }
rootProject.name = "BoxOS"
include(":app", ":terminal-emulator", ":terminal-view")
project(":terminal-emulator").projectDir = file("vendor/terminal-emulator")
project(":terminal-view").projectDir = file("vendor/terminal-view")
