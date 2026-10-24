plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.plugin.serialization")
    id("app.cash.paparazzi") version "1.3.5"
}
android {
    namespace = "io.boxos.app"
    compileSdk = 35
    ndkVersion = "27.0.12077973"
    defaultConfig {
        applicationId = "io.boxos.app"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "1.0.0"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    buildFeatures { compose = true; buildConfig = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    packaging { jniLibs { useLegacyPackaging = true; keepDebugSymbols += setOf("**/libboxkernel.so", "**/libboxloader.so") } }
    buildTypes { release { isMinifyEnabled = false } }
    testOptions { unitTests.isIncludeAndroidResources = true }
}
val buildKernel by tasks.registering(Exec::class) {
    onlyIf { providers.gradleProperty("skipNativeBuild").orNull != "true" }
    commandLine("bash", rootProject.file("scripts/build-native.sh").absolutePath)
    inputs.dir(rootProject.file("vendor/boxkernel/src"))
    inputs.file(rootProject.file("vendor/boxkernel/build.rs"))
    inputs.dir(rootProject.file("vendor/boxkernel/loader"))
    inputs.dir(rootProject.file("vendor/boxkernel/data"))
    inputs.files(rootProject.file("vendor/boxkernel/Cargo.toml"), rootProject.file("vendor/boxkernel/Cargo.lock"), rootProject.file("vendor/boxkernel/rust-toolchain.toml"), rootProject.file("scripts/build-native.sh"))
    outputs.dir(file("src/main/jniLibs"))
}
tasks.named("preBuild") { dependsOn(buildKernel) }
dependencies {
    implementation(project(":terminal-view"))
    implementation(platform("androidx.compose:compose-bom:2024.12.01"))
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-core")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("org.apache.commons:commons-compress:1.27.1")
    implementation("org.tukaani:xz:1.10")
    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation("junit:junit:4.13.2")
}
