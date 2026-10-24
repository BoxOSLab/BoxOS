/*
 * Copyright 2024 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package androidx.compose.material.icons.rounded

import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.materialIcon
import androidx.compose.material.icons.materialPath
import androidx.compose.ui.graphics.vector.ImageVector

public val Icons.Rounded.SettingsBackupRestore: ImageVector
    get() {
        if (_settingsBackupRestore != null) {
            return _settingsBackupRestore!!
        }
        _settingsBackupRestore = materialIcon(name = "Rounded.SettingsBackupRestore") {
            materialPath {
                moveTo(11.77f, 3.0f)
                curveToRelative(-2.65f, 0.07f, -5.0f, 1.28f, -6.6f, 3.16f)
                lineTo(3.85f, 4.85f)
                curveTo(3.54f, 4.54f, 3.0f, 4.76f, 3.0f, 5.21f)
                verticalLineTo(9.5f)
                curveTo(3.0f, 9.78f, 3.22f, 10.0f, 3.5f, 10.0f)
                horizontalLineToRelative(4.29f)
                curveToRelative(0.45f, 0.0f, 0.67f, -0.54f, 0.35f, -0.85f)
                lineTo(6.59f, 7.59f)
                curveTo(7.88f, 6.02f, 9.82f, 5.0f, 12.0f, 5.0f)
                curveToRelative(4.32f, 0.0f, 7.74f, 3.94f, 6.86f, 8.41f)
                curveToRelative(-0.54f, 2.77f, -2.81f, 4.98f, -5.58f, 5.47f)
                curveToRelative(-3.8f, 0.68f, -7.18f, -1.74f, -8.05f, -5.16f)
                curveTo(5.11f, 13.3f, 4.71f, 13.0f, 4.27f, 13.0f)
                horizontalLineToRelative(0.0f)
                curveToRelative(-0.65f, 0.0f, -1.14f, 0.61f, -0.98f, 1.23f)
                curveTo(4.28f, 18.12f, 7.8f, 21.0f, 12.0f, 21.0f)
                curveToRelative(5.06f, 0.0f, 9.14f, -4.17f, 9.0f, -9.26f)
                curveTo(20.86f, 6.86f, 16.65f, 2.88f, 11.77f, 3.0f)
                close()
                moveTo(14.0f, 12.0f)
                curveToRelative(0.0f, -1.1f, -0.9f, -2.0f, -2.0f, -2.0f)
                reflectiveCurveToRelative(-2.0f, 0.9f, -2.0f, 2.0f)
                reflectiveCurveToRelative(0.9f, 2.0f, 2.0f, 2.0f)
                reflectiveCurveTo(14.0f, 13.1f, 14.0f, 12.0f)
                close()
            }
        }
        return _settingsBackupRestore!!
    }

private var _settingsBackupRestore: ImageVector? = null
