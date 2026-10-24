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

public val Icons.Rounded.TextDecrease: ImageVector
    get() {
        if (_textDecrease != null) {
            return _textDecrease!!
        }
        _textDecrease = materialIcon(name = "Rounded.TextDecrease") {
            materialPath {
                moveTo(2.61f, 19.0f)
                lineTo(2.61f, 19.0f)
                curveToRelative(0.48f, 0.0f, 0.91f, -0.3f, 1.06f, -0.75f)
                lineToRelative(1.01f, -2.83f)
                horizontalLineToRelative(5.65f)
                lineToRelative(0.99f, 2.82f)
                curveTo(11.48f, 18.7f, 11.91f, 19.0f, 12.39f, 19.0f)
                curveToRelative(0.79f, 0.0f, 1.33f, -0.79f, 1.05f, -1.52f)
                lineTo(9.19f, 6.17f)
                curveTo(8.93f, 5.47f, 8.25f, 5.0f, 7.5f, 5.0f)
                reflectiveCurveTo(6.07f, 5.47f, 5.81f, 6.17f)
                lineTo(1.56f, 17.48f)
                curveTo(1.28f, 18.21f, 1.83f, 19.0f, 2.61f, 19.0f)
                close()
                moveTo(7.44f, 7.6f)
                horizontalLineToRelative(0.12f)
                lineToRelative(2.03f, 5.79f)
                horizontalLineTo(5.41f)
                lineTo(7.44f, 7.6f)
                close()
                moveTo(15.0f, 12.0f)
                curveToRelative(0.0f, -0.55f, 0.45f, -1.0f, 1.0f, -1.0f)
                horizontalLineToRelative(6.0f)
                curveToRelative(0.55f, 0.0f, 1.0f, 0.45f, 1.0f, 1.0f)
                reflectiveCurveToRelative(-0.45f, 1.0f, -1.0f, 1.0f)
                horizontalLineToRelative(-6.0f)
                curveTo(15.45f, 13.0f, 15.0f, 12.55f, 15.0f, 12.0f)
                close()
            }
        }
        return _textDecrease!!
    }

private var _textDecrease: ImageVector? = null
