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

public val Icons.Rounded.Layers: ImageVector
    get() {
        if (_layers != null) {
            return _layers!!
        }
        _layers = materialIcon(name = "Rounded.Layers") {
            materialPath {
                moveTo(12.6f, 18.06f)
                curveToRelative(-0.36f, 0.28f, -0.87f, 0.28f, -1.23f, 0.0f)
                lineToRelative(-6.15f, -4.78f)
                curveToRelative(-0.36f, -0.28f, -0.86f, -0.28f, -1.22f, 0.0f)
                curveToRelative(-0.51f, 0.4f, -0.51f, 1.17f, 0.0f, 1.57f)
                lineToRelative(6.76f, 5.26f)
                curveToRelative(0.72f, 0.56f, 1.73f, 0.56f, 2.46f, 0.0f)
                lineToRelative(6.76f, -5.26f)
                curveToRelative(0.51f, -0.4f, 0.51f, -1.17f, 0.0f, -1.57f)
                lineToRelative(-0.01f, -0.01f)
                curveToRelative(-0.36f, -0.28f, -0.86f, -0.28f, -1.22f, 0.0f)
                lineToRelative(-6.15f, 4.79f)
                close()
                moveTo(13.23f, 15.04f)
                lineToRelative(6.76f, -5.26f)
                curveToRelative(0.51f, -0.4f, 0.51f, -1.18f, 0.0f, -1.58f)
                lineToRelative(-6.76f, -5.26f)
                curveToRelative(-0.72f, -0.56f, -1.73f, -0.56f, -2.46f, 0.0f)
                lineTo(4.01f, 8.21f)
                curveToRelative(-0.51f, 0.4f, -0.51f, 1.18f, 0.0f, 1.58f)
                lineToRelative(6.76f, 5.26f)
                curveToRelative(0.72f, 0.56f, 1.74f, 0.56f, 2.46f, -0.01f)
                close()
            }
        }
        return _layers!!
    }

private var _layers: ImageVector? = null
