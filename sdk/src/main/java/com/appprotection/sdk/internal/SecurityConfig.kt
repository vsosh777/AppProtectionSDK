/*
 * Copyright 2025 AppProtectionSDK
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.appprotection.sdk.internal

data class SecurityConfig(
    val memoryScanInterval: Long = 1000L, // 1 second
    val criticalMemoryRegions: List<String> = emptyList(),
    val enableRootDetection: Boolean = true,
    val enableDebugDetection: Boolean = true,
    val enableMemoryMonitoring: Boolean = true,
    val protectionLevel: ProtectionLevel = ProtectionLevel.MEDIUM
)

enum class ProtectionLevel {
    LOW,
    MEDIUM,
    HIGH
} 