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