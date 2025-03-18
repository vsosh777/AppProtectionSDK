package com.appprotection.sdk.internal

data class ProtectionStatus(
    val memoryMonitoring: Boolean,
    val rootDetection: Boolean = false,
    val debugDetection: Boolean = false,
    val criticalRegions: List<String> = emptyList(),
    val protectedRegions: List<String> = emptyList()
) 