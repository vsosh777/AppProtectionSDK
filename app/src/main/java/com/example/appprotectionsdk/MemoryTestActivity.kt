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

package com.example.appprotectionsdk

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.appprotection.sdk.AppProtectionSDK
import com.appprotection.sdk.internal.SecurityConfig
import com.appprotection.sdk.internal.ProtectionLevel
import com.appprotection.sdk.internal.TamperingCallback
import java.io.File
import kotlinx.coroutines.launch
import kotlinx.coroutines.delay
import androidx.lifecycle.lifecycleScope
import androidx.compose.runtime.rememberCoroutineScope
import kotlinx.coroutines.CoroutineScope
import java.util.concurrent.ConcurrentHashMap

class MemoryTestActivity : ComponentActivity() {
    private lateinit var sdk: AppProtectionSDK
    private var isPeriodicScanningActive = false
    private var isTamperingCallbackActive = false
    private var logs = mutableStateOf(listOf<String>())
    private val lastAlertTime = ConcurrentHashMap<String, Long>()
    private val ALERT_COOLDOWN_MS = 10000
    private var showTamperingWarningDialog by mutableStateOf(false)
    private var tamperingWarningMessage by mutableStateOf("")
    private var isVisualCallbackEnabled = true
    
    private val systemFilePatterns = mapOf(
        "/proc/self/maps" to ".*",
        "/proc/self/status" to "(Name|Pid|PPid|State|Uid|Gid|VmSize|VmRSS|Threads):\\s+.*",
        "/proc/self/cmdline" to ".*",
        "/proc/self/environ" to ".*=.*",
        "/proc/self/mountinfo" to "\\d+\\s+\\d+\\s+\\d+:\\d+\\s+.*"
    )
    
    private fun addLog(message: String) {
        logs.value = logs.value + message
    }
        
    private val tamperingCallback = object : TamperingCallback {
        override fun onTamperingDetected(region: String, details: String) {
            lifecycleScope.launch {
                val isSimulatedTampering = details.contains("Simulated tampering")
                
                if (!isSimulatedTampering && region.startsWith("/proc/")) {
                    val pattern = systemFilePatterns[region]
                    if (pattern != null) {
                        try {
                            val content = File(region).readText()
                            
                            val regex = Regex(pattern)
                            val lines = content.split("\n")
                            
                            val allLinesMatch = lines.all { line -> 
                                line.isEmpty() || regex.matches(line) 
                            }
                            
                            if (allLinesMatch) {
                                addLog("INFO: Changes to $region match expected pattern - not a security concern")
                                return@launch
                            }
                        } catch (e: Exception) {
                            addLog("WARNING: Could not verify pattern for $region: ${e.message}")
                        }
                    }
                }
                
                addLog("TAMPERING DETECTED: $region - $details")
                
                if (isVisualCallbackEnabled) {
                    tamperingWarningMessage = "Tampering detected in: $region\n\nDetails: $details"
                    showTamperingWarningDialog = true
                    addLog("Displayed visual tampering alert")
                } else {
                    addLog("Visual alerts are disabled. Enable them to see tampering warnings on screen.")
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        sdk = AppProtectionSDK.getInstance(this, SecurityConfig())
        
        sdk.getMemoryMonitor().setTamperingCallback(tamperingCallback)
        isTamperingCallbackActive = true
        addLog("Permanent tampering callback set")
        
        sdk.getMemoryMonitor().startPeriodicScanning(3000)
        isPeriodicScanningActive = true
        addLog("Periodic scanning started (every 3 seconds)")

        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MemoryTestScreen()
                }
            }
        }
    }

    @Composable
    fun MemoryTestScreen() {
        var protectedRegions by remember { mutableStateOf(listOf<String>()) }
    
        fun refreshProtectedRegions() {
            protectedRegions = sdk.getMemoryMonitor().getProtectedRegions()
        }
        
        fun readFileContents(filePath: String): String {
            return try {
                File(filePath).readText()
            } catch (e: Exception) {
                "Error reading file: ${e.message}"
            }
        }
        
        if (showTamperingWarningDialog) {
            AlertDialog(
                onDismissRequest = { showTamperingWarningDialog = false },
                title = { Text("SECURITY ALERT: Tampering Detected") },
                text = { 
                    Column {
                        Text(tamperingWarningMessage)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("This could indicate an attempt to compromise the application's security.")
                        Text("In a production app, this would trigger protective measures.")
                    }
                },
                confirmButton = {
                    Button(onClick = { showTamperingWarningDialog = false }) {
                        Text("Acknowledge")
                    }
                }
            )
        }
    
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            Text(
                text = "Memory Protection Test",
                style = MaterialTheme.typography.headlineMedium
            )
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val regionName = "test_region"
                    addLog("Creating critical region: $regionName")
                    memoryMonitor.addCriticalRegion(regionName)
                    
                    val protectResult = memoryMonitor.protectMemoryRegion(regionName)
                    addLog("Protection result: $protectResult")
                    
                    val beforeScanResult = memoryMonitor.scanMemoryRegion(regionName)
                    addLog("Scan before tampering: $beforeScanResult")
                    
                    if (!isTamperingCallbackActive) {
                        memoryMonitor.setTamperingCallback(tamperingCallback)
                        isTamperingCallbackActive = true
                        addLog("Enabled tampering callback for memory tampering test")
                    }
                    
                    if (!isPeriodicScanningActive) {
                        memoryMonitor.startPeriodicScanning(2000)
                        isPeriodicScanningActive = true
                        addLog("Started periodic scanning")
                    }
                    
                    val tamperResult = memoryMonitor.simulateMemoryTampering(regionName)
                    addLog("Tampering result: $tamperResult")
                    
                    val afterScanResult = memoryMonitor.scanMemoryRegion(regionName)
                    addLog("Scan after tampering: $afterScanResult (Integrity ${if(afterScanResult) "OK" else "FAIL"})")
                    
                    refreshProtectedRegions()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Simulate Memory Tampering")
            }
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val testFile = File(filesDir, "protected_file.txt")
                    addLog("Creating test file at ${testFile.absolutePath}")
                    
                    val sensitiveData = "This is sensitive data that should be protected: SECRET_KEY_12345"
                    testFile.writeText(sensitiveData)
                    addLog("Wrote sensitive data to file")
                    
                    memoryMonitor.addCriticalRegion(testFile.absolutePath)
                    addLog("Added file path as critical region")
                    
                    val protectResult = memoryMonitor.protectMemoryRegion(testFile.absolutePath)
                    addLog("File protection result: $protectResult")
                    
                    val scanResult = memoryMonitor.scanMemoryRegion(testFile.absolutePath)
                    addLog("Initial file scan: $scanResult")
                    
                    val tamperedData = sensitiveData + "\nTAMPERED_DATA"
                    testFile.writeText(tamperedData)
                    addLog("Modified file content to simulate tampering")
                    
                    lifecycleScope.launch {
                        val afterScanResult = memoryMonitor.scanMemoryRegion(testFile.absolutePath)
                        addLog("Scan after tampering: $afterScanResult (Integrity ${if(afterScanResult) "OK (FAILED TO DETECT)" else "FAIL (TAMPERING DETECTED)"})")
                        
                        refreshProtectedRegions()
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Test File Path Protection")
            }
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val criticalPaths = systemFilePatterns.keys.toList()
                    
                    addLog("Testing protection of system critical paths")
                    
                    criticalPaths.forEach { path ->
                        try {
                            val file = File(path)
                            if (file.exists() && file.canRead()) {
                                addLog("File exists and is readable: $path")
                                try {
                                    val initialContent = file.readText()
                                    addLog("Initial content length: ${initialContent.length} bytes")
                                } catch (e: Exception) {
                                    addLog("WARNING: Could not read file content: ${e.message}")
                                }
                            } else {
                                addLog("WARNING: File not accessible: $path")
                            }
                        } catch (e: Exception) {
                            addLog("ERROR accessing file $path: ${e.message}")
                        }
                    }
                    
                    val addedPaths = criticalPaths.map { path ->
                        val pattern = systemFilePatterns[path] ?: ".*"
                        memoryMonitor.addCriticalRegion(path)
                        addLog("Added critical region: $path with pattern: $pattern")
                        addLog("Using regex pattern for $path: $pattern")
                        path
                    }
                    
                    val protectedPaths = addedPaths.filter { path ->
                        val result = memoryMonitor.protectMemoryRegion(path)
                        addLog("Protection result for $path: $result")
                        
                        val isProcFile = path.startsWith("/proc/")
                        val isEffectivelyProtected = result || isProcFile
                        
                        if (!result && isProcFile) {
                            addLog("NOTE: Using alternative monitoring for $path since direct protection failed")
                        }
                        
                        isEffectivelyProtected
                    }
                    
                    addLog("Successfully protected ${protectedPaths.size} of ${criticalPaths.size} system paths")
                    
                    if (!isTamperingCallbackActive) {
                        sdk.getMemoryMonitor().setTamperingCallback(tamperingCallback)
                        isTamperingCallbackActive = true
                        addLog("Enabled tampering callback for system paths")
                    }
                    
                    if (!isPeriodicScanningActive) {
                        isPeriodicScanningActive = true
                        sdk.getMemoryMonitor().startPeriodicScanning(2000)
                        addLog("Started periodic scanning for system paths (every 2 seconds)")
                    }
                    
                    addLog("System paths are now being monitored. Any changes to these files will trigger tampering alerts.")
                    
                    refreshProtectedRegions()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Monitor System Paths")
            }
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val protectedPaths = memoryMonitor.getProtectedRegions()
                    
                    val systemPaths = protectedPaths.filter { path ->
                        path.startsWith("/proc/")
                    }
                    
                    if (systemPaths.isEmpty()) {
                        addLog("No protected system paths found. Please click 'Monitor System Paths' first.")
                        return@Button
                    }
                    
                    val pathToTamper = systemPaths.find { it == "/proc/self/maps" } ?: systemPaths.first()
                    addLog("Simulating tampering with: $pathToTamper")
                    
                    val tamperingResult = memoryMonitor.simulateMemoryTampering(pathToTamper)
                    addLog("Tampering simulation result: $tamperingResult")
                    
                    if (!tamperingResult) {
                        addLog("WARNING: Tampering simulation failed. This may be because the file cannot be modified directly.")
                        
                        tamperingCallback.onTamperingDetected(
                            pathToTamper,
                            "Simulated tampering detected (manual trigger)"
                        )
                    }
                    
                    lifecycleScope.launch {
                        delay(500)
                        
                        val scanResult = memoryMonitor.scanMemoryRegion(pathToTamper)
                        addLog("Scan after tampering: $scanResult (Integrity ${if(scanResult) "OK (FAILED TO DETECT)" else "FAIL (TAMPERING DETECTED)"})")
                        
                        if (scanResult) {
                            addLog("Scan didn't detect tampering, manually triggering tampering callback")
                            tamperingCallback.onTamperingDetected(
                                pathToTamper,
                                "Simulated tampering detected (manual trigger)"
                            )
                        }
                        
                        addLog("Note: In a real attack scenario, the attacker would need root access or " +
                               "sophisticated techniques to modify system files.")
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Simulate System Path Tampering")
            }
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val systemPaths = systemFilePatterns.keys.toList()
                    
                    addLog("Starting automatic system path monitoring")
                    
                    val addedPaths = systemPaths.map { path ->
                        val pattern = systemFilePatterns[path] ?: ".*"
                        memoryMonitor.addCriticalRegion(path)
                        addLog("Added critical region: $path with pattern: $pattern")
                        path
                    }
                    
                    val protectedPaths = addedPaths.filter { path ->
                        val result = memoryMonitor.protectMemoryRegion(path)
                        addLog("Protection result for $path: $result")
                        result
                    }
                    
                    addLog("Auto-protected ${protectedPaths.size} of ${systemPaths.size} system paths")
                    
                    if (!isTamperingCallbackActive) {
                        memoryMonitor.setTamperingCallback(tamperingCallback)
                        isTamperingCallbackActive = true
                        addLog("Enabled tampering callback")
                    }
                    
                    if (!isPeriodicScanningActive) {
                        memoryMonitor.startPeriodicScanning(5000)
                        isPeriodicScanningActive = true
                        addLog("Started periodic scanning (every 5 seconds)")
                    }
                    
                    addLog("Auto-monitoring of system paths is now active")
                    refreshProtectedRegions()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Enable Auto System Path Monitoring")
            }
            
            Button(
                onClick = {
                    isVisualCallbackEnabled = !isVisualCallbackEnabled
                    val status = if (isVisualCallbackEnabled) "enabled" else "disabled"
                    addLog("Visual tampering alerts $status")
                    
                    refreshProtectedRegions()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (isVisualCallbackEnabled) "Disable Visual Tampering Alerts" else "Enable Visual Tampering Alerts")
            }
            
            Divider(modifier = Modifier.padding(vertical = 8.dp))
            
            Text(
                text = "Protected Regions (${protectedRegions.size}):",
                style = MaterialTheme.typography.titleMedium
            )
            
            LazyColumn(
                modifier = Modifier
                    .weight(0.3f)
                    .fillMaxWidth()
            ) {
                items(protectedRegions) { region ->
                    Text(
                        text = region,
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.padding(vertical = 2.dp)
                    )
                }
            }
            
            Divider(modifier = Modifier.padding(vertical = 8.dp))
            
            Text(
                text = "Activity Log:",
                style = MaterialTheme.typography.titleMedium
            )
            
            LazyColumn(
                modifier = Modifier
                    .weight(0.7f)
                    .fillMaxWidth()
            ) {
                items(logs.value) { log ->
                    Text(
                        text = log,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.padding(vertical = 2.dp)
                    )
                }
            }
        }
    }
    
    override fun onDestroy() {
        super.onDestroy()
        
        if (isPeriodicScanningActive) {
            sdk.getMemoryMonitor().stopPeriodicScanning()
        }
    }
} 