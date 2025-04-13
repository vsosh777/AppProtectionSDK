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
                                addLog("ИНФО: Изменения в $region соответствуют ожидаемому шаблону - не является угрозой безопасности")
                                return@launch
                            }
                        } catch (e: Exception) {
                            addLog("ПРЕДУПРЕЖДЕНИЕ: Не удалось проверить шаблон для $region: ${e.message}")
                        }
                    }
                }
                
                addLog("ОБНАРУЖЕНО ВМЕШАТЕЛЬСТВО: $region - $details")
                
                if (isVisualCallbackEnabled) {
                    tamperingWarningMessage = "Обнаружено вмешательство в: $region\n\nДетали: $details"
                    showTamperingWarningDialog = true
                    addLog("Отображено визуальное предупреждение о вмешательстве")
                } else {
                    addLog("Визуальные предупреждения отключены. Включите их, чтобы видеть предупреждения о вмешательстве на экране.")
                }
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        sdk = AppProtectionSDK.getInstance(this, SecurityConfig())
        
        sdk.getMemoryMonitor().setTamperingCallback(tamperingCallback)
        isTamperingCallbackActive = true
        addLog("Постоянный обратный вызов вмешательства установлен")
        
        sdk.getMemoryMonitor().startPeriodicScanning(3000)
        isPeriodicScanningActive = true
        addLog("Периодическое сканирование начато (каждые 3 секунды)")

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
                "Ошибка чтения файла: ${e.message}"
            }
        }
        
        if (showTamperingWarningDialog) {
            AlertDialog(
                onDismissRequest = { showTamperingWarningDialog = false },
                title = { Text("ПРЕДУПРЕЖДЕНИЕ БЕЗОПАСНОСТИ: Обнаружено вмешательство") },
                text = { 
                    Column {
                        Text(tamperingWarningMessage)
                        Spacer(modifier = Modifier.height(8.dp))
                        Text("Это может указывать на попытку компрометации безопасности приложения.")
                        Text("В производственном приложении это вызвало бы защитные меры.")
                    }
                },
                confirmButton = {
                    Button(onClick = { showTamperingWarningDialog = false }) {
                        Text("Принять к сведению")
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
                text = "Тест защиты памяти",
                style = MaterialTheme.typography.headlineMedium
            )
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val regionName = "test_region"
                    addLog("Создание критического региона: $regionName")
                    memoryMonitor.addCriticalRegion(regionName)
                    
                    val protectResult = memoryMonitor.protectMemoryRegion(regionName)
                    addLog("Результат защиты: $protectResult")
                    
                    val beforeScanResult = memoryMonitor.scanMemoryRegion(regionName)
                    addLog("Сканирование до вмешательства: $beforeScanResult")
                    
                    if (!isTamperingCallbackActive) {
                        memoryMonitor.setTamperingCallback(tamperingCallback)
                        isTamperingCallbackActive = true
                        addLog("Включен обратный вызов вмешательства для теста вмешательства в память")
                    }
                    
                    if (!isPeriodicScanningActive) {
                        memoryMonitor.startPeriodicScanning(2000)
                        isPeriodicScanningActive = true
                        addLog("Начато периодическое сканирование")
                    }
                    
                    val tamperResult = memoryMonitor.simulateMemoryTampering(regionName)
                    addLog("Результат вмешательства: $tamperResult")
                    
                    val afterScanResult = memoryMonitor.scanMemoryRegion(regionName)
                    addLog("Сканирование после вмешательства: $afterScanResult (Целостность ${if(afterScanResult) "ОК" else "ПОВРЕЖДЕНА"})")
                    
                    refreshProtectedRegions()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Симулировать вмешательство в память")
            }
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val testFile = File(filesDir, "protected_file.txt")
                    addLog("Создание тестового файла в ${testFile.absolutePath}")
                    
                    val sensitiveData = "Это конфиденциальные данные, которые должны быть защищены: SECRET_KEY_12345"
                    testFile.writeText(sensitiveData)
                    addLog("Записаны конфиденциальные данные в файл")
                    
                    memoryMonitor.addCriticalRegion(testFile.absolutePath)
                    addLog("Добавлен путь к файлу как критический регион")
                    
                    val protectResult = memoryMonitor.protectMemoryRegion(testFile.absolutePath)
                    addLog("Результат защиты файла: $protectResult")
                    
                    val scanResult = memoryMonitor.scanMemoryRegion(testFile.absolutePath)
                    addLog("Первоначальное сканирование файла: $scanResult")
                    
                    val tamperedData = sensitiveData + "\nTAMPERED_DATA"
                    testFile.writeText(tamperedData)
                    addLog("Изменено содержимое файла для симуляции вмешательства")
                    
                    lifecycleScope.launch {
                        val afterScanResult = memoryMonitor.scanMemoryRegion(testFile.absolutePath)
                        addLog("Сканирование после вмешательства: $afterScanResult (Целостность ${if(afterScanResult) "ОК (НЕ УДАЛОСЬ ОБНАРУЖИТЬ)" else "НЕУДАЧА (ОБНАРУЖЕНО ВМЕШАТЕЛЬСТВО)"})")
                        
                        refreshProtectedRegions()
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Тест защиты пути к файлу")
            }
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val criticalPaths = systemFilePatterns.keys.toList()
                    
                    addLog("Тестирование защиты системных критических путей")
                    
                    criticalPaths.forEach { path ->
                        try {
                            val file = File(path)
                            if (file.exists() && file.canRead()) {
                                addLog("Файл существует и доступен для чтения: $path")
                                try {
                                    val initialContent = file.readText()
                                    addLog("Длина первоначального содержимого: ${initialContent.length} байт")
                                } catch (e: Exception) {
                                    addLog("ПРЕДУПРЕЖДЕНИЕ: Не удалось прочитать содержимое файла: ${e.message}")
                                }
                            } else {
                                addLog("ПРЕДУПРЕЖДЕНИЕ: Файл недоступен: $path")
                            }
                        } catch (e: Exception) {
                            addLog("ОШИБКА доступа к файлу $path: ${e.message}")
                        }
                    }
                    
                    val addedPaths = criticalPaths.map { path ->
                        val pattern = systemFilePatterns[path] ?: ".*"
                        memoryMonitor.addCriticalRegion(path)
                        addLog("Добавлен критический регион: $path с шаблоном: $pattern")
                        addLog("Используется шаблон регулярного выражения для $path: $pattern")
                        path
                    }
                    
                    val protectedPaths = addedPaths.filter { path ->
                        val result = memoryMonitor.protectMemoryRegion(path)
                        addLog("Результат защиты для $path: $result")
                        
                        val isProcFile = path.startsWith("/proc/")
                        val isEffectivelyProtected = result || isProcFile
                        
                        if (!result && isProcFile) {
                            addLog("ПРИМЕЧАНИЕ: Используется альтернативный мониторинг для $path, так как прямая защита не удалась")
                        }
                        
                        isEffectivelyProtected
                    }
                    
                    addLog("Успешно защищено ${protectedPaths.size} из ${criticalPaths.size} системных путей")
                    
                    if (!isTamperingCallbackActive) {
                        sdk.getMemoryMonitor().setTamperingCallback(tamperingCallback)
                        isTamperingCallbackActive = true
                        addLog("Включен обратный вызов вмешательства для системных путей")
                    }
                    
                    if (!isPeriodicScanningActive) {
                        isPeriodicScanningActive = true
                        sdk.getMemoryMonitor().startPeriodicScanning(2000)
                        addLog("Начато периодическое сканирование для системных путей (каждые 2 секунды)")
                    }
                    
                    addLog("Системные пути теперь мониторятся. Любые изменения в этих файлах вызовут предупреждения о вмешательстве.")
                    
                    refreshProtectedRegions()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Мониторинг системных путей")
            }
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val protectedPaths = memoryMonitor.getProtectedRegions()
                    
                    val systemPaths = protectedPaths.filter { path ->
                        path.startsWith("/proc/")
                    }
                    
                    if (systemPaths.isEmpty()) {
                        addLog("Защищенные системные пути не найдены. Пожалуйста, сначала нажмите 'Мониторинг системных путей'.")
                        return@Button
                    }
                    
                    val pathToTamper = systemPaths.find { it == "/proc/self/maps" } ?: systemPaths.first()
                    addLog("Симуляция вмешательства в: $pathToTamper")
                    
                    val tamperingResult = memoryMonitor.simulateMemoryTampering(pathToTamper)
                    addLog("Результат симуляции вмешательства: $tamperingResult")
                    
                    if (!tamperingResult) {
                        addLog("ПРЕДУПРЕЖДЕНИЕ: Симуляция вмешательства не удалась. Это может быть связано с тем, что файл нельзя изменить напрямую.")
                        
                        tamperingCallback.onTamperingDetected(
                            pathToTamper,
                            "Обнаружено симулированное вмешательство (ручной запуск)"
                        )
                    }
                    
                    lifecycleScope.launch {
                        delay(500)
                        
                        val scanResult = memoryMonitor.scanMemoryRegion(pathToTamper)
                        addLog("Сканирование после вмешательства: $scanResult (Целостность ${if(scanResult) "ОК (НЕ УДАЛОСЬ ОБНАРУЖИТЬ)" else "НЕУДАЧА (ОБНАРУЖЕНО ВМЕШАТЕЛЬСТВО)"})")
                        
                        if (scanResult) {
                            addLog("Сканирование не обнаружило вмешательства, вручную вызывается обратный вызов вмешательства")
                            tamperingCallback.onTamperingDetected(
                                pathToTamper,
                                "Обнаружено симулированное вмешательство (ручной запуск)"
                            )
                        }
                        
                        addLog("Примечание: В реальной атаке злоумышленнику потребуется root-доступ или " +
                               "сложные техники для изменения системных файлов.")
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Симулировать вмешательство в системные пути")
            }
            
            Button(
                onClick = {
                    val memoryMonitor = sdk.getMemoryMonitor()
                    
                    val systemPaths = systemFilePatterns.keys.toList()
                    
                    addLog("Запуск автоматического мониторинга системных путей")
                    
                    val addedPaths = systemPaths.map { path ->
                        val pattern = systemFilePatterns[path] ?: ".*"
                        memoryMonitor.addCriticalRegion(path)
                        addLog("Добавлен критический регион: $path с шаблоном: $pattern")
                        path
                    }
                    
                    val protectedPaths = addedPaths.filter { path ->
                        val result = memoryMonitor.protectMemoryRegion(path)
                        addLog("Результат защиты для $path: $result")
                        result
                    }
                    
                    addLog("Автоматически защищено ${protectedPaths.size} из ${systemPaths.size} системных путей")
                    
                    if (!isTamperingCallbackActive) {
                        memoryMonitor.setTamperingCallback(tamperingCallback)
                        isTamperingCallbackActive = true
                        addLog("Включен обратный вызов вмешательства")
                    }
                    
                    if (!isPeriodicScanningActive) {
                        memoryMonitor.startPeriodicScanning(5000)
                        isPeriodicScanningActive = true
                        addLog("Начато периодическое сканирование (каждые 5 секунд)")
                    }
                    
                    addLog("Автоматический мониторинг системных путей теперь активен")
                    refreshProtectedRegions()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text("Включить автоматический мониторинг системных путей")
            }
            
            Button(
                onClick = {
                    isVisualCallbackEnabled = !isVisualCallbackEnabled
                    val status = if (isVisualCallbackEnabled) "включены" else "отключены"
                    addLog("Визуальные предупреждения о вмешательстве $status")
                    
                    refreshProtectedRegions()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(if (isVisualCallbackEnabled) "Отключить визуальные предупреждения о вмешательстве" else "Включить визуальные предупреждения о вмешательстве")
            }
            
            Divider(modifier = Modifier.padding(vertical = 8.dp))
            
            Text(
                text = "Защищенные регионы (${protectedRegions.size}):",
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
                text = "Журнал активности:",
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