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
import androidx.compose.foundation.background
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.rememberScrollState
import com.appprotection.sdk.AppProtectionSDK
import com.appprotection.sdk.internal.SecurityConfig
import com.appprotection.sdk.internal.ProtectionLevel
import com.appprotection.sdk.internal.ProtectionStatus

class MainActivity : ComponentActivity() {
    private lateinit var sdk: AppProtectionSDK

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val config = SecurityConfig(
            memoryScanInterval = 1000L,
            criticalMemoryRegions = listOf("test_region"),
            enableRootDetection = true,
            enableDebugDetection = true,
            enableMemoryMonitoring = true,
            protectionLevel = ProtectionLevel.HIGH
        )
        sdk = AppProtectionSDK.getInstance(this, config)
        sdk.initialize()

        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    MainScreen(sdk)
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        sdk.stopProtection()
    }
}

@Composable
fun MainScreen(sdk: AppProtectionSDK) {
    var protectionStatus by remember { mutableStateOf(sdk.isProtected()) }
    var memoryStatus by remember { mutableStateOf(sdk.getProtectionStatus()) }
    var rootStatus by remember { mutableStateOf("Проверка статуса root...") }
    var debugStatus by remember { mutableStateOf("Не проверено") }
    var isMonitoringDebug by remember { mutableStateOf(false) }
    var showDebuggerDetectedDialog by remember { mutableStateOf(false) }
    var simulateTermination by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        val isRooted = sdk.isDeviceRooted()
        rootStatus = if (isRooted) "Устроиство рутировано!" else "Устроиство не рутировано"
    }
    
    LaunchedEffect(isMonitoringDebug) {
        if (isMonitoringDebug) {
            while (isMonitoringDebug) {
                val isBeingDebugged = sdk.isBeingDebugged()
                debugStatus = if (isBeingDebugged) {
                    showDebuggerDetectedDialog = true
                    "Отладчик обнаружен! (Авто)"
                } else {
                    "Отладчик не обнаружен (Мониторинг...)"
                }
                kotlinx.coroutines.delay(1000)
            }
        }
    }
    
    if (simulateTermination) {
        Box(
            modifier = Modifier
                .fillMaxSize()
                .background(MaterialTheme.colorScheme.error),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Text(
                    text = "ПРИЛОЖЕНИЕ ЗАВЕРШЕНО",
                    style = MaterialTheme.typography.headlineMedium,
                    color = MaterialTheme.colorScheme.onError
                )
                Text(
                    text = "Обнаружено нарушение безопасности: Подключен отладчик",
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onError
                )
                Button(
                    onClick = { simulateTermination = false },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.onError,
                        contentColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text("Вернуться в приложение (Только демонстрация)")
                }
            }
        }
        return
    }

    if (showDebuggerDetectedDialog) {
        AlertDialog(
            onDismissRequest = { showDebuggerDetectedDialog = false },
            title = { Text("Предупреждение безопасности") },
            text = { 
                Column {
                    Text("Обнаружен отладчик! Это может указывать на попытку взлома приложения.")
                    Spacer(modifier = Modifier.height(8.dp))
                    Text("В реальном приложении это вызвало бы защитные меры, такие как:")
                    Text("• Завершение работы приложения")
                    Text("• Удаление конфиденциальных данных")
                    Text("• Уведомление систем безопасности")
                    Text("• Логирование инцидента")
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showDebuggerDetectedDialog = false
                        simulateTermination = true
                    }
                ) {
                    Text("Симулировать завершение")
                }
            },
            dismissButton = {
                Button(
                    onClick = { showDebuggerDetectedDialog = false }
                ) {
                    Text("Отклонить (Только демонстрация)")
                }
            }
        )
    }

    val scrollState = rememberScrollState()
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(scrollState),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Тест AppProtectionSDK",
            style = MaterialTheme.typography.headlineMedium
        )

        StatusCard(
            title = "Общий статус защиты",
            status = if (protectionStatus) "Активен" else "Неактивен"
        )

        StatusCard(
            title = "Мониторинг памяти",
            status = if (memoryStatus.memoryMonitoring) "Активен" else "Неактивен"
        )

        StatusCard(
            title = "Обнаружение отладки",
            status = debugStatus,
            statusColor = when {
                debugStatus.contains("Обнаружен отладчик") -> MaterialTheme.colorScheme.error
                debugStatus.contains("Отладчик не обнаружен") -> MaterialTheme.colorScheme.primary
                else -> MaterialTheme.colorScheme.onSurface
            }
        )

        if (memoryStatus.criticalRegions.isNotEmpty()) {
            StatusCard(
                title = "Критические регионы",
                content = {
                    Column(
                        modifier = Modifier.padding(vertical = 4.dp)
                    ) {
                        memoryStatus.criticalRegions.forEach { region ->
                            Text(
                                text = region,
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.padding(vertical = 4.dp)
                            )
                        }
                    }
                }
            )
        }

        if (memoryStatus.protectedRegions.isNotEmpty()) {
            StatusCard(
                title = "Защищенные регионы",
                content = {
                    LazyColumn(
                        modifier = Modifier.height(100.dp)
                    ) {
                        items(memoryStatus.protectedRegions) { region ->
                            Text(
                                text = region,
                                style = MaterialTheme.typography.bodyMedium,
                                modifier = Modifier.padding(vertical = 4.dp)
                            )
                        }
                    }
                }
            )
        }

        Button(
            onClick = {
                protectionStatus = sdk.isProtected()
                memoryStatus = sdk.getProtectionStatus()
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Проверить статус")
        }

        Button(
            onClick = {
                val isBeingDebugged = sdk.isBeingDebugged()
                debugStatus = if (isBeingDebugged) {
                    showDebuggerDetectedDialog = true
                    "Обнаружен отладчик!"
                } else {
                    "Отладчик не обнаружен"
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Проверить статус отладки")
        }
        
        Button(
            onClick = {
                isMonitoringDebug = !isMonitoringDebug
                if (!isMonitoringDebug) {
                    debugStatus = "Мониторинг остановлен"
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(if (isMonitoringDebug) "Остановить мониторинг отладки" else "Начать мониторинг отладки")
        }

        Button(
            onClick = {
                sdk.stopProtection()
                protectionStatus = sdk.isProtected()
                memoryStatus = sdk.getProtectionStatus()
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Остановить защиту")
        }

        Button(
            onClick = {
                sdk.initialize()
                protectionStatus = sdk.isProtected()
                memoryStatus = sdk.getProtectionStatus()
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Запустить защиту")
        }
        
        Button(
            onClick = {
                val intent = android.content.Intent(sdk.getContext(), MemoryTestActivity::class.java)
                intent.addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK)
                sdk.getContext().startActivity(intent)
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Тест защиты памяти")
        }

        Text(
            text = "Тест обнаружения root",
            style = MaterialTheme.typography.headlineMedium
        )
        Spacer(modifier = Modifier.height(16.dp))
        Text(
            text = rootStatus,
            style = MaterialTheme.typography.bodyLarge
        )
        
        Spacer(modifier = Modifier.height(32.dp))
    }
}

@Composable
fun StatusCard(
    title: String,
    status: String? = null,
    statusColor: androidx.compose.ui.graphics.Color = MaterialTheme.colorScheme.primary,
    content: @Composable (() -> Unit)? = null
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.Start
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleMedium
            )
            if (status != null) {
                Text(
                    text = status,
                    style = MaterialTheme.typography.bodyLarge,
                    color = statusColor
                )
            }
            content?.invoke()
        }
    }
}