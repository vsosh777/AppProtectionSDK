# Руководство по интеграции AppProtectionSDK

## Содержание
1. [Подготовка проекта](#подготовка-проекта)
2. [Базовая интеграция](#базовая-интеграция)
3. [Расширенная настройка](#расширенная-настройка)
4. [Обработка событий безопасности](#обработка-событий-безопасности)
5. [Рекомендации по безопасности](#рекомендации-по-безопасности)
6. [Устранение неполадок](#устранение-неполадок)

## Подготовка проекта

### Требования к системе
- Android Studio Arctic Fox или новее
- Android SDK API 21 или выше
- Gradle 7.0 или выше
- Kotlin 1.8 или выше
- NDK (рекомендуется версия 21.4.7075529 или выше)

### Настройка Gradle

1. Добавьте репозиторий в `settings.gradle.kts`:
```kotlin
dependencyResolutionManagement {
    repositories {
        // Добавьте репозиторий с SDK
        maven { url = uri("https://your-repository-url") }
    }
}
```

2. Добавьте зависимость в `build.gradle.kts` уровня приложения:
```kotlin
dependencies {
    implementation("com.appprotection:sdk:1.0.0")
}
```

3. Настройте NDK в `local.properties`:
```properties
ndk.dir=/path/to/your/ndk
```

## Базовая интеграция

### 1. Инициализация SDK

Добавьте инициализацию SDK в ваше главное приложение (Application класс):

```kotlin
class MyApplication : Application() {
    private lateinit var appProtectionSDK: AppProtectionSDK

    override fun onCreate() {
        super.onCreate()
        
        // Создание базовой конфигурации
        val config = SecurityConfig(
            memoryScanInterval = 1000L,
            criticalMemoryRegions = listOf("sensitive_data"),
            enableRootDetection = true,
            enableDebugDetection = true,
            enableMemoryMonitoring = true,
            protectionLevel = ProtectionLevel.HIGH
        )

        // Инициализация SDK
        appProtectionSDK = AppProtectionSDK.getInstance(this, config)
        appProtectionSDK.initialize()
    }

    override fun onTerminate() {
        super.onTerminate()
        appProtectionSDK.stopProtection()
    }
}
```

### 2. Регистрация Application класса

Добавьте в `AndroidManifest.xml`:

```xml
<application
    android:name=".MyApplication"
    ...>
    <!-- Остальные компоненты -->
</application>
```

## Расширенная настройка

### Настройка уровней защиты

SDK предоставляет три уровня защиты:

```kotlin
enum class ProtectionLevel {
    LOW,    // Только логирование
    MEDIUM, // Очистка данных + логирование
    HIGH    // Завершение приложения + очистка данных + логирование
}
```

### Настройка критических регионов памяти

```kotlin
val config = SecurityConfig(
    criticalMemoryRegions = listOf(
        "user_credentials",
        "encryption_keys",
        "sensitive_data"
    ),
    // Другие настройки...
)
```

### Настройка интервалов сканирования

```kotlin
val config = SecurityConfig(
    memoryScanInterval = 500L, // Сканирование каждые 500мс
    // Другие настройки...
)
```

## Обработка событий безопасности

### 1. Реализация слушателя событий

```kotlin
class SecurityManager(private val context: Context) {
    private val sdk: AppProtectionSDK = // получение экземпляра SDK

    init {
        sdk.addTamperingListener(object : AppProtectionSDK.TamperingListener {
            override fun onTamperingDetected(region: String, details: String) {
                when (sdk.getProtectionLevel()) {
                    ProtectionLevel.HIGH -> handleHighLevelThreat(region, details)
                    ProtectionLevel.MEDIUM -> handleMediumLevelThreat(region, details)
                    ProtectionLevel.LOW -> handleLowLevelThreat(region, details)
                }
            }
        })
    }

    private fun handleHighLevelThreat(region: String, details: String) {
        // 1. Логирование
        Log.e("Security", "Критическая угроза в регионе: $region")
        
        // 2. Очистка данных
        clearSensitiveData()
        
        // 3. Завершение приложения
        (context as? Activity)?.finish()
    }

    private fun handleMediumLevelThreat(region: String, details: String) {
        // 1. Логирование
        Log.w("Security", "Угроза в регионе: $region")
        
        // 2. Очистка данных
        clearSensitiveData()
    }

    private fun handleLowLevelThreat(region: String, details: String) {
        // Только логирование
        Log.i("Security", "Подозрительная активность в регионе: $region")
    }
}
```

### 2. Мониторинг статуса защиты

```kotlin
class SecurityMonitor {
    private val sdk: AppProtectionSDK = // получение экземпляра SDK

    fun checkSecurityStatus() {
        val status = sdk.getProtectionStatus()
        
        if (!status.memoryMonitoring) {
            Log.w("Security", "Мониторинг памяти неактивен")
        }
        
        if (status.rootDetection) {
            Log.w("Security", "Обнаружен root-доступ")
        }
        
        if (status.debugDetection) {
            Log.w("Security", "Обнаружен режим отладки")
        }
    }
}
```

## Рекомендации по безопасности

1. **Инициализация SDK**
   - Инициализируйте SDK как можно раньше в жизненном цикле приложения
   - Используйте Application класс для инициализации
   - Проверяйте статус инициализации перед использованием защищенных функций

2. **Уровни защиты**
   - Используйте HIGH уровень для критически важных данных
   - MEDIUM уровень подходит для большинства приложений
   - LOW уровень рекомендуется только для тестирования

3. **Критические регионы**
   - Определяйте только действительно важные регионы памяти
   - Избегайте избыточного мониторинга
   - Регулярно обновляйте список защищаемых регионов

4. **Обработка событий**
   - Реализуйте надежную систему логирования
   - Обеспечьте безопасное хранение логов
   - Рассмотрите возможность отправки логов на сервер

## Устранение неполадок

### Частые проблемы

1. **SDK не инициализируется**
   - Проверьте правильность конфигурации Gradle
   - Убедитесь, что NDK установлен и настроен
   - Проверьте логи на наличие ошибок инициализации

2. **Ложные срабатывания**
   - Проверьте настройки интервалов сканирования
   - Убедитесь, что критические регионы определены корректно
   - Проверьте настройки уровня защиты

3. **Проблемы с производительностью**
   - Уменьшите частоту сканирования памяти
   - Оптимизируйте список критических регионов
   - Используйте профилирование для выявления узких мест

### Получение поддержки

При возникновении проблем:
1. Проверьте документацию
2. Изучите примеры кода
3. Создайте issue в репозитории проекта
4. Обратитесь в службу поддержки 