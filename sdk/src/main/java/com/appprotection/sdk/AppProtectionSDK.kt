package com.appprotection.sdk

import android.content.Context
import android.util.Log
import com.appprotection.sdk.internal.MemoryMonitor
import com.appprotection.sdk.internal.RootDetector
import com.appprotection.sdk.internal.DebugDetector
import com.appprotection.sdk.internal.SecurityConfig
import com.appprotection.sdk.internal.ProtectionStatus
import com.appprotection.sdk.internal.ProtectionLevel
import com.appprotection.sdk.internal.TamperingCallback

/**
 * Main SDK class for application protection features
 * 
 * This class provides a comprehensive set of security features to protect Android applications:
 * - Memory tampering detection
 * - Root detection
 * - Debug detection
 * - Memory region protection
 * 
 * The SDK follows a singleton pattern and should be initialized with a security configuration.
 */
class AppProtectionSDK private constructor(
    private val context: Context,
    private val config: SecurityConfig
) {
    private val memoryMonitor: MemoryMonitor = MemoryMonitor()
    private val rootDetector: RootDetector = RootDetector(context)
    private val debugDetector: DebugDetector = DebugDetector(context)
    
    /**
     * Interface for receiving tampering detection events.
     * Implement this interface to be notified when memory tampering is detected in the application.
     */
    interface TamperingListener {
        /**
         * Called when tampering is detected in a memory region.
         * This method is invoked whenever the SDK detects unauthorized modifications to protected memory regions.
         * 
         * @param region The name or identifier of the tampered region
         * @param details Additional details about the tampering, such as the type of modification detected
         */
        fun onTamperingDetected(region: String, details: String)
    }
    
    private val tamperingListeners = mutableListOf<TamperingListener>()

    companion object {
        private const val TAG = "AppProtectionSDK"
        private var instance: AppProtectionSDK? = null

        /**
         * Gets or creates the singleton instance of AppProtectionSDK
         * 
         * @param context The application context
         * @param config The security configuration for the SDK
         * @return The singleton instance of AppProtectionSDK
         */
        @JvmStatic
        fun getInstance(context: Context, config: SecurityConfig): AppProtectionSDK {
            return instance ?: synchronized(this) {
                instance ?: AppProtectionSDK(context.applicationContext, config).also { instance = it }
            }
        }
    }

    /**
     * Initializes the SDK with the tampering callback
     * Sets up the internal callback to notify registered listeners when tampering is detected
     */
    init {
        memoryMonitor.setTamperingCallback(object : TamperingCallback {
            override fun onTamperingDetected(region: String, details: String) {
                Log.w(TAG, "Memory tampering detected in region: $region")
                Log.w(TAG, "Details: $details")
                
                synchronized(tamperingListeners) {
                    tamperingListeners.forEach { listener ->
                        try {
                            listener.onTamperingDetected(region, details)
                        } catch (e: Exception) {
                            Log.e(TAG, "Error notifying tampering listener", e)
                        }
                    }
                }
                
                when (config.protectionLevel) {
                    ProtectionLevel.HIGH -> {
                        Log.w(TAG, "HIGH protection level: App would be terminated in production")
                    }
                    ProtectionLevel.MEDIUM -> {
                        Log.w(TAG, "MEDIUM protection level: Wiping sensitive data")
                    }
                    else -> {
                        Log.w(TAG, "LOW protection level: Logging incident only")
                    }
                }
            }
        })
    }

    /**
     * Initializes the SDK protection features
     * 
     * This method should be called after getting the SDK instance to start the protection features.
     * It sets up critical memory regions and starts the protection mechanisms based on the configuration.
     */
    fun initialize() {
        Log.d(TAG, "Initializing AppProtectionSDK")
        
        config.criticalMemoryRegions.forEach { region ->
            memoryMonitor.addCriticalRegion(region)
            Log.d(TAG, "Added critical region: $region")
        }
        
        startProtection()
        
        if (config.enableMemoryMonitoring && config.memoryScanInterval > 0) {
            memoryMonitor.startPeriodicScanning(config.memoryScanInterval)
            Log.d(TAG, "Started periodic memory scanning with interval: ${config.memoryScanInterval}ms")
        }
    }

    /**
     * Starts all protection mechanisms based on the configuration
     * 
     * Enables memory monitoring, root detection, and debug detection if they are enabled in the configuration.
     */
    private fun startProtection() {
        if (config.enableMemoryMonitoring) {
            memoryMonitor.startMonitoring()
        }

        if (config.enableRootDetection) {
            rootDetector.startDetection()
        }

        if (config.enableDebugDetection) {
            debugDetector.startDetection()
        }
    }

    /**
     * Stops all protection mechanisms
     * 
     * This method stops memory monitoring, root detection, and debug detection.
     * Call this method when protection is no longer needed or when the application is shutting down.
     */
    fun stopProtection() {
        memoryMonitor.stopMonitoring()
        rootDetector.stopDetection()
        debugDetector.stopDetection()
    }

    /**
     * Checks if protection is currently active
     * 
     * @return true if all enabled protection mechanisms are active, false otherwise
     */
    fun isProtected(): Boolean {
        return memoryMonitor.isMonitoring() &&
               rootDetector.isDetecting() &&
               debugDetector.isDetecting()
    }

    /**
     * Gets the current protection status
     * 
     * @return A ProtectionStatus object containing the status of all protection mechanisms
     */
    fun getProtectionStatus(): ProtectionStatus {
        return ProtectionStatus(
            memoryMonitoring = memoryMonitor.isMonitoring(),
            rootDetection = rootDetector.isDetecting(),
            debugDetection = debugDetector.isDetecting(),
            criticalRegions = memoryMonitor.getCriticalRegions(),
            protectedRegions = memoryMonitor.getProtectedRegions()
        )
    }

    /**
     * Checks if the device is rooted
     * 
     * @return true if the device is rooted, false otherwise
     */
    fun isDeviceRooted(): Boolean {
        return rootDetector.isDeviceRooted()
    }

    /**
     * Checks if the application is being debugged
     * 
     * @return true if the application is being debugged, false otherwise
     */
    fun isBeingDebugged(): Boolean {
        return debugDetector.isBeingDebugged()
    }

    /**
     * Gets the memory monitor instance
     * 
     * This method provides access to the underlying memory monitor for advanced usage.
     * 
     * @return The MemoryMonitor instance
     */
    fun getMemoryMonitor(): MemoryMonitor {
        return memoryMonitor
    }
    
    /**
     * Gets the application context
     * 
     * @return The application context
     */
    fun getContext(): Context {
        return context
    }
    
    /**
     * Add a listener to be notified when tampering is detected.
     * Multiple listeners can be added to receive tampering notifications.
     * 
     * @param listener The listener to be notified when tampering is detected
     */
    fun addTamperingListener(listener: TamperingListener) {
        synchronized(tamperingListeners) {
            tamperingListeners.add(listener)
        }
    }
    
    /**
     * Remove a tampering listener.
     * The listener will no longer receive tampering notifications.
     * 
     * @param listener The listener to be removed
     */
    fun removeTamperingListener(listener: TamperingListener) {
        synchronized(tamperingListeners) {
            tamperingListeners.remove(listener)
        }
    }
    
    /**
     * Protect a sensitive memory region
     * 
     * This method adds protection to a specific memory region to detect tampering.
     * 
     * @param regionName The name or identifier of the memory region to protect
     * @return true if the region was successfully protected, false otherwise
     */
    fun protectMemoryRegion(regionName: String): Boolean {
        return memoryMonitor.protectMemoryRegion(regionName)
    }
    
    /**
     * Scan all protected memory regions for tampering
     * 
     * This method performs an immediate scan of all protected memory regions to check for tampering.
     * 
     * @return true if all regions are intact, false if any tampering is detected
     */
    fun scanAllProtectedRegions(): Boolean {
        return memoryMonitor.scanAllProtectedRegions()
    }
} 