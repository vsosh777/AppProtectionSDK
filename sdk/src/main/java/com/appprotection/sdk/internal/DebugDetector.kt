package com.appprotection.sdk.internal

import android.app.ActivityManager
import android.content.Context
import android.os.Debug
import android.util.Log
import java.io.BufferedReader
import java.io.File
import java.io.FileReader

/**
 * Detects if the application is being debugged or if debugging tools are attached
 * Provides various methods to check for different debugging indicators
 */
class DebugDetector(private val context: Context) {
    companion object {
        private const val TAG = "DebugDetector"
    }

    private var isDetecting = false

    /**
     * Starts the debug detection process
     * Does nothing if detection is already active
     */
    fun startDetection() {
        if (isDetecting) {
            return
        }

        isDetecting = true
        Log.d(TAG, "Debug detection started")
    }

    /**
     * Stops the debug detection process
     * Does nothing if detection is not active
     */
    fun stopDetection() {
        if (!isDetecting) {
            return
        }

        isDetecting = false
        Log.d(TAG, "Debug detection stopped")
    }

    /**
     * Checks if debug detection is currently active
     * @return true if detection is active, false otherwise
     */
    fun isDetecting(): Boolean = isDetecting

    /**
     * Checks if the application is currently being debugged using multiple detection methods
     * @return true if any debugging indicator is detected, false otherwise
     */
    fun isBeingDebugged(): Boolean {
        return try {
            checkDebuggerConnected() ||
            checkDebuggerAttached() ||
            checkDebuggerPort() ||
            checkDebuggerProcess() ||
            checkDebuggerTracerPid()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking for debugger", e)
            false
        }
    }

    /**
     * Checks if a debugger is connected using Android's Debug API
     * @return true if a debugger is connected, false otherwise
     */
    private fun checkDebuggerConnected(): Boolean {
        return Debug.isDebuggerConnected()
    }

    /**
     * Checks for debugger attachment by attempting a debug-only operation
     * @return true if a debugger is attached, false otherwise
     */
    private fun checkDebuggerAttached(): Boolean {
        return try {
            Debug.threadCpuTimeNanos()
            false
        } catch (e: Exception) {
            true
        }
    }

    /**
     * Checks for common debugger ports in use
     * @return true if any debugger port is in use, false otherwise
     */
    private fun checkDebuggerPort(): Boolean {
        return try {
            val ports = arrayOf(23946, 23947, 23948)
            ports.any { port ->
                File("/proc/net/tcp").readLines().any { line ->
                    line.contains(":$port")
                }
            }
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Checks for debugger processes running on the device
     * @return true if any debugger process is detected, false otherwise
     */
    private fun checkDebuggerProcess(): Boolean {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val runningProcesses = activityManager.runningAppProcesses

        return runningProcesses?.any { processInfo ->
            processInfo.processName.contains("debug") ||
            processInfo.processName.contains("gdb") ||
            processInfo.processName.contains("lldb") ||
            processInfo.processName.contains("ida")
        } ?: false
    }

    /**
     * Checks for a tracer process attached to the application
     * @return true if a tracer process is detected, false otherwise
     */
    private fun checkDebuggerTracerPid(): Boolean {
        return try {
            val reader = BufferedReader(FileReader("/proc/self/status"))
            val lines = reader.readLines()
            reader.close()

            val tracerPidLine = lines.find { it.startsWith("TracerPid:") }
            tracerPidLine?.let {
                val pid = it.substringAfter(":").trim().toIntOrNull()
                pid != null && pid > 0
            } ?: false
        } catch (e: Exception) {
            false
        }
    }
} 