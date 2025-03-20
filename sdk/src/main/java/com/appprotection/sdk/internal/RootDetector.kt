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

import android.content.Context
import android.os.Build
import android.util.Log
import java.io.File

/**
 * Detects if the device is rooted or has root access
 * Uses multiple detection methods to identify root indicators
 */
class RootDetector(private val context: Context) {
    companion object {
        private const val TAG = "RootDetector"
        private val ROOT_PATHS = arrayOf(
            "/system/app/Superuser.apk",
            "/system/xbin/su",
            "/system/bin/su",
            "/sbin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/data/local/su"
        )
    }

    private var isDetecting = false

    /**
     * Starts the root detection process
     * Does nothing if detection is already active
     */
    fun startDetection() {
        if (isDetecting) {
            return
        }

        isDetecting = true
        Log.d(TAG, "Root detection started")
    }

    /**
     * Stops the root detection process
     * Does nothing if detection is not active
     */
    fun stopDetection() {
        if (!isDetecting) {
            return
        }

        isDetecting = false
        Log.d(TAG, "Root detection stopped")
    }

    /**
     * Checks if root detection is currently active
     * @return true if detection is active, false otherwise
     */
    fun isDetecting(): Boolean = isDetecting

    /**
     * Checks if the device is rooted using multiple detection methods
     * @return true if any root indicator is detected, false otherwise
     */
    fun isDeviceRooted(): Boolean {
        return try {
            checkRootPaths() ||
            checkBuildTags() ||
            checkTestKeys() ||
            checkSuExists() ||
            checkRootPackages() ||
            checkRootCloakingApps()
        } catch (e: Exception) {
            Log.e(TAG, "Error checking for root", e)
            false
        }
    }

    /**
     * Checks for the existence of common root-related files and directories
     * @return true if any root path exists, false otherwise
     */
    private fun checkRootPaths(): Boolean {
        return ROOT_PATHS.any { File(it).exists() }
    }

    /**
     * Checks if the device build tags indicate a test or development build
     * @return true if test-keys are present in build tags, false otherwise
     */
    private fun checkBuildTags(): Boolean {
        return Build.TAGS != null && Build.TAGS.contains("test-keys")
    }

    /**
     * Checks if the device build type indicates a test or debug build
     * @return true if build type contains "test" or "debug", false otherwise
     */
    private fun checkTestKeys(): Boolean {
        return Build.TYPE.contains("test") || Build.TYPE.contains("debug")
    }

    /**
     * Checks if the su binary can be executed
     * @return true if su command can be executed, false otherwise
     */
    private fun checkSuExists(): Boolean {
        return try {
            Runtime.getRuntime().exec("su")
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * Checks for the presence of known root management packages
     * @return true if any root package is installed, false otherwise
     */
    private fun checkRootPackages(): Boolean {
        val rootPackages = arrayOf(
            "com.noshufou.android.su",
            "com.thirdparty.superuser",
            "eu.chainfire.supersu",
            "com.topjohnwu.magisk"
        )

        return context.packageManager.getInstalledPackages(0)
            .any { packageInfo ->
                rootPackages.contains(packageInfo.packageName)
            }
    }

    /**
     * Checks for the presence of known root cloaking applications
     * @return true if any root cloaking app is installed, false otherwise
     */
    private fun checkRootCloakingApps(): Boolean {
        val cloakingApps = arrayOf(
            "com.koushikdutta.superuser",
            "com.kingroot.kinguser",
            "com.kingo.root",
            "com.smedialink.oneclickroot"
        )

        return context.packageManager.getInstalledPackages(0)
            .any { packageInfo ->
                cloakingApps.contains(packageInfo.packageName)
            }
    }
} 