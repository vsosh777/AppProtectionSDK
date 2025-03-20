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

#include "app_protection_jni.h"
#include <android/log.h>
#include <vector>
#include <map>

#define TAG "AppProtectionJNI"

struct TamperingCallbackInfo {
    jobject callbackObj;
    jmethodID methodId;
};

std::map<jlong, TamperingCallbackInfo> g_callbackMap;

JavaVM* g_jvm = nullptr;

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    g_jvm = vm;
    return JNI_VERSION_1_6;
}

void jniTamperingCallback(const std::string& region, const std::string& details, jlong handle) {
    JNIEnv* env;
    jint result = g_jvm->GetEnv((void**)&env, JNI_VERSION_1_6);
    if (result == JNI_EDETACHED) {
        if (g_jvm->AttachCurrentThread(&env, NULL) != 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to attach thread for tampering callback");
            return;
        }
    } else if (result != JNI_OK) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get JNI environment for tampering callback");
        return;
    }

    auto it = g_callbackMap.find(handle);
    if (it == g_callbackMap.end() || it->second.callbackObj == NULL) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "No tampering callback registered for handle: %lld", handle);
        if (result == JNI_EDETACHED) {
            g_jvm->DetachCurrentThread();
        }
        return;
    }

    TamperingCallbackInfo& callbackInfo = it->second;

    jstring jRegion = env->NewStringUTF(region.c_str());
    jstring jDetails = env->NewStringUTF(details.c_str());

    env->CallVoidMethod(callbackInfo.callbackObj, callbackInfo.methodId, jRegion, jDetails);

    env->DeleteLocalRef(jRegion);
    env->DeleteLocalRef(jDetails);

    if (env->ExceptionCheck()) {
        env->ExceptionDescribe();
        env->ExceptionClear();
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Exception occurred during tampering callback");
    }

    if (result == JNI_EDETACHED) {
        g_jvm->DetachCurrentThread();
    }
}

static MemoryMonitor* getMemoryMonitor(jlong handle) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Getting monitor for handle: %lld", handle);
    return reinterpret_cast<MemoryMonitor*>(handle);
}

JNIEXPORT jlong JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeCreate(JNIEnv* env, jobject thiz) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Creating new MemoryMonitor");
    MemoryMonitor* monitor = new MemoryMonitor();
    jlong handle = reinterpret_cast<jlong>(monitor);
    __android_log_print(ANDROID_LOG_INFO, TAG, "Created monitor with handle: %lld", handle);
    return handle;
}

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeDestroy(JNIEnv* env, jobject thiz, jlong handle) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Destroying monitor with handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (monitor) {
        delete monitor;
        __android_log_print(ANDROID_LOG_INFO, TAG, "Monitor destroyed successfully");
    } else {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to destroy monitor - handle is null");
    }
}

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeStartMonitoring(JNIEnv* env, jobject thiz, jlong handle) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Starting monitoring for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to start monitoring - monitor is null");
        return JNI_FALSE;
    }
    bool result = monitor->startMonitoring();
    __android_log_print(ANDROID_LOG_INFO, TAG, "Monitoring start result: %d", result);
    return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeStopMonitoring(JNIEnv* env, jobject thiz, jlong handle) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Stopping monitoring for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (monitor) {
        monitor->stopMonitoring();
        __android_log_print(ANDROID_LOG_INFO, TAG, "Monitoring stopped successfully");
    } else {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to stop monitoring - monitor is null");
    }
}

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeIsMonitoring(JNIEnv* env, jobject thiz, jlong handle) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Checking monitoring status for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to check monitoring status - monitor is null");
        return JNI_FALSE;
    }
    bool result = monitor->isMonitoring();
    __android_log_print(ANDROID_LOG_INFO, TAG, "Monitoring status: %d", result);
    return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobject JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeGetCriticalRegions(JNIEnv* env, jobject thiz, jlong handle) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Getting critical regions for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get critical regions - monitor is null");
        jclass arrayListClass = env->FindClass("java/util/ArrayList");
        jmethodID constructor = env->GetMethodID(arrayListClass, "<init>", "()V");
        return env->NewObject(arrayListClass, constructor);
    }

    jclass arrayListClass = env->FindClass("java/util/ArrayList");
    jmethodID constructor = env->GetMethodID(arrayListClass, "<init>", "()V");
    jobject arrayList = env->NewObject(arrayListClass, constructor);
    jmethodID addMethod = env->GetMethodID(arrayListClass, "add", "(Ljava/lang/Object;)Z");

    std::vector<std::string> regions = monitor->getCriticalRegions();
    
    for (const auto& region : regions) {
        jstring jRegion = env->NewStringUTF(region.c_str());
        env->CallBooleanMethod(arrayList, addMethod, jRegion);
        env->DeleteLocalRef(jRegion);
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "Returning %zu critical regions", regions.size());
    return arrayList;
}

JNIEXPORT jobject JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeGetProtectedRegions(JNIEnv* env, jobject thiz, jlong handle) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Getting protected regions for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get protected regions - monitor is null");
        jclass arrayListClass = env->FindClass("java/util/ArrayList");
        jmethodID constructor = env->GetMethodID(arrayListClass, "<init>", "()V");
        return env->NewObject(arrayListClass, constructor);
    }

    jclass arrayListClass = env->FindClass("java/util/ArrayList");
    jmethodID constructor = env->GetMethodID(arrayListClass, "<init>", "()V");
    jobject arrayList = env->NewObject(arrayListClass, constructor);
    jmethodID addMethod = env->GetMethodID(arrayListClass, "add", "(Ljava/lang/Object;)Z");

    std::vector<std::string> regions = monitor->getProtectedRegions();
    
    for (const auto& region : regions) {
        jstring jRegion = env->NewStringUTF(region.c_str());
        env->CallBooleanMethod(arrayList, addMethod, jRegion);
        env->DeleteLocalRef(jRegion);
    }

    __android_log_print(ANDROID_LOG_INFO, TAG, "Returning %zu protected regions", regions.size());
    return arrayList;
}

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeScanMemoryRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Scanning memory region for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to scan memory region - monitor is null");
        return JNI_FALSE;
    }

    const char* regionStr = env->GetStringUTFChars(region, nullptr);
    bool result = monitor->scanMemoryRegion(regionStr);
    env->ReleaseStringUTFChars(region, regionStr);
    __android_log_print(ANDROID_LOG_INFO, TAG, "Memory region scan result: %d", result);
    return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeCompareMemoryRegions(JNIEnv* env, jobject thiz, jlong handle, jstring region1, jstring region2) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Comparing memory regions for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to compare memory regions - monitor is null");
        return JNI_FALSE;
    }

    const char* region1Str = env->GetStringUTFChars(region1, nullptr);
    const char* region2Str = env->GetStringUTFChars(region2, nullptr);
    bool result = monitor->compareMemoryRegions(region1Str, region2Str);
    env->ReleaseStringUTFChars(region1, region1Str);
    env->ReleaseStringUTFChars(region2, region2Str);
    __android_log_print(ANDROID_LOG_INFO, TAG, "Memory regions comparison result: %d", result);
    return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeAddCriticalRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Adding critical region for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to add critical region - monitor is null");
        return;
    }

    const char* regionStr = env->GetStringUTFChars(region, nullptr);
    monitor->addCriticalRegion(regionStr);
    env->ReleaseStringUTFChars(region, regionStr);
    __android_log_print(ANDROID_LOG_INFO, TAG, "Critical region added successfully");
}

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeRemoveCriticalRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Removing critical region for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to remove critical region - monitor is null");
        return;
    }

    const char* regionStr = env->GetStringUTFChars(region, nullptr);
    monitor->removeCriticalRegion(regionStr);
    env->ReleaseStringUTFChars(region, regionStr);
    __android_log_print(ANDROID_LOG_INFO, TAG, "Critical region removed successfully");
}

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeProtectMemoryRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Protecting memory region for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to protect memory region - monitor is null");
        return JNI_FALSE;
    }

    const char* regionStr = env->GetStringUTFChars(region, nullptr);
    bool result = monitor->protectMemoryRegion(regionStr);
    env->ReleaseStringUTFChars(region, regionStr);
    __android_log_print(ANDROID_LOG_INFO, TAG, "Memory region protection result: %d", result);
    return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeUnprotectMemoryRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Unprotecting memory region for handle: %lld", handle);
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to unprotect memory region - monitor is null");
        return JNI_FALSE;
    }

    const char* regionStr = env->GetStringUTFChars(region, nullptr);
    bool result = monitor->unprotectMemoryRegion(regionStr);
    env->ReleaseStringUTFChars(region, regionStr);
    __android_log_print(ANDROID_LOG_INFO, TAG, "Memory region unprotection result: %d", result);
    return result ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeSimulateMemoryTampering(
        JNIEnv *env, jobject thiz, jlong handle, jstring region) {
    __android_log_print(ANDROID_LOG_INFO, "MemoryMonitorJNI", "Simulating memory tampering with handle: %lld", (long long)handle);
    
    MemoryMonitor* monitor = reinterpret_cast<MemoryMonitor*>(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, "MemoryMonitorJNI", "Invalid memory monitor handle");
        return JNI_FALSE;
    }
    
    const char* regionCStr = env->GetStringUTFChars(region, nullptr);
    std::string regionStr(regionCStr);
    env->ReleaseStringUTFChars(region, regionCStr);
    
    bool result = monitor->simulateMemoryTampering(regionStr);
    
    __android_log_print(ANDROID_LOG_INFO, "MemoryMonitorJNI", "Memory tampering simulation result: %s", 
                        result ? "success" : "failed");
    
    return result ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeSetTamperingCallback(
        JNIEnv* env, jobject thiz, jlong handle, jobject callback) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Setting tampering callback for handle: %lld", handle);
    
    MemoryMonitor* monitor = getMemoryMonitor(handle);
    if (!monitor) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to set tampering callback - monitor is null");
        return;
    }
    
    auto it = g_callbackMap.find(handle);
    if (it != g_callbackMap.end() && it->second.callbackObj != NULL) {
        env->DeleteGlobalRef(it->second.callbackObj);
        g_callbackMap.erase(it);
    }
    
    if (callback == NULL) {
        monitor->setTamperingCallback(nullptr);
        __android_log_print(ANDROID_LOG_INFO, TAG, "Tampering callback cleared for handle: %lld", handle);
        return;
    }
    
    jclass callbackClass = env->GetObjectClass(callback);
    if (callbackClass == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get callback class");
        return;
    }
    
    jmethodID methodId = env->GetMethodID(callbackClass, "onTamperingDetected", "(Ljava/lang/String;Ljava/lang/String;)V");
    if (methodId == NULL) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get onTamperingDetected method");
        env->DeleteLocalRef(callbackClass);
        return;
    }
    
    jobject globalCallback = env->NewGlobalRef(callback);
    
    TamperingCallbackInfo callbackInfo;
    callbackInfo.callbackObj = globalCallback;
    callbackInfo.methodId = methodId;
    g_callbackMap[handle] = callbackInfo;
    
    monitor->setTamperingCallback([handle](const std::string& region, const std::string& details) {
        jniTamperingCallback(region, details, handle);
    });
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "Tampering callback set successfully for handle: %lld", handle);
    env->DeleteLocalRef(callbackClass);
} 