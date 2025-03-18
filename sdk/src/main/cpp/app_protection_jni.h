#ifndef APP_PROTECTION_JNI_H
#define APP_PROTECTION_JNI_H

#include <jni.h>
#include "memory_monitor.h"

#ifdef __cplusplus
extern "C" {
#endif

JNIEXPORT jlong JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeCreate(JNIEnv* env, jobject thiz);

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeDestroy(JNIEnv* env, jobject thiz, jlong handle);

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeStartMonitoring(JNIEnv* env, jobject thiz, jlong handle);

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeStopMonitoring(JNIEnv* env, jobject thiz, jlong handle);

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeIsMonitoring(JNIEnv* env, jobject thiz, jlong handle);

JNIEXPORT jobject JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeGetCriticalRegions(JNIEnv* env, jobject thiz, jlong handle);

JNIEXPORT jobject JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeGetProtectedRegions(JNIEnv* env, jobject thiz, jlong handle);

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeScanMemoryRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region);

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeCompareMemoryRegions(JNIEnv* env, jobject thiz, jlong handle, jstring region1, jstring region2);

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeAddCriticalRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region);

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeRemoveCriticalRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region);

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeProtectMemoryRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region);

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeUnprotectMemoryRegion(JNIEnv* env, jobject thiz, jlong handle, jstring region);

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeSimulateMemoryTampering(JNIEnv* env, jobject thiz, jlong handle, jstring region);

JNIEXPORT jboolean JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeScanAllProtectedRegions(JNIEnv* env, jobject thiz, jlong handle);

JNIEXPORT void JNICALL
Java_com_appprotection_sdk_internal_MemoryMonitor_nativeSetTamperingCallback(JNIEnv* env, jobject thiz, jlong handle, jobject callback);

#ifdef __cplusplus
}
#endif

#endif