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

#ifndef APP_PROTECTION_MEMORY_MONITOR_H
#define APP_PROTECTION_MEMORY_MONITOR_H

#include <jni.h>
#include <string>
#include <vector>
#include <functional>
#include <map>
#include <set>

typedef std::function<void(const std::string&, const std::string&)> TamperingCallback;

class MemoryMonitor {
public:
    MemoryMonitor();
    ~MemoryMonitor();

    bool startMonitoring();
    void stopMonitoring();
    bool isMonitoring() const;
    
    bool scanMemoryRegion(const std::string& region);
    bool compareMemoryRegions(const std::string& region1, const std::string& region2);
    bool scanAllProtectedRegions();
    
    void addCriticalRegion(const std::string& region);
    void removeCriticalRegion(const std::string& region);
    const std::vector<std::string>& getCriticalRegions() const;
    
    bool protectMemoryRegion(const std::string& region);
    bool unprotectMemoryRegion(const std::string& region);
    const std::vector<std::string>& getProtectedRegions() const;
    
    bool isSystemFile(const std::string& path) const;
    bool scanSystemFile(const std::string& path);
    
    bool simulateMemoryTampering(const std::string& region);
    
    void setTamperingCallback(TamperingCallback callback);
    
    void notifyTampering(const std::string& region, const std::string& details);

private:
    bool is_monitoring_;
    std::vector<std::string> critical_regions_;
    std::vector<std::string> protected_regions_;
    TamperingCallback tampering_callback_;
    std::map<std::string, std::set<std::string>> system_file_critical_lines_;
    
    bool readMemoryRegion(const std::string& region, void* buffer, size_t size);
    bool writeMemoryRegion(const std::string& region, const void* buffer, size_t size);
    bool getMemoryRegionInfo(const std::string& region, void* info);
    
    bool extractCriticalLines(const std::string& path, std::string& content);
};

#endif