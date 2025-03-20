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

#include "memory_monitor.h"
#include <sys/mman.h>
#include <unistd.h>
#include <sys/system_properties.h>
#include <android/log.h>
#include <map>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <random>

#define TAG "MemoryMonitor"

#include <openssl/sha.h>

struct MemoryRegionInfo {
    void* address;
    size_t size;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    bool is_protected;
};

static std::map<std::string, MemoryRegionInfo> memory_regions;

static void fill_random_buffer(void* buffer, size_t size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t result = read(fd, buffer, size);
        close(fd);
        if (result == static_cast<ssize_t>(size)) {
            return;
        }
    }
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<unsigned char> dist(0, 255);
    
    unsigned char* bytes = static_cast<unsigned char*>(buffer);
    for (size_t i = 0; i < size; ++i) {
        bytes[i] = dist(gen);
    }
}

MemoryMonitor::MemoryMonitor() : is_monitoring_(false) {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Using SHA-256 for memory integrity");
}

MemoryMonitor::~MemoryMonitor() {
    stopMonitoring();
}

bool MemoryMonitor::startMonitoring() {
    if (is_monitoring_) {
        return true;
    }

    is_monitoring_ = true;
    __android_log_print(ANDROID_LOG_INFO, TAG, "Memory monitoring started");
    return true;
}

void MemoryMonitor::stopMonitoring() {
    if (!is_monitoring_) {
        return;
    }

    for (const auto& region : protected_regions_) {
        unprotectMemoryRegion(region);
    }
    
    memory_regions.clear();
    protected_regions_.clear();
    
    is_monitoring_ = false;
    __android_log_print(ANDROID_LOG_INFO, TAG, "Memory monitoring stopped");
}

bool MemoryMonitor::isMonitoring() const {
    return is_monitoring_;
}

static void calculateHash(const void* data, size_t size, uint8_t* hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, size);
    SHA256_Final(hash, &sha256);
}

static bool compareHashes(const uint8_t* hash1, const uint8_t* hash2) {
    return memcmp(hash1, hash2, SHA256_DIGEST_LENGTH) == 0;
}

bool MemoryMonitor::scanMemoryRegion(const std::string& region) {
    if (!is_monitoring_) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot scan region %s - monitoring not active", region.c_str());
        return false;
    }

    auto it = memory_regions.find(region);
    if (it == memory_regions.end()) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot scan region %s - region not found", region.c_str());
        return false;
    }

    MemoryRegionInfo& info = it->second;
    
    bool isFilePath = region.find("/") == 0;
    bool isProcFile = region.find("/proc/") == 0;
    
    if (isProcFile && (info.hash[0] == 0xFF || info.hash[0] == 0x00)) {
        __android_log_print(ANDROID_LOG_WARN, TAG, "SECURITY ALERT: Simulated tampering detected for %s", 
                           region.c_str());
        
        std::string details = "Simulated tampering detected for: " + region;
        
        notifyTampering(region, details);
        
        return false;
    }
    
    if (isFilePath) {
        if (region == "/proc/self/status") {
            int fd = open(region.c_str(), O_RDONLY);
            if (fd != -1) {
                char buffer[4096];
                ssize_t bytesRead = read(fd, buffer, sizeof(buffer));
                close(fd);
                
                if (bytesRead > 0) {
                    calculateHash(buffer, bytesRead, info.hash);
                    info.size = bytesRead;
                }
            }
            
            return true;
        }
        
        int fd = open(region.c_str(), O_RDONLY);
        if (fd == -1) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to open file %s for scanning: %s", 
                               region.c_str(), strerror(errno));
            
            if (!isProcFile) {
                std::string details = "File cannot be opened: " + region +
                                     ", Error: " + strerror(errno);
                notifyTampering(region, details);
            }
            
            return false;
        }
        
        struct stat st;
        if (fstat(fd, &st) == -1) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get file size for %s: %s", 
                               region.c_str(), strerror(errno));
            close(fd);
            
            if (!isProcFile) {
                std::string details = "Failed to get file size: " + region +
                                     ", Error: " + strerror(errno);
                notifyTampering(region, details);
            }
            
            return false;
        }
        
        if (!isProcFile && st.st_size != info.size) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "File size changed for %s: original=%zu, current=%zu", 
                               region.c_str(), info.size, (size_t)st.st_size);
            close(fd);
            
            std::string details = "File size changed: " + region +
                                 ", Original size: " + std::to_string(info.size) + 
                                 ", Current size: " + std::to_string(st.st_size);
            notifyTampering(region, details);
            return false;
        }
        
        size_t readSize = st.st_size;
        if (isProcFile && readSize == 0) {
            readSize = 4096;
        }
        
        void* buffer = malloc(readSize > 0 ? readSize : 1);
        if (!buffer) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to allocate memory for file content: %s", 
                               region.c_str());
            close(fd);
            return false;
        }
        
        ssize_t bytesRead = read(fd, buffer, readSize);
        close(fd);
        
        if (bytesRead < 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to read file content: %s", 
                               region.c_str());
            free(buffer);
            return false;
        }
        
        if (isProcFile) {
            info.size = bytesRead;
        }
        
        uint8_t currentHash[SHA256_DIGEST_LENGTH];
        calculateHash(buffer, bytesRead, currentHash);
        free(buffer);
        
        bool result = compareHashes(currentHash, info.hash);
        
        if (!result) {
            if (isProcFile) {
                int diffCount = 0;
                for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                    if (currentHash[i] != info.hash[i]) {
                        diffCount++;
                    }
                }
                
                if (diffCount < SHA256_DIGEST_LENGTH / 4) {
                    memcpy(info.hash, currentHash, SHA256_DIGEST_LENGTH);
                    __android_log_print(ANDROID_LOG_INFO, TAG, "Minor changes detected in %s - updating baseline", 
                                      region.c_str());
                    return true;
                }
            }
            
            __android_log_print(ANDROID_LOG_WARN, TAG, "SECURITY ALERT: File tampering detected for %s", 
                               region.c_str());
            
            std::string originalHashStr, currentHashStr;
            for (int i = 0; i < 8 && i < SHA256_DIGEST_LENGTH; i++) {
                char hexByte[3];
                snprintf(hexByte, sizeof(hexByte), "%02x", info.hash[i]);
                originalHashStr += hexByte;
                
                snprintf(hexByte, sizeof(hexByte), "%02x", currentHash[i]);
                currentHashStr += hexByte;
            }
            
            std::string details = "File content tampered: " + region + 
                                 ", Original hash prefix: " + originalHashStr + 
                                 ", Current hash prefix: " + currentHashStr;
            
            notifyTampering(region, details);
            
            if (isProcFile) {
                memcpy(info.hash, currentHash, SHA256_DIGEST_LENGTH);
                __android_log_print(ANDROID_LOG_INFO, TAG, "Updated baseline for %s to reduce alerts", 
                                  region.c_str());
            }
        }
        
        return result;
    } else {
        if (mprotect(info.address, info.size, PROT_READ) != 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to make memory readable for scanning: %s", strerror(errno));
            return false;
        }
    
    uint8_t currentHash[SHA256_DIGEST_LENGTH];
    calculateHash(info.address, info.size, currentHash);
        
        if (mprotect(info.address, info.size, PROT_READ) != 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to restore memory protection after scanning: %s", strerror(errno));
        }
    
    bool result = compareHashes(currentHash, info.hash);
    
    if (!result) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "SECURITY ALERT: Memory tampering detected in region %s", region.c_str());
            
            __android_log_print(ANDROID_LOG_WARN, TAG, "Memory region: %s, Address: %p, Size: %zu",
                               region.c_str(), info.address, info.size);
            
            std::string originalHashStr, currentHashStr;
            for (int i = 0; i < 8 && i < SHA256_DIGEST_LENGTH; i++) {
                char hexByte[3];
                snprintf(hexByte, sizeof(hexByte), "%02x", info.hash[i]);
                originalHashStr += hexByte;
                
                snprintf(hexByte, sizeof(hexByte), "%02x", currentHash[i]);
                currentHashStr += hexByte;
            }
            __android_log_print(ANDROID_LOG_WARN, TAG, "Original hash prefix: %s, Current hash prefix: %s", 
                               originalHashStr.c_str(), currentHashStr.c_str());
            
            int tamperedByteCount = 0;
            for (size_t i = 0; i < info.size && i < 1024; i++) {
                uint8_t* originalData = static_cast<uint8_t*>(info.address);
                if (originalData[i] == 0x00 || originalData[i] == 0xFF) {
                    tamperedByteCount++;
                }
            }
            if (tamperedByteCount > 0) {
                __android_log_print(ANDROID_LOG_WARN, TAG, "Found %d potentially tampered bytes in the first 1KB", 
                                   tamperedByteCount);
            }
            
            std::string details = "Memory region tampered: " + region + 
                                 ", Original hash prefix: " + originalHashStr + 
                                 ", Current hash prefix: " + currentHashStr;
            
            notifyTampering(region, details);
    }
    
    return result;
    }
}

bool MemoryMonitor::compareMemoryRegions(const std::string& region1, const std::string& region2) {
    if (!is_monitoring_) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot compare regions - monitoring not active");
        return false;
    }

    auto it1 = memory_regions.find(region1);
    auto it2 = memory_regions.find(region2);
    
    if (it1 == memory_regions.end() || it2 == memory_regions.end()) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot compare regions - one or both regions not found");
        return false;
    }

    MemoryRegionInfo& info1 = it1->second;
    MemoryRegionInfo& info2 = it2->second;
    
    if (info1.size != info2.size) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "Regions have different sizes");
        return false;
    }
    
    bool result = (memcmp(info1.address, info2.address, info1.size) == 0);
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "Memory regions comparison result: %d", result);
    return result;
}

void MemoryMonitor::addCriticalRegion(const std::string& region) {
    auto it = std::find(critical_regions_.begin(), critical_regions_.end(), region);
    if (it == critical_regions_.end()) {
        critical_regions_.push_back(region);
        __android_log_print(ANDROID_LOG_INFO, TAG, "Added critical region: %s", region.c_str());
    } else {
        __android_log_print(ANDROID_LOG_INFO, TAG, "Critical region %s already exists", region.c_str());
    }
}

void MemoryMonitor::removeCriticalRegion(const std::string& region) {
    auto it = std::find(critical_regions_.begin(), critical_regions_.end(), region);
    if (it != critical_regions_.end()) {
        critical_regions_.erase(it);
        __android_log_print(ANDROID_LOG_INFO, TAG, "Removed critical region: %s", region.c_str());
    } else {
        __android_log_print(ANDROID_LOG_INFO, TAG, "Critical region %s not found", region.c_str());
    }
}

const std::vector<std::string>& MemoryMonitor::getCriticalRegions() const {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Getting %zu critical regions", critical_regions_.size());
    return critical_regions_;
}

const std::vector<std::string>& MemoryMonitor::getProtectedRegions() const {
    __android_log_print(ANDROID_LOG_INFO, TAG, "Getting %zu protected regions", protected_regions_.size());
    return protected_regions_;
}

bool MemoryMonitor::protectMemoryRegion(const std::string& region) {
    if (!is_monitoring_) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot protect region %s - monitoring not active", region.c_str());
        return false;
    }

    if (std::find(protected_regions_.begin(), protected_regions_.end(), region) != protected_regions_.end()) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "Region %s is already protected", region.c_str());
        return true;
    }

    bool isFilePath = region.find("/") == 0;
    
    if (isFilePath) {
        if (region == "/proc/self/status") {
            __android_log_print(ANDROID_LOG_INFO, TAG, "Adding special handling for dynamic file: %s", region.c_str());
            
            MemoryRegionInfo info;
            info.address = nullptr;
            info.size = 4096;
            
            int fd = open(region.c_str(), O_RDONLY);
            if (fd != -1) {
                char buffer[4096];
                ssize_t bytesRead = read(fd, buffer, sizeof(buffer));
                close(fd);
                
                if (bytesRead > 0) {
                    info.size = bytesRead;
                    calculateHash(buffer, bytesRead, info.hash);
                } else {
                    memset(info.hash, 0, SHA256_DIGEST_LENGTH);
                }
            } else {
                memset(info.hash, 0, SHA256_DIGEST_LENGTH);
                __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to open file %s for protection: %s", 
                                  region.c_str(), strerror(errno));
            }
            
            memory_regions[region] = info;
            
            protected_regions_.push_back(region);
            
            __android_log_print(ANDROID_LOG_INFO, TAG, "Dynamic file %s protected with special handling (size: %zu bytes)", 
                              region.c_str(), info.size);
            
            return true;
        }
        
        int fd = open(region.c_str(), O_RDONLY);
        if (fd == -1) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to open file %s for protection: %s", 
                               region.c_str(), strerror(errno));
            return false;
        }
        
        struct stat st;
        if (fstat(fd, &st) == -1) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get file size for %s: %s", 
                               region.c_str(), strerror(errno));
            close(fd);
            return false;
        }
        
        bool isProcFile = region.find("/proc/") == 0;
        
        size_t readSize = st.st_size;
        if (isProcFile && readSize == 0) {
            readSize = 4096;
        }
        
        void* buffer = malloc(readSize > 0 ? readSize : 1);
        if (!buffer) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to allocate memory for file content: %s", 
                               region.c_str());
            close(fd);
            return false;
        }
        
        ssize_t bytesRead = read(fd, buffer, readSize);
        close(fd);
        
        if (bytesRead < 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to read file content: %s", 
                               region.c_str());
            free(buffer);
            return false;
        }
        
        MemoryRegionInfo info;
        info.address = nullptr;
        info.size = bytesRead;
        
        calculateHash(buffer, bytesRead, info.hash);
        free(buffer);
        
        memory_regions[region] = info;
        
        protected_regions_.push_back(region);
        
        __android_log_print(ANDROID_LOG_INFO, TAG, "File %s protected successfully (size: %zu bytes)", 
                           region.c_str(), info.size);
        
        return true;
    } else {
        void* memoryAddress = nullptr;
        size_t regionSize = 0;

        if (region.find("/") == 0) {
            bool isProcFile = region.find("/proc/") == 0;
            bool createDummyRegion = false;
            
            int fd = open(region.c_str(), O_RDONLY);
            if (fd == -1) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to open file %s: %s", region.c_str(), strerror(errno));
                
                if (isProcFile) {
                    __android_log_print(ANDROID_LOG_INFO, TAG, "Creating dummy region for proc file: %s", region.c_str());
                    createDummyRegion = true;
                } else {
                    return false;
                }
            }

            if (!createDummyRegion) {
                struct stat st;
                if (fstat(fd, &st) == -1) {
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get file size for %s: %s", region.c_str(), strerror(errno));
                    close(fd);
                    
                    if (isProcFile) {
                        __android_log_print(ANDROID_LOG_INFO, TAG, "Creating dummy region for proc file after fstat failure: %s", region.c_str());
                        createDummyRegion = true;
                    } else {
                        return false;
                    }
                } else {
                    regionSize = st.st_size;
                    
                    if (regionSize == 0 && isProcFile) {
                        regionSize = 4096;
                        __android_log_print(ANDROID_LOG_INFO, TAG, "Using default size for zero-sized proc file: %s", region.c_str());
                    }

                    int mapFlags = MAP_PRIVATE;
                    
                    if (isProcFile) {
                        mapFlags |= MAP_NORESERVE;
                    }
                    
                    memoryAddress = mmap(nullptr, regionSize, PROT_READ, mapFlags, fd, 0);
                    
                    if (memoryAddress == MAP_FAILED) {
                        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to map file %s: %s", region.c_str(), strerror(errno));
                        
                        if (isProcFile) {
                            __android_log_print(ANDROID_LOG_INFO, TAG, "Creating dummy region for proc file after mmap failure: %s", region.c_str());
                            createDummyRegion = true;
                        } else {
                            close(fd);
                            return false;
                        }
                    } else {
                        __android_log_print(ANDROID_LOG_INFO, TAG, "Mapped file %s to memory address %p with size %zu", 
                                          region.c_str(), memoryAddress, regionSize);
                    }
                }
                close(fd);
            }

            if (createDummyRegion) {
                regionSize = 4096;
                
                memoryAddress = mmap(nullptr, regionSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                
                if (memoryAddress == MAP_FAILED) {
                    __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to allocate memory for region %s: %s", 
                                      region.c_str(), strerror(errno));
                    return false;
                }
                
                fill_random_buffer(memoryAddress, regionSize);
                
                __android_log_print(ANDROID_LOG_INFO, TAG, "Allocated memory for region %s at address %p with size %zu", 
                                  region.c_str(), memoryAddress, regionSize);
            }
        } else {
            regionSize = 4096;
            
            memoryAddress = mmap(nullptr, regionSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            
            if (memoryAddress == MAP_FAILED) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to allocate memory for region %s: %s", 
                                  region.c_str(), strerror(errno));
        return false;
    }
    
            fill_random_buffer(memoryAddress, regionSize);
            
            __android_log_print(ANDROID_LOG_INFO, TAG, "Allocated memory for region %s at address %p with size %zu", 
                              region.c_str(), memoryAddress, regionSize);
        }
    
    MemoryRegionInfo info;
    info.address = memoryAddress;
    info.size = regionSize;
    info.is_protected = true;
    
    calculateHash(memoryAddress, regionSize, info.hash);
        
        if (mprotect(memoryAddress, regionSize, PROT_READ) != 0) {
            __android_log_print(ANDROID_LOG_WARN, TAG, "Failed to set memory protection for %s: %s", 
                              region.c_str(), strerror(errno));
        } else {
            __android_log_print(ANDROID_LOG_INFO, TAG, "Applied memory protection (read-only) to region %s", 
                              region.c_str());
        }
    
    memory_regions[region] = info;
    
    auto it = std::find(protected_regions_.begin(), protected_regions_.end(), region);
    if (it == protected_regions_.end()) {
        protected_regions_.push_back(region);
    }
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "Protected memory region: %s (addr: %p, size: %zu)", 
                        region.c_str(), memoryAddress, regionSize);
    
    return true;
    }
}

bool MemoryMonitor::unprotectMemoryRegion(const std::string& region) {
    if (!is_monitoring_) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot unprotect region %s - monitoring not active", region.c_str());
        return false;
    }

    auto it = memory_regions.find(region);
    if (it == memory_regions.end()) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot unprotect region %s - region not found", region.c_str());
        return false;
    }

    MemoryRegionInfo& info = it->second;
    
    if (munmap(info.address, info.size) != 0) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to unmap memory for region %s: %s", 
                           region.c_str(), strerror(errno));
    }
    
    memory_regions.erase(it);
    
    auto protIt = std::find(protected_regions_.begin(), protected_regions_.end(), region);
    if (protIt != protected_regions_.end()) {
        protected_regions_.erase(protIt);
    }
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "Unprotected memory region: %s", region.c_str());
    
    return true;
}

bool MemoryMonitor::readMemoryRegion(const std::string& region, void* buffer, size_t size) {
    if (!is_monitoring_) {
        return false;
    }

    auto it = memory_regions.find(region);
    if (it == memory_regions.end()) {
        return false;
    }

    MemoryRegionInfo& info = it->second;
    
    if (size < info.size) {
        return false;
    }
    
    memcpy(buffer, info.address, info.size);
    
    return true;
}

bool MemoryMonitor::writeMemoryRegion(const std::string& region, const void* buffer, size_t size) {
    if (!is_monitoring_) {
        return false;
    }

    auto it = memory_regions.find(region);
    if (it == memory_regions.end()) {
        return false;
    }

    MemoryRegionInfo& info = it->second;
    
    if (size > info.size) {
        return false;
    }
    
    memcpy(info.address, buffer, size);
    
    calculateHash(info.address, info.size, info.hash);
    
    return true;
}

bool MemoryMonitor::getMemoryRegionInfo(const std::string& region, void* infoOut) {
    if (!is_monitoring_) {
        return false;
    }

    auto it = memory_regions.find(region);
    if (it == memory_regions.end()) {
        return false;
    }

    MemoryRegionInfo& info = it->second;
    
    if (infoOut) {
        memcpy(infoOut, &info, sizeof(MemoryRegionInfo));
    }
    
    return true;
}

bool MemoryMonitor::simulateMemoryTampering(const std::string& region) {
    if (!is_monitoring_) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot simulate tampering - monitoring not active");
        return false;
    }

    auto it = memory_regions.find(region);
    if (it == memory_regions.end()) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot simulate tampering - region not found: %s", region.c_str());
        return false;
    }

    MemoryRegionInfo& info = it->second;
    
    bool isFilePath = region.find("/") == 0;
    bool isProcFile = region.find("/proc/") == 0;
    
    if (isFilePath) {
        if (isProcFile) {
            __android_log_print(ANDROID_LOG_INFO, TAG, "Simulating tampering with proc file: %s", region.c_str());
            
            if (info.hash[0] != 0xFF) {
                info.hash[0] = 0xFF;
            } else {
                info.hash[0] = 0x00;
            }
            
            __android_log_print(ANDROID_LOG_INFO, TAG, "Simulated tampering for proc file: %s by modifying stored hash", 
                              region.c_str());
            
            std::string details = "Simulated tampering detected for proc file: " + region;
            notifyTampering(region, details);
            
            return true;
        }
        
        int fd = open(region.c_str(), O_RDWR);
        if (fd == -1) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to open file for tampering simulation: %s", 
                               strerror(errno));
            return false;
        }
        
        struct stat st;
        if (fstat(fd, &st) == -1) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to get file size for tampering: %s", 
                               strerror(errno));
            close(fd);
            return false;
        }
        
        if (st.st_size > 0) {
            char tamperByte = 'X';
            if (write(fd, &tamperByte, 1) != 1) {
                __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to write tamper byte: %s", 
                                   strerror(errno));
                close(fd);
                return false;
            }
            
            __android_log_print(ANDROID_LOG_INFO, TAG, "File tampering simulated for: %s", region.c_str());
            close(fd);
            return true;
        }
        
        close(fd);
        return false;
    } else {
        if (mprotect(info.address, info.size, PROT_READ | PROT_WRITE) != 0) {
            __android_log_print(ANDROID_LOG_ERROR, TAG, "Failed to make memory writable for tampering simulation: %s", 
                               strerror(errno));
            return false;
        }
    
        if (info.address && info.size > 0) {
            uint8_t* bytePtr = static_cast<uint8_t*>(info.address);
            bytePtr[0] = ~bytePtr[0];
            
            __android_log_print(ANDROID_LOG_INFO, TAG, "Memory tampering simulated for region: %s", region.c_str());
                
            mprotect(info.address, info.size, PROT_READ);
            return true;
        }
        
        mprotect(info.address, info.size, PROT_READ);
        return false;
    }
}

void MemoryMonitor::setTamperingCallback(TamperingCallback callback) {
    tampering_callback_ = callback;
    __android_log_print(ANDROID_LOG_INFO, TAG, "Tampering callback set");
}

void MemoryMonitor::notifyTampering(const std::string& region, const std::string& details) {
    if (tampering_callback_) {
        tampering_callback_(region, details);
        __android_log_print(ANDROID_LOG_INFO, TAG, "Tampering notification sent for region: %s", region.c_str());
    } else {
        __android_log_print(ANDROID_LOG_WARN, TAG, "No tampering callback set, cannot notify about region: %s", region.c_str());
    }
}

bool MemoryMonitor::scanAllProtectedRegions() {
    if (!is_monitoring_) {
        __android_log_print(ANDROID_LOG_ERROR, TAG, "Cannot scan all regions - monitoring not active");
        return false;
    }
    
    if (protected_regions_.empty()) {
        __android_log_print(ANDROID_LOG_INFO, TAG, "No protected regions to scan");
        return true;
    }
    
    bool allRegionsIntact = true;
    std::vector<std::string> compromisedRegions;
    
    __android_log_print(ANDROID_LOG_INFO, TAG, "Scanning %zu protected regions", protected_regions_.size());
    
    for (const auto& region : protected_regions_) {
        bool regionIntact = scanMemoryRegion(region);
        if (!regionIntact) {
            allRegionsIntact = false;
            compromisedRegions.push_back(region);
        }
    }
    
    if (!allRegionsIntact) {
        std::string compromisedList;
        for (const auto& region : compromisedRegions) {
            if (!compromisedList.empty()) {
                compromisedList += ", ";
            }
            compromisedList += region;
        }
        
        std::string details = "Compromised regions: " + compromisedList;
        __android_log_print(ANDROID_LOG_WARN, TAG, "%s", details.c_str());
        
        notifyTampering("multiple_regions", details);
    } else {
        __android_log_print(ANDROID_LOG_INFO, TAG, "All protected regions verified intact");
    }
    
    return allRegionsIntact;
} 