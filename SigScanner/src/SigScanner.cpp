#define NOMINMAX
#include "SigScanner.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <fstream>
#include <array>
#include <unordered_map>

#ifdef _WIN32
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#pragma comment(lib, "Psapi.lib")
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#endif

#ifdef _MSC_VER
#include <intrin.h> 

inline uint32_t builtin_ctz(uint32_t x) {
    unsigned long index;
    if (_BitScanForward(&index, x)) {
        return static_cast<uint32_t>(index);
    }
    return 32;
}
#else
inline uint32_t builtin_ctz(uint32_t x) {
    return __builtin_ctz(x);
}
#endif

namespace scan {

    SigPattern::SigPattern(const std::string& pattern) {
        Parse(pattern);
    }

    SigPattern::SigPattern(const char* pattern) {
        Parse(std::string(pattern));
    }

    SigPattern::SigPattern(const std::vector<byte_t>& bytes) {
        m_pattern.reserve(bytes.size());
        for (const auto& byte : bytes) {
            m_pattern.emplace_back(byte, true);
        }
        m_size = m_pattern.size();

        std::stringstream ss;
        for (const auto& [byte, exact] : m_pattern) {
            if (exact) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
            }
            else {
                ss << "? ";
            }
        }
        m_sig_str = ss.str();
    }

    SigPattern::SigPattern(const std::vector<std::pair<byte_t, bool>>& pattern) : m_pattern(pattern) {
        m_size = m_pattern.size();

        std::stringstream ss;
        for (const auto& [byte, exact] : m_pattern) {
            if (exact) {
                ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
            }
            else {
                ss << "? ";
            }
        }
        m_sig_str = ss.str();
    }

    void SigPattern::Parse(const std::string& pattern) {
        m_pattern.clear();
        m_sig_str = pattern;

        std::istringstream ss(pattern);
        std::string token;
        while (ss >> token) {
            if (token == "?" || token == "??") {
                m_pattern.emplace_back(0, false);
            }
            else {
                byte_t value = static_cast<byte_t>(std::stoi(token, nullptr, 16));
                m_pattern.emplace_back(value, true);
            }
        }

        m_size = m_pattern.size();
    }

    void SigPattern::Prepare() {
        if (m_prepared) return;

        m_mask_bytes.resize(m_size);
        m_val_bytes.resize(m_size);

        for (std::size_t i = 0; i < m_size; ++i) {
            m_mask_bytes[i] = m_pattern[i].second ? 0xFF : 0x00;
            m_val_bytes[i] = m_pattern[i].first;
        }

        std::array<byte_t, 32> first_bytes{};
        std::array<byte_t, 32> first_mask{};

        for (std::size_t i = 0; i < std::min<std::size_t>(32, m_size); ++i) {
            first_bytes[i] = m_val_bytes[i];
            first_mask[i] = m_mask_bytes[i];
        }

        m_first_bytes_avx = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(first_bytes.data()));
        m_first_mask_avx = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(first_mask.data()));

        m_first_bytes_sse = _mm_loadu_si128(reinterpret_cast<const __m128i*>(first_bytes.data()));
        m_first_mask_sse = _mm_loadu_si128(reinterpret_cast<const __m128i*>(first_mask.data()));

        m_prepared = true;
    }

    bool SigPattern::Match(const byte_t* data, std::size_t length) const {
        if (!data || length < m_size) return false;

        for (std::size_t i = 0; i < m_size; ++i) {
            if (m_pattern[i].second && data[i] != m_pattern[i].first) {
                return false;
            }
        }

        return true;
    }

    bool SigPattern::MatchAVX2(const byte_t* data, std::size_t length) const {
        if (!m_prepared || !data || length < m_size) return false;

        if (m_size <= 32) {
            __m256i data_vec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data));
            __m256i masked_data = _mm256_and_si256(data_vec, m_first_mask_avx);
            __m256i masked_pattern = _mm256_and_si256(m_first_bytes_avx, m_first_mask_avx);
            __m256i cmp = _mm256_cmpeq_epi8(masked_data, masked_pattern);

            uint32_t mask = _mm256_movemask_epi8(cmp);
            uint32_t required = (1U << std::min<std::size_t>(32, m_size)) - 1;

            return (mask & required) == required;
        }

        if (!Match(data, 32)) return false;

        return Match(data, length);
    }

    bool SigPattern::MatchSSE(const byte_t* data, std::size_t length) const {
        if (!m_prepared || !data || length < m_size) return false;

        if (m_size <= 16) {
            __m128i data_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(data));
            __m128i masked_data = _mm_and_si128(data_vec, m_first_mask_sse);
            __m128i masked_pattern = _mm_and_si128(m_first_bytes_sse, m_first_mask_sse);
            __m128i cmp = _mm_cmpeq_epi8(masked_data, masked_pattern);

            uint16_t mask = _mm_movemask_epi8(cmp);
            uint16_t required = (1U << std::min<std::size_t>(16, m_size)) - 1;

            return (mask & required) == required;
        }

        if (!Match(data, 16)) return false;

        return Match(data, length);
    }

    const std::vector<std::pair<byte_t, bool>>& SigPattern::GetPattern() const {
        return m_pattern;
    }

    const std::string& SigPattern::GetSigString() const {
        return m_sig_str;
    }

    std::size_t SigPattern::Size() const {
        return m_size;
    }

    bool SigPattern::IsPrepared() const {
        return m_prepared;
    }

    const byte_t* SigPattern::MaskBytes() const {
        return m_mask_bytes.data();
    }

    const byte_t* SigPattern::ValBytes() const {
        return m_val_bytes.data();
    }

    const __m256i& SigPattern::FirstBytesAVX() const {
        return m_first_bytes_avx;
    }

    const __m256i& SigPattern::FirstMaskAVX() const {
        return m_first_mask_avx;
    }

    const __m128i& SigPattern::FirstBytesSSE() const {
        return m_first_bytes_sse;
    }

    const __m128i& SigPattern::FirstMaskSSE() const {
        return m_first_mask_sse;
    }

    address_t ScanResult::Follow() const {
        return Read<address_t>();
    }

    address_t ScanResult::ResolveRelative(std::size_t instruction_size) const {
        int32_t rel_offset = Read<int32_t>();
        return address + instruction_size + rel_offset;
    }

    ProcessMemory::ProcessMemory() : m_pid(0), m_handle(nullptr) {}

    ProcessMemory::ProcessMemory(std::uint32_t pid) : m_pid(0), m_handle(nullptr) {
        Initialize(pid);
    }

    ProcessMemory::ProcessMemory(const std::string& process_name) : m_pid(0), m_handle(nullptr) {
        Initialize(process_name);
    }

    ProcessMemory::~ProcessMemory() {
#ifdef _WIN32
        if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }
#endif
    }

    bool ProcessMemory::Initialize(std::uint32_t pid) {
        m_pid = pid;
        m_regions.clear();

#ifdef _WIN32
        if (m_handle && m_handle != INVALID_HANDLE_VALUE) {
            CloseHandle(m_handle);
        }

        m_handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (!m_handle || m_handle == INVALID_HANDLE_VALUE) {
            return false;
        }

        MEMORY_BASIC_INFORMATION mbi{};
        address_t address = 0;

        while (VirtualQueryEx(m_handle, reinterpret_cast<void*>(address), &mbi, sizeof(mbi))) {
            if ((mbi.State & MEM_COMMIT) && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE))) {
                m_regions.emplace_back(reinterpret_cast<address_t>(mbi.BaseAddress), mbi.RegionSize);
            }

            address = reinterpret_cast<address_t>(mbi.BaseAddress) + mbi.RegionSize;
        }
#else
        std::string path = "/proc/" + std::to_string(pid) + "/maps";
        std::ifstream maps(path);
        if (!maps.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(maps, line)) {
            std::istringstream iss(line);

            std::string range;
            iss >> range;

            std::size_t dash = range.find('-');
            if (dash == std::string::npos) continue;

            address_t start = std::stoull(range.substr(0, dash), nullptr, 16);
            address_t end = std::stoull(range.substr(dash + 1), nullptr, 16);

            std::string perms;
            iss >> perms;

            if (perms[0] == 'r') {
                m_regions.emplace_back(start, end - start);
            }
        }

        m_handle = reinterpret_cast<void*>(1);
#endif

        m_initialized = true;
        return true;
    }

    bool ProcessMemory::Initialize(const std::string& process_name) {
#ifdef _WIN32
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(entry);

        if (!Process32First(snapshot, &entry)) {
            CloseHandle(snapshot);
            return false;
        }

        std::uint32_t pid = 0;
        do {
            char narrow_name[MAX_PATH] = { 0 };
            WideCharToMultiByte(CP_ACP, 0, entry.szExeFile, -1,
                narrow_name, sizeof(narrow_name), NULL, NULL);
            std::string name = narrow_name;

            if (name == process_name) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));

        CloseHandle(snapshot);

        if (pid == 0) {
            return false;
        }

        return Initialize(pid);
#else
        DIR* dir = opendir("/proc");
        if (!dir) {
            return false;
        }

        std::uint32_t pid = 0;
        struct dirent* entry;

        while ((entry = readdir(dir)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;

            std::string name = entry->d_name;
            if (!std::all_of(name.begin(), name.end(), ::isdigit)) continue;

            std::string cmd_path = "/proc/" + name + "/cmdline";
            std::ifstream cmd_file(cmd_path);
            if (!cmd_file.is_open()) continue;

            std::string cmd;
            std::getline(cmd_file, cmd);

            std::size_t pos = cmd.rfind('/');
            if (pos != std::string::npos) {
                cmd = cmd.substr(pos + 1);
            }

            if (cmd == process_name) {
                pid = std::stoul(name);
                break;
            }
        }

        closedir(dir);

        if (pid == 0) {
            return false;
        }

        return Initialize(pid);
#endif
    }

    std::vector<region_t> ProcessMemory::GetRegions() const {
        return m_regions;
    }

    bool ProcessMemory::ReadMemory(address_t address, void* buffer, std::size_t size) const {
        if (!m_initialized || !buffer || size == 0) {
            return false;
        }

#ifdef _WIN32
        SIZE_T read;
        return ReadProcessMemory(m_handle, reinterpret_cast<void*>(address), buffer, size, &read) && read == size;
#else
        std::string mem_path = "/proc/" + std::to_string(m_pid) + "/mem";
        int fd = open(mem_path.c_str(), O_RDONLY);
        if (fd == -1) {
            return false;
        }

        bool result = lseek(fd, address, SEEK_SET) != -1 && read(fd, buffer, size) == static_cast<ssize_t>(size);
        close(fd);

        return result;
#endif
    }

    result_t<std::vector<byte_t>> ProcessMemory::ReadRegion(const region_t& region) const {
        if (!m_initialized) {
            return std::nullopt;
        }

        std::vector<byte_t> buffer(region.second);
        if (!ReadMemory(region.first, buffer.data(), region.second)) {
            return std::nullopt;
        }

        return buffer;
    }

    bool ProcessMemory::IsValid() const {
        return m_initialized && m_handle != nullptr;
    }

    std::uint32_t ProcessMemory::GetPID() const {
        return m_pid;
    }

    void* ProcessMemory::GetHandle() const {
        return m_handle;
    }

    // Modified ModuleMemory implementation
    ModuleMemory::ModuleMemory() : m_base(0), m_size(0) {}

    ModuleMemory::ModuleMemory(const ProcessMemory& process, const std::string& module_name) : m_base(0), m_size(0) {
        Initialize(process, module_name);
    }

    ModuleMemory::ModuleMemory(address_t base, std::size_t size, const std::string& name, const ProcessMemory& process)
        : m_base(base), m_size(size), m_name(name) {
        Initialize(base, size, name, process);
    }

    bool ModuleMemory::Initialize(const ProcessMemory& process, const std::string& module_name) {
#ifdef _WIN32
        HMODULE modules[1024];
        DWORD cbNeeded;

        if (!EnumProcessModules(process.GetHandle(), modules, sizeof(modules), &cbNeeded)) {
            return false;
        }

        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char modName[MAX_PATH];
            if (GetModuleBaseNameA(process.GetHandle(), modules[i], modName, sizeof(modName))) {
                if (module_name == modName) {
                    MODULEINFO mi{};
                    if (GetModuleInformation(process.GetHandle(), modules[i], &mi, sizeof(mi))) {
                        m_base = reinterpret_cast<address_t>(mi.lpBaseOfDll);
                        m_size = mi.SizeOfImage;
                        m_name = module_name;
                        return Initialize(m_base, m_size, m_name, process);
                    }
                }
            }
        }
        return false;
#else
        // Linux implementation would need similar changes
        return false;
#endif
    }

    bool ModuleMemory::Initialize(address_t base, std::size_t size, const std::string& name, const ProcessMemory& process) {
        m_base = base;
        m_size = size;
        m_name = name;
        m_initialized = true;

        return LoadFromMemory(process);
    }

    bool ModuleMemory::LoadFromMemory(const ProcessMemory& process) {
        if (!m_initialized) {
            return false;
        }

        m_data.resize(m_size);

#ifdef _WIN32
        SIZE_T bytesRead;
        if (!ReadProcessMemory(process.GetHandle(), reinterpret_cast<void*>(m_base), m_data.data(), m_size, &bytesRead)) {
            return false;
        }
        return bytesRead > 0;
#else
        // Linux implementation would need similar changes
        return false;
#endif
    }

    bool ModuleMemory::LoadFromFile(const std::string& path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        if (!file.is_open()) {
            return false;
        }

        std::size_t size = file.tellg();
        file.seekg(0);

        m_data.resize(size);
        file.read(reinterpret_cast<char*>(m_data.data()), size);

        m_size = size;
        m_initialized = true;

        return true;
    }

    const std::vector<byte_t>& ModuleMemory::GetData() const {
        return m_data;
    }

    address_t ModuleMemory::GetBase() const {
        return m_base;
    }

    std::size_t ModuleMemory::GetSize() const {
        return m_size;
    }

    const std::string& ModuleMemory::GetName() const {
        return m_name;
    }

    bool ModuleMemory::IsValid() const {
        return m_initialized && !m_data.empty();
    }

    ThreadPool::ThreadPool(std::size_t thread_count) {
        m_threads.reserve(thread_count);
        for (std::size_t i = 0; i < thread_count; ++i) {
            m_threads.emplace_back([this]() {
                while (true) {
                    std::function<void()> job;

                    {
                        std::unique_lock<std::mutex> lock(m_mutex);
                        m_condition.wait(lock, [this]() { return m_stop || !m_jobs.empty(); });

                        if (m_stop && m_jobs.empty()) {
                            return;
                        }

                        job = std::move(m_jobs.back());
                        m_jobs.pop_back();
                    }

                    job();

                    {
                        std::lock_guard<std::mutex> lock(m_mutex);
                        m_active_jobs--;
                    }
                }
                });
        }
    }

    ThreadPool::~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(m_mutex);
            m_stop = true;
        }

        m_condition.notify_all();

        for (auto& thread : m_threads) {
            thread.join();
        }
    }

    void ThreadPool::Wait() {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_condition.wait(lock, [this]() { return m_active_jobs == 0; });
    }


    SigScanner::SigScanner() : m_thread_pool(std::thread::hardware_concurrency()) {}

    SigScanner::SigScanner(const ScanOptions& options) : m_options(options), m_thread_pool(options.thread_count) {}

    SigScanner::SigScanner(std::uint32_t pid, const ScanOptions& options) : m_options(options), m_thread_pool(options.thread_count) {
        Initialize(pid);
    }

    SigScanner::SigScanner(const std::string& process_name, const ScanOptions& options) : m_options(options), m_thread_pool(options.thread_count) {
        Initialize(process_name);
    }

    bool SigScanner::Initialize(std::uint32_t pid) {
        return m_process.Initialize(pid);
    }

    bool SigScanner::Initialize(const std::string& process_name) {
        return m_process.Initialize(process_name);
    }

    // Modified AddModule method to use the process handle
    bool SigScanner::AddModule(const std::string& module_name) {
        auto module = ModuleMemory(m_process, module_name);
        if (!module.IsValid()) {
            return false;
        }

        m_modules.push_back(std::move(module));
        return true;
    }

    // Modified AddModule method to use the process handle
    bool SigScanner::AddModule(address_t base, std::size_t size, const std::string& name) {
        auto module = ModuleMemory(base, size, name, m_process);
        if (!module.IsValid()) {
            return false;
        }

        m_modules.push_back(std::move(module));
        return true;
    }

    result_t<ScanResult> SigScanner::Scan(const SigPattern& pattern, const std::string& module_name) {
        if (!pattern.IsPrepared()) {
            SigPattern prepared_pattern = pattern;
            prepared_pattern.Prepare();
            return Scan(prepared_pattern, module_name);
        }

        if (!module_name.empty()) {
            auto it = std::find_if(m_modules.begin(), m_modules.end(), [&](const ModuleMemory& module) {
                return module.GetName() == module_name;
                });

            if (it != m_modules.end()) {
                const auto& module = *it;
                const auto& data = module.GetData();

                switch (m_options.type) {
                case ScanType::AVX2:
                    return ScanMemoryAVX2(data.data(), data.size(), pattern, module.GetBase());
                case ScanType::MultithreadAVX2:
                    return ScanMemoryMultithreaded(data.data(), data.size(), pattern, module.GetBase());
                default:
                    return ScanMemoryNormal(data.data(), data.size(), pattern, module.GetBase());
                }
            }
        }
        else {
            for (const auto& module : m_modules) {
                const auto& data = module.GetData();

                result_t<ScanResult> result;
                switch (m_options.type) {
                case ScanType::AVX2:
                    result = ScanMemoryAVX2(data.data(), data.size(), pattern, module.GetBase());
                    break;
                case ScanType::MultithreadAVX2:
                    result = ScanMemoryMultithreaded(data.data(), data.size(), pattern, module.GetBase());
                    break;
                default:
                    result = ScanMemoryNormal(data.data(), data.size(), pattern, module.GetBase());
                    break;
                }

                if (result) {
                    return result;
                }
            }
        }

        return std::nullopt;
    }

    result_t<ScanResult> SigScanner::Scan(const std::string& pattern, const std::string& module_name) {
        SigPattern sig_pattern(pattern);
        sig_pattern.Prepare();
        return Scan(sig_pattern, module_name);
    }

    std::vector<ScanResult> SigScanner::ScanAll(const SigPattern& pattern, const std::string& module_name) {
        if (!pattern.IsPrepared()) {
            SigPattern prepared_pattern = pattern;
            prepared_pattern.Prepare();
            return ScanAll(prepared_pattern, module_name);
        }

        std::vector<ScanResult> results;

        if (!module_name.empty()) {
            auto it = std::find_if(m_modules.begin(), m_modules.end(), [&](const ModuleMemory& module) {
                return module.GetName() == module_name;
                });

            if (it != m_modules.end()) {
                const auto& module = *it;
                const auto& data = module.GetData();

                std::vector<ScanResult> module_results;
                switch (m_options.type) {
                case ScanType::AVX2:
                    module_results = ScanAllMemoryAVX2(data.data(), data.size(), pattern, module.GetBase());
                    break;
                case ScanType::MultithreadAVX2:
                    module_results = ScanAllMemoryMultithreaded(data.data(), data.size(), pattern, module.GetBase());
                    break;
                default:
                    module_results = ScanAllMemoryNormal(data.data(), data.size(), pattern, module.GetBase());
                    break;
                }

                results.insert(results.end(), module_results.begin(), module_results.end());
            }
        }
        else {
            for (const auto& module : m_modules) {
                const auto& data = module.GetData();

                std::vector<ScanResult> module_results;
                switch (m_options.type) {
                case ScanType::AVX2:
                    module_results = ScanAllMemoryAVX2(data.data(), data.size(), pattern, module.GetBase());
                    break;
                case ScanType::MultithreadAVX2:
                    module_results = ScanAllMemoryMultithreaded(data.data(), data.size(), pattern, module.GetBase());
                    break;
                default:
                    module_results = ScanAllMemoryNormal(data.data(), data.size(), pattern, module.GetBase());
                    break;
                }

                for (auto& result : module_results) {
                    result.module_name = module.GetName();
                }

                results.insert(results.end(), module_results.begin(), module_results.end());
            }
        }

        if (m_options.reverse) {
            std::reverse(results.begin(), results.end());
        }

        return results;
    }

    std::vector<ScanResult> SigScanner::ScanAll(const std::string& pattern, const std::string& module_name) {
        SigPattern sig_pattern(pattern);
        sig_pattern.Prepare();
        return ScanAll(sig_pattern, module_name);
    }

    result_t<ScanResult> SigScanner::ScanMemoryNormal(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) const {
        if (!data || size == 0 || !pattern.IsPrepared() || pattern.Size() > size) {
            return std::nullopt;
        }

        std::size_t pattern_size = pattern.Size();

        for (std::size_t i = 0; i <= size - pattern_size; ++i) {
            if (pattern.Match(data + i, pattern_size)) {
                ScanResult result;
                result.address = base_address + i;
                result.offset = static_cast<offset_t>(i);

                if (m_options.relative) {
                    result.address = result.ResolveRelative(m_options.relative_offset);
                }

                return result;
            }
        }

        return std::nullopt;
    }

    result_t<ScanResult> SigScanner::ScanMemoryAVX2(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) const {
        if (!data || size == 0 || !pattern.IsPrepared() || pattern.Size() > size) {
            return std::nullopt;
        }

        std::size_t pattern_size = pattern.Size();

        for (std::size_t i = 0; i <= size - pattern_size; i += 32) {
            if (i + 32 <= size) {
                __m256i data_vec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
                __m256i masked_data = _mm256_and_si256(data_vec, pattern.FirstMaskAVX());
                __m256i masked_pattern = _mm256_and_si256(pattern.FirstBytesAVX(), pattern.FirstMaskAVX());
                __m256i cmp = _mm256_cmpeq_epi8(masked_data, masked_pattern);

                uint32_t mask = _mm256_movemask_epi8(cmp);

                if (mask != 0) {
                    uint32_t trailing_zeros = builtin_ctz(mask);

                    if (i + trailing_zeros + pattern_size <= size && pattern.Match(data + i + trailing_zeros, pattern_size)) {
                        ScanResult result;
                        result.address = base_address + i + trailing_zeros;
                        result.offset = static_cast<offset_t>(i + trailing_zeros);

                        if (m_options.relative) {
                            result.address = result.ResolveRelative(m_options.relative_offset);
                        }

                        return result;
                    }
                }
            }
            else {
                return ScanMemoryNormal(data + i, size - i, pattern, base_address + i);
            }
        }

        return std::nullopt;
    }

    result_t<ScanResult> SigScanner::ScanMemoryMultithreaded(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) {
        if (!data || size == 0 || !pattern.IsPrepared() || pattern.Size() > size) {
            return std::nullopt;
        }

        std::size_t chunk_size = m_options.chunk_size;
        std::size_t pattern_size = pattern.Size();
        std::size_t num_chunks = (size + chunk_size - 1) / chunk_size;

        std::mutex result_mutex;
        std::optional<ScanResult> final_result;
        std::atomic<bool> found(false);

        std::vector<std::future<void>> futures;
        futures.reserve(num_chunks);

        for (std::size_t chunk = 0; chunk < num_chunks && !found; ++chunk) {
            std::size_t start = chunk * chunk_size;
            std::size_t end = std::min(start + chunk_size, size);

            if (end - start < pattern_size) continue;

            futures.push_back(m_thread_pool.Enqueue([&, start, end]() {
                if (found) return;

                auto result = ScanMemoryAVX2(data + start, end - start, pattern, base_address + start);

                if (result) {
                    std::unique_lock<std::mutex> lock(result_mutex);
                    if (!found.exchange(true)) {
                        final_result = result;
                    }
                }
                }));
        }

        for (auto& future : futures) {
            future.wait();
        }

        return final_result;
    }

    std::vector<ScanResult> SigScanner::ScanAllMemoryNormal(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) const {
        std::vector<ScanResult> results;

        if (!data || size == 0 || !pattern.IsPrepared() || pattern.Size() > size) {
            return results;
        }

        std::size_t pattern_size = pattern.Size();

        for (std::size_t i = 0; i <= size - pattern_size; ++i) {
            if (pattern.Match(data + i, pattern_size)) {
                ScanResult result;
                result.address = base_address + i;
                result.offset = static_cast<offset_t>(i);

                if (m_options.relative) {
                    result.address = result.ResolveRelative(m_options.relative_offset);
                }

                results.push_back(result);
            }
        }

        return results;
    }

    std::vector<ScanResult> SigScanner::ScanAllMemoryAVX2(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) const {
        std::vector<ScanResult> results;

        if (!data || size == 0 || !pattern.IsPrepared() || pattern.Size() > size) {
            return results;
        }

        std::size_t pattern_size = pattern.Size();

        for (std::size_t i = 0; i <= size - pattern_size; i += 32) {
            if (i + 32 <= size) {
                __m256i data_vec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(data + i));
                __m256i masked_data = _mm256_and_si256(data_vec, pattern.FirstMaskAVX());
                __m256i masked_pattern = _mm256_and_si256(pattern.FirstBytesAVX(), pattern.FirstMaskAVX());
                __m256i cmp = _mm256_cmpeq_epi8(masked_data, masked_pattern);

                uint32_t mask = _mm256_movemask_epi8(cmp);

                while (mask != 0) {
                    uint32_t trailing_zeros = builtin_ctz(mask);

                    if (i + trailing_zeros + pattern_size <= size && pattern.Match(data + i + trailing_zeros, pattern_size)) {
                        ScanResult result;
                        result.address = base_address + i + trailing_zeros;
                        result.offset = static_cast<offset_t>(i + trailing_zeros);

                        if (m_options.relative) {
                            result.address = result.ResolveRelative(m_options.relative_offset);
                        }

                        results.push_back(result);
                    }

                    mask &= (mask - 1);
                }
            }
            else {
                auto remaining_results = ScanAllMemoryNormal(data + i, size - i, pattern, base_address + i);
                results.insert(results.end(), remaining_results.begin(), remaining_results.end());
                break;
            }
        }

        return results;
    }

    std::vector<ScanResult> SigScanner::ScanAllMemoryMultithreaded(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) {
        std::vector<ScanResult> results;

        if (!data || size == 0 || !pattern.IsPrepared() || pattern.Size() > size) {
            return results;
        }

        std::size_t chunk_size = m_options.chunk_size;
        std::size_t pattern_size = pattern.Size();
        std::size_t num_chunks = (size + chunk_size - 1) / chunk_size;

        std::mutex results_mutex;
        std::vector<std::future<std::vector<ScanResult>>> futures;
        futures.reserve(num_chunks);

        for (std::size_t chunk = 0; chunk < num_chunks; ++chunk) {
            std::size_t start = chunk * chunk_size;
            std::size_t end = std::min(start + chunk_size, size);

            if (end - start < pattern_size) continue;

            futures.push_back(m_thread_pool.Enqueue([&, start, end]() {
                return ScanAllMemoryAVX2(data + start, end - start, pattern, base_address + start);
                }));
        }

        for (auto& future : futures) {
            auto chunk_results = future.get();

            std::unique_lock<std::mutex> lock(results_mutex);
            results.insert(results.end(), chunk_results.begin(), chunk_results.end());
        }

        if (m_options.reverse) {
            std::reverse(results.begin(), results.end());
        }

        return results;
    }

    const ProcessMemory& SigScanner::GetProcess() const {
        return m_process;
    }

    const std::vector<ModuleMemory>& SigScanner::GetModules() const {
        return m_modules;
    }

    const ScanOptions& SigScanner::GetOptions() const {
        return m_options;
    }

    void SigScanner::SetOptions(const ScanOptions& options) {
        m_options = options;
    }

}