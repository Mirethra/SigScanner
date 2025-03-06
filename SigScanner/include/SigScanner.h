#pragma once

#include <vector>
#include <string>
#include <memory>
#include <functional>
#include <cstdint>
#include <immintrin.h>
#include <optional>
#ifndef THREADPOOL_H
#define THREADPOOL_H
#include <mutex>
#endif
#include <thread>
#include <future>

#include <immintrin.h>

namespace scan {

    using byte_t = unsigned char;
    using address_t = uintptr_t;
    using offset_t = std::ptrdiff_t;
    using region_t = std::pair<address_t, std::size_t>;

    template<typename T>
    using result_t = std::optional<T>;

    enum class ScanType {
        Normal,
        AVX2,
        MultithreadAVX2
    };

    struct ScanOptions {
        ScanType type = ScanType::Normal;
        std::size_t thread_count = std::thread::hardware_concurrency();
        std::size_t chunk_size = 1024 * 1024;
        bool relative = false;
        std::size_t relative_offset = 0;
        bool reverse = false;
    };

    class SigPattern {
    public:
        SigPattern() = default;
        SigPattern(const std::string& pattern);
        SigPattern(const char* pattern);
        SigPattern(const std::vector<byte_t>& bytes);
        SigPattern(const std::vector<std::pair<byte_t, bool>>& pattern);

        void Parse(const std::string& pattern);
        void Prepare();

        bool Match(const byte_t* data, std::size_t length) const;
        bool MatchAVX2(const byte_t* data, std::size_t length) const;
        bool MatchSSE(const byte_t* data, std::size_t length) const;

        const std::vector<std::pair<byte_t, bool>>& GetPattern() const;
        const std::string& GetSigString() const;
        std::size_t Size() const;
        bool IsPrepared() const;

        const byte_t* MaskBytes() const;
        const byte_t* ValBytes() const;

        const __m256i& FirstBytesAVX() const;
        const __m256i& FirstMaskAVX() const;
        const __m128i& FirstBytesSSE() const;
        const __m128i& FirstMaskSSE() const;

    private:
        std::vector<std::pair<byte_t, bool>> m_pattern;
        std::string m_sig_str;
        std::size_t m_size = 0;
        bool m_prepared = false;

        std::vector<byte_t> m_mask_bytes;
        std::vector<byte_t> m_val_bytes;

        __m256i m_first_bytes_avx{};
        __m256i m_first_mask_avx{};
        __m128i m_first_bytes_sse{};
        __m128i m_first_mask_sse{};
    };

    struct ScanResult {
        address_t address = 0;
        offset_t offset = 0;
        std::string module_name;

        address_t Follow() const;
        address_t ResolveRelative(std::size_t instruction_size) const;

        template<typename T>
        T Read() const {
            return *reinterpret_cast<T*>(address);
        }
    };

    class ProcessMemory {
    public:
        ProcessMemory();
        ProcessMemory(std::uint32_t pid);
        ProcessMemory(const std::string& process_name);
        ~ProcessMemory();

        bool Initialize(std::uint32_t pid);
        bool Initialize(const std::string& process_name);

        std::vector<region_t> GetRegions() const;
        bool ReadMemory(address_t address, void* buffer, std::size_t size) const;
        result_t<std::vector<byte_t>> ReadRegion(const region_t& region) const;

        bool IsValid() const;
        std::uint32_t GetPID() const;
        void* GetHandle() const;

    private:
        std::uint32_t m_pid;
        void* m_handle;
        std::vector<region_t> m_regions;
        bool m_initialized = false;
    };

    class ModuleMemory {
    public:
        ModuleMemory();
        ModuleMemory(const ProcessMemory& process, const std::string& module_name);
        ModuleMemory(address_t base, std::size_t size, const std::string& name, const ProcessMemory& process);

        bool Initialize(const ProcessMemory& process, const std::string& module_name);
        bool Initialize(address_t base, std::size_t size, const std::string& name, const ProcessMemory& process);
        bool LoadFromMemory(const ProcessMemory& process);
        bool LoadFromFile(const std::string& path);

        const std::vector<byte_t>& GetData() const;
        address_t GetBase() const;
        std::size_t GetSize() const;
        const std::string& GetName() const;
        bool IsValid() const;

    private:
        address_t m_base;
        std::size_t m_size;
        std::string m_name;
        std::vector<byte_t> m_data;
        bool m_initialized = false;
    };

    class ThreadPool {
    public:
        ThreadPool(std::size_t thread_count);
        ~ThreadPool();

        template<typename F, typename... Args>
        auto Enqueue(F&& f, Args&&... args) -> std::future<typename std::invoke_result<F, Args...>::type> {
            using return_type = typename std::invoke_result<F, Args...>::type;

            auto task = std::make_shared<std::packaged_task<return_type()>>(
                std::bind(std::forward<F>(f), std::forward<Args>(args)...)
            );

            std::future<return_type> res = task->get_future();
            {
                std::unique_lock<std::mutex> lock(m_mutex);
                if (m_stop) {
                    throw std::runtime_error("enqueue on stopped ThreadPool");
                }

                m_jobs.emplace_back([task]() { (*task)(); });
                m_active_jobs++;
            }

            m_condition.notify_one();
            return res;
        }

        void Wait();

    private:
        std::vector<std::thread> m_threads;
        std::vector<std::function<void()>> m_jobs;
        std::mutex m_mutex;
        std::condition_variable m_condition;
        bool m_stop = false;
        std::atomic<std::size_t> m_active_jobs{ 0 };
    };

    class SigScanner {
    public:
        SigScanner();
        SigScanner(const ScanOptions& options);
        SigScanner(std::uint32_t pid, const ScanOptions& options = ScanOptions{});
        SigScanner(const std::string& process_name, const ScanOptions& options = ScanOptions{});

        bool Initialize(std::uint32_t pid);
        bool Initialize(const std::string& process_name);

        bool AddModule(const std::string& module_name);
        bool AddModule(address_t base, std::size_t size, const std::string& name);

        result_t<ScanResult> Scan(const SigPattern& pattern, const std::string& module_name = "");
        result_t<ScanResult> Scan(const std::string& pattern, const std::string& module_name = "");

        std::vector<ScanResult> ScanAll(const SigPattern& pattern, const std::string& module_name = "");
        std::vector<ScanResult> ScanAll(const std::string& pattern, const std::string& module_name = "");

        const ProcessMemory& GetProcess() const;
        const std::vector<ModuleMemory>& GetModules() const;
        const ScanOptions& GetOptions() const;
        void SetOptions(const ScanOptions& options);

    private:
        result_t<ScanResult> ScanMemoryNormal(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) const;
        result_t<ScanResult> ScanMemoryAVX2(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) const;
        result_t<ScanResult> ScanMemoryMultithreaded(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address);

        std::vector<ScanResult> ScanAllMemoryNormal(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) const;
        std::vector<ScanResult> ScanAllMemoryAVX2(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address) const;
        std::vector<ScanResult> ScanAllMemoryMultithreaded(const byte_t* data, std::size_t size, const SigPattern& pattern, address_t base_address);

        ProcessMemory m_process;
        std::vector<ModuleMemory> m_modules;
        ScanOptions m_options;
        ThreadPool m_thread_pool;
    };

}