#pragma once

#include <string>
#include <fstream>
#include <mutex>
#include <memory>
#include <sstream>
#include <cstdint>
#include <cstdarg>

namespace ebpf_monitor {

enum class LogLevel : uint8_t {
    TRACE = 0,
    DEBUG = 1,
    INFO  = 2,
    WARN  = 3,
    ERROR = 4,
    FATAL = 5,
    OFF   = 6,
};

class Logger {
public:
    static Logger& instance();

    void set_level(LogLevel level);
    void set_console(bool enable);
    void set_file(const std::string& path, size_t max_size = 50 * 1024 * 1024, int max_files = 5);
    void set_module(const std::string& module);

    void log(LogLevel level, const char* file, int line, const char* fmt, ...);
    void vlog(LogLevel level, const char* file, int line, const char* fmt, va_list args);

    void trace(const char* file, int line, const char* fmt, ...);
    void debug(const char* file, int line, const char* fmt, ...);
    void info (const char* file, int line, const char* fmt, ...);
    void warn (const char* file, int line, const char* fmt, ...);
    void error(const char* file, int line, const char* fmt, ...);
    void fatal(const char* file, int line, const char* fmt, ...);

    bool should_log(LogLevel level) const { return level >= level_; }
    static const char* level_name(LogLevel level);
    static LogLevel parse_level(const std::string& s);

private:
    Logger() = default;
    ~Logger();
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;

    void write(LogLevel level, const char* file, int line, const char* msg);
    void rotate_if_needed();
    std::string format_time();
    const char* extract_filename(const char* path);

    LogLevel level_ = LogLevel::INFO;
    bool console_ = true;
    std::string module_;
    std::mutex mutex_;
    std::ofstream file_stream_;
    std::string file_path_;
    size_t max_file_size_ = 50 * 1024 * 1024;
    int max_files_ = 5;
    size_t current_size_ = 0;
};

#define LOG_MODULE(name) ebpf_monitor::Logger::instance().set_module(name)
#define LOG_TRACE(fmt, ...) ebpf_monitor::Logger::instance().trace(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) ebpf_monitor::Logger::instance().debug(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_INFO(fmt, ...)  ebpf_monitor::Logger::instance().info(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...)  ebpf_monitor::Logger::instance().warn(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) ebpf_monitor::Logger::instance().error(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_FATAL(fmt, ...) ebpf_monitor::Logger::instance().fatal(__FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_SHOULD(level)   ebpf_monitor::Logger::instance().should_log(ebpf_monitor::LogLevel::level)

} // namespace ebpf_monitor
