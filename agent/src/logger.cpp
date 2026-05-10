#include "logger.h"
#include <iostream>
#include <chrono>
#include <ctime>
#include <cstring>
#include <iomanip>
#include <filesystem>

namespace fs = std::filesystem;

namespace ebpf_monitor {

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

Logger::~Logger() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (file_stream_.is_open()) {
        file_stream_.flush();
        file_stream_.close();
    }
}

void Logger::set_level(LogLevel level) { level_ = level; }
void Logger::set_console(bool enable) { console_ = enable; }

void Logger::set_file(const std::string& path, size_t max_size, int max_files) {
    std::lock_guard<std::mutex> lock(mutex_);
    file_path_ = path;
    max_file_size_ = max_size;
    max_files_ = max_files;
    auto parent = fs::path(path).parent_path();
    if (!parent.empty() && !fs::exists(parent))
        fs::create_directories(parent);
    if (file_stream_.is_open()) file_stream_.close();
    file_stream_.open(path, std::ios::app);
    if (file_stream_.is_open()) current_size_ = file_stream_.tellp();
}

void Logger::set_module(const std::string& module) { module_ = module; }

const char* Logger::level_name(LogLevel level) {
    switch (level) {
        case LogLevel::TRACE: return "TRACE";
        case LogLevel::DEBUG: return "DEBUG";
        case LogLevel::INFO:  return "INFO ";
        case LogLevel::WARN:  return "WARN ";
        case LogLevel::ERROR: return "ERROR";
        case LogLevel::FATAL: return "FATAL";
        default:              return "?????";
    }
}

LogLevel Logger::parse_level(const std::string& s) {
    if (s == "trace" || s == "TRACE") return LogLevel::TRACE;
    if (s == "debug" || s == "DEBUG") return LogLevel::DEBUG;
    if (s == "info"  || s == "INFO")  return LogLevel::INFO;
    if (s == "warn"  || s == "WARN")  return LogLevel::WARN;
    if (s == "error" || s == "ERROR") return LogLevel::ERROR;
    if (s == "fatal" || s == "FATAL") return LogLevel::FATAL;
    if (s == "off"   || s == "OFF")   return LogLevel::OFF;
    return LogLevel::INFO;
}

const char* Logger::extract_filename(const char* path) {
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

std::string Logger::format_time() {
    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    struct tm tm_buf;
    localtime_r(&time_t_now, &tm_buf);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tm_buf.tm_year + 1900, tm_buf.tm_mon + 1, tm_buf.tm_mday,
             tm_buf.tm_hour, tm_buf.tm_min, tm_buf.tm_sec, (int)ms.count());
    return buf;
}

void Logger::rotate_if_needed() {
    if (file_path_.empty() || !file_stream_.is_open()) return;
    if (current_size_ < max_file_size_) return;
    file_stream_.close();
    for (int i = max_files_ - 1; i >= 1; --i) {
        std::string old_name = file_path_ + "." + std::to_string(i);
        std::string new_name = file_path_ + "." + std::to_string(i + 1);
        if (fs::exists(old_name)) {
            if (i == max_files_ - 1) fs::remove(old_name);
            else fs::rename(old_name, new_name);
        }
    }
    if (fs::exists(file_path_))
        fs::rename(file_path_, file_path_ + ".1");
    file_stream_.open(file_path_, std::ios::app);
    current_size_ = 0;
}

void Logger::write(LogLevel level, const char* file, int line, const char* msg) {
    const char* fname = extract_filename(file);
    std::string time_str = format_time();
    std::ostringstream oss;
    oss << "[" << time_str << "] [" << level_name(level) << "] ";
    if (!module_.empty()) oss << "[" << module_ << "] ";
    oss << "[" << fname << ":" << line << "] " << msg << "\n";
    std::string line_str = oss.str();

    std::lock_guard<std::mutex> lock(mutex_);
    if (console_) {
        const char* color = "";
        const char* reset = "\033[0m";
        switch (level) {
            case LogLevel::TRACE: color = "\033[90m"; break;
            case LogLevel::DEBUG: color = "\033[36m"; break;
            case LogLevel::INFO:  color = "\033[32m"; break;
            case LogLevel::WARN:  color = "\033[33m"; break;
            case LogLevel::ERROR: color = "\033[31m"; break;
            case LogLevel::FATAL: color = "\033[35;1m"; break;
            default: break;
        }
        std::cerr << color << line_str << reset;
    }
    if (file_stream_.is_open()) {
        file_stream_ << line_str;
        file_stream_.flush();
        current_size_ += line_str.size();
        rotate_if_needed();
    }
}

void Logger::log(LogLevel level, const char* file, int line, const char* fmt, ...) {
    if (level < level_) return;
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    write(level, file, line, buf);
}

void Logger::vlog(LogLevel level, const char* file, int line, const char* fmt, va_list args) {
    if (level < level_) return;
    char buf[2048];
    vsnprintf(buf, sizeof(buf), fmt, args);
    write(level, file, line, buf);
}

void Logger::trace(const char* file, int line, const char* fmt, ...) {
    if (LogLevel::TRACE < level_) return;
    va_list args; va_start(args, fmt); vlog(LogLevel::TRACE, file, line, fmt, args); va_end(args);
}
void Logger::debug(const char* file, int line, const char* fmt, ...) {
    if (LogLevel::DEBUG < level_) return;
    va_list args; va_start(args, fmt); vlog(LogLevel::DEBUG, file, line, fmt, args); va_end(args);
}
void Logger::info(const char* file, int line, const char* fmt, ...) {
    if (LogLevel::INFO < level_) return;
    va_list args; va_start(args, fmt); vlog(LogLevel::INFO, file, line, fmt, args); va_end(args);
}
void Logger::warn(const char* file, int line, const char* fmt, ...) {
    if (LogLevel::WARN < level_) return;
    va_list args; va_start(args, fmt); vlog(LogLevel::WARN, file, line, fmt, args); va_end(args);
}
void Logger::error(const char* file, int line, const char* fmt, ...) {
    if (LogLevel::ERROR < level_) return;
    va_list args; va_start(args, fmt); vlog(LogLevel::ERROR, file, line, fmt, args); va_end(args);
}
void Logger::fatal(const char* file, int line, const char* fmt, ...) {
    va_list args; va_start(args, fmt); vlog(LogLevel::FATAL, file, line, fmt, args); va_end(args);
}

} // namespace ebpf_monitor
