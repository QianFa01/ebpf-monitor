// Tests for logger.cpp - log level parsing and filtering
// Build: g++ -std=c++17 -I../src -o test_logger test_logger.cpp ../src/logger.cpp -lpthread
// Run: ./test_logger

#include <cassert>
#include <iostream>
#include <string>

#include "logger.h"

using namespace ebpf_monitor;

void test_level_name() {
    assert(std::string(Logger::level_name(LogLevel::TRACE)) == "TRACE");
    assert(std::string(Logger::level_name(LogLevel::DEBUG)) == "DEBUG");
    assert(std::string(Logger::level_name(LogLevel::INFO))  == "INFO");
    assert(std::string(Logger::level_name(LogLevel::WARN))  == "WARN");
    assert(std::string(Logger::level_name(LogLevel::ERROR)) == "ERROR");
    assert(std::string(Logger::level_name(LogLevel::FATAL)) == "FATAL");
    std::cout << "  PASS: test_level_name" << std::endl;
}

void test_parse_level() {
    assert(Logger::parse_level("trace") == LogLevel::TRACE);
    assert(Logger::parse_level("debug") == LogLevel::DEBUG);
    assert(Logger::parse_level("info")  == LogLevel::INFO);
    assert(Logger::parse_level("warn")  == LogLevel::WARN);
    assert(Logger::parse_level("error") == LogLevel::ERROR);
    assert(Logger::parse_level("fatal") == LogLevel::FATAL);
    assert(Logger::parse_level("TRACE") == LogLevel::TRACE);
    assert(Logger::parse_level("DEBUG") == LogLevel::DEBUG);
    assert(Logger::parse_level("unknown") == LogLevel::INFO);
    std::cout << "  PASS: test_parse_level" << std::endl;
}

void test_should_log() {
    Logger::instance().set_level(LogLevel::WARN);

    assert(Logger::instance().should_log(LogLevel::TRACE) == false);
    assert(Logger::instance().should_log(LogLevel::DEBUG) == false);
    assert(Logger::instance().should_log(LogLevel::INFO)  == false);
    assert(Logger::instance().should_log(LogLevel::WARN)  == true);
    assert(Logger::instance().should_log(LogLevel::ERROR) == true);
    assert(Logger::instance().should_log(LogLevel::FATAL) == true);

    Logger::instance().set_level(LogLevel::TRACE);
    assert(Logger::instance().should_log(LogLevel::TRACE) == true);
    assert(Logger::instance().should_log(LogLevel::DEBUG) == true);

    Logger::instance().set_level(LogLevel::ERROR);
    assert(Logger::instance().should_log(LogLevel::WARN) == false);
    assert(Logger::instance().should_log(LogLevel::ERROR) == true);

    std::cout << "  PASS: test_should_log" << std::endl;
}

int main() {
    std::cout << "Running logger tests..." << std::endl;
    Logger::instance().set_console(false);
    test_level_name();
    test_parse_level();
    test_should_log();
    std::cout << "All logger tests passed!" << std::endl;
    return 0;
}
