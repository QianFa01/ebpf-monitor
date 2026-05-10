#include "ebpf_loader.h"
#include "event_reader.h"
#include "event_sender.h"
#include "container_utils.h"
#include "event_types.h"
#include "logger.h"

#include <string>
#include <vector>
#include <sstream>
#include <csignal>
#include <cstring>
#include <getopt.h>
#include <unistd.h>
#include <chrono>
#include <atomic>

using namespace ebpf_monitor;

static std::atomic<bool> g_running{true};

static void signal_handler(int sig) {
    LOG_INFO("Received signal %d, shutting down...", sig);
    g_running = false;
}

static void print_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s [OPTIONS]\n"
        "\nOptions:\n"
        "  -s, --server URL       Web server URL (default: http://localhost:8000)\n"
        "  -e, --events TYPES     Comma-separated: process,network,file (default: all)\n"
        "  -b, --batch-size N     Events per HTTP batch (default: 100)\n"
        "  -f, --flush-ms MS      Flush interval ms (default: 100)\n"
        "  -l, --log-file PATH    Log file path (default: console only)\n"
        "  -L, --log-level LEVEL  trace/debug/info/warn/error (default: info)\n"
        "  -v, --verbose          Shortcut for --log-level debug\n"
        "  -h, --help             Show this help\n"
        "\nExample:\n"
        "  %s -s http://192.168.1.100:8000 -e process,network -L debug -l /var/log/agent.log\n",
        prog, prog);
}

struct Config {
    std::string server_url = "http://localhost:8000";
    std::vector<std::string> event_types = {"process", "network", "file"};
    size_t batch_size = 100;
    int flush_ms = 100;
    bool verbose = false;
    std::string log_file;
    LogLevel log_level = LogLevel::INFO;
};

static Config parse_args(int argc, char** argv) {
    Config config;
    static struct option long_options[] = {
        {"server", required_argument, 0, 's'},
        {"events", required_argument, 0, 'e'},
        {"batch-size", required_argument, 0, 'b'},
        {"flush-ms", required_argument, 0, 'f'},
        {"log-file", required_argument, 0, 'l'},
        {"log-level", required_argument, 0, 'L'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    int opt;
    while ((opt = getopt_long(argc, argv, "s:e:b:f:l:L:vh", long_options, nullptr)) != -1) {
        switch (opt) {
            case 's': config.server_url = optarg; break;
            case 'e': {
                config.event_types.clear();
                std::istringstream iss(optarg);
                std::string token;
                while (std::getline(iss, token, ',')) config.event_types.push_back(token);
                break;
            }
            case 'b': config.batch_size = std::stoul(optarg); break;
            case 'f': config.flush_ms = std::stoi(optarg); break;
            case 'l': config.log_file = optarg; break;
            case 'L': config.log_level = Logger::parse_level(optarg); break;
            case 'v': config.verbose = true; break;
            case 'h': print_usage(argv[0]); exit(0);
            default: print_usage(argv[0]); exit(1);
        }
    }
    if (config.verbose && config.log_level > LogLevel::DEBUG) config.log_level = LogLevel::DEBUG;
    return config;
}

static bool has_type(const Config& config, const std::string& type) {
    for (const auto& t : config.event_types) { if (t == type) return true; }
    return false;
}

static std::string find_bpf_object(const std::string& name) {
    char exe_path[1024];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len > 0) {
        exe_path[len] = '\0';
        std::string dir(exe_path);
        auto pos = dir.rfind('/');
        if (pos != std::string::npos) {
            dir = dir.substr(0, pos);
            std::string path = dir + "/../bpf/" + name;
            if (access(path.c_str(), R_OK) == 0) return path;
            path = dir + "/bpf/" + name;
            if (access(path.c_str(), R_OK) == 0) return path;
        }
    }
    std::string path = "./bpf/" + name;
    if (access(path.c_str(), R_OK) == 0) return path;
    path = "/opt/ebpf-monitor/bpf/" + name;
    if (access(path.c_str(), R_OK) == 0) return path;
    return name;
}

int main(int argc, char** argv) {
    Config config = parse_args(argc, argv);

    auto& logger = Logger::instance();
    logger.set_level(config.log_level);
    logger.set_console(true);
    if (!config.log_file.empty()) logger.set_file(config.log_file);
    LOG_MODULE("main");

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    LOG_INFO("=== eBPF Security Monitor Agent ===");
    LOG_INFO("Server:     %s", config.server_url.c_str());
    LOG_INFO("Log level:  %s", Logger::level_name(config.log_level));
    if (!config.log_file.empty()) LOG_INFO("Log file:   %s", config.log_file.c_str());

    std::string events_str;
    for (size_t i = 0; i < config.event_types.size(); ++i) {
        if (i > 0) events_str += ", ";
        events_str += config.event_types[i];
    }
    LOG_INFO("Events:     %s", events_str.c_str());

    if (EbpfLoader::has_btf()) LOG_INFO("BTF: available (CO-RE enabled)");
    else LOG_INFO("BTF: not available (using legacy kprobes)");

    ContainerUtils container_utils;
    EventReader reader(container_utils);
    EventSender sender(config.server_url, config.batch_size, config.flush_ms);

    std::vector<std::unique_ptr<EbpfLoader>> loaders;

    auto load_monitor = [&](const std::string& name, const std::string& map, EventCategory cat) {
        auto loader = std::make_unique<EbpfLoader>();
        std::string path = find_bpf_object(name);
        if (loader->load_object(path)) {
            if (loader->attach_all()) {
                reader.add_perf_buffer(*loader, map, cat);
                LOG_INFO("[OK] %s monitoring enabled", name.c_str());
            }
        }
        loaders.push_back(std::move(loader));
    };

    if (has_type(config, "process")) load_monitor("process_monitor.bpf.o", "process_events", EventCategory::PROCESS);
    if (has_type(config, "network")) load_monitor("network_monitor.bpf.o", "network_events", EventCategory::NETWORK);
    if (has_type(config, "file"))    load_monitor("file_monitor.bpf.o", "file_events", EventCategory::FILE);

    sender.start();
    reader.start([&sender](const Event& evt) { sender.enqueue(Event(evt)); });
    LOG_INFO("Monitoring started. Press Ctrl+C to stop.");

    auto last_stats = std::chrono::steady_clock::now();
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_stats).count();
        if (elapsed >= 10) {
            uint64_t read = reader.get_events_read();
            uint64_t lost = reader.get_events_lost();
            uint64_t sent = sender.get_events_sent();
            uint64_t errors = sender.get_send_errors();
            LOG_INFO("[Stats] read=%llu sent=%llu lost=%llu errors=%llu (%llu events/sec)",
                     (unsigned long long)read, (unsigned long long)sent,
                     (unsigned long long)lost, (unsigned long long)errors,
                     (unsigned long long)(read / (elapsed ? elapsed : 1)));
            last_stats = now;
        }
    }

    LOG_INFO("Stopping...");
    reader.stop();
    sender.stop();
    LOG_INFO("Final stats: read=%llu sent=%llu lost=%llu errors=%llu",
             (unsigned long long)reader.get_events_read(),
             (unsigned long long)sender.get_events_sent(),
             (unsigned long long)reader.get_events_lost(),
             (unsigned long long)sender.get_send_errors());
    return 0;
}
