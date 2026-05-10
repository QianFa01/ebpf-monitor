#pragma once

#include "event_types.h"
#include "container_utils.h"
#include "ebpf_loader.h"
#include <functional>
#include <thread>
#include <atomic>
#include <vector>

struct perf_buffer;

namespace ebpf_monitor {

using EventCallback = std::function<void(const Event&)>;

class EventReader {
public:
    EventReader(ContainerUtils& container_utils);
    ~EventReader();

    bool add_perf_buffer(EbpfLoader& loader, const std::string& map_name, EventCategory category);
    void start(EventCallback callback);
    void stop();

    uint64_t get_events_read() const { return events_read_; }
    uint64_t get_events_lost() const { return events_lost_; }

private:
    void reader_thread();
    void handle_process_event(const void* data, size_t size);
    void handle_network_event(const void* data, size_t size);
    void handle_file_event(const void* data, size_t size);

    ContainerUtils& container_utils_;
    EventCallback callback_;

    struct PerfBufferInfo {
        int map_fd;
        EventCategory category;
        struct perf_buffer* pb;
    };
    std::vector<PerfBufferInfo> perf_buffers_;

    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> events_read_{0};
    std::atomic<uint64_t> events_lost_{0};
};

} // namespace ebpf_monitor
