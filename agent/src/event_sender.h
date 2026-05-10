#pragma once

#include "event_types.h"
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <condition_variable>

namespace ebpf_monitor {

class EventSender {
public:
    EventSender(const std::string& server_url, size_t batch_size = 100, int flush_interval_ms = 100);
    ~EventSender();

    void enqueue(Event event);
    void start();
    void stop();

    uint64_t get_events_sent() const { return events_sent_; }
    uint64_t get_send_errors() const { return send_errors_; }

private:
    void sender_thread();
    std::string serialize_events(const std::vector<Event>& events);
    bool send_batch(const std::string& json);

    std::string server_url_;
    size_t batch_size_;
    int flush_interval_ms_;

    std::vector<Event> buffer_;
    std::mutex buffer_mutex_;
    std::condition_variable cv_;

    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> events_sent_{0};
    std::atomic<uint64_t> send_errors_{0};
};

} // namespace ebpf_monitor
