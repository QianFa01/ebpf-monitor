#include "event_reader.h"
#include "logger.h"
#include <bpf/libbpf.h>
#include <cstring>
#include <sys/epoll.h>
#include <unistd.h>

namespace ebpf_monitor {

static void process_event_cb(void *ctx, int cpu, void *data, __u32 size) {
    static_cast<EventReader*>(ctx)->handle_process_event(data, size);
}
static void network_event_cb(void *ctx, int cpu, void *data, __u32 size) {
    static_cast<EventReader*>(ctx)->handle_network_event(data, size);
}
static void file_event_cb(void *ctx, int cpu, void *data, __u32 size) {
    static_cast<EventReader*>(ctx)->handle_file_event(data, size);
}
static void lost_events_cb(void *ctx, int cpu, __u64 cnt) {
    static_cast<EventReader*>(ctx)->events_lost_ += cnt;
    LOG_WARN("Lost %llu events on CPU %d", (unsigned long long)cnt, cpu);
}

EventReader::EventReader(ContainerUtils& container_utils) : container_utils_(container_utils) {}
EventReader::~EventReader() { stop(); }

bool EventReader::add_perf_buffer(EbpfLoader& loader, const std::string& map_name, EventCategory category) {
    int map_fd = loader.get_perf_buffer_fd(map_name);
    if (map_fd < 0) {
        LOG_ERROR("Failed to get perf buffer fd for: %s", map_name.c_str());
        return false;
    }
    PerfBufferInfo info;
    info.map_fd = map_fd;
    info.category = category;
    info.pb = nullptr;
    perf_buffers_.push_back(info);
    LOG_INFO("Registered perf buffer: %s (fd=%d)", map_name.c_str(), map_fd);
    return true;
}

void EventReader::start(EventCallback callback) {
    callback_ = callback;
    running_ = true;
    for (auto& info : perf_buffers_) {
        perf_buffer_sample_fn sample_cb = nullptr;
        switch (info.category) {
            case EventCategory::PROCESS: sample_cb = process_event_cb; break;
            case EventCategory::NETWORK: sample_cb = network_event_cb; break;
            case EventCategory::FILE:    sample_cb = file_event_cb;    break;
        }
        info.pb = perf_buffer__new(info.map_fd, 16, sample_cb, lost_events_cb, this, nullptr);
        if (libbpf_get_error(info.pb)) {
            LOG_ERROR("Failed to create perf buffer for fd %d", info.map_fd);
            info.pb = nullptr;
        }
    }
    thread_ = std::thread(&EventReader::reader_thread, this);
    LOG_INFO("Event reader started (%zu perf buffers)", perf_buffers_.size());
}

void EventReader::stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
    for (auto& info : perf_buffers_) {
        if (info.pb) { perf_buffer__free(info.pb); info.pb = nullptr; }
    }
    LOG_INFO("Event reader stopped");
}

void EventReader::reader_thread() {
    while (running_) {
        bool any_active = false;
        for (auto& info : perf_buffers_) {
            if (info.pb) {
                int err = perf_buffer__poll(info.pb, 100);
                if (err < 0 && err != -EINTR) LOG_ERROR("perf_buffer__poll error: %d", err);
                any_active = true;
            }
        }
        if (!any_active) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void EventReader::handle_process_event(const void* data, size_t size) {
    if (size < sizeof(ProcessEventRaw)) return;
    const auto* raw = static_cast<const ProcessEventRaw*>(data);
    Event evt = from_raw(*raw);
    auto container = container_utils_.get_container_info(evt.pid);
    evt.container_id = container.id;
    evt.container_name = container.name;
    events_read_++;
    if (LOG_SHOULD(DEBUG)) {
        const char* type_str = event_type_name(evt.category, evt.event_type);
        if (evt.event_type == static_cast<uint32_t>(ProcessEventType::PRIV_ESC)) {
            LOG_WARN("%s pid=%u old_uid=%u->%u comm=%s filename=%s%s%s",
                     type_str, evt.pid, evt.ppid, evt.uid, evt.comm.c_str(), evt.filename.c_str(),
                     evt.container_id.empty() ? "" : " container=", evt.container_id.c_str());
        } else {
            LOG_DEBUG("%s pid=%u ppid=%u uid=%u comm=%s filename=%s%s%s",
                      type_str, evt.pid, evt.ppid, evt.uid, evt.comm.c_str(), evt.filename.c_str(),
                      evt.container_id.empty() ? "" : " container=", evt.container_id.c_str());
        }
    }
    if (callback_) callback_(evt);
}

void EventReader::handle_network_event(const void* data, size_t size) {
    if (size < sizeof(NetworkEventRaw)) return;
    const auto* raw = static_cast<const NetworkEventRaw*>(data);
    Event evt = from_raw(*raw);
    auto container = container_utils_.get_container_info(evt.pid);
    evt.container_id = container.id;
    evt.container_name = container.name;
    events_read_++;
    if (LOG_SHOULD(DEBUG)) {
        const char* proto = evt.protocol == 6 ? "TCP" : evt.protocol == 17 ? "UDP" : "?";
        LOG_DEBUG("%s pid=%u comm=%s %s %s:%u -> %s:%u%s%s",
                  event_type_name(evt.category, evt.event_type), evt.pid, evt.comm.c_str(), proto,
                  evt.src_addr.c_str(), evt.src_port, evt.dst_addr.c_str(), evt.dst_port,
                  evt.container_id.empty() ? "" : " container=", evt.container_id.c_str());
    }
    if (callback_) callback_(evt);
}

void EventReader::handle_file_event(const void* data, size_t size) {
    if (size < sizeof(FileEventRaw)) return;
    const auto* raw = static_cast<const FileEventRaw*>(data);
    Event evt = from_raw(*raw);
    auto container = container_utils_.get_container_info(evt.pid);
    evt.container_id = container.id;
    evt.container_name = container.name;
    events_read_++;
    if (LOG_SHOULD(DEBUG)) {
        const char* type_str = event_type_name(evt.category, evt.event_type);
        if (evt.event_type == static_cast<uint32_t>(FileEventType::RENAME)) {
            LOG_DEBUG("%s pid=%u comm=%s %s -> %s%s%s", type_str, evt.pid, evt.comm.c_str(),
                      evt.old_filename.c_str(), evt.filename.c_str(),
                      evt.container_id.empty() ? "" : " container=", evt.container_id.c_str());
        } else if (evt.event_type == static_cast<uint32_t>(FileEventType::CHMOD)) {
            LOG_DEBUG("%s pid=%u comm=%s %s mode=%o%s%s", type_str, evt.pid, evt.comm.c_str(),
                      evt.filename.c_str(), evt.mode,
                      evt.container_id.empty() ? "" : " container=", evt.container_id.c_str());
        } else {
            LOG_DEBUG("%s pid=%u comm=%s %s%s%s", type_str, evt.pid, evt.comm.c_str(),
                      evt.filename.c_str(), evt.container_id.empty() ? "" : " container=", evt.container_id.c_str());
        }
    }
    if (callback_) callback_(evt);
}

} // namespace ebpf_monitor
