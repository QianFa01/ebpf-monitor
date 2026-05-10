#include "event_sender.h"
#include "logger.h"
#include <sstream>
#include <cstring>
#include <chrono>
#include <curl/curl.h>

namespace ebpf_monitor {

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    return size * nmemb;
}

static std::string json_escape(const std::string& s) {
    std::string result;
    result.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b";  break;
            case '\f': result += "\\f";  break;
            case '\n': result += "\\n";  break;
            case '\r': result += "\\r";  break;
            case '\t': result += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", (unsigned char)c);
                    result += buf;
                } else { result += c; }
        }
    }
    return result;
}

EventSender::EventSender(const std::string& server_url, size_t batch_size, int flush_interval_ms)
    : server_url_(server_url), batch_size_(batch_size), flush_interval_ms_(flush_interval_ms) {
    curl_global_init(CURL_GLOBAL_ALL);
}

EventSender::~EventSender() {
    stop();
    curl_global_cleanup();
}

void EventSender::enqueue(Event event) {
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    buffer_.push_back(std::move(event));
    if (buffer_.size() >= batch_size_) cv_.notify_one();
}

void EventSender::start() {
    running_ = true;
    thread_ = std::thread(&EventSender::sender_thread, this);
    LOG_INFO("Event sender started, server=%s batch_size=%zu flush_ms=%d",
             server_url_.c_str(), batch_size_, flush_interval_ms_);
}

void EventSender::stop() {
    running_ = false;
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
    std::lock_guard<std::mutex> lock(buffer_mutex_);
    if (!buffer_.empty()) {
        LOG_INFO("Flushing %zu remaining events on shutdown", buffer_.size());
        std::string json = serialize_events(buffer_);
        send_batch(json);
        buffer_.clear();
    }
    LOG_INFO("Event sender stopped");
}

void EventSender::sender_thread() {
    while (running_) {
        std::vector<Event> batch;
        {
            std::unique_lock<std::mutex> lock(buffer_mutex_);
            cv_.wait_for(lock, std::chrono::milliseconds(flush_interval_ms_),
                         [this] { return !buffer_.empty() || !running_; });
            if (!buffer_.empty()) batch.swap(buffer_);
        }
        if (!batch.empty()) {
            LOG_TRACE("Sending batch of %zu events", batch.size());
            std::string json = serialize_events(batch);
            if (!send_batch(json)) {
                LOG_WARN("Batch send failed, re-queuing %zu events", batch.size());
                std::lock_guard<std::mutex> lock(buffer_mutex_);
                if (buffer_.size() < 10000) {
                    buffer_.insert(buffer_.end(), std::make_move_iterator(batch.begin()),
                                   std::make_move_iterator(batch.end()));
                } else {
                    LOG_ERROR("Buffer full (%zu), dropping %zu events", buffer_.size(), batch.size());
                }
            }
        }
    }
}

std::string EventSender::serialize_events(const std::vector<Event>& events) {
    std::ostringstream oss;
    oss << "[";
    for (size_t i = 0; i < events.size(); ++i) {
        const auto& e = events[i];
        if (i > 0) oss << ",";
        oss << "{\"timestamp\":" << e.timestamp_ns
            << ",\"category\":\"" << category_name(e.category) << "\""
            << ",\"event_type\":\"" << event_type_name(e.category, e.event_type) << "\""
            << ",\"pid\":" << e.pid << ",\"ppid\":" << e.ppid
            << ",\"uid\":" << e.uid << ",\"gid\":" << e.gid
            << ",\"comm\":\"" << json_escape(e.comm) << "\""
            << ",\"container_id\":\"" << json_escape(e.container_id) << "\""
            << ",\"container_name\":\"" << json_escape(e.container_name) << "\"";
        if (e.category == EventCategory::PROCESS) {
            oss << ",\"filename\":\"" << json_escape(e.filename) << "\"";
            if (e.event_type == static_cast<uint32_t>(ProcessEventType::EXIT)) oss << ",\"exit_code\":" << e.exit_code;
            if (e.event_type == static_cast<uint32_t>(ProcessEventType::PRIV_ESC)) oss << ",\"old_uid\":" << e.ppid;
        } else if (e.category == EventCategory::NETWORK) {
            oss << ",\"src_addr\":\"" << json_escape(e.src_addr) << "\""
                << ",\"dst_addr\":\"" << json_escape(e.dst_addr) << "\""
                << ",\"src_port\":" << e.src_port << ",\"dst_port\":" << e.dst_port
                << ",\"protocol\":" << (int)e.protocol;
        } else if (e.category == EventCategory::FILE) {
            oss << ",\"filename\":\"" << json_escape(e.filename) << "\"";
            if (!e.old_filename.empty()) oss << ",\"old_filename\":\"" << json_escape(e.old_filename) << "\"";
            if (e.event_type == static_cast<uint32_t>(FileEventType::CHMOD)) oss << ",\"mode\":" << e.mode;
            if (e.event_type == static_cast<uint32_t>(FileEventType::MODIFY)) oss << ",\"write_bytes\":" << e.flags;
        }
        oss << "}";
    }
    oss << "]";
    return oss.str();
}

bool EventSender::send_batch(const std::string& json) {
    CURL *curl = curl_easy_init();
    if (!curl) { send_errors_++; LOG_ERROR("Failed to create CURL handle"); return false; }

    struct curl_slist *headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    std::string url = server_url_ + "/api/events";

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, json.size());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    curl_slist_free_all(headers);
    curl_easy_destroy(curl);

    if (res != CURLE_OK) {
        send_errors_++;
        LOG_ERROR("CURL error: %s (url=%s)", curl_easy_strerror(res), url.c_str());
        return false;
    }
    if (http_code != 200) {
        send_errors_++;
        LOG_WARN("HTTP %ld from %s", http_code, url.c_str());
        return false;
    }

    size_t count = 0;
    for (size_t i = 0; i < json.size(); i++) { if (json[i] == '{') count++; }
    events_sent_ += count;
    return true;
}

} // namespace ebpf_monitor
