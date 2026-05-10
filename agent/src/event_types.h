#pragma once

#include <cstdint>
#include <string>
#include <cstring>

namespace ebpf_monitor {

enum class EventCategory : uint8_t {
    PROCESS = 1,
    NETWORK = 2,
    FILE    = 3,
};

enum class ProcessEventType : uint32_t {
    CREATE   = 1,
    EXIT     = 2,
    PRIV_ESC = 3,
};

enum class NetworkEventType : uint32_t {
    TCP_CONNECT = 10,
    TCP_ACCEPT  = 11,
    TCP_CLOSE   = 12,
    UDP_SEND    = 20,
    UDP_RECV    = 21,
};

enum class FileEventType : uint32_t {
    CREATE = 30,
    MODIFY = 31,
    DELETE = 32,
    RENAME = 33,
    CHMOD  = 34,
    CHOWN  = 35,
};

struct ProcessEventRaw {
    uint64_t timestamp;
    uint32_t event_type;
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    uint32_t gid;
    uint32_t exit_code;
    uint32_t cgroup_id;
    char     comm[16];
    char     filename[256];
    char     args[512];
};

struct NetworkEventRaw {
    uint64_t timestamp;
    uint32_t event_type;
    uint32_t pid;
    uint32_t uid;
    uint32_t cgroup_id;
    uint32_t saddr;
    uint32_t daddr;
    uint16_t sport;
    uint16_t dport;
    uint8_t  proto;
    uint8_t  pad[3];
    char     comm[16];
};

struct FileEventRaw {
    uint64_t timestamp;
    uint32_t event_type;
    uint32_t pid;
    uint32_t uid;
    uint32_t gid;
    uint32_t cgroup_id;
    uint32_t mode;
    uint32_t flags;
    char     comm[16];
    char     filename[256];
    char     old_filename[256];
};

struct Event {
    uint64_t    timestamp_ns;
    EventCategory category;
    uint32_t    event_type;
    uint32_t    pid;
    uint32_t    ppid;
    uint32_t    uid;
    uint32_t    gid;
    std::string comm;
    std::string container_id;
    std::string container_name;
    std::string filename;
    std::string old_filename;
    uint32_t    exit_code;
    uint32_t    mode;
    uint32_t    flags;
    std::string src_addr;
    std::string dst_addr;
    uint16_t    src_port;
    uint16_t    dst_port;
    uint8_t     protocol;
};

inline Event from_raw(const ProcessEventRaw& raw) {
    Event evt;
    evt.timestamp_ns = raw.timestamp;
    evt.category = EventCategory::PROCESS;
    evt.event_type = raw.event_type;
    evt.pid = raw.pid;
    evt.ppid = raw.ppid;
    evt.uid = raw.uid;
    evt.gid = raw.gid;
    evt.comm = std::string(raw.comm, strnlen(raw.comm, sizeof(raw.comm)));
    evt.filename = std::string(raw.filename, strnlen(raw.filename, sizeof(raw.filename)));
    evt.exit_code = raw.exit_code;
    evt.cgroup_id = raw.cgroup_id;
    return evt;
}

inline Event from_raw(const NetworkEventRaw& raw) {
    Event evt;
    evt.timestamp_ns = raw.timestamp;
    evt.category = EventCategory::NETWORK;
    evt.event_type = raw.event_type;
    evt.pid = raw.pid;
    evt.uid = raw.uid;
    evt.comm = std::string(raw.comm, strnlen(raw.comm, sizeof(raw.comm)));
    evt.cgroup_id = raw.cgroup_id;
    char buf[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = raw.saddr;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    evt.src_addr = buf;
    addr.s_addr = raw.daddr;
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    evt.dst_addr = buf;
    evt.src_port = raw.sport;
    evt.dst_port = raw.dport;
    evt.protocol = raw.proto;
    return evt;
}

inline Event from_raw(const FileEventRaw& raw) {
    Event evt;
    evt.timestamp_ns = raw.timestamp;
    evt.category = EventCategory::FILE;
    evt.event_type = raw.event_type;
    evt.pid = raw.pid;
    evt.uid = raw.uid;
    evt.gid = raw.gid;
    evt.comm = std::string(raw.comm, strnlen(raw.comm, sizeof(raw.comm)));
    evt.filename = std::string(raw.filename, strnlen(raw.filename, sizeof(raw.filename)));
    evt.old_filename = std::string(raw.old_filename, strnlen(raw.old_filename, sizeof(raw.old_filename)));
    evt.mode = raw.mode;
    evt.flags = raw.flags;
    evt.cgroup_id = raw.cgroup_id;
    return evt;
}

inline const char* event_type_name(EventCategory cat, uint32_t type) {
    switch (cat) {
        case EventCategory::PROCESS:
            switch (static_cast<ProcessEventType>(type)) {
                case ProcessEventType::CREATE:   return "process_create";
                case ProcessEventType::EXIT:     return "process_exit";
                case ProcessEventType::PRIV_ESC: return "privilege_escalation";
                default: return "process_unknown";
            }
        case EventCategory::NETWORK:
            switch (static_cast<NetworkEventType>(type)) {
                case NetworkEventType::TCP_CONNECT: return "tcp_connect";
                case NetworkEventType::TCP_ACCEPT:  return "tcp_accept";
                case NetworkEventType::TCP_CLOSE:   return "tcp_close";
                case NetworkEventType::UDP_SEND:    return "udp_send";
                case NetworkEventType::UDP_RECV:    return "udp_recv";
                default: return "network_unknown";
            }
        case EventCategory::FILE:
            switch (static_cast<FileEventType>(type)) {
                case FileEventType::CREATE: return "file_create";
                case FileEventType::MODIFY: return "file_modify";
                case FileEventType::DELETE: return "file_delete";
                case FileEventType::RENAME: return "file_rename";
                case FileEventType::CHMOD:  return "file_chmod";
                case FileEventType::CHOWN:  return "file_chown";
                default: return "file_unknown";
            }
        default: return "unknown";
    }
}

inline const char* category_name(EventCategory cat) {
    switch (cat) {
        case EventCategory::PROCESS: return "process";
        case EventCategory::NETWORK: return "network";
        case EventCategory::FILE:    return "file";
        default: return "unknown";
    }
}

} // namespace ebpf_monitor
