#pragma once

#include <string>
#include <unordered_map>
#include <mutex>
#include <cstdint>

namespace ebpf_monitor {

struct ContainerInfo {
    std::string id;
    std::string name;
    std::string runtime;
    bool        is_container;
};

class ContainerUtils {
public:
    ContainerUtils() = default;
    ContainerInfo get_container_info(uint32_t pid);
    void clear_cache();

private:
    ContainerInfo parse_cgroup(uint32_t pid);
    std::string detect_container_name(uint32_t pid, const std::string& cgroup_path);
    std::string get_namespace_id(uint32_t pid);

    std::mutex cache_mutex_;
    std::unordered_map<uint32_t, ContainerInfo> cache_;
};

} // namespace ebpf_monitor
