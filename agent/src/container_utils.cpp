#include "container_utils.h"
#include "logger.h"
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>

namespace fs = std::filesystem;

namespace ebpf_monitor {

ContainerInfo ContainerUtils::get_container_info(uint32_t pid) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = cache_.find(pid);
    if (it != cache_.end()) return it->second;
    ContainerInfo info = parse_cgroup(pid);
    cache_[pid] = info;
    return info;
}

void ContainerUtils::clear_cache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    LOG_DEBUG("Container info cache cleared (%zu entries)", cache_.size());
    cache_.clear();
}

ContainerInfo ContainerUtils::parse_cgroup(uint32_t pid) {
    ContainerInfo info;
    info.is_container = false;
    std::string cgroup_path = "/proc/" + std::to_string(pid) + "/cgroup";
    std::ifstream cgroup_file(cgroup_path);
    if (!cgroup_file.is_open()) return info;

    std::string line;
    while (std::getline(cgroup_file, line)) {
        auto pos = line.find(':');
        if (pos == std::string::npos) continue;
        pos = line.find(':', pos + 1);
        if (pos == std::string::npos) continue;
        std::string cgroup = line.substr(pos + 1);

        auto extract_id = [&](const std::string& marker, const std::string& runtime) -> bool {
            auto p = cgroup.find(marker);
            if (p == std::string::npos) return false;
            p += marker.length();
            auto end = cgroup.find('/', p);
            if (end == std::string::npos) end = cgroup.length();
            info.id = cgroup.substr(p, std::min(end - p, (size_t)12));
            info.runtime = runtime;
            info.is_container = true;
            info.name = detect_container_name(pid, cgroup);
            LOG_TRACE("PID %u detected as %s container %s", pid, runtime.c_str(), info.id.c_str());
            return true;
        };

        if (extract_id("/docker/", "docker")) return info;
        if (extract_id("/cri-containerd-", "containerd")) return info;
        if (extract_id("/crio-", "crio")) return info;
        if (extract_id("/libpod-", "podman")) return info;

        if (cgroup.find("/kubepods/") != std::string::npos) {
            auto last_slash = cgroup.rfind('/');
            if (last_slash != std::string::npos && last_slash < cgroup.length() - 1) {
                std::string candidate = cgroup.substr(last_slash + 1);
                if (candidate.length() >= 12) {
                    info.id = candidate.substr(0, 12);
                    info.runtime = "containerd";
                    info.is_container = true;
                    info.name = detect_container_name(pid, cgroup);
                    LOG_TRACE("PID %u detected as K8s pod container %s", pid, info.id.c_str());
                    return info;
                }
            }
        }

        if (cgroup.find("/lxc/") != std::string::npos) {
            auto name_pos = cgroup.find("/lxc/") + 5;
            auto name_end = cgroup.find('/', name_pos);
            if (name_end == std::string::npos) name_end = cgroup.length();
            info.name = cgroup.substr(name_pos, name_end - name_pos);
            info.runtime = "lxc";
            info.is_container = true;
            info.id = get_namespace_id(pid);
            LOG_TRACE("PID %u detected as LXC container %s", pid, info.name.c_str());
            return info;
        }
    }
    return info;
}

std::string ContainerUtils::detect_container_name(uint32_t pid, const std::string& cgroup_path) {
    std::string hostname_path = "/proc/" + std::to_string(pid) + "/root/etc/hostname";
    std::ifstream hostname_file(hostname_path);
    if (hostname_file.is_open()) {
        std::string name;
        std::getline(hostname_file, name);
        if (!name.empty() && name != "localhost") return name;
    }
    std::string environ_path = "/proc/" + std::to_string(pid) + "/environ";
    std::ifstream environ_file(environ_path);
    if (environ_file.is_open()) {
        std::string content((std::istreambuf_iterator<char>(environ_file)),
                            std::istreambuf_iterator<char>());
        size_t pos = 0;
        while (pos < content.length()) {
            size_t end = content.find('\0', pos);
            if (end == std::string::npos) end = content.length();
            std::string entry = content.substr(pos, end - pos);
            if (entry.find("HOSTNAME=") == 0) return entry.substr(9);
            pos = end + 1;
        }
    }
    return "";
}

std::string ContainerUtils::get_namespace_id(uint32_t pid) {
    std::string ns_path = "/proc/" + std::to_string(pid) + "/ns/mnt";
    struct stat st;
    if (stat(ns_path.c_str(), &st) == 0) return std::to_string(st.st_ino);
    return "";
}

} // namespace ebpf_monitor
