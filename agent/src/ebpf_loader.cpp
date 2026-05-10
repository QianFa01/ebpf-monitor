#include "ebpf_loader.h"
#include "logger.h"
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <cstring>
#include <cerrno>

namespace ebpf_monitor {

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) {
    if (level == LIBBPF_DEBUG) return 0;
    char buf[1024];
    vsnprintf(buf, sizeof(buf), format, args);
    switch (level) {
        case LIBBPF_WARN:  LOG_WARN("[libbpf] %s", buf); break;
        case LIBBPF_INFO:  LOG_DEBUG("[libbpf] %s", buf); break;
        default:           LOG_TRACE("[libbpf] %s", buf); break;
    }
    return 0;
}

EbpfLoader::EbpfLoader() { libbpf_set_print(libbpf_print_fn); }
EbpfLoader::~EbpfLoader() { cleanup(); }

bool EbpfLoader::has_btf() {
    return access("/sys/kernel/btf/vmlinux", R_OK) == 0;
}

bool EbpfLoader::load_object(const std::string& path) {
    LIBBPF_OPTS(bpf_object_open_opts, opts);
    obj_ = bpf_object__open(path.c_str());
    if (libbpf_get_error(obj_)) {
        LOG_ERROR("Failed to open BPF object: %s error: %s", path.c_str(), strerror(errno));
        obj_ = nullptr;
        return false;
    }
    int err = bpf_object__load(obj_);
    if (err) {
        LOG_ERROR("Failed to load BPF object: %s error: %s", path.c_str(), strerror(-err));
        bpf_object__close(obj_);
        obj_ = nullptr;
        return false;
    }
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj_) {
        BpfProgramInfo info;
        info.name = bpf_program__name(prog);
        info.prog_fd = bpf_program__fd(prog);
        info.link = nullptr;
        programs_.push_back(info);
    }
    LOG_INFO("Loaded BPF object: %s (%zu programs)", path.c_str(), programs_.size());
    return true;
}

bool EbpfLoader::attach_all() {
    if (!obj_) return false;
    struct bpf_program *prog;
    int idx = 0;
    bpf_object__for_each_program(prog, obj_) {
        struct bpf_link *link = nullptr;
        enum bpf_prog_type type = bpf_program__type(prog);
        if (type == BPF_PROG_TYPE_TRACEPOINT) {
            const char *sec = bpf_program__section_name(prog);
            std::string section(sec);
            auto slash1 = section.find('/');
            auto slash2 = section.find('/', slash1 + 1);
            if (slash1 != std::string::npos && slash2 != std::string::npos) {
                std::string category = section.substr(slash1 + 1, slash2 - slash1 - 1);
                std::string tp_name = section.substr(slash2 + 1);
                link = bpf_program__attach_tracepoint(prog, category.c_str(), tp_name.c_str());
                if (libbpf_get_error(link)) {
                    LOG_ERROR("Failed to attach tracepoint %s/%s: %s", category.c_str(), tp_name.c_str(), strerror(errno));
                    link = nullptr;
                } else {
                    LOG_INFO("Attached tracepoint: %s/%s", category.c_str(), tp_name.c_str());
                }
            }
        } else if (type == BPF_PROG_TYPE_KPROBE) {
            const char *sec = bpf_program__section_name(prog);
            std::string section(sec);
            bool is_return = section.find("kretprobe") != std::string::npos;
            auto slash = section.find('/');
            std::string func_name = (slash != std::string::npos) ? section.substr(slash + 1) : "";
            if (!func_name.empty()) {
                link = bpf_program__attach_kprobe(prog, is_return, func_name.c_str());
                if (libbpf_get_error(link)) {
                    LOG_ERROR("Failed to attach %s %s: %s", is_return ? "kretprobe" : "kprobe", func_name.c_str(), strerror(errno));
                    link = nullptr;
                } else {
                    LOG_INFO("Attached %s: %s", is_return ? "kretprobe" : "kprobe", func_name.c_str());
                }
            }
        }
        if (link) {
            links_.push_back(link);
            if (idx < (int)programs_.size()) programs_[idx].link = link;
        }
        idx++;
    }
    return !links_.empty();
}

int EbpfLoader::get_perf_buffer_fd(const std::string& map_name) {
    if (!obj_) return -1;
    struct bpf_map *map = bpf_object__find_map_by_name(obj_, map_name.c_str());
    if (!map) {
        LOG_ERROR("BPF map not found: %s", map_name.c_str());
        return -1;
    }
    return bpf_map__fd(map);
}

void EbpfLoader::cleanup() {
    for (auto *link : links_) { if (link) bpf_link__destroy(link); }
    links_.clear();
    programs_.clear();
    if (obj_) { bpf_object__close(obj_); obj_ = nullptr; }
}

} // namespace ebpf_monitor
