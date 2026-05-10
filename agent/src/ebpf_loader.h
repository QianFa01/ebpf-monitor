#pragma once

#include <string>
#include <vector>
#include <functional>
#include <memory>

struct bpf_object;
struct bpf_program;
struct bpf_link;
struct perf_buffer;

namespace ebpf_monitor {

struct BpfProgramInfo {
    std::string name;
    int prog_fd;
    struct bpf_link* link;
};

class EbpfLoader {
public:
    EbpfLoader();
    ~EbpfLoader();

    bool load_object(const std::string& path);
    bool attach_all();
    int get_perf_buffer_fd(const std::string& map_name);
    const std::vector<BpfProgramInfo>& get_programs() const { return programs_; }
    void cleanup();
    static bool has_btf();

private:
    struct bpf_object* obj_ = nullptr;
    std::vector<BpfProgramInfo> programs_;
    std::vector<struct bpf_link*> links_;
};

} // namespace ebpf_monitor
