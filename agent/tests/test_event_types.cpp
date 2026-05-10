// Tests for event_types.h - from_raw() conversions and event_type_name()
// Build: g++ -std=c++17 -I../src -o test_event_types test_event_types.cpp
// Run: ./test_event_types

#include <cassert>
#include <cstring>
#include <iostream>
#include <arpa/inet.h>

#include "event_types.h"

using namespace ebpf_monitor;

void test_from_raw_process() {
    ProcessEventRaw raw{};
    raw.timestamp = 1234567890;
    raw.event_type = static_cast<uint32_t>(ProcessEventType::CREATE);
    raw.pid = 100;
    raw.ppid = 1;
    raw.uid = 1000;
    raw.gid = 1000;
    raw.exit_code = 0;
    raw.cgroup_id = 0;
    strncpy(raw.comm, "test-proc", sizeof(raw.comm));
    strncpy(raw.filename, "/usr/bin/test", sizeof(raw.filename));

    Event evt = from_raw(raw);

    assert(evt.timestamp_ns == 1234567890);
    assert(evt.category == EventCategory::PROCESS);
    assert(evt.event_type == static_cast<uint32_t>(ProcessEventType::CREATE));
    assert(evt.pid == 100);
    assert(evt.ppid == 1);
    assert(evt.uid == 1000);
    assert(evt.gid == 1000);
    assert(evt.comm == "test-proc");
    assert(evt.filename == "/usr/bin/test");
    assert(evt.exit_code == 0);
    std::cout << "  PASS: test_from_raw_process" << std::endl;
}

void test_from_raw_process_null_trimming() {
    ProcessEventRaw raw{};
    strncpy(raw.comm, "short", sizeof(raw.comm));
    strncpy(raw.filename, "/tmp/f", sizeof(raw.filename));

    Event evt = from_raw(raw);
    assert(evt.comm == "short");
    assert(evt.filename == "/tmp/f");
    std::cout << "  PASS: test_from_raw_process_null_trimming" << std::endl;
}

void test_from_raw_network() {
    NetworkEventRaw raw{};
    raw.timestamp = 9876543210;
    raw.event_type = static_cast<uint32_t>(NetworkEventType::TCP_CONNECT);
    raw.pid = 200;
    raw.uid = 0;
    raw.saddr = inet_addr("127.0.0.1");
    raw.daddr = inet_addr("192.168.1.1");
    raw.sport = 12345;
    raw.dport = 80;
    raw.proto = 6;
    strncpy(raw.comm, "curl", sizeof(raw.comm));

    Event evt = from_raw(raw);

    assert(evt.timestamp_ns == 9876543210);
    assert(evt.category == EventCategory::NETWORK);
    assert(evt.pid == 200);
    assert(evt.src_addr == "127.0.0.1");
    assert(evt.dst_addr == "192.168.1.1");
    assert(evt.src_port == 12345);
    assert(evt.dst_port == 80);
    assert(evt.protocol == 6);
    assert(evt.comm == "curl");
    std::cout << "  PASS: test_from_raw_network" << std::endl;
}

void test_from_raw_file() {
    FileEventRaw raw{};
    raw.timestamp = 1111111111;
    raw.event_type = static_cast<uint32_t>(FileEventType::CREATE);
    raw.pid = 300;
    raw.uid = 0;
    raw.gid = 0;
    raw.mode = 0644;
    raw.flags = 0;
    strncpy(raw.comm, "touch", sizeof(raw.comm));
    strncpy(raw.filename, "/tmp/test.txt", sizeof(raw.filename));
    strncpy(raw.old_filename, "", sizeof(raw.old_filename));

    Event evt = from_raw(raw);

    assert(evt.timestamp_ns == 1111111111);
    assert(evt.category == EventCategory::FILE);
    assert(evt.pid == 300);
    assert(evt.comm == "touch");
    assert(evt.filename == "/tmp/test.txt");
    assert(evt.old_filename == "");
    assert(evt.mode == 0644);
    std::cout << "  PASS: test_from_raw_file" << std::endl;
}

void test_event_type_name_process() {
    assert(std::string(event_type_name(EventCategory::PROCESS, 1)) == "process_create");
    assert(std::string(event_type_name(EventCategory::PROCESS, 2)) == "process_exit");
    assert(std::string(event_type_name(EventCategory::PROCESS, 3)) == "privilege_escalation");
    assert(std::string(event_type_name(EventCategory::PROCESS, 99)) == "process_unknown");
    std::cout << "  PASS: test_event_type_name_process" << std::endl;
}

void test_event_type_name_network() {
    assert(std::string(event_type_name(EventCategory::NETWORK, 10)) == "tcp_connect");
    assert(std::string(event_type_name(EventCategory::NETWORK, 11)) == "tcp_accept");
    assert(std::string(event_type_name(EventCategory::NETWORK, 12)) == "tcp_close");
    assert(std::string(event_type_name(EventCategory::NETWORK, 20)) == "udp_send");
    assert(std::string(event_type_name(EventCategory::NETWORK, 21)) == "udp_recv");
    assert(std::string(event_type_name(EventCategory::NETWORK, 99)) == "network_unknown");
    std::cout << "  PASS: test_event_type_name_network" << std::endl;
}

void test_event_type_name_file() {
    assert(std::string(event_type_name(EventCategory::FILE, 30)) == "file_create");
    assert(std::string(event_type_name(EventCategory::FILE, 31)) == "file_modify");
    assert(std::string(event_type_name(EventCategory::FILE, 32)) == "file_delete");
    assert(std::string(event_type_name(EventCategory::FILE, 33)) == "file_rename");
    assert(std::string(event_type_name(EventCategory::FILE, 34)) == "file_chmod");
    assert(std::string(event_type_name(EventCategory::FILE, 35)) == "file_chown");
    assert(std::string(event_type_name(EventCategory::FILE, 99)) == "file_unknown");
    std::cout << "  PASS: test_event_type_name_file" << std::endl;
}

void test_category_name() {
    assert(std::string(category_name(EventCategory::PROCESS)) == "process");
    assert(std::string(category_name(EventCategory::NETWORK)) == "network");
    assert(std::string(category_name(EventCategory::FILE)) == "file");
    std::cout << "  PASS: test_category_name" << std::endl;
}

int main() {
    std::cout << "Running event_types tests..." << std::endl;
    test_from_raw_process();
    test_from_raw_process_null_trimming();
    test_from_raw_network();
    test_from_raw_file();
    test_event_type_name_process();
    test_event_type_name_network();
    test_event_type_name_file();
    test_category_name();
    std::cout << "All event_types tests passed!" << std::endl;
    return 0;
}
