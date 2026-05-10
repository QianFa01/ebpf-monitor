cmake_minimum_required(VERSION 3.16)
project(ebpf_monitor_agent CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)
pkg_check_modules(LIBCURL REQUIRED libcurl)
pkg_check_modules(ZLIB REQUIRED zlib)

include_directories(
    ${LIBBPF_INCLUDE_DIRS}
    ${LIBCURL_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

link_directories(
    ${LIBBPF_LIBRARY_DIRS}
    ${LIBCURL_LIBRARY_DIRS}
    ${ZLIB_LIBRARY_DIRS}
)

set(AGENT_SOURCES
    src/main.cpp
    src/ebpf_loader.cpp
    src/event_reader.cpp
    src/event_sender.cpp
    src/container_utils.cpp
    src/logger.cpp
)

add_executable(ebpf-monitor-agent ${AGENT_SOURCES})

target_link_libraries(ebpf-monitor-agent
    ${LIBBPF_LIBRARIES}
    ${LIBCURL_LIBRARIES}
    ${ZLIB_LIBRARIES}
    elf z pthread
)

target_include_directories(ebpf-monitor-agent PRIVATE ${LIBBPF_INCLUDE_DIRS})

find_program(CLANG clang)
find_program(BPFTOOL bpftool)

if(CLANG AND BPFTOOL)
    set(BPF_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/bpf)
    set(BPF_OUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/bpf)
    file(MAKE_DIRECTORY ${BPF_OUT_DIR})

    execute_process(COMMAND uname -r OUTPUT_VARIABLE KERNEL_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE)
    set(KERNEL_HEADERS /usr/src/linux-headers-${KERNEL_VERSION})

    set(BPF_PROGRAMS process_monitor network_monitor file_monitor)

    foreach(prog ${BPF_PROGRAMS})
        add_custom_command(
            OUTPUT ${BPF_OUT_DIR}/${prog}.bpf.o
            COMMAND ${CLANG} -target bpf -D__TARGET_ARCH_x86
                -I${BPF_SRC_DIR} -I${KERNEL_HEADERS}/include
                -I${KERNEL_HEADERS}/arch/x86/include
                -I${KERNEL_HEADERS}/arch/x86/include/generated
                -g -O2 -c ${BPF_SRC_DIR}/${prog}.bpf.c
                -o ${BPF_OUT_DIR}/${prog}.bpf.o
            DEPENDS ${BPF_SRC_DIR}/${prog}.bpf.c
            COMMENT "Compiling BPF program: ${prog}"
        )
        list(APPEND BPF_OUTPUTS ${BPF_OUT_DIR}/${prog}.bpf.o)
    endforeach()

    add_custom_target(bpf_programs ALL DEPENDS ${BPF_OUTPUTS})
    add_dependencies(ebpf-monitor-agent bpf_programs)
    install(FILES ${BPF_OUTPUTS} DESTINATION share/ebpf-monitor/bpf)
else()
    message(WARNING "clang or bpftool not found - BPF programs will not be compiled automatically")
endif()

install(TARGETS ebpf-monitor-agent DESTINATION bin)
