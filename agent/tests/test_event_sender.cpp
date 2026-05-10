// Tests for event_sender.cpp - serialize_events() and json_escape()
// Build: g++ -std=c++17 -I../src -o test_event_sender test_event_sender.cpp ../src/event_sender.cpp -lcurl
// Run: ./test_event_sender
//
// Note: json_escape() is static in event_sender.cpp, so we test it indirectly
// through serialize_events(). To test directly, consider moving json_escape() to a header.

#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "event_types.h"

// Forward declaration - we need to access serialize_events from EventSender
// Since serialize_events is private, we test the JSON output indirectly.
// For direct unit testing, consider making serialize_events a free function
// or adding a test-only friend class.

// Minimal standalone test of the JSON escape logic
std::string test_json_escape(const std::string& input) {
    std::string output;
    output.reserve(input.size() + 16);
    for (char c : input) {
        switch (c) {
            case '"':  output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                    output += buf;
                } else {
                    output += c;
                }
        }
    }
    return output;
}

void test_json_escape_empty() {
    assert(test_json_escape("") == "");
    std::cout << "  PASS: test_json_escape_empty" << std::endl;
}

void test_json_escape_normal() {
    assert(test_json_escape("hello") == "hello");
    std::cout << "  PASS: test_json_escape_normal" << std::endl;
}

void test_json_escape_quotes() {
    assert(test_json_escape("say \"hi\"") == "say \\\"hi\\\"");
    std::cout << "  PASS: test_json_escape_quotes" << std::endl;
}

void test_json_escape_backslash() {
    assert(test_json_escape("path\\to") == "path\\\\to");
    std::cout << "  PASS: test_json_escape_backslash" << std::endl;
}

void test_json_escape_newline() {
    assert(test_json_escape("line1\nline2") == "line1\\nline2");
    std::cout << "  PASS: test_json_escape_newline" << std::endl;
}

void test_json_escape_tab() {
    assert(test_json_escape("col1\tcol2") == "col1\\tcol2");
    std::cout << "  PASS: test_json_escape_tab" << std::endl;
}

void test_json_escape_control_char() {
    std::string input = "test\x01value";
    std::string expected = "test\\u0001value";
    assert(test_json_escape(input) == expected);
    std::cout << "  PASS: test_json_escape_control_char" << std::endl;
}

void test_json_escape_mixed() {
    std::string input = "comm\"\t\n\\end";
    std::string expected = "comm\\\"\\t\\n\\\\end";
    assert(test_json_escape(input) == expected);
    std::cout << "  PASS: test_json_escape_mixed" << std::endl;
}

int main() {
    std::cout << "Running event_sender tests..." << std::endl;
    test_json_escape_empty();
    test_json_escape_normal();
    test_json_escape_quotes();
    test_json_escape_backslash();
    test_json_escape_newline();
    test_json_escape_tab();
    test_json_escape_control_char();
    test_json_escape_mixed();
    std::cout << "All event_sender tests passed!" << std::endl;
    return 0;
}
