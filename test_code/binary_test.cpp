#include <catch2/catch_all.hpp>
#include "binary.h"
#include <iostream>
#include <vector>

using namespace std;
using namespace codeinject::binary;

TEST_CASE("File Descriptor") {
    FileDescriptor f{"open_file"};
    std::vector<uint8_t> data{'\x48', '\x45', '\x4c'};
    f.write_data(std::move(data), 4);
    char array[10];
    f.read_data(0, array);
    for(const auto& v :array) {
        cout << v;
    }
    cout << endl;
}

TEST_CASE("Binary") {
    Binary binary{"notepad.exe"};
    std::cout << binary.m_bits_str << std::endl;
    std::cout << binary.m_binary_type_str << std::endl;
    std::cout << binary.m_original_entry_point << std::endl;
    std::cout << binary.m_number_of_sections << endl;
}