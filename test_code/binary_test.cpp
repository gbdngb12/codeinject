#include "binary.h"

#include <catch2/catch_all.hpp>
#include <iostream>
#include <vector>
#include <variant>

using namespace std;
using namespace codeinject::binary;

TEST_CASE("FileDescriptor") {
    FileDescriptor file{"/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/file_stream_test"};
    auto ret = file.read_data(0, 10);
    for (const auto& d : ret) {
        cout << d;
    }
    std::vector<uint8_t> data{'\x12', '\x33', '\x55'};
    file.write_data(data, 0);
    std::cout << std::endl;
}

TEST_CASE("BinaryParser") {
    BinaryParser binary{"/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/pe_64"};
    auto parsed_biary = binary.create_binary();
    std::visit([](auto&& ptr) {
        using T = std::decay_t<decltype(ptr)>;
        if constexpr (std::is_same_v<T, elf32_ptr>) {
            std::cout << "elf32!!" << std::endl;

        } else if constexpr (std::is_same_v<T, elf64_ptr>) {
            std::cout << "elf64" << std::endl;

        } else if constexpr (std::is_same_v<T, pe64_ptr>) {
            std::cout << ptr.get()->m_dos_header.e_magic << std::endl;
            std::cout << "pe64" << std::endl;

        } else if constexpr (std::is_same_v<T, pe32_ptr>) {

            std::cout << "pe32" << std::endl;
        } 
    },
               parsed_biary);
}