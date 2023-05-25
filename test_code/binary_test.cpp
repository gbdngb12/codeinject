#include "binary.h"

#include <catch2/catch_all.hpp>
#include <iostream>
#include <variant>
#include <vector>

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
    BinaryParser open_binary{"/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/pe_64"};
    auto parsed_binary = open_binary.create_binary();

    std::visit([](auto&& binary) {
        using T = std::decay_t<decltype(binary)>;

        if constexpr (std::is_same_v<T, elf32_ptr>) {
            std::cout << "Binary type: ELF32" << std::endl;
            // need to test
        } else if constexpr (std::is_same_v<T, elf64_ptr>) {
            std::cout << "Binary type: ELF64" << std::endl;
            CodeBinary<Elf64_Shdr> codebinary{"/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/linux_backdoor.bin"};
            auto code = codebinary.get_code();
        } else if constexpr (std::is_same_v<T, pe32_ptr>) {
            std::cout << "Binary type: PE32" << std::endl;
            // need to test
        } else if constexpr (std::is_same_v<T, pe64_ptr>) {
            std::cout << "Binary type: PE64" << std::endl;
            CodeBinary<PE_SECTION_HEADER> codebinary{"/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/win_backdoor.bin"};
            auto code = codebinary.get_code();
            PeInject<pe64_ptr> peinject{std::move(binary)};
            peinject.inject_code(code);
        }
    },
               parsed_binary);
}