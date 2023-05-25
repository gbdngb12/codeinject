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
    BinaryParser binary{"/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/pe_64"};
    auto parsed_binary = binary.create_binary();
    // binary_type에 접근하여 해당 타입을 출력하는 방법
     if (std::holds_alternative<elf32_ptr>(parsed_binary)) {
        std::cout << "Binary type: ELF32" << std::endl;
        // need to test
    } else if (std::holds_alternative<elf64_ptr>(parsed_binary)) {
        std::cout << "Binary type: ELF64" << std::endl;
        CodeBinary<Elf64_Shdr> codebinary{"/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/linux_backdoor.bin"};
        auto code = codebinary.get_code();
    } else if (std::holds_alternative<pe32_ptr>(parsed_binary)) {
        std::cout << "Binary type: PE32" << std::endl;
        // need to test
    } else if (std::holds_alternative<pe64_ptr>(parsed_binary)) {
        std::cout << "Binary type: PE64" << std::endl;
        CodeBinary<PE_SECTION_HEADER> codebinary{"/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/win_backdoor.bin"};
        auto code = codebinary.get_code();
    }
}