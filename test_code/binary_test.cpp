#include "binary.h"
#include "inject.h"
#include <catch2/catch_all.hpp>
#include <iostream>
#define excutable_file "/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/elf_64"
#define bin_file "/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/linux_backdoor.bin"
#define edit_file "/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/file_stream_test"
using namespace std;
using namespace codeinject::binary;
using namespace codeinject::inject;

struct my{
  int a = 0x12345678;
  char c = 0x99;
};

TEST_CASE("FileDescriptor") {
  FileDescriptor file_descriptor{excutable_file};
  auto struc = file_descriptor.read_data<IMAGE_DOS_HEADER>(0, sizeof(IMAGE_DOS_HEADER));
  std::cout << struc.e_lfanew << std::endl;
  FileDescriptor file_descriptor2{edit_file};
  std::vector<uint8_t> vec{'\x11', '\x22','\x33', '\x44'};
  file_descriptor2.write_data<std::vector<uint8_t>>(0, 4, std::move(vec));
  //struct my s{};
  //FileDescriptor file_descriptor_1{edit_file};
  //file_descriptor_1.write_data(4, sizeof(struct my), std::move(s));
}

TEST_CASE("Bfd") {
  Bfd bfd_test{excutable_file};

}

TEST_CASE("ELf64 Binary") {
  BinaryParser binary{excutable_file};
  auto elf_binary = std::make_shared<ElfBinary<Elf64_Shdr, Elf64_Ehdr, Elf64_Phdr>>(binary);
  elf_binary->parse_every_thing();

  BinaryParser binary2{bin_file};
  CodeBinary code_binary{binary2};

  ElfCodeInject<Elf64_Shdr, Elf64_Ehdr, Elf64_Phdr> elf64_code_inject{elf_binary, std::move(code_binary.m_code)};
  elf64_code_inject.inject_code();
}

TEST_CASE("ELf32 Binary") {
  BinaryParser binary{excutable_file};
  auto elf_binary = std::make_shared<ElfBinary<Elf32_Shdr, Elf32_Ehdr, Elf32_Phdr>>(binary);
  elf_binary->parse_every_thing();

  BinaryParser binary2{bin_file};
  CodeBinary code_binary{binary2};

  ElfCodeInject<Elf32_Shdr, Elf32_Ehdr, Elf32_Phdr> elf32_code_inject{elf_binary, std::move(code_binary.m_code)};
  elf32_code_inject.inject_code();
}

TEST_CASE("PE32 Binary") {
  BinaryParser binary{excutable_file};
  auto pe_binary = std::make_shared<PeBinary<PE_SECTION_HEADER , PE_DOS_HEADER , PE32_HEADERS>>(binary);
  pe_binary->parse_every_thing();

  BinaryParser binary2{bin_file};
  CodeBinary code_binary{binary2};

  PeCodeInject<PE_SECTION_HEADER , PE_DOS_HEADER , PE32_HEADERS> pe32_code_inject{pe_binary, std::move(code_binary.m_code)};
  pe32_code_inject.inject_code();
}

TEST_CASE("PE64 Binary") {
  BinaryParser binary{excutable_file};
  auto pe_binary = std::make_shared<PeBinary<PE_SECTION_HEADER , PE_DOS_HEADER , PE64_HEADERS>>(binary);
  pe_binary->parse_every_thing();

  BinaryParser binary2{bin_file};
  CodeBinary code_binary{binary2};

  PeCodeInject<PE_SECTION_HEADER , PE_DOS_HEADER , PE64_HEADERS> pe64_code_inject{pe_binary, std::move(code_binary.m_code)};
  pe64_code_inject.inject_code();
}