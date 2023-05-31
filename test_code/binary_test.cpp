#include "binary.h"
#include <catch2/catch_all.hpp>
#include <iostream>
#define test_file "/home/dong/Downloads/elf_backdoor/backdoor/codeinject/test_files/pe_64"
using namespace std;
using namespace codeinject::binary;



TEST_CASE("FileDescriptor") {
  FileDescriptor file_descriptor{test_file};
  auto struc = file_descriptor.read_struct<IMAGE_DOS_HEADER>(0, sizeof(IMAGE_DOS_HEADER));
  std::cout << struc.e_lfanew << std::endl;
}

TEST_CASE("Bfd") {
  Bfd bfd_test{test_file};

}

TEST_CASE("BinaryParser") {
  BinaryParser binary{test_file};
  //BaseBinary base{binary};
  PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE64_HEADERS> pe_binary{binary};
  pe_binary.parse_every_thing();

  Section<PE_SECTION_HEADER> sec;
  memcpy(std::get<0>(sec.m_section_header).Name, "abcde\0\0\0", 8);
  std::get<1>(sec.m_section_header) = 0x208;
  std::get<2>(sec.m_section_header) = sizeof(PE_SECTION_HEADER);
  sec.m_section = std::make_tuple(std::vector<uint8_t>{'\x00','\x01','\x02'}, 0x0400, 0x024800);
  pe_binary.edit_section(".text", sec, EditMode::EDIT);
}
