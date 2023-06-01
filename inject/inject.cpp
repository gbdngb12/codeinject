#include "inject.h"
#include <iostream>
#include <utility>

namespace codeinject::inject {
CodeInject::CodeInject(std::vector<uint8_t> code) : m_code{std::move(code)} {

}

template<typename T, typename U, typename V>
bool PeCodeInject<T, U, V>::inject_code() {
  std::cout << "pe inject code" << std::endl;
  return false;
}
template<typename T, typename U, typename V>
PeCodeInject<T, U, V>::PeCodeInject(std::shared_ptr<binary::PeBinary<T, U, V>> pe_binary, std::vector<uint8_t> code)
    : m_pe_binary_ptr{pe_binary}, CodeInject(std::move(code)) {

}

template<typename T, typename U, typename V>
bool ElfCodeInject<T, U, V>::inject_code() {
  std::cout << "elf inject code" << std::endl;

  return true;
}
template<typename T, typename U, typename V>
ElfCodeInject<T, U, V>::ElfCodeInject(std::shared_ptr<binary::ElfBinary<T, U, V>> elf_binary, std::vector<uint8_t> code)
    : m_elf_binary_ptr{elf_binary}, CodeInject(std::move(code)) {

}
};

template
class codeinject::inject::PeCodeInject<PE_SECTION_HEADER, PE_DOS_HEADER, PE64_HEADERS>;
template
class codeinject::inject::PeCodeInject<PE_SECTION_HEADER, PE_DOS_HEADER, PE32_HEADERS>;
template
class codeinject::inject::ElfCodeInject<Elf32_Shdr, Elf32_Ehdr, Elf32_Phdr>;
template
class codeinject::inject::ElfCodeInject<Elf64_Shdr, Elf64_Ehdr, Elf64_Phdr>;
