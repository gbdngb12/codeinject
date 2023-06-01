#pragma once
#include <vector>
#include "binary.h"
#include <cstdint>
namespace codeinject::inject {
class CodeInject {
 public:
  std::vector<uint8_t> m_code;
  virtual bool inject_code() = 0;
  CodeInject(std::vector<uint8_t>);
};

template<typename T, typename U, typename V>
class PeCodeInject : public CodeInject {
 public:
  std::shared_ptr<codeinject::binary::PeBinary<T, U, V>> m_pe_binary_ptr;
  virtual bool inject_code() override;
  PeCodeInject(std::shared_ptr<codeinject::binary::PeBinary<T, U, V>>, std::vector<uint8_t> code);
};

template<typename T, typename U, typename V>
class ElfCodeInject : public CodeInject {
 public:
  std::shared_ptr<codeinject::binary::ElfBinary<T, U, V>> m_elf_binary_ptr;
  virtual bool inject_code() override;
  ElfCodeInject(std::shared_ptr<codeinject::binary::ElfBinary<T, U, V>>, std::vector<uint8_t> code);

};
};