#include "binary.h"
#include "inject.h"
#include <string>
#include <utility>
#include <variant>

using namespace std;
using namespace codeinject::binary;
using namespace codeinject::inject;

variant<elf_32_ptr, elf_64_ptr, pe_32_ptr, pe_64_ptr, code_ptr> create_binary(const BinaryParser &binary) {
  const auto &binary_type = binary.get_binary_type();
  if (binary_type == BinaryType::ELF32) {
    return make_shared<elf_32>(std::ref(binary));
  } else if (binary_type == BinaryType::ELF64) {
    return make_shared<elf_64>(std::ref(binary));
  } else if (binary_type == BinaryType::PE32) {
    return make_shared<pe_32>(std::ref(binary));
  } else if (binary_type == BinaryType::PE64) {
    return make_shared<pe_64>(std::ref(binary));
  } else if (binary_type == BinaryType::CODE) {
    return make_shared<code>(std::ref(binary));
  } else {
    cerr << "unknown binary type" << endl;
    exit(1);
  }
}

int main(int argc, const char *argv[]) {
  size_t address = 0;
  if (argc < 3) {
    cerr << "usage ./<codeinject> <target> <inject> <address>" << endl;
    exit(1);
  } else if (argc >= 4) {
    address = strtoul(argv[3], NULL, 0);
  }
  BinaryParser binary{argv[1]};
  auto parsed_binary = create_binary(binary);

  std::visit([&argv, &address](auto &&obj) {
    BinaryParser code_binary{argv[2]};
    CodeBinary parsed_code_binary{code_binary};
    using T = std::decay_t<decltype(obj)>;
    if constexpr (std::is_same_v<T, elf_32_ptr>) {
      obj->parse_every_thing();
      CodeInject &&codeinject = elf_32_codeinject(std::move(obj), std::move(parsed_code_binary.m_code), address);
      codeinject.inject_code();
    } else if constexpr (std::is_same_v<T, elf_64_ptr>) {
      obj->parse_every_thing();
      CodeInject &&codeinject = elf_64_codeinject(std::move(obj), std::move(parsed_code_binary.m_code), address);
      codeinject.inject_code();
    } else if constexpr (std::is_same_v<T, pe_32_ptr>) {
      obj->parse_every_thing();
      CodeInject &&codeinject = pe_32_codeinject(std::move(obj), std::move(parsed_code_binary.m_code));
      codeinject.inject_code();
    } else if constexpr (std::is_same_v<T, pe_64_ptr>) {
      obj->parse_every_thing();
      CodeInject &&codeinject = pe_64_codeinject(std::move(obj), std::move(parsed_code_binary).m_code);
      codeinject.inject_code();
    } else {
      std::cerr << "unknown binary type" << std::endl;
      exit(1);
    }
  }, parsed_binary);

  return 0;
}