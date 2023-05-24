#include <memory>
#include <string>

#include "binary.h"
#include "inject.h"

int main() {
    auto binary = std::make_unique<codeinject::binary::Binary>("notepad.exe");
    auto binary_type = binary->get_binary_type();
    std::unique_ptr<codeinject::inject::CodeInject> binary_code_inject;

    if (binary_type == codeinject::binary::Binary::BinaryType::ELF) {
        binary_code_inject = std::make_unique<codeinject::inject::ElfBinary>();
    } else if (binary_type == codeinject::binary::Binary::BinaryType::PE) {
        binary_code_inject = std::make_unique<codeinject::inject::PeBinary>();
    }

    binary_code_inject->inject_code("mybinary.bin");

    return 0;
}