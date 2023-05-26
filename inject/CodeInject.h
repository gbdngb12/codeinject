#pragma once
#include <vector>
#include <vector>
#include "binary.h"

namespace codeinject::inject {
class CodeInject {
   public:
    CodeInject() = default;
    virtual void inject_code(std::vector<uint8_t> code) = 0;
    virtual void add_section(std::string sec_name) = 0;
};

template <typename P>
class PeInject : public CodeInject {
   public:
    P m_binary;
    PeInject(P ptr);
    void inject_code(std::vector<uint8_t> code) override;
    void add_section(std::string sec_name) override;
};

template <typename P>
class ElfInject : public CodeInject {
   public:
    P m_binary;
    ElfInject(P ptr);
    void inject_code(std::vector<uint8_t> code) override;
    void add_section(std::string sec_name) override;
};
};