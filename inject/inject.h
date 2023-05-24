#pragma once
#include <memory>
#include <vector>

#include "binary.h"
namespace codeinject::inject {

class CodeReader {
   public:
    virtual ~CodeReader() = default;
    /**
     * @brief 읽은 코드
     *
     */
    std::vector<uint8_t> m_bytes;
    /**
     * @brief 해당 파일을 열고 코드를 읽는다.
     *
     * @param fname 읽고자 하는 파일
     */
    bool read_code(std::string fname);
    /**
     * @brief 읽은 코드를 리턴한다.
     *
     * @return std::vector<uint8_t>
     */
    std::vector<uint8_t> get_code() const noexcept;
};

class CodeInject {
   public:
    virtual ~CodeInject() = default;
    CodeInject(codeinject::binary::Binary *binary);
    /**
     * @brief 코드를 읽는 객체
     *
     */
    CodeReader m_code_reader;
    /**
     * @brief 바이너리 객체
     *
     */
    std::unique_ptr<codeinject::binary::Binary> m_binary;
    /**
     * @brief 파일로부터 코드를 읽어 코드를 삽입한다.
     *
     * @return int
     */
    virtual int inject_code(std::string);

    /**
     * @brief 이름의 섹션을 삽입한다.
     *
     * @return int
     */
    virtual int add_section(std::string) = 0;
};

class PeBinary : public CodeInject {
   public:
    PeBinary(codeinject::binary::Binary *binary);
    virtual ~PeBinary() = default;
    virtual int inject_code(std::string) override;
    virtual int add_section(std::string) = 0;
};

class ElfBinary : public CodeInject {
   public:
    ElfBinary(codeinject::binary::Binary *binary);
    virtual ~ElfBinary() = default;
    virtual int inject_code(std::string) override;
    virtual int add_section(std::string) = 0;
};
}  // namespace codeinject::inject