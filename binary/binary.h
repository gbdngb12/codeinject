#pragma once
#include <bfd.h>
#include <libelf.h>
#include <gelf.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "elf.h"
#include "winnt.h"

enum class BinaryType {
    PE32 = 0,
    PE64 = 1,
    ELF32 = 2,
    ELF64 = 3
};

enum class SectionType {
    SEC_TYPE_NONE = 0, /** @brief */
    SEC_TYPE_CODE = 1, /** @brief Code Section*/
    SEC_TYPE_DATA = 2  /** @brief Data Section*/
};

namespace codeinject::binary {

template <typename T, typename U, typename V>
class PeBinary;
template <typename T, typename U, typename V>
class ElfBinary;

using pe32 = PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE32_HEADERS>;
using pe64 = PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE64_HEADERS>;
using elf32 = ElfBinary<Elf32_Shdr, Elf32_Ehdr, Elf32_Phdr>;
using elf64 = ElfBinary<Elf64_Shdr, Elf64_Ehdr, Elf64_Phdr>;

using pe32_ptr = std::unique_ptr<pe32>;
using pe64_ptr = std::unique_ptr<pe64>;
using elf32_ptr = std::unique_ptr<elf32>;
using elf64_ptr = std::unique_ptr<elf64>;

/**
 * @brief 파일에 읽고 쓰는 클래스
 *
 */
class FileDescriptor {
   private:
    // public:
    /**
     * @brief 파일의 이름
     *
     */
    std::string m_fname;

    ///**
    // * @brief low file descriptor
    // * 
    // */
    //int m_fd;
    //std::FILE* m_file;
    /**
     * @brief
     *
     */
    std::fstream m_file_stream;
    protected:
    /**
     * @brief 미래에 사용할수도있으니 남겨놓는다. low level 관리를 위해
     * 
     */
    int m_fd;
   public:
   virtual ~FileDescriptor();
    std::string get_file_name() const noexcept;
    /**
     * @brief 파일을 연다.
     *
     * @param fname
     */
    FileDescriptor(std::string fname);

    /**
     * @brief 이미 열린 파일 스트림을 받는다.
     *
     * @param fstream
     */
    // FileDescriptor(std::fstream fstream);
    /**
     * @brief pos 위치에 string을 쓴다.
     *
     * @param string 문자열
     * @param pos 위치
     * @return int 쓴 바이트수
     */
    int write_data(std::vector<uint8_t>, int pos);

    /**
     * @brief pos 위치에 size만큼 데이터를 읽는다.
     *
     * @param pos
     * @param size
     * @return std::vector<uint8_t>
     */
    std::vector<uint8_t> read_data(int pos, int size);
};

/**
 * @brief SectionHeader의 정보를 저장하는 클래스
 *
 * @tparam T Section Header
 */
template <typename T>
class SectionHeader {
   public:
    /**
     * @brief section header
     *
     */
    T m_section_header;
    /**
     * @brief section header를 가져온다.
     *
     * @return T
     */
    T get_section_header() const {
        return m_section_header;
    }
};

/**
 * @brief Section의 정보를 저장하는 클래스
 *
 * @tparam T Section Header
 */
template <typename T>
class Section : public SectionHeader<T> {
   public:
    /**
     * @brief section의 실제 데이터
     *
     */
    std::vector<uint8_t> m_bytes;
};

/**
 * @brief 현재 로드한 바이너리의 section의 코드, 이름, vma, vsize, fileoffset을 설정하는 클래스
 *
 * @tparam T SectionHeader의 구조
 */
template <typename T>
class BaseBinary : public FileDescriptor {
   public:
    virtual ~BaseBinary();
    /**
     * @brief file name과 bfd핸들러를 받아 Binary 객체를 생성
     *
     * @param fname
     * @param bfd_h
     */
    BaseBinary(std::string fname, bfd* bfd_h, BinaryType binary_type);
    /**
     * @brief vector<uint8_t>를 구조체로 바꾸는 함수
     *
     * @tparam K 바꾸고 싶은 구조체
     * @param data
     * @return K 바꾸고 싶은 구조체
     */
    template <typename K>
    K vec_to_struct(std::vector<uint8_t>&& data);

    /**
     * @brief 섹션들의 실제 정보를 파싱한다.
     *
     */
    virtual void parse_section();

    /**
     * @brief section의 정보
     *
     */
    std::vector<Section<T>> m_sections;
    /**
     * @brief 각 바이너리에 맞게 모든 구조체 값을 파싱한다.
     *
     */
    virtual void parse_every_thing() = 0;
    /**
     * @brief m_sections의 SectionHeader를 순회하면서 값을 저장한다.
     * 
     */
    virtual void set_section_header(std::vector<uint8_t>&& data);
    /**
     * @brief 혹시모를 미래를 위해 bfd 핸들러는 남겨 놓는다.
     *
     */
    bfd* m_bfd_h;
    BinaryType m_binary_type;
};

/**
 * @brief Elf바이너리의 elf header, program header를 읽는 클래스
 *
 * @tparam T Section Header의 구조
 * @tparam U elf header
 * @tparam V program header
 */
template <typename T, typename U, typename V>
class ElfBinary : public BaseBinary<T> {
   public:
    virtual ~ElfBinary();
    ElfBinary(std::string fname, bfd* bfd_h, BinaryType binary_type);
    void libelf_open();
    /**
     * @brief elf header
     *
     */
    U m_elf_header;
    /**
     * @brief program header
     *
     */
    std::vector<V> m_program_header;
    /**
     * @brief 바이너리의 모든 정보를 파싱한다.
     *
     */
    virtual void parse_every_thing() override;
    /**
     * @brief elf의 elf header를 파싱한다.
     * 
     */
    void parse_elf_header();
    /**
     * @brief elf의 program header를 파싱한다.
     * 
     */
    void parse_program_header();
    /**
     * @brief elf의 section header를 파싱한다.
     * 
     */
    void parse_section_header();

    /**
     * @brief elf바이너리의 추가적인 섹션 정보를 파싱한다.
     *
     */
    virtual void parse_section() override;

    /**
     * @brief libelf를 이용하기 위한 자료
     * 
     */
    Elf* m_elf;// elf descriptor
    //GElf_Ehdr m_ehdr; // elf header
};

/**
 * @brief pe바이너리의 dos header, pe header를 읽는 클래스
 *
 * @tparam T Section Header의 구조
 * @tparam U dos_header
 * @tparam V pe_header
 */
template <typename T, typename U, typename V>
class PeBinary : public BaseBinary<T> {
   public:
    PeBinary(std::string fname, bfd* bfd_h, BinaryType binary_type);
    /**
     * @brief DOS Header
     *
     */
    U m_dos_header;
    /**
     * @brief PE Header
     *
     */
    V m_pe_header;
    /**
     * @brief section정보를 파싱한다.
     *
     */
    virtual void parse_every_thing() override;

    /**
     * @brief MS-DOS Header를 파싱한다.
     *
     */
    void parse_dos_header();
    /**
     * @brief PE Header를 파싱한다.
     *
     */
    void parse_pe_header();
    /**
     * @brief section Header를 파싱한다.
     *
     */
    void parse_section_header();
    /**
     * @brief pe바이너리의 추가적인 section 정보를 파싱한다.
     *
     */
    virtual void parse_section() override;
    int m_number_of_image_data_dir;
};

class BinaryParser {
   private:
    void open_bfd();

   public:
    BinaryParser(std::string fname);
    std::variant<elf32_ptr, elf64_ptr, pe32_ptr, pe64_ptr> create_binary();
    bfd* m_bfd_h;
    std::string m_fname;
    // bfd* get_bfd_handler() const noexcept;
    // BinaryType get_binary_type() const noexcept;
    BinaryType m_binary_type;
};

};  // namespace codeinject::binary