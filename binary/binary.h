#pragma once
#include <bfd.h>
#include <gelf.h>
#include <libelf.h>

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
    // int m_fd;
    // std::FILE* m_file;
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

    int get_file_size() {
        m_file_stream.seekg(0, std::ios::end);
        return m_file_stream.tellg();
    }
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
    std::string m_section_name;
};

/**
 * @brief bfd를 다루는 클래스
 *
 */
class Bfd : public FileDescriptor {
   public:
    virtual ~Bfd();
    /**
     * @brief 파일로 bfd 핸들러를 연다.
     *
     * @param fname
     */
    Bfd(std::string fname);
    /**
     * @brief 미리 생성된 bfd 핸들러가 있으면 저장한다.
     *
     * @param fname
     * @param bfd_h
     */
    Bfd(std::string fname, std::shared_ptr<bfd> bfd_h);
    std::shared_ptr<bfd> m_bfd_h;
    inline static int bfd_inited = 0;
    virtual void open_bfd();
};

/**
 * @brief 섹션의 실제 정보만 다루는 클래스
 *
 * @tparam T
 */
template <typename T>
class SectionBinary : public Bfd {
   public:
    /**
     * @brief Section을 가져옴
     * 
     * @param sec_name 
     * @return Section<T>& 
     */
    virtual Section<T>& operator[](std::string&& sec_name);
    /**
     * @brief 실제 섹션의 내용을 변경함, 없으면 추가함
     * 
     * @param sec 
     * @return Section<T>& 
     */
    virtual Section<T>& operator=(Section<T>&& sec) = 0;
    SectionBinary(std::string fname, std::shared_ptr<bfd> bfd_h);
    /**
     * @brief 미리 생성된 bfd handler가 없는 경우
     *
     * @param fname
     */
    SectionBinary(std::string fname);

    std::vector<Section<T>> m_sections;
    virtual void parse_section();  // 실제 section의 data를 파싱한다.
    /**
     * @brief vector<uint8_t>를 구조체로 바꾸는 함수
     *
     * @tparam K 바꾸고 싶은 구조체
     * @param data
     * @return K 바꾸고 싶은 구조체
     */
    template <typename K>
    K vec_to_struct(std::vector<uint8_t>&& data);

    template<typename K>
    std::vector<uint8_t> struct_to_vec(const K& data);
};

/**
 * @brief 현재 로드한 바이너리의 section의 코드, 이름, vma, vsize, fileoffset을 설정하는 클래스
 *
 * @tparam T SectionHeader의 구조
 */
template <typename T>
class BaseBinary : public SectionBinary<T> {
   public:
    virtual ~BaseBinary() = default;
    /**
     * @brief file name과 bfd핸들러를 받아 Binary 객체를 생성
     *
     * @param fname
     * @param bfd_h
     */
    BaseBinary(std::string fname, std::shared_ptr<bfd> bfd_h, BinaryType binary_type);

    /**
     * @brief 각 바이너리에 맞게 모든 구조체 값을 파싱한다.
     *
     */
    virtual void parse_every_thing() = 0;
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
    // ElfBinary(std::string fname, BinaryType binary_type);
    ElfBinary(std::string fname, std::shared_ptr<bfd> bfd_h, BinaryType binary_type);


    virtual Section<T>& operator=(Section<T>&& sec) override;

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
     * @brief libelf를 이용하기 위한 자료
     *
     */
    Elf* m_elf;  // elf descriptor
    // GElf_Ehdr m_ehdr; // elf header
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
    PeBinary() = default;
    PeBinary(std::string fname, std::shared_ptr<bfd> bfd_h, BinaryType binary_type);

    virtual Section<T>& operator=(Section<T>&& sec) override;
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

    int m_number_of_image_data_dir;

    /**
     * @brief m_sections의 SectionHeader를 순회하면서 값을 저장한다.
     *
     */
    virtual void set_section_header(std::vector<uint8_t>& data);
};

template <typename T>
class CodeBinary : public SectionBinary<T> {
   public:
    virtual Section<T>& operator=(Section<T>&& sec) override {
    }
    CodeBinary(std::string fname);
    virtual void open_bfd() override;
    std::vector<uint8_t> get_code() const;
};

class BinaryParser : public Bfd {
   public:
    BinaryParser(std::string fname);
    std::variant<elf32_ptr, elf64_ptr, pe32_ptr, pe64_ptr> create_binary();
    BinaryType m_binary_type;
};

};  // namespace codeinject::binary