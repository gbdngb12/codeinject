#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <tuple>
#include <bfd.h>
#include <cstring>
#include <libelf.h>
#include <gelf.h>
#include <fstream>
#include <iostream>
#define FMT_HEADER_ONLY
#include "fmt/format.h"
namespace std {
using fmt::format;
using fmt::format_error;
using fmt::formatter;
}  // namespace std

#include "winnt.h"
#include "elf.h"


namespace codeinject::binary {
enum class BinaryType {
  PE32 = 0,
  PE64 = 1,
  ELF32 = 2,
  ELF64 = 3,
  CODE = 4
};

enum class EditMode {
  APPEND = 0,
  EDIT = 1
};

class FileDescriptor {
 public:
  FileDescriptor(const FileDescriptor &) = delete;
  FileDescriptor &operator=(const FileDescriptor &) = delete;
  virtual ~FileDescriptor() = default;

  /**
   * 파일의 이름
   */
  std::string m_fname;

  std::fstream m_file_stream;

  /**
   * S에 값을 읽는다.
   * @tparam S 구조체 또는 vector
   * @param pos 읽을 위치
   * @param size 읽을 크기
   * @return 구조체
   */
  template<typename S>
  S read_data(int pos, int size);

  /**
   * S에 값을 쓴다.
   * @tparam S 구조체 또는 vector
   * @param pos 쓸 위치
   * @param size 쓸 크기
   * @param struct_data 구조체
   */
  template<typename S>
  void write_data(int pos, int size, S &&struct_data);

  /**
   * 파일을 연다.
   * @param fname
   */
  explicit FileDescriptor(std::string fname);
  /**
   * 파일을 열지 않는다.
   */
  explicit FileDescriptor() = default;


  /**
   * 파일의 이름을 설정한다.
   * @param fname
   */
  void set_file_name(std::string fname);

  int get_file_size();

};

class Bfd : public FileDescriptor {
 public:
  /**
 * 바이너리 타입
 */
  BinaryType m_binary_type;
  /**
   * bfd handler
   */
  std::shared_ptr<bfd> m_bfd_h;
  /**
   * 파일의 이름을 설정하고 bfd_handler를 연다.
   * @param fname 파일 이름
   */
  explicit Bfd(std::string fname);
  /**
   * 파일을 열고 기존의 bfd_handler를 설정한다.
   * @param fname
   * @param bfd_h
   */
  explicit Bfd(std::string fname, std::shared_ptr<bfd> bfd_h, BinaryType);

  explicit Bfd(std::string fname, BinaryType);
  /**
   * bfd handler를 연다.
   */
  void open_bfd();
  inline static int bfd_inited = 0;
};

class BinaryParser : public Bfd {
 public:

  /**
   * 바이너리를 연다.
   * @param fname
   */
  explicit BinaryParser(std::string fname);

  /**
   * 바이너리의 타입을 가져온다.
   * @return
   */
  BinaryType get_binary_type() const;
};

/**
 * 섹션 정보
 * @tparam T Section Header
 */
template<typename T>
class Section {
 public:
  Section() = default;
  /**
   * 실제 section의 이름
   */
  std::string m_section_name;
  /**
   * Section Header, file offset, file size
   */
  std::tuple<T, int, int> m_section_header;

  /**
   * 실제 section의 정보, file offset ,file size
   */
  std::tuple<std::vector<uint8_t>, int, int> m_section;

  /**
   * Section의 모든 정보 이동
   * @param sec
   * @return
   */
  Section<T> &operator=(Section<T> &&sec) noexcept = default;

  Section(const Section<T> &) = default;              // Disabling copy constructor
  Section<T> &operator=(const Section<T> &) = default;   // Disabling copy assignment operator
  //Section& operator=(Section&&) = delete;        // Disabling move assignment operator

};

template<typename T>
class BaseBinary : public Bfd {
 public:
  /**
   * 바이너리 parser 정보를 이동한다.
   * @param parser
   */
  explicit BaseBinary(const BinaryParser &parser);

  /**
   * 실제 section들의 정보
   */
  std::vector<Section<T>> m_sections;

  /**
   * 나머지 바이너리에 필요한 모든 정보를 파싱한다.
   */
  virtual void parse_every_thing() = 0;

  /**
   * 실제 Section의 정보를 가져온다.
   * @return Section<T>의 참조
   */
  Section<T> &get_section(std::string);
  /**
   * 실제 Section의 정보를 수정한다.(파일에도 적용됨)
   * @param sec_name target Section의 이름
   * @param sec 수정한 section의 정보
   * @param mode 수정, 삽입
   * @return 수정한 Section<T>
   */
  virtual bool edit_section(std::string sec_name, const Section<T> &sec, EditMode mode) = 0;

};

/**
 *
 * @tparam T Section Header
 * @tparam U DOS Header
 * @tparam V PE Header
 */
template<typename T, typename U, typename V>
class PeBinary : public BaseBinary<T> {
 public:
  PeBinary(PeBinary &&) = default;
  /**
   * DOS Header, file offset, file size
   */
  std::tuple<U, int, int> m_dos_header;
  /**
   * PE Header, file offset, file size
   */
  std::tuple<V, int, int> m_pe_header;

  virtual void parse_every_thing() override;

  explicit PeBinary(const BinaryParser &parser);
  /**
   * dos header를 파싱한다.
   */
  void parse_dos_header();
  /**
   * pe header를 파싱한다.
   */
  void parse_pe_header();
  /**
   * section, section header를 파싱한다.
   */
  void parse_section();

  virtual bool edit_section(std::string sec_name, const Section<T> &sec, EditMode mode) override;

  /**
   * PE HEADER를 수정한다.
   * @param pe_header
   * @return
   */
  bool edit_pe_header(const V &pe_header);

  /**
   * DOS HEADER를 수정한다.
   * @param dos_header
   * @return
   */
  bool edit_dos_header(const U &dos_header);

};
template<typename T, typename U, typename V>
class ElfBinary : public BaseBinary<T> {
 public:
  int m_fd;
  ElfBinary(ElfBinary &&) = default;
  virtual ~ElfBinary();
  /**
   * elf executable header
   */
  std::tuple<U, int, int> m_elf_header;
  /**
   * elf program header
   */
  std::vector<std::tuple<V, int, int>> m_program_header;

  virtual void parse_every_thing() override;

  virtual bool edit_section(std::string sec_name, const Section<T> &sec, EditMode mode) override;

  explicit ElfBinary(const BinaryParser &parser);

  bool edit_elf_header(const V &elf_header);

  bool edit_program_header(const U &program_header);
  Elf *m_elf;

  /**
   * elf header를 파싱한다.
   */
  void parse_elf_header();

  /**
   * program header를 파싱한다.
   */
  void parse_program_header();

  /**
   * section, section header를 파싱한다.
   */
  void parse_section();
};

class CodeBinary : public Bfd {
 public:
  std::vector<uint8_t> m_code;
  CodeBinary(const BinaryParser &parser);
  CodeBinary(CodeBinary &&) = default;
  CodeBinary &operator=(CodeBinary &&) = default;
};


};