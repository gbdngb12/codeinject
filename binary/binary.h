#pragma once
#include <vector>
#include <cstdint>
#include <string>
#include <memory>
#include <tuple>
#include <bfd.h>
#include <cstring>
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
  /**
   * 파일의 이름
   */
  std::string m_fname;
  /**
   * @brief 미래를 위해 사용되는 low level 파일 디스크립터
   */
  int m_fd = -1;

  /**
   * S에 값을 읽는다.
   * @tparam S 구조체 형식
   * @param pos 읽을 위치
   * @param size 읽을 크기
   * @return 구조체
   */
  template<typename S>
  S read_struct(int pos, int size);

  /**
   * S에 값을 쓴다.
   * @tparam S 구조체 형식
   * @param pos 쓸 위치
   * @param size 쓸 크기
   * @param struct_data 구조체
   */
  template<typename S>
  void write_struct(int pos, int size, S &&struct_data);

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
   * fd를 닫는다.
   */
  virtual ~FileDescriptor();

  /**
   * 파일의 이름을 설정한다.
   * @param fname
   */
  void set_file_name(std::string fname);

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
  Section<T>& operator=(Section<T>&& sec) noexcept = default;

  Section(const Section<T>&) = default;              // Disabling copy constructor
  Section<T>& operator=(const Section<T>&) = default;   // Disabling copy assignment operator
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
  Section<T>& get_section(std::string);
  /**
   * 실제 Section의 정보를 수정한다.(파일에도 적용됨)
   * @param sec_name target Section의 이름
   * @param sec 수정한 section의 정보
   * @param mode 수정, 삽입
   * @return 수정한 Section<T>
   */
  bool edit_section(std::string sec_name, const Section<T>& sec, EditMode mode);

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
  /**
   * DOS Header, file offset, file size
   */
  std::tuple<U, int, int> m_dos_header;
  /**
   * PE Header, file offset, file size
   */
  std::tuple<V, int, int> m_pe_header;

  virtual void parse_every_thing() override;

  explicit PeBinary(const BinaryParser& parser);
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

};


};