#pragma once
#include <vector>
#include "binary.h"
#include <cstdint>
namespace codeinject::inject {
class CodeInject {
 public:
  std::vector<uint8_t> m_code;
  /**
* 삽입할 섹션의 이름
*/
  std::string m_inject_section_name;
  /**
   * 대상섹션의 이름
   */
  std::string m_target_section_name;
  /**
 * 삽입한 코드의 파일 오프셋
 */
  int m_inject_offset;
  /**
   * 삽입한 섹션의 가상 메모리 주소
   */
  size_t m_inject_vaddr;
  /**
   * 삽입한 코드의 크기
   */
  int m_inject_size;

  /**
   * 삽입한 섹션의 인덱스
   */
  int m_inject_index;
  virtual bool inject_code() = 0;
  CodeInject(std::vector<uint8_t>, std::string inject_name, std::string target_name);
};

template<typename T, typename U, typename V>
class PeCodeInject : public CodeInject {
 public:
  enum class SectionFlag {
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
    IMAGE_SCN_MEM_READ = 0x40000000,
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
  };
  enum class DLLCharacteristics {
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF = 0x4000,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100
  };
  /**
   * section 정렬값
   */
  int m_section_alignment;

  std::shared_ptr<codeinject::binary::PeBinary<T, U, V>> m_pe_binary_ptr;
  virtual bool inject_code() override;
  PeCodeInject(std::shared_ptr<codeinject::binary::PeBinary<T, U, V>>, std::vector<uint8_t> code);

  int calc_alignment(int);

  /**
   * 섹션 헤더 정보를 추가한다.
   */
  void write_sections();

  /**
   * PE Optional Header 정보를 수정한다.
   * EP, SizeOfImage, DLLCharacteristic
   */
  void rewrite_pe_optional_header();

  /**
   * PE File Header 정보를 수정한다.
   * 섹션의 수를 수정한다.
   */
  void rewrite_pe_file_header();
};

template<typename T, typename U, typename V>
class ElfCodeInject : public CodeInject {
 public:
  /**
   * 수정할 프로그램 헤더의 인덱스
   */
  int m_program_header_index;

  /**
   * 수정할 섹션의 이름 인덱스
   */
  int m_name_index;

  std::shared_ptr<codeinject::binary::ElfBinary<T, U, V>> m_elf_binary_ptr;
  virtual bool inject_code() override;
  ElfCodeInject(std::shared_ptr<codeinject::binary::ElfBinary<T, U, V>>, std::vector<uint8_t> code);

  /**
   * PT_NOTE Segment를 찾고 인덱스를 설정한다.
   * @return 못찾으면 프로그램 종료
   */
  void find_rewriteable_segment();

  /**
   * 바이너리 끝에 코드를 삽입한다.
   */
  void write_code();

  /**
   * 파일 오프셋은 나두고, 가상 메모리 주소를 정렬한다.
   */
  void align_code();

  /**
   * section header을 덮어쓴다.
   */
  void rewrite_code_section();

  /**
   * section header를 정렬한다.
   */
  void reorder_shdrs();

  /**
   * 최대의 vaddr을 계산한다.
   */
  //void calc_vaddr();

  /**
   * section의 이름을 덮어쓴다.
   */
  void rewrite_section_name();

  /**
   * segment를 덮어쓴다.
   */
  void rewrite_code_segment();

  /**
   * EP를 수정한다.
   */
  void rewrite_entry_point();

};
};