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
  int m_program_header_index;
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

  int m_inject_index;

  std::string m_target_section_name;

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