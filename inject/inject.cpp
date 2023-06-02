#include "inject.h"
#include <iostream>
#include <utility>
#include <string>
#include <algorithm>
#include <exception>
namespace codeinject::inject {
CodeInject::CodeInject(std::vector<uint8_t> code) : m_code{std::move(code)} {

}

template<typename T, typename U, typename V>
bool PeCodeInject<T, U, V>::inject_code() {
  std::cout << "pe inject code" << std::endl;
  return false;
}
template<typename T, typename U, typename V>
PeCodeInject<T, U, V>::PeCodeInject(std::shared_ptr<binary::PeBinary<T, U, V>> pe_binary, std::vector<uint8_t> code)
    : m_pe_binary_ptr{pe_binary}, CodeInject(std::move(code)) {

}

template<typename T, typename U, typename V>
bool ElfCodeInject<T, U, V>::inject_code() {
  std::cout << "elf inject code" << std::endl;
  // 0. PT_NOTE Segment를 찾고 인덱스를 저장한다.
  find_rewriteable_segment();
  // 1. 바이너리 끝에 코드를 삽입한다.
  write_code();
  // 2. 바이너리 끝에 삽입된 코드의 가상 메모리 주소를 정렬한다, 파일은 그대로
  align_code();
  // 3. 섹션 헤더를 덮어쓴다.
  rewrite_code_section();
  // 4. 섹션 이름을 덮어쓴다.
  rewrite_section_name();
  // 5. program header를 덮어쓴다.(찾은 인덱스)
  rewrite_code_segment();
  // 6. EP를 수정한다.
  rewrite_entry_point();
  return true;
}
template<typename T, typename U, typename V>
ElfCodeInject<T, U, V>::ElfCodeInject(std::shared_ptr<binary::ElfBinary<T, U, V>> elf_binary, std::vector<uint8_t> code)
    : m_elf_binary_ptr{elf_binary},
      CodeInject(std::move(code)),
      m_program_header_index{0},
      m_target_section_name{".note.ABI-tag"} {
  m_inject_size = this->m_code.size();
  m_inject_offset = this->m_elf_binary_ptr->get_file_size();
  /**
   * @TODO 하드 코딩된값!! 반드시 수정해야함!
   */
  m_inject_vaddr = 0x800000;
}

template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::find_rewriteable_segment() {
  auto &program_headers = this->m_elf_binary_ptr->m_program_header;
  int i = 0;
  for (auto &&p : program_headers) {
    auto &program_header = std::get<0>(p);
    if (program_header.p_type == PT_NOTE) {
      m_program_header_index = i;
      return;
    }
    i++;
  }
  std::cerr << "Failed to Find PT_NOTE Segment" << std::endl;
  exit(1);
}
template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::write_code() {
  // 코드 삽입 성공
  this->m_elf_binary_ptr->template write_data<std::vector<uint8_t>>(m_inject_offset, m_inject_size, std::move(this->m_code));
}
template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::align_code() {
  // section의 가상 메모리 주소 = (파일끝%4096) - (0x800000%4096) 만큼 더한다
  int n = (m_inject_offset % 4096) - (m_inject_vaddr % 4096);
  m_inject_vaddr += n;
}
template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::rewrite_code_section() {
  int index = 0;
  for (auto &&sec : this->m_elf_binary_ptr->m_sections) {
    if (!sec.m_section_name.compare(m_target_section_name)) {
      // 1. 먼저 섹션 헤더 정보 덮어 씌운다.
      T section_header{};
      section_header.sh_name = std::get<0>(sec.m_section_header).sh_name; // 문자열 테이블의 오프셋
      section_header.sh_type = SHT_PROGBITS;                // 데이터 또는 코드
      section_header.sh_flags = SHF_ALLOC | SHF_EXECINSTR;  // 메모리 적재 & 실행가능
      section_header.sh_addr = m_inject_vaddr;             // 섹션의 가상메모리 주소
      section_header.sh_offset = m_inject_offset;               // 섹션 시작 부분의 파일 오프셋
      section_header.sh_size = m_inject_offset;                 // 섹션 코드의 크기
      section_header.sh_link = 0;                           // 코드 섹션에서는 사용하지 않음
      section_header.sh_info = 0;                           // 코드 섹션에서는 사용하지 않음
      section_header.sh_addralign = 16;                     // 메모리 정렬
      section_header.sh_entsize = 0;                        // 코드 섹션에서는 사용하지 않음
      sec.m_section_name = ".injected";
      std::get<0>(sec.m_section_header) = std::move(section_header);
      m_inject_index = index;
      // 2. 섹션을 정렬한다.
      reorder_shdrs();
      return;
    }
    index++;
  }
  std::cerr << "not found .note.ABI-tag\n";
  exit(1);
}

template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::reorder_shdrs() {
  // section header를 정렬한다.
  // @TODO 삽입하고자 하는 섹션의 이름 크기 비교
  int direction = 0; // 정렬할 방향 -1 : 왼쪽(더 가상 메모리가 낮은 위치로), 0 정상 위치, + : 오른쪽(더 가상 메모리가 높은 위치로)
  int skip = 0; // SHT_PROGBITS (코드 섹션이 아닌경우) 스킵할 섹션 인덱스의 수

  // 이전 섹션의 정보를 가져온다.
  auto *cur_section = &this->m_elf_binary_ptr->m_sections[m_inject_index - 1];
  auto *cur_section_header = &(std::get<0>(cur_section->m_section_header));
  auto *cur_section_addr = &(cur_section_header->sh_addr);

  auto *inject_section = &(this->m_elf_binary_ptr->m_sections[m_inject_index]);
  auto *inject_section_header = &(std::get<0>(inject_section->m_section_header));
  auto *inject_section_addr = &(inject_section_header->sh_addr);

  if (*cur_section_addr > *inject_section_addr) {
    /* Injected section header must be moved left */
    direction = -1;
  }
// 참조 변수 재할당 문제!!
  cur_section = &(this->m_elf_binary_ptr->m_sections[m_inject_index + 1]); //참조로 바꾸는것이 아닌 값만 바꾸는것!! 참조로 다시 받아야함!
  cur_section_header = &(std::get<0>(cur_section->m_section_header));
  cur_section_addr = &(cur_section_header->sh_addr);

  if (*cur_section_addr < *inject_section_addr) {
    /* Injected section header must be moved left */
    direction = 1;
  }

  if (direction == 0) {
    /* Section headers are already in order */
    return;
  }

  while (1) {
    cur_section = &(this->m_elf_binary_ptr->m_sections[m_inject_index + direction + skip]);
    cur_section_header = &(std::get<0>(cur_section->m_section_header));
    cur_section_addr = &(cur_section_header->sh_addr);

    if ((direction < 0 && *cur_section_addr <= *inject_section_addr)
        || (direction > 0 && *cur_section_addr >= *inject_section_addr)) {
      /* The order is okay from this point on */
      break;
    }

    /* Only reorder code section headers */
    if (cur_section_header->sh_type != SHT_PROGBITS) {
      skip += direction;
      continue;
    }

    std::swap(*cur_section_header, *inject_section_header);
    std::swap(cur_section->m_section_name, inject_section->m_section_name);
    // 실제 파일에 쓰기
    this->m_elf_binary_ptr->edit_section_header(*cur_section , binary::EditMode::EDIT);

    this->m_elf_binary_ptr->edit_section_header(*inject_section, binary::EditMode::EDIT);
    m_inject_index += direction + skip;
    skip = 0;
    inject_section = &(this->m_elf_binary_ptr->m_sections[m_inject_index]);
    inject_section_header = &(std::get<0>(inject_section->m_section_header));
    inject_section_addr = &(inject_section_header->sh_addr);
  }

}
template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::rewrite_section_name() {

}
template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::rewrite_code_segment() {
  auto& program_header = std::get<0>(this->m_elf_binary_ptr->m_program_header[m_program_header_index]);
  program_header.p_type   = PT_LOAD;         /* type */
  program_header.p_offset = m_inject_offset;     /* file offset to start of segment */
  program_header.p_vaddr  = m_inject_vaddr; /* virtual address to load segment at */
  program_header.p_paddr  = m_inject_vaddr; /* physical address to load segment at */
  program_header.p_filesz = m_inject_size;     /* byte size in file */
  program_header.p_memsz  = m_inject_size;     /* byte size in memory */
  program_header.p_flags  = PF_R | PF_X;     /* flags */
  program_header.p_align  = 0x1000;          /* alignment in memory and file */
  this->m_elf_binary_ptr->edit_program_header(program_header, m_program_header_index);

}
template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::rewrite_entry_point() {

}
};

template
class codeinject::inject::PeCodeInject<PE_SECTION_HEADER, PE_DOS_HEADER, PE64_HEADERS>;
template
class codeinject::inject::PeCodeInject<PE_SECTION_HEADER, PE_DOS_HEADER, PE32_HEADERS>;
template
class codeinject::inject::ElfCodeInject<Elf32_Shdr, Elf32_Ehdr, Elf32_Phdr>;
template
class codeinject::inject::ElfCodeInject<Elf64_Shdr, Elf64_Ehdr, Elf64_Phdr>;
