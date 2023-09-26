#include "inject.h"
#include <iostream>
#include <utility>
#include <string>
#include <algorithm>
#include <exception>
namespace codeinject::inject {
CodeInject::CodeInject(std::vector<uint8_t> code,
                       std::string inject_name,
                       std::string target_name) : m_code{std::move(code)},
                                                  m_inject_section_name{std::move(inject_name)},
                                                  m_target_section_name{std::move(target_name)} {
}

template<typename T, typename U, typename V>
bool PeCodeInject<T, U, V>::inject_code() {
  std::cout << "pe inject code" << std::endl;

  // 1. 섹션 헤더, 섹션 정보, 코드를 추가한다.
  write_sections();

  // 2. PE Header 정보를 수정한다.
  rewrite_pe_header();


  return true;
}

template<typename T, typename U, typename V>
void PeCodeInject<T, U, V>::write_sections() {
  // 가상 메모리 주소 계산해야함
  // VirtualSize = 삽입한 코드의 크기를 SectionAlignment로 정렬한값
  // VirualAddress = 정렬조건에 맞게 계산해야함(마지막 섹션참고)
  // SizeOfRawData = 삽입한 코드의 크기
  // PointerToRawData = 삽입한 코드의 위치
  // 특성 = 실행 가능 코드 | 초기화 데이터 | 읽기 가능 섹션
  auto &pe_optional_header = std::get<0>(this->m_pe_binary_ptr->m_pe_header).OptionalHeader;
  binary::Section<T> sec{};
  sec.m_section_name = this->m_inject_section_name;
  sec.m_section = std::make_tuple(m_code, m_inject_offset, m_inject_size);
  auto &section_header = std::get<0>(sec.m_section_header);
  memcpy(&section_header.Name, m_inject_section_name.c_str(), m_inject_section_name.size());
  section_header.Misc.VirtualSize = m_inject_size;
  this->m_inject_vaddr = calc_alignment(
      std::get<0>(this->m_pe_binary_ptr->m_sections.back().m_section_header).VirtualAddress
          + std::get<0>(this->m_pe_binary_ptr->m_sections.back().m_section_header).Misc.VirtualSize, pe_optional_header.SectionAlignment);
  section_header.VirtualAddress = this->m_inject_vaddr;
  section_header.SizeOfRawData = this->m_inject_size;
  section_header.PointerToRawData = this->m_inject_offset;
  section_header.Characteristics =
      static_cast<int>(SectionFlag::IMAGE_SCN_MEM_READ) | static_cast<int>(SectionFlag::IMAGE_SCN_MEM_EXECUTE)
          | static_cast<int>(SectionFlag::IMAGE_SCN_CNT_INITIALIZED_DATA);// 실행가능 코드 | 초기화데이터 | 읽기 가능섹션
  std::get<1>(sec.m_section_header) =
      std::get<1>(this->m_pe_binary_ptr->m_sections.back().m_section_header) + sizeof(T);
  std::get<2>(sec.m_section_header) = sizeof(T);
  sec.m_section = std::make_tuple(this->m_code, this->m_inject_offset, this->m_inject_size);
  this->m_pe_binary_ptr->edit_section_header(std::move(sec), binary::EditMode::APPEND);
}
template<typename T, typename U, typename V>
int PeCodeInject<T, U, V>::calc_alignment(int value, int alignment_value) {
  return value + alignment_value - value % alignment_value;
}
template<typename T, typename U, typename V>
void PeCodeInject<T, U, V>::rewrite_pe_header() {
  // AddressOfEntryPoint = 삽입한 코드의 가상 메모리
  // SizeOfImage = 기존 값 + 삽입한 코드의 VirtualAddress + VirtualSize를 SectionAlignment로 정렬한 값
  // DLLCharacteristics = 메모리 보호 기법 제거
  // rewrite pe optional header
  auto &pe_optional_header = std::get<0>(this->m_pe_binary_ptr->m_pe_header).OptionalHeader;
  pe_optional_header.AddressOfEntryPoint = this->m_inject_vaddr; //EP
  pe_optional_header.SizeOfImage = calc_alignment(m_inject_vaddr + m_inject_size, pe_optional_header.SectionAlignment); //전체 크기
  pe_optional_header.DllCharacteristics &= ~(static_cast<int>(DLLCharacteristics::IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
      | static_cast<int>(DLLCharacteristics::IMAGE_DLLCHARACTERISTICS_GUARD_CF)
      | static_cast<int>(DLLCharacteristics::IMAGE_DLLCHARACTERISTICS_NX_COMPAT));// 메모리 보호 기법 제거
  rewrite_pe_file_header();
  this->m_pe_binary_ptr->edit_pe_header();
}
template<typename T, typename U, typename V>
void PeCodeInject<T, U, V>::rewrite_pe_file_header() {
  // NumberOfSection 한개 증가
  auto &pe_file_header = std::get<0>(this->m_pe_binary_ptr->m_pe_header).FileHeader;
  pe_file_header.NumberOfSections++;
}
template<typename T, typename U, typename V>
PeCodeInject<T, U, V>::PeCodeInject(std::shared_ptr<binary::PeBinary<T, U, V>> pe_binary, std::vector<uint8_t> code)
    : m_pe_binary_ptr{pe_binary}, CodeInject(std::move(code), ".inject", ""/*일단 비움(섹션 추가이므로)*/) {
  auto file_alignment = std::get<0>(this->m_pe_binary_ptr->m_pe_header).OptionalHeader.FileAlignment;
  this->m_inject_size = calc_alignment(this->m_code.size(), file_alignment);
  // @todo file offset 보정 필요!
  this->m_inject_offset = calc_alignment(this->m_pe_binary_ptr->get_file_size(), file_alignment);
  std::cout << std::hex <<this->m_inject_offset << "\n";
  this->m_section_alignment = std::get<0>(this->m_pe_binary_ptr->m_pe_header).OptionalHeader.SectionAlignment;
}

template<typename T, typename U, typename V>
bool ElfCodeInject<T, U, V>::inject_code() {
  std::cout << "elf inject code" << std::endl;
  // 0. PT_NOTE Segment를 찾고 인덱스를 저장한다.
  find_rewriteable_segment(); // Okay
  // 1. 바이너리 끝에 코드를 삽입한다.
  write_code(); // Okay
  // 2. 바이너리 끝에 삽입된 코드의 가상 메모리 주소를 정렬한다, 파일은 그대로
  align_code(); // Okay
  // 3. 섹션 헤더를 덮어쓴다.
  rewrite_code_section(); //Okay
  // 4. 섹션 이름을 덮어쓴다.
  rewrite_section_name(); // Okay
  // 5. program header를 덮어쓴다.(찾은 인덱스)
  rewrite_code_segment(); // Okay
  // 6. EP를 수정한다.
  rewrite_entry_point(); // Okay
  return true;
}
template<typename T, typename U, typename V>
ElfCodeInject<T, U, V>::ElfCodeInject(std::shared_ptr<binary::ElfBinary<T, U, V>> elf_binary,
                                      std::vector<uint8_t> code,
                                      size_t address)
    : m_elf_binary_ptr{elf_binary},
      CodeInject(std::move(code), ".injected", ".note.ABI-tag"),
      m_program_header_index{0} {
  this->m_inject_size = this->m_code.size();
  this->m_inject_offset = this->m_elf_binary_ptr->get_file_size();
  if (!address) {
    this->m_inject_vaddr = 0x800000;
  } else {
    this->m_inject_vaddr = address;
  }
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
  this->m_elf_binary_ptr->template write_data<std::vector<uint8_t>>(m_inject_offset,
                                                                    m_inject_size,
                                                                    std::move(this->m_code));
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
      section_header.sh_name = this->m_name_index = std::get<0>(sec.m_section_header).sh_name; // 문자열 테이블의 오프셋
      section_header.sh_type = SHT_PROGBITS;                // 데이터 또는 코드
      section_header.sh_flags = SHF_ALLOC | SHF_EXECINSTR;  // 메모리 적재 & 실행가능
      section_header.sh_addr = this->m_inject_vaddr;             // 섹션의 가상메모리 주소
      section_header.sh_offset = this->m_inject_offset;               // 섹션 시작 부분의 파일 오프셋
      section_header.sh_size = this->m_inject_size;                 // 섹션 코드의 크기
      section_header.sh_link = 0;                           // 코드 섹션에서는 사용하지 않음
      section_header.sh_info = 0;                           // 코드 섹션에서는 사용하지 않음
      section_header.sh_addralign = 16;                     // 메모리 정렬
      section_header.sh_entsize = 0;                        // 코드 섹션에서는 사용하지 않음
      sec.m_section_name = ".injected";
      std::get<0>(sec.m_section_header) = std::move(section_header);
      this->m_inject_index = index;
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
  auto *cur_section = &this->m_elf_binary_ptr->m_sections[this->m_inject_index - 1];
  auto *cur_section_header = &(std::get<0>(cur_section->m_section_header));
  auto *cur_section_addr = &(cur_section_header->sh_addr);

  auto *inject_section = &(this->m_elf_binary_ptr->m_sections[this->m_inject_index]);
  auto *inject_section_header = &(std::get<0>(inject_section->m_section_header));
  auto *inject_section_addr = &(inject_section_header->sh_addr);

  if (*cur_section_addr > *inject_section_addr) {
    /* Injected section header must be moved left */
    direction = -1;
  }
// 참조 변수 재할당 문제!!
  cur_section = &(this->m_elf_binary_ptr->m_sections[this->m_inject_index + 1]); //참조로 바꾸는것이 아닌 값만 바꾸는것!! 참조로 다시 받아야함!
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
    cur_section = &(this->m_elf_binary_ptr->m_sections[this->m_inject_index + direction + skip]);
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
    this->m_elf_binary_ptr->edit_section_header(*cur_section, binary::EditMode::EDIT);

    this->m_elf_binary_ptr->edit_section_header(*inject_section, binary::EditMode::EDIT);
    this->m_inject_index += direction + skip;
    skip = 0;
    inject_section = &(this->m_elf_binary_ptr->m_sections[this->m_inject_index]);
    inject_section_header = &(std::get<0>(inject_section->m_section_header));
    inject_section_addr = &(inject_section_header->sh_addr);
  }

}
template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::rewrite_section_name() {
  // shstrtab 섹션을 가져와서 이름을 수정한다.
  auto &shstrtab_section = this->m_elf_binary_ptr->get_section(".shstrtab");// 참조
  if (shstrtab_section.m_section_name.size() < this->m_inject_section_name.size()) {
    std::cerr << "error section name size" << std::endl;
    exit(1);
  }
  int name_pos = std::get<1>(shstrtab_section.m_section) + m_name_index;
  //memset(&(std::get<0>(shstrtab_section.m_section)),0, shstrtab_section.m_section_name.size());
  for (size_t i = 0; i < this->m_inject_section_name.size(); i++) {
    std::get<0>(shstrtab_section.m_section)[m_name_index + i] = static_cast<uint8_t>(this->m_inject_section_name[i]);
  }
  std::get<0>(shstrtab_section.m_section)[m_name_index + this->m_inject_section_name.size()] = '\0';
  this->m_elf_binary_ptr->edit_section(shstrtab_section, binary::EditMode::EDIT);
}
template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::rewrite_code_segment() {
  auto &program_header = std::get<0>(this->m_elf_binary_ptr->m_program_header[m_program_header_index]);
  program_header.p_type = PT_LOAD;         /* type */
  program_header.p_offset = this->m_inject_offset;     /* file offset to start of segment */
  program_header.p_vaddr = this->m_inject_vaddr; /* virtual address to load segment at */
  program_header.p_paddr = this->m_inject_vaddr; /* physical address to load segment at */
  program_header.p_filesz = this->m_inject_size;     /* byte size in file */
  program_header.p_memsz = this->m_inject_size;     /* byte size in memory */
  program_header.p_flags = PF_R | PF_X;     /* flags */
  program_header.p_align = 0x1000;          /* alignment in memory and file */
  this->m_elf_binary_ptr->edit_program_header(program_header, m_program_header_index);

}
template<typename T, typename U, typename V>
void ElfCodeInject<T, U, V>::rewrite_entry_point() {
  auto &elf_header = std::get<0>(this->m_elf_binary_ptr->m_elf_header);
  elf_header.e_entry = this->m_inject_vaddr;
  this->m_elf_binary_ptr->edit_elf_header(elf_header);
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
