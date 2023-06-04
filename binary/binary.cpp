#include "binary.h"
#include <utility>
#include <fcntl.h>
#include <iostream>

namespace codeinject::binary {
FileDescriptor::FileDescriptor(std::string fname) :
    m_fname{std::move(fname)}, m_file_stream{m_fname} {
  if (!m_file_stream) {
    std::cout << std::format("Failed to open {}", m_fname) << std::endl;
    exit(1);
  }
}

void FileDescriptor::set_file_name(std::string fname) {
  this->m_fname = std::move(fname);

}

int FileDescriptor::get_file_size() {
  m_file_stream.seekg(0, std::ios::end);
  std::streampos fileSize = m_file_stream.tellg(); // Get the current position (which is the end of the file)
  return fileSize;
}

template<typename S>
void FileDescriptor::write_data(int pos, int size, const S &struct_data) {
  if constexpr (std::is_same_v<S, std::vector<uint8_t>>) {
    m_file_stream.seekp(pos, std::ios_base::beg);
    m_file_stream.write(reinterpret_cast<const char *>(struct_data.data()), size);
    if (!m_file_stream) {
      std::cerr << std::format("write error\n");
      exit(1);
    }
  } else {
    m_file_stream.seekp(pos);
    const char *byte_data = reinterpret_cast<const char *>(&struct_data);
    m_file_stream.write(byte_data, size);
    if (!m_file_stream) {
      std::cerr << std::format("write error\n");
      exit(1);
    }
  }
}

template<typename S>
S FileDescriptor::read_data(int pos, int size) {
  std::vector<uint8_t> buf(size);

  m_file_stream.seekg(pos, std::ios_base::beg);
  m_file_stream.read(reinterpret_cast<char *>(buf.data()), size);
  if (!m_file_stream) {
    std::cerr << std::format("read error\n");
    exit(1);
  }
  if constexpr (std::is_same_v<S, std::vector<uint8_t>>) {
    return buf;
  } else {
    const auto *data_ptr = reinterpret_cast<const std::byte *>(buf.data());
    const S *struct_ptr = reinterpret_cast<const S *>(data_ptr);
    return *struct_ptr;
  }
}

Bfd::Bfd(std::string fname) : FileDescriptor() {
  this->set_file_name(std::move(fname));
  open_bfd();
}

void Bfd::open_bfd() {
  // bfd를 초기화 한다.
  if (!bfd_inited) {
    bfd_init();
    bfd_inited = 1;
  }
  // bfd를 연다.

  auto bfd_deleter = [](bfd *handler) {
    if (handler) {
      bfd_close(handler);
    }
  };

  m_bfd_h = std::move(std::shared_ptr<bfd>(bfd_openr(this->m_fname.c_str(), NULL), bfd_deleter));
  if (!m_bfd_h) {
    std::cerr << std::format("Failed to open binary {} {}\n", m_fname, bfd_errmsg(bfd_get_error()));
    exit(1);
  }

}
Bfd::Bfd(std::string fname, std::shared_ptr<bfd> bfd_h, BinaryType binary_type)
    : FileDescriptor(std::move(fname)), m_bfd_h{std::make_shared<bfd>(*bfd_h)}, m_binary_type{binary_type} {}
Bfd::Bfd(std::string fname, BinaryType) : FileDescriptor(std::move(fname)) {

}

BinaryParser::BinaryParser(std::string fname) : Bfd(std::move(fname)) {
  // 바이너리 파일의 형식을 정한다.
  if (!bfd_check_format(m_bfd_h.get(), bfd_object)) {
    // 여기는 코드 파일
    this->m_binary_type = BinaryType::CODE;
  } else {
    // PE, ELF 중에 하나
    bfd_set_error(bfd_error_no_error);

    if (bfd_get_flavour(this->m_bfd_h.get()) == bfd_target_unknown_flavour) {
      std::cerr << std::format("unrecognized format for binary '{}' {}\n", this->m_fname, bfd_errmsg(bfd_get_error()));
      exit(1);
    }
    int binary_type = 0;
    switch (this->m_bfd_h->xvec->flavour) {
      case bfd_target_elf_flavour:binary_type = 1;  // ELF
        break;
      case bfd_target_coff_flavour:binary_type = 0;  // PE
        break;
      case bfd_target_unknown_flavour:[[fallthrough]];
      default:std::cerr << "unsupported binary type " << m_bfd_h->xvec->name << std::endl;
        exit(1);
        break;
    }
    int binary_bits = 0;
    switch (this->m_bfd_h->arch_info->mach) {
      case bfd_mach_i386_i386:binary_bits = 0;  // 32
        break;
      case bfd_mach_x86_64:binary_bits = 1;  // 64
        break;
      default:std::cerr << "unsupported architecture " << m_bfd_h->xvec->name << std::endl;
        exit(1);
        break;
    }
    this->m_binary_type = static_cast<BinaryType>((binary_type << 1) | binary_bits);
  }
}
BinaryType BinaryParser::get_binary_type() const {
  return this->m_binary_type;
}

template<typename T>
BaseBinary<T>::BaseBinary(const BinaryParser &parser) : Bfd(std::move(parser.m_fname),
                                                            std::make_shared<bfd>(*parser.m_bfd_h),
                                                            parser.m_binary_type) {
}

template<typename T>
Section<T> &BaseBinary<T>::get_section(std::string sec_name) {
  for (auto &sec : m_sections) {
    if (sec.m_section_name.find(std::move(sec_name)) != std::string::npos) {
      return std::ref(sec);
    }
  }
}

template<typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_every_thing() {
  // 1. DOS_HEADER를 파싱한다.
  parse_dos_header();
  // 2. PE_HEADER를 파싱한다.
  parse_pe_header();
  // 3. Section header ,section을 파싱한다.
  parse_section();
}

template<typename T, typename U, typename V>
PeBinary<T, U, V>::PeBinary(const BinaryParser &parser):BaseBinary<T>(parser) {}

template<typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_dos_header() {
  int pos = 0;
  int size = sizeof(U);
  this->m_dos_header = std::make_tuple(std::move(this->template read_data<U>(pos, size)), pos, size);
}

template<typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_pe_header() {
  int pos = std::get<0>(this->m_dos_header).e_lfanew;
  int size = sizeof(V);
  this->m_pe_header = std::make_tuple(std::move(this->template read_data<V>(pos, size)), pos, size);
}

template<typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_section() {
  // 1. section header정보 파싱
  int pos = std::get<0>(this->m_dos_header).e_lfanew +  //PE Header File Offset
      sizeof(V) + //sizeof(PE Header without IMAGE_DATA_DIRECTORY)
      std::get<0>(this->m_pe_header).OptionalHeader.NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY);
  int size = sizeof(T); // Section Header의 크기

  auto sec_count = this->m_bfd_h->section_count; //Section의 수
  for (int i{0}; i < sec_count; ++i) {
    auto section_header = this->template read_data<T>(pos + i * size, size);
    auto section_name = std::move(std::string(reinterpret_cast<char *>(section_header.Name),
                                              reinterpret_cast<char *>(section_header.Name) + 8));
    auto code_size = section_header.SizeOfRawData;
    auto code_file_offset = section_header.PointerToRawData;

    auto bytes = this->template read_data<std::vector<uint8_t>>(code_file_offset, code_size);

    Section<T> sec{};
    sec.m_section_name = std::move(section_name);
    sec.m_section_header = std::make_tuple(section_header, pos + i * size, size);
    sec.m_section = std::make_tuple(std::move(bytes), code_file_offset, code_size);
    this->m_sections.push_back(std::move(sec));
  }
}
template<typename T, typename U, typename V>
bool PeBinary<T, U, V>::edit_section_header(const Section<T> &sec, EditMode mode) {
  if (mode == EditMode::EDIT) {
    // pe의 섹션 헤더 정보를 수정한다.
    this->template write_data<T>(std::get<1>(sec.m_section_header),
                                 std::get<2>(sec.m_section_header),
                                 std::get<0>(sec.m_section_header));
    return true;
  } else if (mode == EditMode::APPEND) {
    // 섹션 추가
    // 첫번째 섹션의 시작지점 - 마지막 섹션 헤더의 끝 파일 오프셋 >= 40 (SECTION HEADER SIZE)
    auto last_sec_header_offset = std::get<1>(this->m_sections.back().m_section_header) + sizeof(T);

    auto first_section_offset = std::get<1>(this->m_sections.front().m_section);
    //    sizeof(V) + //sizeof(PE Header without IMAGE_DATA_DIRECTORY)
    //    std::get<0>(this->m_pe_header).OptionalHeader.NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY);
    auto section_header_size = sizeof(T);
    if (first_section_offset - last_sec_header_offset >= section_header_size) {
      this->m_sections.push_back(std::move(sec));
      this->template write_data<T>(std::get<1>(this->m_sections.back().m_section_header),
                                   std::get<2>(this->m_sections.back().m_section_header),
                                   std::get<0>(this->m_sections.back().m_section_header));
      // 2.section 정보를 파일에 쓴다.
      this->template write_data<std::vector<uint8_t>>(std::get<1>(this->m_sections.back().m_section),
                                                      std::get<2>(this->m_sections.back().m_section),
                                                      std::get<0>(this->m_sections.back().m_section));
      return true;
    } else {
      std::cerr << std::format("Failed to insert Section to Binary {}\n", this->m_fname);
      exit(1);
    }
    return false;
  }
}

template<typename T, typename U, typename V>
bool PeBinary<T, U, V>::edit_section(const Section<T> &sec, EditMode mode) {

  if (mode == EditMode::EDIT) {
    // 기존의 섹션 정보 수정
    this->template write_data<std::vector<uint8_t>>(std::get<1>(sec.m_section),
                                                    std::get<2>(sec.m_section),
                                                    std::get<0>(sec.m_section));
    return true;
  } else if (mode == EditMode::APPEND) {
    return true;
  } else {
    std::cerr << std::format("Failed to insert Section to Binary {}\n", this->m_fname);
    exit(1);
  }
  return false;
}

template<typename T, typename U, typename V>
bool PeBinary<T, U, V>::edit_pe_header() {
  this->template write_data<V>(std::get<1>(this->m_pe_header),
                               std::get<2>(this->m_pe_header),
                               std::get<0>(this->m_pe_header));
  return true;
}

template<typename T, typename U, typename V>
bool PeBinary<T, U, V>::edit_dos_header(const U &dos_header) {
  std::cout << "do nothing now.. in edit dos header" << std::endl;
  return true;
}

template<typename T, typename U, typename V>
ElfBinary<T, U, V>::~ElfBinary() {
  if (m_elf != 0) {
    elf_end(m_elf);
  }
  close(m_fd);
}
template<typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_every_thing() {
  if (elf_version(EV_CURRENT) == EV_NONE) {
    std::cerr << std::format("Failed to initalize libelf\n");
    exit(1);
  }

  m_elf = elf_begin(this->m_fd, ELF_C_READ, NULL);
  if (!m_elf) {
    std::cerr << "failed to open ELF file\n";
    exit(1);
  }

  if (elf_kind(m_elf) != ELF_K_ELF) {
    std::cerr << "Not an ELF executable\n";
    exit(1);
  }

  // 1. elf header를 파싱한다.
  parse_elf_header();

  // 2. program header를 파싱한다.
  parse_program_header();

  // 3. section header, section을 파싱한다.
  parse_section();
}

template<typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_elf_header() {
  if (this->m_binary_type == BinaryType::ELF32) {
    int size = sizeof(U);
    auto ehdr = elf32_getehdr(m_elf);
    memcpy(&(std::get<0>(m_elf_header)), ehdr, size);
    std::get<1>(m_elf_header) = 0;
    std::get<2>(m_elf_header) = size;
  } else if (this->m_binary_type == BinaryType::ELF64) {
    int size = sizeof(U);
    auto ehdr = elf64_getehdr(m_elf);
    memcpy(&(std::get<0>(m_elf_header)), ehdr, size);
    std::get<1>(m_elf_header) = 0;
    std::get<2>(m_elf_header) = size;
  } else {
    exit(1);
  }
}
template<typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_program_header() {
  int size = sizeof(V);
  auto count = std::get<0>(m_elf_header).e_phnum;
  for (int i{0}; i < count; ++i) {
    V program_header{};
    if (this->m_binary_type == BinaryType::ELF32) {
      auto phdr = elf32_getphdr(m_elf);
      memcpy(&program_header, &phdr[i], size);
    } else if (this->m_binary_type == BinaryType::ELF64) {
      auto phdr = elf64_getphdr(m_elf);
      memcpy(&program_header, &phdr[i], size);
    } else {
      exit(1);
    }
    m_program_header.push_back(std::move(std::make_tuple(std::move(program_header),
                                                         std::get<0>(m_elf_header).e_phoff + size * i,
                                                         size)));
  }
}
template<typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_section() {
  Elf_Scn *scn = nullptr;
  size_t shstrndx;
  int section_header_size = sizeof(T);
  int i = 0;

  if (elf_getshdrstrndx(m_elf, &shstrndx) < 0) {
    std::cerr << "Failed to get string table section index\n";
    exit(1);
  }
  // 아니.. 이거 그냥 파일자체가 망가진거였음
  asection *bfd_sec = this->m_bfd_h->sections;

  while ((scn = elf_nextscn(m_elf, scn)) && (bfd_sec)) {
    Section<T> tmp_sec;

    int section_offset = bfd_sec->filepos;
    int section_size = bfd_sec->size;
    const char *section_name;
    if (this->m_binary_type == BinaryType::ELF32) {
      auto shdr = elf32_getshdr(scn);
      memcpy(&std::get<0>(tmp_sec.m_section_header), shdr, section_header_size);
      section_name = elf_strptr(m_elf, shstrndx, shdr->sh_name);
    } else if (this->m_binary_type == BinaryType::ELF64) {
      auto shdr = elf64_getshdr(scn);
      memcpy(&std::get<0>(tmp_sec.m_section_header), shdr, section_header_size);
      section_name = elf_strptr(m_elf, shstrndx, shdr->sh_name);
    } else {
      exit(1);
    }

    std::vector<uint8_t> bytes(section_size);
    if (!bfd_get_section_contents(this->m_bfd_h.get(), bfd_sec, bytes.data(), 0, section_size)) {
      std::cerr << std::format("failed to read section {} {}\n", section_name, bfd_errmsg(bfd_get_error()));
    }
    tmp_sec.m_section = std::make_tuple(std::move(bytes), section_offset, section_size);
    tmp_sec.m_section_name = std::string(section_name);
    auto section_header_offset = std::get<0>(this->m_elf_header).e_shoff;// section header의 오프셋
    std::get<1>(tmp_sec.m_section_header) =
        section_header_offset + section_header_size/*NULL Section*/+ section_header_size * i++;
    std::get<2>(tmp_sec.m_section_header) = section_header_size;
    bfd_sec = bfd_sec->next;
    this->m_sections.push_back(std::move(tmp_sec));
  }
  //. shstrtab 정보 읽기
  while (scn) {
    int section_header_offset =
        std::get<1>(this->m_sections.back().m_section_header) + std::get<2>(this->m_sections.back().m_section_header);
    int section_header_size = sizeof(T);
    int section_offset = 0;
    int section_size = 0;
    const char *section_name;
    Section<T> tmp_sec;
    if (this->m_binary_type == BinaryType::ELF32) {
      auto shdr = elf32_getshdr(scn);
      memcpy(&std::get<0>(tmp_sec.m_section_header), shdr, section_header_size);
      section_name = elf_strptr(m_elf, shstrndx, shdr->sh_name);
      section_offset = shdr->sh_offset;
      section_size = shdr->sh_size;
    } else if (this->m_binary_type == BinaryType::ELF64) {
      auto shdr = elf64_getshdr(scn);
      memcpy(&std::get<0>(tmp_sec.m_section_header), shdr, section_header_size);
      section_name = elf_strptr(m_elf, shstrndx, shdr->sh_name);
      section_offset = shdr->sh_offset;
      section_size = shdr->sh_size;
    } else {
      exit(1);
    }
    auto bytes = this->template read_data<std::vector<uint8_t>>(section_offset, section_size);
    std::get<1>(tmp_sec.m_section_header) = section_header_offset;
    std::get<2>(tmp_sec.m_section_header) = section_header_size;
    tmp_sec.m_section_name = std::move(std::string(section_name));
    tmp_sec.m_section = std::make_tuple(bytes, section_offset, section_size);
    this->m_sections.push_back(std::move(tmp_sec));
    scn = elf_nextscn(m_elf, scn);
  }
}

template<typename T, typename U, typename V>
ElfBinary<T, U, V>::ElfBinary(const BinaryParser &parser)
    : BaseBinary<T>(parser), m_elf{0}, m_fd{open(this->m_fname.c_str(), O_RDWR)} {
  if (m_fd == -1) {
    perror("open");
    exit(1);
  }
}

template<typename T, typename U, typename V>
bool ElfBinary<T, U, V>::edit_elf_header(const U &elf_header) {
  memcpy(&std::get<0>(this->m_elf_header), &elf_header, sizeof(U));
  // 이제 실제로 파일에 써야함
  this->template write_data<U>(std::get<1>(this->m_elf_header),
                               std::get<2>(this->m_elf_header),
                               std::get<0>(this->m_elf_header));
  return true;
}

template<typename T, typename U, typename V>
bool ElfBinary<T, U, V>::edit_program_header(const V &program_header, int index) {
  auto &program_header_ref = this->m_program_header[index];
  this->template write_data<V>(std::get<1>(program_header_ref),
                               std::get<2>(program_header_ref),
                               std::get<0>(program_header_ref));
  return true;
}

template<typename T, typename U, typename V>
bool ElfBinary<T, U, V>::edit_section_header(const Section<T> &sec, EditMode mode) {
  if (mode == EditMode::EDIT) {
    // 1. Section Header 정보를 파일에 쓴다.
    this->template write_data<T>(std::get<1>(sec.m_section_header),
                                 std::get<2>(sec.m_section_header),
                                 std::get<0>(sec.m_section_header));
    return true;
  } else if (mode == EditMode::APPEND) {
    // 섹션 추가
    std::cerr << "not supported APPEND Mode\n";
    return false;

  } else {
    std::cerr << std::format("Failed to insert Section to Binary {}\n", this->m_fname);
    exit(1);
  }
  return true;
}
template<typename T, typename U, typename V>
bool ElfBinary<T, U, V>::edit_section(const Section<T> &sec, EditMode mode) {
  /// 실제 섹션을 수정하고 파일에 기록한다.
  //section 정보를 파일에 쓴다.
  this->template write_data<std::vector<uint8_t>>(std::get<1>(sec.m_section),
                                                  std::get<2>(sec.m_section),
                                                  std::get<0>(sec.m_section));
  return true;
}

CodeBinary::CodeBinary(const BinaryParser &parser) : Bfd(std::move(parser.m_fname), std::move(parser.m_binary_type)),
                                                     m_code{this->read_data<std::vector<uint8_t>>(0,
                                                                                                  this->get_file_size())} {
}

};

// 템플릿 인스턴스화
template
class codeinject::binary::PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE64_HEADERS>;
template
class codeinject::binary::PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE32_HEADERS>;
template
class codeinject::binary::BaseBinary<PE_SECTION_HEADER>;
template
class codeinject::binary::ElfBinary<Elf32_Shdr, Elf32_Ehdr, Elf32_Phdr>;
template
class codeinject::binary::ElfBinary<Elf64_Shdr, Elf64_Ehdr, Elf64_Phdr>;
template
class codeinject::binary::BaseBinary<Elf32_Shdr>;
template
class codeinject::binary::BaseBinary<Elf64_Shdr>;


