#include "binary.h"
#include <utility>
#include <fcntl.h>
#include <iostream>

namespace codeinject::binary {
FileDescriptor::FileDescriptor(std::string fname) :
    m_fname{std::move(fname)}, m_fd{open(m_fname.c_str(), O_RDWR)} {
  if (m_fd == -1) {
    perror("open");
    //std::cout << std::format("Failed to open {}", m_fname) << std::endl;
    exit(1);
  }
}

FileDescriptor::~FileDescriptor() {
  if (m_fd != -1) {
    if (close(m_fd) == -1) {
      perror("close");
      exit(1);
    }
  }
}
void FileDescriptor::set_file_name(std::string fname) {
  this->m_fname = std::move(fname);

}

template<typename S>
void FileDescriptor::write_struct(int pos, int size, S &&struct_data) {
  const std::byte *data_ptr = reinterpret_cast<const std::byte *>(&struct_data);

  lseek(m_fd, pos, SEEK_SET);
  auto bytes_written = write(m_fd, data_ptr, size);
  if (bytes_written == -1) {
    perror("write");
    exit(1);
  }
}

template<typename S>
S FileDescriptor::read_struct(int pos, int size) {
  // S로 바로 읽어보자
  std::vector<uint8_t> buf(size);

  lseek(m_fd, pos, SEEK_SET);
  auto bytes_read = read(m_fd, buf.data(), size);
  if (bytes_read == -1 && (bytes_read == size)) {
    perror("read");
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

template<typename T>
bool BaseBinary<T>::edit_section(std::string sec_name, const Section<T> &sec, EditMode mode) {
  auto &sec_header_ref = get_section(std::move(sec_name));

  if (mode == EditMode::EDIT) {
    // Section Header, Section code 모두 수정
    //memcpy(std::get<0>(sec_ref.m_section_header).Name, ".abcd\0\0\0", 8);
    //auto ret = std::get<0>(this->m_sections[0].m_section_header).Name;

    // 1. Section Header 정보를 파일에 쓴다.
    sec_header_ref = std::move(sec);
    this->template write_struct<T>(std::get<1>(sec_header_ref.m_section_header),std::get<2>(sec_header_ref.m_section_header),std::move(std::get<0>(sec_header_ref.m_section_header)));
    // 2.section 정보를 파일에 쓴다. -> 내일 여기서 부터
    this->template write_struct<std::vector<uint8_t>>(std::get<1>(sec_header_ref.m_section),std::get<2>(sec_header_ref.m_section),std::move(std::get<0>(sec_header_ref.m_section)));

    return true;
  } else if (mode == EditMode::APPEND) {
    return true;
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
  this->m_dos_header = std::make_tuple(std::move(this->template read_struct<U>(pos, size)), pos, size);
}

template<typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_pe_header() {
  int pos = std::get<0>(this->m_dos_header).e_lfanew;
  int size = sizeof(V);
  this->m_pe_header = std::make_tuple(std::move(this->template read_struct<V>(pos, size)), pos, size);
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
    auto section_header = this->template read_struct<T>(pos + i * size, size);
    auto section_name = std::move(std::string(reinterpret_cast<char *>(section_header.Name),
                                              reinterpret_cast<char *>(section_header.Name) + 8));
    auto code_size = section_header.SizeOfRawData;
    auto code_file_offset = section_header.PointerToRawData;

    auto bytes = this->template read_struct<std::vector<uint8_t>>(code_file_offset, code_size);

    Section<T> sec{};
    sec.m_section_name = std::move(section_name);
    sec.m_section_header = std::make_tuple(section_header, pos + i * size, size);
    sec.m_section = std::make_tuple(std::move(bytes), code_file_offset, code_size);
    this->m_sections.push_back(std::move(sec));
  }
}

};

// 템플릿 인스턴스화
template
class codeinject::binary::PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE64_HEADERS>;
template
class codeinject::binary::BaseBinary<PE_SECTION_HEADER>;