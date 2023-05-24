#include "binary.h"

#include <utility>

namespace codeinject::binary {

FileDescriptor::FileDescriptor(std::string fname) : m_fname{std::move(fname)}, m_file_stream{m_fname} {
    if (!m_file_stream) {
        std::cerr << "open error" << m_fname << std::endl;
        exit(1);
    }
}

int FileDescriptor::write_data(std::vector<uint8_t> data, int pos) {
    m_file_stream.seekp(pos);
    for (auto&& d : data) {
        m_file_stream << d;
        if (!m_file_stream.good()) {
            std::cerr << "failed to write" << m_fname << std::endl;
            exit(1);
        }
    }
    return data.size();
}

std::vector<uint8_t> FileDescriptor::read_data(int pos, int size) {
    m_file_stream.seekg(pos);
    std::vector<uint8_t> buffer(size);
    m_file_stream.read(reinterpret_cast<char*>(buffer.data()), size);
    return buffer;
}

BinaryParser::BinaryParser(std::string fname) : m_fname{std::move(fname)} {
    open_bfd();
    // set Binary Type
    int binary_type = 0;
    switch (m_bfd_h->xvec->flavour) {
        case bfd_target_elf_flavour:
            binary_type = 1;  // ELF
            break;
        case bfd_target_coff_flavour:
            binary_type = 0;  // PE
            break;
        case bfd_target_unknown_flavour:
            [[fallthrough]];
        default:
            std::cerr << "unsupported binary type " << m_bfd_h->xvec->name << std::endl;
            exit(1);
            break;
    }
    int binary_bits = 0;
    switch (m_bfd_h->arch_info->mach) {
        case bfd_mach_i386_i386:
            binary_bits = 0;  // 32
            break;
        case bfd_mach_x86_64:
            binary_bits = 1;  // 64
            break;
        default:
            std::cerr << "unsupported architecture " << m_bfd_h->xvec->name << std::endl;
            exit(1);
            break;
    }
    m_binary_type = static_cast<BinaryType>((binary_type << 1) | binary_bits);
}

void BinaryParser::open_bfd() {
    static int bfd_inited = 0;  // bfd_init()함수를 딱 1번만 호출하기 위함.
    if (!bfd_inited) {
        bfd_init();
        bfd_inited = 1;
    }
    m_bfd_h = bfd_openr(m_fname.c_str(), NULL);  // 두번째 매개변수는 바이너리의 형식을 넘겨줘야한다. NULL이면 자동 판단
    if (!m_bfd_h) {
        std::cerr << "failed to open binary " << m_fname << " " << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }

    if (!bfd_check_format(m_bfd_h, bfd_object)) {  // 바이너리의 타입을 확인한다. 실행가능한바이너리, 재배치 가능한 Object파일, Shared Library
        std::cerr << "file " << m_fname << "does not look like an executable " << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }

    /*
        일부 버전의 bfd_check_format함수는 실행전 '잘못된 형식 오류'를 초기 설정후 함수를 실행하고
        이를 수동으로 해제 해야한다.
    */
    bfd_set_error(bfd_error_no_error);

    if (bfd_get_flavour(m_bfd_h) == bfd_target_unknown_flavour) {  // msdos, coff, elf등의 알려진 파일 형식을 반환하는 함수
        std::cerr << "unrecognized format for binary " << m_fname << " " << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }
}

//bfd* BinaryParser::get_bfd_handler() const noexcept {
//    if (!m_bfd_h) {
//        return m_bfd_h;
//    } else {
//        exit(1);
//    }
//}

template <typename T>
BaseBinary<T>::BaseBinary(std::string fname, bfd* bfd_h, BinaryType binary_type) : FileDescriptor(fname), m_bfd_h{bfd_h}, m_binary_type{binary_type} {
    parse_section();
    parse_section_header();
}

template <typename T>
void BaseBinary<T>::parse_section() {
    std::cout << "section 정보를 파싱한다." << std::endl;


}

template <typename T>
void BaseBinary<T>::parse_section_header() {
    std::cout << "section header 정보를 파싱한다." << std::endl;

}

//BinaryType BinaryParser::get_binary_type() const noexcept {
//    return m_binary_type;
//}

template <typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_header_helper() {
    // std::cout << static_cast<int>(this->m_binary_type) << "elf parse!" << std::endl;
}

template <typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_section_helper() {
    // std::cout << static_cast<int>(this->m_binary_type) << "elf parse!" << std::endl;
}

template <typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_section_header_helper() {
    // std::cout << static_cast<int>(this->m_binary_type) << "elf parse!" << std::endl;
}

template <typename T, typename U, typename V>
ElfBinary<T, U, V>::ElfBinary(std::string fname, bfd* bfd_h, BinaryType binary_type) : BaseBinary<T>(std::move(fname), bfd_h, binary_type) {
    parse_header_helper();
    parse_section_helper();
    parse_section_header_helper();
}



template <typename T, typename U, typename V>
PeBinary<T, U, V>::PeBinary(std::string fname, bfd* bfd_h, BinaryType binary_type) : BaseBinary<T>(std::move(fname), bfd_h, binary_type) {
    parse_header_helper();
    parse_section_helper();
    parse_section_header_helper();
}

template <typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_header_helper() {
    // std::cout << static_cast<int>(this->m_binary_type) << "pe parse!" << std::endl;
}

template <typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_section_header_helper() {
    // std::cout << static_cast<int>(this->m_binary_type) << "pe parse!" << std::endl;
}

template <typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_section_helper() {
    // std::cout << static_cast<int>(this->m_binary_type) << "pe parse!" << std::endl;
}


std::variant<elf32_ptr, elf64_ptr, pe32_ptr, pe64_ptr> BinaryParser::create_binary() {
    if (m_binary_type == BinaryType::ELF32) {
        std::cout << "elf32" << std::endl;
        return std::make_unique<elf32>(m_fname, m_bfd_h, m_binary_type);
    } else if (m_binary_type == BinaryType::ELF64) {
        std::cout << "elf64" << std::endl;
        return std::make_unique<elf64>(m_fname, m_bfd_h, m_binary_type);
    } else if (m_binary_type == BinaryType::PE32) {
        std::cout << "pe32" << std::endl;
        return std::make_unique<pe32>(m_fname, m_bfd_h, m_binary_type);
    } else if (m_binary_type == BinaryType::PE64) {
        std::cout << "pe64" << std::endl;
        return std::make_unique<pe64>(m_fname, m_bfd_h, m_binary_type);
    }
}

}  // namespace codeinject::binary

// 템플릿 클래스 인스턴스화
template class codeinject::binary::PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE32_HEADERS>;
template class codeinject::binary::PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE64_HEADERS>;
template class codeinject::binary::ElfBinary<Elf32_Shdr, Elf32_Ehdr, Elf32_Phdr>;
template class codeinject::binary::ElfBinary<Elf64_Shdr, Elf64_Ehdr, Elf64_Phdr>;