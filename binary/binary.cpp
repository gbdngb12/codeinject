#include "binary.h"

#include <iostream>
#include <utility>

namespace codeinject::binary {

FileDescriptor::FileDescriptor(std::string fname) : m_file_name{std::move(fname)}, m_file_stream{m_file_name} {
    if (!m_file_stream) {
        std::cout << "Failed to open " << m_file_name << std::endl;
        exit(1);
    }
}

void FileDescriptor::write_data(std::vector<uint8_t> data, int pos) {
    m_file_stream.seekp(pos);
    for (auto&& v : data) {
        m_file_stream << v;
    }
}

Binary::Binary(std::string fname) : FileDescriptor(std::move(fname)) {
    open_bfd();
    load_binary_bfd();
    load_sections_bfd();  // 바이너리의 섹션수를 가져온다.
}

void Binary::open_bfd() {
    if (!bfd_inited) {
        bfd_init();
        bfd_inited = 1;
    }
    m_bfd_h = bfd_openr(this->m_file_name.c_str(), NULL);

    if (!m_bfd_h) {
        std::cerr << "failed to open binary " << this->m_file_name << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }

    if (!bfd_check_format(m_bfd_h, bfd_object)) {  // 실행 가능한 파일, 재배치 가능한 오브젝트 파일, 공유 라이브러리인지 확인한다.
        std::cerr << this->m_file_name << "does not look like an executable" << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }

    bfd_set_error(bfd_error_no_error);

    if (bfd_get_flavour(m_bfd_h) == bfd_target_unknown_flavour) {
        std::cerr << this->m_file_name << "unrecognized format for binary" << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }
}

void Binary::load_binary_bfd() {
    const bfd_arch_info_type* bfd_info;

    this->m_original_entry_point = bfd_get_start_address(m_bfd_h);  // Get entry Point Address

    this->m_binary_type_str = std::string{m_bfd_h->xvec->name};  // bfd_target 구조체 => 현재 바이너리 타입에 해당하는 구조체
    switch (m_bfd_h->xvec->flavour) {
        case bfd_target_elf_flavour:
            this->m_binary_type = BinaryType::ELF;
            break;
        case bfd_target_coff_flavour:
            this->m_binary_type = BinaryType::PE;
            break;
        case bfd_target_unknown_flavour:
            [[fallthrough]];
        default:
            std::cerr << "unsupported binary type (%s)"
                      << m_bfd_h->xvec->name << std::endl;
            exit(1);
    }

    bfd_info = bfd_get_arch_info(m_bfd_h);
    this->m_bits_str = std::string{bfd_info->printable_name};

    switch (bfd_info->mach) {
        case bfd_mach_i386_i386:
            this->m_bits_machine = BitsMachine::X86_32;
            break;
        case bfd_mach_x86_64:
            this->m_bits_machine = BitsMachine::X86_64;
            break;
        default:
            std::cerr << "unsupported architecture" << bfd_info->printable_name << std::endl;
            exit(1);
    }

    // load_symbols_bfd(bfd_h, bin);  // 복잡한 과정을 수반하므로 별도의 함수 load_symbol_bfd를 만들어 호출
    // load_dynsym_bfd(bfd_h, bin);

    // if (load_sections_bfd(bfd_h, bin) < 0)
    //     exit(1);

    // if (bfd_h)
    //     bfd_close(bfd_h);
}

Binary::~Binary() {
    bfd_close(m_bfd_h);
}

void Binary::load_sections_bfd() {
    m_number_of_sections = bfd_count_sections(m_bfd_h);

    int bfd_flags;
    asection* bfd_sec;
    uint64_t vma, size;
    const char* secname;
    SectionHeader::SectionType sectype;
    for (bfd_sec = m_bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
        bfd_flags = bfd_sec->flags;  // bfd_flags = bfd_get_section_flags(bfd_h, bfd_sec);

        sectype = SectionHeader::SectionType::SEC_TYPE_NONE;
        if (bfd_flags & SEC_CODE) {
            sectype = SectionHeader::SectionType::SEC_TYPE_CODE;
        } else if (bfd_flags & SEC_DATA) {
            sectype = SectionHeader::SectionType::SEC_TYPE_DATA;
        } else {
            continue;
        }

        vma = bfd_section_vma(bfd_sec);
        size = bfd_section_size(bfd_sec);
        secname = bfd_section_name(bfd_sec);
        if (!secname)
            secname = "<unnamed>";

        this->m_sections.push_back(Section());
        sec = &bin->sections.back();

        sec->binary = bin;
        sec->name = std::string(secname);
        sec->type = sectype;
        sec->vma = vma;
        sec->size = size;
        sec->bytes = (uint8_t*)malloc(size);
        if (!sec->bytes) {
            fprintf(stderr, "out of memory\n");
            return -1;
        }

        if (!bfd_get_section_contents(bfd_h, bfd_sec, sec->bytes, 0, size)) {
            fprintf(stderr, "failed to read section '%s' (%s)\n", secname, bfd_errmsg(bfd_get_error()));
            return -1;
        }
    }
}
};  // namespace codeinject::binary