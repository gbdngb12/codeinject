#include "binary.h"

#include <fcntl.h>

#include <ranges>
#include <span>
#include <utility>

namespace codeinject::binary {
FileDescriptor::~FileDescriptor() {
    // close(m_fd);
}

FileDescriptor::FileDescriptor(std::string fname) : m_fname{std::move(fname)}, m_file_stream{m_fname} {
    if (!m_file_stream) {
        std::cerr << "open error" << m_fname << std::endl;
        exit(1);
    }
}

std::string FileDescriptor::get_file_name() const noexcept {
    return m_fname;
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

Bfd::Bfd(std::string fname, std::shared_ptr<bfd> bfd_h) : FileDescriptor(std::move(fname)), m_bfd_h{(bfd_h)} {
}

Bfd::Bfd(std::string fname) : FileDescriptor(std::move(fname)) {
    // open_bfd();// 생성자에서는 호출하면 안됨!! 미래를 호출하지 않음
}

void Bfd::open_bfd() {
    static int bfd_inited = 0;  // bfd_init()함수를 딱 1번만 호출하기 위함.
    if (!bfd_inited) {
        bfd_init();
        bfd_inited = 1;
    }
    m_bfd_h = std::shared_ptr<bfd>(bfd_openr(this->get_file_name().c_str(), NULL));

    // m_bfd_h = std::make_shared<bfd>(bfd_openr(this->get_file_name().c_str(), NULL));  // 두번째 매개변수는 바이너리의 형식을 넘겨줘야한다. NULL이면 자동 판단
    if (!m_bfd_h) {
        std::cerr << "failed to open binary " << this->get_file_name() << " " << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }

    if (!bfd_check_format(m_bfd_h.get(), bfd_object)) {  // 바이너리의 타입을 확인한다. 실행가능한바이너리, 재배치 가능한 Object파일, Shared Library
        std::cerr << "file " << this->get_file_name() << "does not look like an executable " << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }

    /*
        일부 버전의 bfd_check_format함수는 실행전 '잘못된 형식 오류'를 초기 설정후 함수를 실행하고
        이를 수동으로 해제 해야한다.
    */
    bfd_set_error(bfd_error_no_error);
    auto file_type = bfd_get_flavour(m_bfd_h.get());
    if (file_type == bfd_target_unknown_flavour) {  // msdos, coff, elf등의 알려진 파일 형식을 반환하는 함수
        std::cerr << "unrecognized format for binary " << this->get_file_name() << " " << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }
}

Bfd::~Bfd() {
    // auto count = m_bfd_h.use_count();
    // if (count == 1) {
    //     bfd_close(m_bfd_h.get());
    // }
}

template <typename T>
SectionBinary<T>::SectionBinary(std::string fname, std::shared_ptr<bfd> bfd_h) : Bfd(std::move(fname), bfd_h) {
    parse_section();
}

template <typename T>
SectionBinary<T>::SectionBinary(std::string fname) : Bfd(std::move(fname)) {
    // parse_section();
}

template <typename T>
void SectionBinary<T>::parse_section() {
    for (asection* bfd_sec = m_bfd_h->sections; bfd_sec; bfd_sec = bfd_sec->next) {
        unsigned int bfd_flags = bfd_sec->flags;
        if (!(bfd_flags & (SEC_CODE | SEC_DATA))) {
            continue;
        }
        auto secname = bfd_section_name(bfd_sec);
        /*
        //const char* secname;

        //vma = bfd_section_vma(bfd_sec);
        //size = bfd_section_size(bfd_sec);
        //secname = bfd_section_name(bfd_sec);
        //if (!secname)
        //    secname = "<unnamed>";

        //bin->sections.push_back(Section());
        //sec = &bin->sections.back();

        //sec->binary = bin;
        //sec->name = std::string(secname);
        //sec->type = sectype;
        //sec->vma = vma;
        //sec->size = size;
        //sec->bytes = (uint8_t*)malloc(size);
        //if (!sec->bytes) {
        //    fprintf(stderr, "out of memory\n");
        //    return -1;
        //}*/

        auto size = bfd_section_size(bfd_sec);
        std::vector<uint8_t> bytes(size);

        if (!bfd_get_section_contents(m_bfd_h.get(), bfd_sec, bytes.data(), 0, size)) {
            std::cerr << "failed to read section" << secname << bfd_errmsg(bfd_get_error()) << std::endl;
            exit(1);
        }
        Section<T> sec;
        sec.m_bytes = std::move(bytes);
        m_sections.push_back(std::move(sec));
        auto& sec_ref = m_sections.back();
        sec_ref.m_section_name = std::move(std::string{secname});
    }
}

BinaryParser::BinaryParser(std::string fname) : Bfd(std::move(fname)) {
    this->open_bfd();
    // set Binary Type
    int binary_type = 0;
    switch (this->m_bfd_h->xvec->flavour) {
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
    switch (this->m_bfd_h->arch_info->mach) {
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

template <typename T>
BaseBinary<T>::BaseBinary(std::string fname, std::shared_ptr<bfd> bfd_h, BinaryType binary_type) : SectionBinary<T>(fname, bfd_h), m_binary_type{std::move(binary_type)} {
}

template <typename T>
template <typename K>
K SectionBinary<T>::vec_to_struct(std::vector<uint8_t>&& data) {
    const auto* dataPtr = reinterpret_cast<const std::byte*>(data.data());
    const auto* struct_data = std::bit_cast<const K*>(dataPtr);
    return K{*struct_data};
}

template <typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_every_thing() {
    // 각 바이너리의 구조체에 맞게 모든 값을 파싱한다.
    if constexpr (std::is_same_v<T, Elf32_Shdr> || std::is_same_v<T, Elf64_Shdr>) {
        // 1. elf header를 파싱한다.
        parse_elf_header();
        // 2. program header를 파싱한다.
        parse_program_header();
        // 3. section header를 파싱한다.
        parse_section_header();
        // 4. 실제 section들의 정보를 파싱한다.
    } else {
        std::cerr << "Unknown section header" << std::endl;
        exit(1);
    }
}

template <typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_elf_header() {
    if constexpr (std::is_same_v<U, Elf32_Ehdr>) {
        auto ehdr = elf32_getehdr(m_elf);
        ehdr->e_ehsize;
        memcpy(&m_elf_header, ehdr, sizeof(U));
    } else if constexpr (std::is_same_v<U, Elf64_Ehdr>) {
        GElf_Ehdr ehdr;
        gelf_getehdr(m_elf, &ehdr);
        memcpy(&m_elf_header, &ehdr, sizeof(U));
    } else {
        std::cerr << "Unkown elf header" << std::endl;
    }
}

template <typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_program_header() {
    int number_of_program_header = m_elf_header.e_phnum;
    if constexpr (std::is_same_v<V, Elf32_Phdr>) {
        for (int i = 0; i < number_of_program_header; i++) {
            auto phdr = elf32_getphdr(m_elf);
            V program_header{};
            memcpy(&program_header, phdr, sizeof(V));
            m_program_header.push_back(std::move(program_header));
        }
    } else if constexpr (std::is_same_v<V, Elf64_Phdr>) {
        GElf_Phdr phdr;
        for (int i = 0; i < number_of_program_header; i++) {
            gelf_getphdr(m_elf, i, &phdr);
            V program_header{};
            memcpy(&program_header, &phdr, sizeof(V));
            m_program_header.push_back(std::move(program_header));
        }
    } else {
        std::cerr << "Unkown elf header" << std::endl;
    }
}

template <typename T, typename U, typename V>
void ElfBinary<T, U, V>::parse_section_header() {
    const char* s;
    Elf_Scn* scn;
    size_t shstrndx;
    int index = 0;
    if (elf_getshdrstrndx(m_elf, &shstrndx) < 0) {
        std::cerr << "Failed to get string table section index" << std::endl;
        exit(1);
    }
    scn = nullptr;
    while ((scn = elf_nextscn(m_elf, scn))) {
        if constexpr (std::is_same_v<T, Elf32_Shdr>) {
            auto shdr = elf32_getshdr(scn);
            if (!shdr) {
                std::cerr << "Failed to get section header" << std::endl;
                exit(1);
            }
            T section_header{};
            auto str = std::string(elf_strptr(m_elf, shstrndx, shdr->sh_name));
            memcpy(&section_header, shdr, sizeof(T));

            this->m_sections[index].m_section_header = std::move(section_header);
        } else if constexpr (std::is_same_v<T, Elf64_Shdr>) {
            GElf_Shdr shdr;
            if (!gelf_getshdr(scn, &shdr)) {
                std::cerr << "Failed to get section header" << std::endl;
                exit(1);
            }
            T section_header{};
            auto str = std::string(elf_strptr(m_elf, shstrndx, shdr.sh_name));
            memcpy(&section_header, &shdr, sizeof(T));
            this->m_sections[index].m_section_header = std::move(section_header);
        } else {
            std::cerr << "Unkown elf header" << std::endl;
        }
    }
}

template <typename T, typename U, typename V>
ElfBinary<T, U, V>::~ElfBinary() {
    close(this->m_fd);
}

template <typename T, typename U, typename V>
void ElfBinary<T, U, V>::libelf_open() {
    // libelf를 위한 값들을 연다.
    if (elf_version(EV_CURRENT) == EV_NONE) {
        std::cerr << "ELF library initialization failed: " << elf_errmsg(-1) << std::endl;
        exit(1);
    }
    // 읽기 전용으로 사용
    // C레거시 코드를 사용하기위해 임시적으로 읽기모드로 fd 생성

    this->m_fd = open(this->get_file_name().c_str(), O_RDONLY);
    if (this->m_fd == -1) {
        std::cerr << "Failed to open file" << std::endl;
        exit(1);
    }

    m_elf = elf_begin(this->m_fd, ELF_C_READ, NULL);
    if (!m_elf) {
        std::cerr << "Failed to open ELF file " << std::endl;
        exit(1);
    }

    if (elf_kind(m_elf) != ELF_K_ELF) {
        std::cerr << "not an ELF executable" << std::endl;
        exit(1);
    }
}

template <typename T, typename U, typename V>
ElfBinary<T, U, V>::ElfBinary(std::string fname, std::shared_ptr<bfd> bfd_h, BinaryType binary_type) : BaseBinary<T>(std::move(fname), bfd_h, binary_type) {
    // libelf를 위한것들을 연다.
    libelf_open();
    // 나머지 모든것들을 파싱한다.
    parse_every_thing();
}

template <typename T, typename U, typename V>
PeBinary<T, U, V>::PeBinary(std::string fname, std::shared_ptr<bfd> bfd_h, BinaryType binary_type) : BaseBinary<T>(std::move(fname), bfd_h, binary_type) {
    parse_every_thing();
}

template <typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_every_thing() {
    // 구조체에 맞게 모든 값을 파싱한다.
    // T is PE_SECTION_HEADER
    if constexpr (std::is_same_v<T, PE_SECTION_HEADER>) {
        // 1. 파일을 연다 -> 객체 생성하면서 이미 열려있음 m_file_stream으로 접근
        // 2. DOS_HEADER를 파싱한다.
        parse_dos_header();
        // 3. PE_HEADER를 파싱한다.
        parse_pe_header();
        // 4. Section HEADER를 파싱한다.
        parse_section_header();
    } else {
        std::cerr << "unknown section header" << std::endl;
        exit(1);
    }
}

template <typename T, typename U, typename V>
void PeBinary<T, U, V>::set_section_header(std::vector<uint8_t>& data) {
    auto n = this->m_sections.size();
    auto retSpan = std::span<uint8_t>(data.data(), data.size());
    auto secHeaderSpan = std::span<T>(reinterpret_cast<T*>(std::move(retSpan.data())), n);

    int index = 0;
    for (auto&& sec : this->m_sections) {
        sec.m_section_header = std::move(secHeaderSpan[index++]);
    }
}

template <typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_dos_header() {
    // PE DOS Header를 파싱한다.
    // U is PE_DOS_HEADER
    if constexpr (std::is_same_v<U, PE_DOS_HEADER>) {
        m_dos_header = this->template vec_to_struct<U>(std::move(this->read_data(0, sizeof(U))));
    } else {
        std::cerr << "Unkown dos header" << std::endl;
        exit(1);
    }
}

template <typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_pe_header() {
    // PE HEADER를 파싱한다.
    // V is PE_HEADER
    if constexpr (std::is_same_v<V, PE32_HEADERS> || std::is_same_v<V, PE64_HEADERS>) {
        m_pe_header = this->template vec_to_struct<V>(std::move(this->read_data(m_dos_header.e_lfanew, sizeof(V))));
        m_number_of_image_data_dir = m_pe_header.OptionalHeader.NumberOfRvaAndSizes;
    } else {
        std::cerr << "Unknown pe header" << std::endl;
        exit(1);
    }
}

// 현재 IMAGE_DATA_DIRECTORY는 파싱하지 않았음
template <typename T, typename U, typename V>
void PeBinary<T, U, V>::parse_section_header() {
    // PE section header를 파싱한다.
    // T is PE_SECTION_HEADER
    if constexpr (std::is_same_v<T, PE_SECTION_HEADER>) {
        auto n = m_pe_header.FileHeader.NumberOfSections;
        auto section_header_file_offset = m_dos_header.e_lfanew /*PE Header File offset*/
                                          + sizeof(V)           /*sizeof(PE Header without IMAGE_DATA_DIRECTORY)*/
                                          + (sizeof(IMAGE_DATA_DIRECTORY) * m_number_of_image_data_dir);
        auto data = this->read_data(section_header_file_offset, sizeof(T) * n);
        /**
         * @brief section header 정보를 설정한다.
         *
         */
        set_section_header(data);
        // 이름 설정

        // for(int i = 0; i < n; ++i) {
        //     std::span myspan{data};
        //     std::span subspan { std::move(myspan.subspan(i*sizeof(T), 8))};
        //     std::string name{subspan.begin(), subspan.end()};
        //
        //    //this->m_sections[i].set_section_name(std::move(name));  // 설정된 이름을 섹션에 설정
        //}

    } else {
        std::cerr << "Unkown section header" << std::endl;
        exit(1);
    }
}

std::variant<elf32_ptr, elf64_ptr, pe32_ptr, pe64_ptr> BinaryParser::create_binary() {
    if (m_binary_type == BinaryType::ELF32) {
        std::cout << "elf32" << std::endl;
        return std::make_unique<elf32>(this->get_file_name(), (m_bfd_h), m_binary_type);
    } else if (m_binary_type == BinaryType::ELF64) {
        std::cout << "elf64" << std::endl;
        return std::make_unique<elf64>(this->get_file_name(), (m_bfd_h), m_binary_type);
    } else if (m_binary_type == BinaryType::PE32) {
        std::cout << "pe32" << std::endl;
        return std::make_unique<pe32>(this->get_file_name(), (m_bfd_h), m_binary_type);
    } else if (m_binary_type == BinaryType::PE64) {
        std::cout << "pe64" << std::endl;
        return std::make_unique<pe64>(this->get_file_name(), (m_bfd_h), m_binary_type);
    }
}
template <typename T>
CodeBinary<T>::CodeBinary(std::string fname) : SectionBinary<T>(std::move(fname)) {
    open_bfd();
}

template <typename T>
void CodeBinary<T>::open_bfd() {
    static int bfd_inited = 0;  // bfd_init()함수를 딱 1번만 호출하기 위함.
    if (!bfd_inited) {
        bfd_init();
        bfd_inited = 1;
    }
    this->m_bfd_h = std::shared_ptr<bfd>(bfd_openr(this->get_file_name().c_str(), NULL));

    if (!this->m_bfd_h) {
        std::cerr << "failed to open binary " << this->get_file_name() << " " << bfd_errmsg(bfd_get_error()) << std::endl;
        exit(1);
    }

    if (bfd_check_format(this->m_bfd_h.get(), bfd_object)) {  // 바이너리의 타입을 확인한다. 실행가능한바이너리, 재배치 가능한 Object파일, Shared Library
        // PE 코드인경우 직접 파싱
        this->parse_section();
        return;
    } else {  // 파일 자체가 코드인 경우
        // auto size = this->get_file_size();
        auto ret = this->read_data(0, this->get_file_size());
        Section<T> sec;
        sec.m_bytes.resize(ret.size());
        std::ranges::move(ret, begin(sec.m_bytes));
        this->m_sections.push_back(std::move(sec));
    }
}
template <typename T>
std::vector<uint8_t> CodeBinary<T>::get_code() const {
    return this->m_sections.back().m_bytes;
}

template <typename P>
PeInject<P>::PeInject(P ptr) : m_binary{std::move(ptr)} {}

template <typename P>
ElfInject<P>::ElfInject(P ptr) : m_binary{std::move(ptr)} {}

template <typename P>
void PeInject<P>::inject_code(std::vector<uint8_t> code) {
    // 구현 내용 추가
    std::cout << "PeInject::inject_code called" << std::endl;
    
}

template <typename P>
void PeInject<P>::add_section(std::string sec_name) {
    // 구현 내용 추가
    std::cout << "PeInject::add_section called" << std::endl;

}

template <typename P>
void ElfInject<P>::inject_code(std::vector<uint8_t> code) {
    // 구현 내용 추가
    std::cout << "ElfInject::inject_code called" << std::endl;
}

template <typename P>
void ElfInject<P>::add_section(std::string sec_name) {
    // 구현 내용 추가
    std::cout << "ElfInject::add_section called" << std::endl;
}

}  // namespace codeinject::binary
// 템플릿 클래스 인스턴스화
template class codeinject::binary::ElfInject<codeinject::binary::elf32_ptr>;
template class codeinject::binary::ElfInject<codeinject::binary::elf64_ptr>;
template class codeinject::binary::PeInject<codeinject::binary::pe32_ptr>;
template class codeinject::binary::PeInject<codeinject::binary::pe64_ptr>;
template class codeinject::binary::CodeBinary<Elf64_Shdr>;
template class codeinject::binary::CodeBinary<PE_SECTION_HEADER>;
template class codeinject::binary::PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE32_HEADERS>;
template class codeinject::binary::PeBinary<PE_SECTION_HEADER, PE_DOS_HEADER, PE64_HEADERS>;
template class codeinject::binary::ElfBinary<Elf32_Shdr, Elf32_Ehdr, Elf32_Phdr>;
template class codeinject::binary::ElfBinary<Elf64_Shdr, Elf64_Ehdr, Elf64_Phdr>;