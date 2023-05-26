#include "CodeInject.h"

namespace codeinject::inject {
template <typename P>
PeInject<P>::PeInject(P ptr) : m_binary{std::move(ptr)} {}

template <typename P>
ElfInject<P>::ElfInject(P ptr) : m_binary{std::move(ptr)} {}

template <typename P>
void PeInject<P>::inject_code(std::vector<uint8_t> code) {
    // 구현 내용 추가
    std::cout << "PeInject::inject_code called" << std::endl;
    // @ TODO
    // 1. 첫번째 섹션 시작 파일 오프셋 - (마지막 섹션의 파일오프셋 + sizeof(SECTION_HEADER)) >= sizeof(SECTION_HEADER)
    // 없으면 종료
    // 2. NumberOfSection 값 1증가
    // 3. 코드의 크기 계산, -> 가상 메모리 크기도 그냥 코드의 크기와 같게 계산
    // 4. 파일끝에 코드를 삽입 -> 값도 저장해야함
    // 5. 가상 메모리 정렬 값 읽어온다.
    // 6. 마지막 섹션의 가상메모리 주소 + 크기
    // 7. 정렬 값으로 삽입할 섹션의 가상 메모리 주소를 계산한다.
    // 8. 플래그 설정
    // 9. 전체 가상 메모리 크기도 수정(SizeOfImage)
    // 10. 엔트리포인트 주소 수정
    auto& pe_header = m_binary.get()->m_pe_header;
}

template <typename P>
void PeInject<P>::add_section(std::string sec_name) {
    // 구현 내용 추가
    std::cout << "PeInject::add_section called" << std::endl;
    // if constexpr (std::is_same_v<P, pe64_ptr>) {
    // } else if constexpr (std::is_same_v<P, pe32_ptr>) {
    // }
}

template <typename P>
void ElfInject<P>::inject_code(std::vector<uint8_t> code) {
    // 구현 내용 추가
    std::cout << "ElfInject::inject_code called" << std::endl;
    // if constexpr (std::is_same_v<P, elf64_ptr>) {
    // } else if constexpr (std::is_same_v<P, elf32_ptr>) {
    // }
}

template <typename P>
void ElfInject<P>::add_section(std::string sec_name) {
    // 구현 내용 추가
    std::cout << "ElfInject::add_section called" << std::endl;
    // if constexpr (std::is_same_v<P, elf64_ptr>) {
    // } else if constexpr (std::is_same_v<P, elf32_ptr>) {
    // }
}
};  // namespace codeinject::inject

template class codeinject::inject::ElfInject<codeinject::binary::elf32_ptr>;
template class codeinject::inject::ElfInject<codeinject::binary::elf64_ptr>;
template class codeinject::inject::PeInject<codeinject::binary::pe32_ptr>;
template class codeinject::inject::PeInject<codeinject::binary::pe64_ptr>;