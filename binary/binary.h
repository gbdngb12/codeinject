#pragma once
#include <fstream>
#include <string>

#include <bfd.h>
#include <vector>
namespace codeinject::binary {

struct SectionHeader {
    SectionHeader() = default;
    virtual ~SectionHeader() = default;
    enum class SectionType {
        SEC_TYPE_NONE = 0,
        SEC_TYPE_CODE = 1,
        SEC_TYPE_DATA = 2
    };
    /**
     * @brief section의 이름
     *
     */
    std::string m_name;
    /**
     * @brief section의 타입
     *
     */
    SectionType m_section_type;
    /**
     * @brief 파일에서 section의 위치
     *
     */
    uint64_t m_file_offset;
    /**
     * @brief 파일에서 section header의 크기
     *
     */
    uint64_t m_file_size;
};

struct Section {
    Section() = default;
    virtual ~Section() = default;
    /**
     * @brief secion의 가상메모리 주소
     *
     */
    uint64_t m_vma;
    /**
     * @brief section의 가상메모리에서의 크기
     *
     */
    uint64_t m_size;
    /**
     * @brief 실제 코드 정보
     *
     */
    std::vector<uint8_t> m_bytes;
};

class FileDescriptor {
   public:
    /**
     * @brief 파일을 확인하고 파일을 연다.
     *
     * @param fname
     */
    FileDescriptor(std::string fname);
    virtual ~FileDescriptor() = default;

   public:  // protected:
    /**
     * @brief vector의 내용을 파일에 쓴다.
     *
     * @return int
     */
    void write_data(std::vector<uint8_t>, int pos);
    /**
     * @brief 파일의 내용을 읽는다.
     *
     * @return
     */
    void read_data(int pos, auto& data) {
        m_file_stream.seekg(pos);
        m_file_stream >> data;
    }

  //private:
    /**
     * @brief 파일의 이름
     *
     */
    std::string m_file_name;
    /**
     * @brief file stream
     *
     */
    std::fstream m_file_stream;
};

class Binary : public FileDescriptor {
   public:
    /**
     * @brief libbfd를 이용해서 바아니러를 연다.
     * 
     */
    Binary(std::string);
    virtual ~Binary();
    enum class BinaryType {
        ELF = 1,
        PE = 2
    };
    enum class BitsMachine {
        X86_32 = 0,
        X86_64 = 1
    };
    enum class Type {
        DATA = 0,
        OBJECTFILE = 1,
        EXECUTABLE = 2
    };
    /**
     * @brief ELF, PE
     *
     */
    BinaryType m_binary_type; // 설정 완료
    /**
     * @brief ELF, PE에 대한 스트링
     *
     */
    std::string m_binary_type_str; // 설정 완료
    /**
     * @brief X86_32, X86_64
     *
     */
    BitsMachine m_bits_machine; // 설정 완료
    /**
     * @brief X86_32, X86_64에 대한 스트링
     *
     */
    std::string m_bits_str; // 설정 완료
    /**
     * @brief 원래의 엔트리 포인트
     *
     */
    uint64_t m_original_entry_point; // 설정 완료
    /**
     * @brief section의 수
     *
     */
    int m_number_of_sections; // 설정 완료
    /**
     * @brief section header의 파일 오프셋
     *
     */
    uint64_t m_section_header_offset;
    /**
     * @brief section header의 수
     *
     */
    int m_section_header_count;
    /**
     * @brief section header의 크기
     *
     */
    int m_section_header_size;
    /**
     * @brief 실행가능한 파일 / object 파일 / data 파일
     *
     */
    Type m_type;
    /**
     * @brief 섹션들의 정보
     *
     */
    std::vector<Section> m_sections;

    /**
     * @brief libbfd에서 다루는 바이너리 파일 핸들러
     * 
     */
    bfd *m_bfd_h;
    inline static int bfd_inited = 0;
    /**
     * @brief libbfd를 이용해 바이너라 파일을 연다.
     * 
     */
    void open_bfd();

    /**
     * @brief 바이너리의 기본 정보를 분석한다.
     * 
     */
    void load_binary_bfd();

    /**
     * @brief 바이너리의 섹션 정보를 가져온다.
     * 
     */
    void load_sections_bfd();

    BinaryType get_binary_type() const noexcept;
};
}  // namespace codeinject::binary