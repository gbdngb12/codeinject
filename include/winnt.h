typedef unsigned short WORD;
typedef unsigned int DWORD;
typedef unsigned char BYTE;
typedef unsigned long long ULONGLONG;

// PE 코드 삽입을 위해 필요한 정보 
// section header의 마지막 파일 오프셋 - 첫번째 Section의 코드 >= 40(IMAGE_SECTION_HEADER의 크기)

typedef struct _IMAGE_DOS_HEADER {
    WORD e_magic;    /* 00: MZ Header signature */
    WORD e_cblp;     /* 02: Bytes on last page of file */
    WORD e_cp;       /* 04: Pages in file */
    WORD e_crlc;     /* 06: Relocations */
    WORD e_cparhdr;  /* 08: Size of header in paragraphs */
    WORD e_minalloc; /* 0a: Minimum extra paragraphs needed */
    WORD e_maxalloc; /* 0c: Maximum extra paragraphs needed */
    WORD e_ss;       /* 0e: Initial (relative) SS value */
    WORD e_sp;       /* 10: Initial SP value */
    WORD e_csum;     /* 12: Checksum */
    WORD e_ip;       /* 14: Initial IP value */
    WORD e_cs;       /* 16: Initial (relative) CS value */
    WORD e_lfarlc;   /* 18: File address of relocation table */
    WORD e_ovno;     /* 1a: Overlay number */
    WORD e_res[4];   /* 1c: Reserved words */
    WORD e_oemid;    /* 24: OEM identifier (for e_oeminfo) */
    WORD e_oeminfo;  /* 26: OEM information; e_oemid specific */
    WORD e_res2[10]; /* 28: Reserved words */
    DWORD e_lfanew;  /* 3c: Offset to extended header */
} IMAGE_DOS_HEADER, PE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD Machine;
    WORD NumberOfSections; /* PE Inject를 위해 필요한 정보 : 섹션을 추가하기 위해서 */
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics; /* PE Inject를 위해 필요한 정보 : 보안 Flag 삭제 */
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress;
    DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

//#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD Magic; /* 0x20b */
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint; /* PE Inject를 위해 필요한 정보 : Entry Point */
    DWORD BaseOfCode; 
    ULONGLONG ImageBase;
    DWORD SectionAlignment; /* PE Inject를 위해 필요한 정보 : 가상 메모리에 section을 추가할때 시작, 끝 지점 메모리 값 계산을 위해 */
    DWORD FileAlignment;    /* PE Inject를 위해 필요한 정보 : 파일에서 section을 추가할때 시작, 끝 지점 파일 오프셋 계산을 위해 */
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion;
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage; /* PE Inject를 위해 필요한 정보 : 가상 메모리에 로드됐을때의 전체 메모리 크기 */
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD Subsystem;
    WORD DllCharacteristics;
    ULONGLONG SizeOfStackReserve;
    ULONGLONG SizeOfStackCommit;
    ULONGLONG SizeOfHeapReserve;
    ULONGLONG SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    //IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, PE64_HEADERS;

typedef struct _IMAGE_OPTIONAL_HEADER {
    /* Standard fields */

    WORD Magic; /* 0x10b or 0x107 */ /* 0x00 */
    BYTE MajorLinkerVersion;
    BYTE MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint; /* 0x10, PE Inject를 위해 필요한 정보 : Entry Point  */
    DWORD BaseOfCode;
    DWORD BaseOfData;

    /* NT additional fields */

    DWORD ImageBase;
    DWORD SectionAlignment; /* 0x20, PE Inject를 위해 필요한 정보 : 가상 메모리에 section을 추가할때 시작, 끝 지점 메모리 값 계산을 위해 */
    DWORD FileAlignment; /* PE Inject를 위해 필요한 정보 : 파일에서 section을 추가할때 시작, 끝 지점 파일 오프셋 계산을 위해 */
    WORD MajorOperatingSystemVersion;
    WORD MinorOperatingSystemVersion;
    WORD MajorImageVersion;
    WORD MinorImageVersion;
    WORD MajorSubsystemVersion; /* 0x30 */
    WORD MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage; /* PE Inject를 위해 필요한 정보 : 가상 메모리에 로드됐을때의 전체 메모리 크기 */
    DWORD SizeOfHeaders;
    DWORD CheckSum; /* 0x40 */
    WORD Subsystem;
    WORD DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve; /* 0x50 */
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    //IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; /* 0x60 */                                                                    /* 0xE0 */
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature; /* "PE"\0\0 */         /* 0x00 */
    IMAGE_FILE_HEADER FileHeader;           /* 0x04 */
    IMAGE_OPTIONAL_HEADER32 OptionalHeader; /* 0x18 */
} IMAGE_NT_HEADERS32, PE32_HEADERS;
/**
 * @brief PE에 삽입할 섹션 헤더의 정보
 * 
 */
#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct _IMAGE_SECTION_HEADER {
    BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize; // PE inject를 위해 필요한 정보
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData; // PE inject를 위해 필요한 정보
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics; // PE inject를 위해 필요한 정보
} IMAGE_SECTION_HEADER, PE_SECTION_HEADER;
