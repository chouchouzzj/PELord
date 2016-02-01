//size 4+20+96 = 120 = 0x78
//pos:0+IMAGE_DOS_HEADER->e_lfanew
typedef struct _IMAGE_NT_HEADERS {
	DWORD                 Signature;	//'PE' 0x00004550
	IMAGE_FILE_HEADER     FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

#define IMAGE_SIZEOF_FILE_HEADER             20         //����һ������
typedef struct _IMAGE_FILE_HEADER {	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx
WORD  Machine;					//����	0x014c:x86	0x8664:x64	0x0200:Intel Itanium
WORD  NumberOfSections;			//����
DWORD   TimeDateStamp;          //ʱ�����ڴ�
DWORD   PointerToSymbolTable;   //���ű�ָ��
DWORD   NumberOfSymbols;        //������
WORD  SizeOfOptionalHeader;		//��ѡͷ�Ĵ�С
WORD  Characteristics;			//����
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
// size 96
typedef struct _IMAGE_OPTIONAL_HEADER {	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
//--------��׼��--------//
WORD  Magic;                      // 0 ħ��				0x10b:IMAGE_NT_OPTIONAL_HDR32_MAGIC		0x20b:IMAGE_NT_OPTIONAL_HDR64_MAGIC
BYTE  MajorLinkerVersion;         // 2 ���������汾��
BYTE  MinorLinkerVersion;         // 3 ������С�汾��
DWORD SizeOfCode;                 // 4 �����С
DWORD SizeOfInitializedData;      // 8 �ѳ�ʼ�����ݴ�С
DWORD SizeOfUninitializedData;    // 12 δ��ʼ�����ݴ�С
DWORD AddressOfEntryPoint;        // 16 ��ڵ��ַ
DWORD BaseOfCode;                 // 20 �����ַ
DWORD BaseOfData;                 // 24 ���ݻ�ַ
//--------NT���ӵ���--------//
DWORD ImageBase;                  // 28 ӳ���ļ���ַ
DWORD SectionAlignment;           // 32 �ڶ���
DWORD FileAlignment;              // 36 �ļ�����
WORD  MajorOperatingSystemVersion;// 40 ����ϵͳ���汾��
WORD  MinorOperatingSystemVersion;//	����ϵͳС�汾��
WORD  MajorImageVersion;          // 44 ӳ���ļ����汾��
WORD  MinorImageVersion;          //	ӳ���ļ�С�汾��
WORD  MajorSubsystemVersion;      // 48 ��ϵͳ���汾��
WORD  MinorSubsystemVersion;      //	��ϵͳС�汾��
DWORD Win32VersionValue;          // 52 ������1
DWORD SizeOfImage;                // 56 ӳ���ļ���С
DWORD SizeOfHeaders;              // 60	����ͷ�Ĵ�С
DWORD CheckSum;                   // 64 У���
WORD  Subsystem;                  // 68 ��ϵͳ
WORD  DllCharacteristics;         //	DLL����
DWORD SizeOfStackReserve;         // 72 ����ջ�Ĵ�С
DWORD SizeOfStackCommit;          // 76 ָ��ջ�Ĵ�С
DWORD SizeOfHeapReserve;          // 80 �����ѵĴ�С
DWORD SizeOfHeapCommit;           // 84 ָ���ѵĴ�С
DWORD LoaderFlags;                // 88 ��������־
DWORD NumberOfRvaAndSizes;        // 92 RVA�������ʹ�С
IMAGE_DATA_DIRECTORY DataDirectory  [IMAGE_NUMBEROF_DIRECTORY_ENTRIES];   // 96=0x60 ����Ŀ¼���� 16*8 = 128 = 0x80
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;



typedef struct _IMAGE_DATA_DIRECTORY {	//https://msdn.microsoft.com/en-us/library/windows/desktop/ms680305(v=vs.85).aspx
DWORD VirtualAddress;	//�����ַ
DWORD Size;			//��С
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_SIZEOF_SHORT_NAME              8      //����һ������
// size 40 = 0x28
// pos IMAGE_DOS_HEADER->e_lfanew + sizeof(IMAGE_NT_HEADERS)
// num IMAGE_FILE_HEADER->NumberOfSections
typedef struct _IMAGE_SECTION_HEADER {	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];            // 0 ��������
	union {                                         // 8 �������־
		DWORD PhysicalAddress;					//�����ַ
		DWORD VirtualSize;							//�����С
	} Misc;
	DWORD VirtualAddress;                           // 12 �����ַ
	DWORD SizeOfRawData;                            // 16 ԭʼ���ݵĴ�С
	DWORD PointerToRawData;                         // 20 ԭʼ����ָ��
	DWORD PointerToRelocations;                     // 24 �ض�λָ��
	DWORD PointerToLinenumbers;                     // 28 ����ָ��
	WORD  NumberOfRelocations;                      // 32 �ض�λ��Ŀ
	WORD  NumberOfLinenumbers;                      //		������Ŀ
	DWORD Characteristics;                          // 36 ����
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


�仯�ĵط�{
	IMAGE_OPTIONAL_HEADER{
		AddressOfEntryPoint;
		SizeOfImage,
	}
	IMAGE_FILE_HEADER{
		WORD NumberOfSections :  0x00000004
	}
	_IMAGE_SECTION_HEADER {
		BYTE  Name :  .wow
		DWORD VirtualSize :  0x00000013 	 VirtualSizeAlignment : 0x0000a000
		DWORD VirtualAddress :  0x00002000
		DWORD SizeOfRawData :  0x00000200
		DWORD PointerToRawData :  0x00003800
		DWORD PointerToRelocations :  0x00000048
		DWORD PointerToLinenumbers :  0x00050002
		WORD  NumberOfRelocations :  0x00002f00
		WORD  NumberOfLinenumbers :  0x00000000
		DWORD Characteristics :  0xe00000e0
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
}