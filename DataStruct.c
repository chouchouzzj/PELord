//size 4+20+96 = 120 = 0x78
//pos:0+IMAGE_DOS_HEADER->e_lfanew
typedef struct _IMAGE_NT_HEADERS {
	DWORD                 Signature;	//'PE' 0x00004550
	IMAGE_FILE_HEADER     FileHeader;
	IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;

#define IMAGE_SIZEOF_FILE_HEADER             20         //定义一个常量
typedef struct _IMAGE_FILE_HEADER {	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx
WORD  Machine;					//机器	0x014c:x86	0x8664:x64	0x0200:Intel Itanium
WORD  NumberOfSections;			//节数
DWORD   TimeDateStamp;          //时间日期戳
DWORD   PointerToSymbolTable;   //符号表指针
DWORD   NumberOfSymbols;        //符号数
WORD  SizeOfOptionalHeader;		//可选头的大小
WORD  Characteristics;			//特性
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
// size 96
typedef struct _IMAGE_OPTIONAL_HEADER {	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
//--------标准域--------//
WORD  Magic;                      // 0 魔数				0x10b:IMAGE_NT_OPTIONAL_HDR32_MAGIC		0x20b:IMAGE_NT_OPTIONAL_HDR64_MAGIC
BYTE  MajorLinkerVersion;         // 2 链接器主版本号
BYTE  MinorLinkerVersion;         // 3 链接器小版本号
DWORD SizeOfCode;                 // 4 代码大小
DWORD SizeOfInitializedData;      // 8 已初始化数据大小
DWORD SizeOfUninitializedData;    // 12 未初始化数据大小
DWORD AddressOfEntryPoint;        // 16 入口点地址
DWORD BaseOfCode;                 // 20 代码基址
DWORD BaseOfData;                 // 24 数据基址
//--------NT增加的域--------//
DWORD ImageBase;                  // 28 映像文件基址
DWORD SectionAlignment;           // 32 节对齐
DWORD FileAlignment;              // 36 文件对齐
WORD  MajorOperatingSystemVersion;// 40 操作系统主版本号
WORD  MinorOperatingSystemVersion;//	操作系统小版本号
WORD  MajorImageVersion;          // 44 映像文件主版本号
WORD  MinorImageVersion;          //	映像文件小版本号
WORD  MajorSubsystemVersion;      // 48 子系统主版本号
WORD  MinorSubsystemVersion;      //	子系统小版本号
DWORD Win32VersionValue;          // 52 保留项1
DWORD SizeOfImage;                // 56 映像文件大小
DWORD SizeOfHeaders;              // 60	所有头的大小
DWORD CheckSum;                   // 64 校验和
WORD  Subsystem;                  // 68 子系统
WORD  DllCharacteristics;         //	DLL特性
DWORD SizeOfStackReserve;         // 72 保留栈的大小
DWORD SizeOfStackCommit;          // 76 指定栈的大小
DWORD SizeOfHeapReserve;          // 80 保留堆的大小
DWORD SizeOfHeapCommit;           // 84 指定堆的大小
DWORD LoaderFlags;                // 88 加载器标志
DWORD NumberOfRvaAndSizes;        // 92 RVA的数量和大小
IMAGE_DATA_DIRECTORY DataDirectory  [IMAGE_NUMBEROF_DIRECTORY_ENTRIES];   // 96=0x60 数据目录数组 16*8 = 128 = 0x80
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;



typedef struct _IMAGE_DATA_DIRECTORY {	//https://msdn.microsoft.com/en-us/library/windows/desktop/ms680305(v=vs.85).aspx
DWORD VirtualAddress;	//虚拟地址
DWORD Size;			//大小
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_SIZEOF_SHORT_NAME              8      //定义一个常量
// size 40 = 0x28
// pos IMAGE_DOS_HEADER->e_lfanew + sizeof(IMAGE_NT_HEADERS)
// num IMAGE_FILE_HEADER->NumberOfSections
typedef struct _IMAGE_SECTION_HEADER {	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];            // 0 名字数组
	union {                                         // 8 共用体标志
		DWORD PhysicalAddress;					//物理地址
		DWORD VirtualSize;							//虚拟大小
	} Misc;
	DWORD VirtualAddress;                           // 12 虚拟地址
	DWORD SizeOfRawData;                            // 16 原始数据的大小
	DWORD PointerToRawData;                         // 20 原始数据指针
	DWORD PointerToRelocations;                     // 24 重定位指针
	DWORD PointerToLinenumbers;                     // 28 行数指针
	WORD  NumberOfRelocations;                      // 32 重定位数目
	WORD  NumberOfLinenumbers;                      //		行数数目
	DWORD Characteristics;                          // 36 特征
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;


变化的地方{
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