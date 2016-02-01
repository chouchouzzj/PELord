#include "stdafx.h"
#include "PeParser.h"
#include <algorithm>
#include <delayimp.h>

typedef ImgDelayDescr IMAGE_DELAY_IMPORT_DESCRIPTOR;
extern FILE *pFResult;

//调试时才打印该信息，必要的时候也可以打印到文件中去
inline void DebugPrint(const char *vmf, ...)
{
#ifdef _DEBUG
	va_list ap;
	va_start(ap, vmf);
	vprintf(vmf, ap);
	vfprintf(pFResult, vmf, ap);
	va_end(ap);
#endif
}

CPeParser::CPeParser()
{
	
}
CPeParser::CPeParser(const wchar_t *pFileName)
{
	assert(0 != pFileName);
	errno_t err;
	long  PESize = 0;
	long curpos;

	lpFile = NULL;	
	if ((err = _wfopen_s(&pFPE, pFileName, L"rb")) != 0)
	{
		cout << "The file '" << pFileName << "'" << "was not opened!" << endl;
	}

	curpos = ftell(pFPE);
	fseek(pFPE, 0L, SEEK_END);
	PESize = ftell(pFPE);
	fseek(pFPE, curpos, SEEK_SET);
	if (pFPE != NULL){
		lpFile = (char*)malloc(PESize);
		memset(lpFile, 0, PESize);
		fread_s(lpFile, PESize, PESize, 1, pFPE);
	}
}

CPeParser::~CPeParser()
{
	fclose(pFPE);
	delete lpFile;
}

bool CPeParser::is_pe_file()
{
	DWORD dwImageFileType = ImageFileType();
	if (dwImageFileType == 0)
		return false;
	DebugPrint("PE File Type == ");
	switch (dwImageFileType)
	{
	case IMAGE_OS2_SIGNATURE:
		DebugPrint("IMAGE_OS2_SIGNATURE\r\n"); break;
	case IMAGE_OS2_SIGNATURE_LE:
		DebugPrint("IMAGE_OS2_SIGNATURE_LE\r\n"); break;
	case IMAGE_NT_SIGNATURE:
		DebugPrint("IMAGE_NT_SIGNATURE\r\n"); break;
	case IMAGE_DOS_SIGNATURE:
		DebugPrint("IMAGE_DOS_SIGNATURE\r\n"); break;
	default:		break;
	}
	return true;
}

//0:未知的文件类型
DWORD CPeParser::ImageFileType()
{
	/* DOS文件签名先出现。IMAGE_DOS_SIGNATURE  */
	if (*(USHORT *)lpFile == IMAGE_DOS_SIGNATURE)
	{
		/* 从DOS头开始确定PE文件头的位置。 */
		if (LOWORD(*(DWORD *)NTSIGNATURE(lpFile)) == IMAGE_OS2_SIGNATURE
			|| LOWORD(*(DWORD *)NTSIGNATURE(lpFile)) == IMAGE_OS2_SIGNATURE_LE
			)
			return (DWORD)LOWORD(*(DWORD *)NTSIGNATURE(lpFile));
		else if (*(DWORD *)NTSIGNATURE(lpFile) == IMAGE_NT_SIGNATURE){
			return IMAGE_NT_SIGNATURE;
		}
		else{
			return IMAGE_DOS_SIGNATURE;
		}
	}
	else
		/* 未知的文件类型。 */
		return 0;

}
/* 解析DOS MZ部首
IMAGE_DOS_HEADER	0x40字节
typedef struct _IMAGE_DOS_HEADER {  // DOS下的.EXE文件头
USHORT e_magic;         // 魔数
USHORT e_cblp;          // 文件最后一页的字节数
USHORT e_cp;            // 文件的页数
USHORT e_crlc;          // 重定位
USHORT e_cparhdr;       // 段中头的大小
USHORT e_minalloc;      // 需要的最少额外段
USHORT e_maxalloc;      // 需要的最多额外段
USHORT e_ss;            // 初始的(相对的)SS寄存器值
USHORT e_sp;            // 初始的SP寄存器值
USHORT e_csum;          // 校验和
USHORT e_ip;            // 初始的IP寄存器值
USHORT e_cs;            // 初始的(相对的)CS寄存器值
USHORT e_lfarlc;        // 重定位表在文件中的地址
USHORT e_ovno;          // 交叠数
USHORT e_res[4];        // 保留字
USHORT e_oemid;         // OEM识别符(用于e_oeminfo成员)
USHORT e_oeminfo;       // OEM信息; e_oemid中指定的
USHORT e_res2[10];      // 保留字
LONG   e_lfanew;        // 新exe头在文件中的地址	即_IMAGE_NT_HEADERS结构的地址
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
*/
void CPeParser::ParseDosHeader()
{
	m_dosHeader = (IMAGE_DOS_HEADER *)lpFile;
	lfanew = m_dosHeader->e_lfanew;
	//打印DOS MZ部首信息
	DebugPrint("\n——————————IMAGE_DOS_HEADER Info——————————\n"\
		"IMAGE_DOS_HEADER Size : 0x%08x\toffset : 0x%08x\n"\
		"typedef struct _IMAGE_DOS_HEADER {\n"\
		"\tWORD e_magic :  0x%08x\n"\
		"\tWORD e_cblp :  0x%08x\n"\
		"\tWORD e_cp :  0x%08x\n"\
		"\tWORD e_crlc :  0x%08x\n"\
		"\tWORD e_cparhdr :  0x%08x\n"\
		"\tWORD e_minalloc :  0x%08x\n"\
		"\tWORD e_maxalloc :  0x%08x\n"\
		"\tWORD e_ss :  0x%08x\n"\
		"\tWORD e_sp :  0x%08x\n"\
		"\tWORD e_csum :  0x%08x\n"\
		"\tWORD e_ip :  0x%08x\n"\
		"\tWORD e_cs :  0x%08x\n"\
		"\tWORD e_lfarlc :  0x%08x\n"\
		"\tWORD e_ovno :  0x%08x\n"\
		"\tWORD e_res[4] :  0x%08x\n"\
		"\tWORD e_oemid :  0x%08x\n"\
		"\tWORD e_oeminfo :  0x%08x\n"\
		"\tWORD e_res2[10] :  0x%08x\n"\
		"\tLONG e_lfanew :  0x%08x\n"\
		"} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;",
		sizeof(IMAGE_DOS_HEADER),
		lfanew,
		m_dosHeader->e_magic,
		m_dosHeader->e_cblp,
		m_dosHeader->e_cp,
		m_dosHeader->e_crlc,
		m_dosHeader->e_cparhdr,
		m_dosHeader->e_minalloc,
		m_dosHeader->e_maxalloc,
		m_dosHeader->e_ss,
		m_dosHeader->e_sp,
		m_dosHeader->e_csum,
		m_dosHeader->e_ip,
		m_dosHeader->e_cs,
		m_dosHeader->e_lfarlc,
		m_dosHeader->e_ovno,
		m_dosHeader->e_res[4],
		m_dosHeader->e_oemid,
		m_dosHeader->e_oeminfo,
		m_dosHeader->e_res2[10],
		m_dosHeader->e_lfanew);
}

/*	解析PE文件头
//大小 4+20+96 = 120 = 0x78
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
//大小 96
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
// 大小 40 = 0x28
typedef struct _IMAGE_SECTION_HEADER {	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx
	BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];            // 0 名字数组
	union {                                         // 8 共用体标志
	DWORD PhysicalAddress;						//物理地址
	DWORD VirtualSize;							//虚拟大小
	} Misc;
	DWORD VirtualAddress;                           // 12 虚拟地址
	DWORD SizeOfRawData;                            // 16 原始数据的大小
	DWORD PointerToRawData;                         // 20 这是一个物理偏移地址，告诉PE加载器将物理文件偏移PointerToRawData处的数据映射入VritualAddress处
	DWORD PointerToRelocations;                     // 24 重定位指针
	DWORD PointerToLinenumbers;                     // 28 行数指针
	WORD  NumberOfRelocations;                      // 32 重定位数目
	WORD  NumberOfLinenumbers;                      //		行数数目
	DWORD Characteristics;                          // 36 特征
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
*/
void CPeParser::ParseNtHeader()
{
	m_ntHeader = (IMAGE_NT_HEADERS *)(NTSIGNATURE(lpFile));
	m_fileHeader = &(m_ntHeader->FileHeader);
	m_opHeader = &(m_ntHeader->OptionalHeader);
	DebugPrint("\n——————————IMAGE_NT_HEADERS Info——————————\n"\
		"IMAGE_NT_HEADERS Size : 0x%08x	offset : 0x%08x\n"\
		"IMAGE_FILE_HEADER Size : 0x%08x	offset : 0x%08x\n"\
		"IMAGE_OPTIONAL_HEADER Size : 0x%08x	offset : 0x%08x\n"\
		"typedef struct _IMAGE_NT_HEADERS {\n "\
		"\tDWORD Signature :  0x%08x\n"\

		"\tIMAGE_FILE_HEADER{\n"\
		"\t\tWORD Machine :  0x%08x\n"\
		"\t\tWORD NumberOfSections :  0x%08x\n"\
		"\t\tDWORD TimeDateStamp :  0x%08x\n"\
		"\t\tDWORD PointerToSymbolTable :  0x%08x\n"\
		"\t\tDWORD NumberOfSymbols :  0x%08x\n"\
		"\t\tWORD SizeOfOptionalHeader :  0x%08x\n"\
		"\t\tWORD Characteristics :  0x%08x\n"\
		"\t} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER; \n\n"\

		"\tIMAGE_OPTIONAL_HEADER{\n"\
		"\t\tWORD  Magic :  0x%08x\n"\
		"\t\tBYTE  MajorLinkerVersion :  0x%08x\n"\
		"\t\tBYTE  MinorLinkerVersion :  0x%08x\n"\
		"\t\tDWORD SizeOfCode :  0x%08x\n"\
		"\t\tDWORD SizeOfInitializedData :  0x%08x\n"\
		"\t\tDWORD SizeOfUninitializedData :  0x%08x\n"\
		"\t\tDWORD AddressOfEntryPoint :  0x%08x\n"\
		"\t\tDWORD BaseOfCode :  0x%08x\n"\
		"\t\tDWORD BaseOfData :  0x%08x\n"\
		"\t\tDWORD ImageBase :  0x%08x\n"\
		"\t\tDWORD SectionAlignment :  0x%08x\n"\
		"\t\tDWORD FileAlignment :  0x%08x\n"\
		"\t\tWORD  MajorOperatingSystemVersion :  0x%08x\n"\
		"\t\tWORD  MinorOperatingSystemVersion :  0x%08x\n"\
		"\t\tWORD  MajorImageVersion :  0x%08x\n"\
		"\t\tWORD  MinorImageVersion :  0x%08x\n"\
		"\t\tWORD  MajorSubsystemVersion :  0x%08x\n"\
		"\t\tWORD  MinorSubsystemVersion :  0x%08x\n"\
		"\t\tDWORD Win32VersionValue :  0x%08x\n"\
		"\t\tDWORD SizeOfImage :  0x%08x\n"\
		"\t\tDWORD SizeOfHeaders :  0x%08x\n"\
		"\t\tDWORD CheckSum :  0x%08x\n"\
		"\t\tWORD  Subsystem :  0x%08x\n"\
		"\t\tWORD  DllCharacteristics :  0x%08x\n"\
		"\t\tDWORD SizeOfStackReserve :  0x%08x\n"\
		"\t\tDWORD SizeOfStackCommit :  0x%08x\n"\
		"\t\tDWORD SizeOfHeapReserve :  0x%08x\n"\
		"\t\tDWORD SizeOfHeapCommit :  0x%08x\n"\
		"\t\tDWORD LoaderFlags :  0x%08x\n"\
		"\t\tDWORD NumberOfRvaAndSizes :  0x%08x\n"\
		"\t\tIMAGE_DATA_DIRECTORY DataDirectory  [IMAGE_NUMBEROF_DIRECTORY_ENTRIES];\n"\
		"\t} IMAGE_OPTIONAL_HEADER, *PtIMAGE_OPTIONAL_HEADER; \n\n"\
		"} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;\n",
		sizeof(IMAGE_NT_HEADERS),lfanew,
		sizeof(IMAGE_FILE_HEADER), lfanew + sizeof(m_ntHeader->Signature),
		sizeof(IMAGE_OPTIONAL_HEADER), lfanew + sizeof(m_ntHeader->Signature) + sizeof(IMAGE_FILE_HEADER),
		m_ntHeader->Signature,

		m_fileHeader->Machine,
		m_fileHeader->NumberOfSections,
		m_fileHeader->TimeDateStamp,
		m_fileHeader->PointerToSymbolTable,
		m_fileHeader->NumberOfSymbols,
		m_fileHeader->SizeOfOptionalHeader,
		m_fileHeader->Characteristics,

		m_opHeader->Magic,
		m_opHeader->MajorLinkerVersion,
		m_opHeader->MinorLinkerVersion,
		m_opHeader->SizeOfCode,
		m_opHeader->SizeOfInitializedData,
		m_opHeader->SizeOfUninitializedData,
		m_opHeader->AddressOfEntryPoint,
		m_opHeader->BaseOfCode,
		m_opHeader->BaseOfData,
		m_opHeader->ImageBase,
		m_opHeader->SectionAlignment,
		m_opHeader->FileAlignment,
		m_opHeader->MajorOperatingSystemVersion,
		m_opHeader->MinorOperatingSystemVersion,
		m_opHeader->MajorImageVersion,
		m_opHeader->MinorImageVersion,
		m_opHeader->MajorSubsystemVersion,
		m_opHeader->MinorSubsystemVersion,
		m_opHeader->Win32VersionValue,
		m_opHeader->SizeOfImage,
		m_opHeader->SizeOfHeaders,
		m_opHeader->CheckSum,
		m_opHeader->Subsystem,
		m_opHeader->DllCharacteristics,
		m_opHeader->SizeOfStackReserve,
		m_opHeader->SizeOfStackCommit,
		m_opHeader->SizeOfHeapReserve,
		m_opHeader->SizeOfHeapCommit,
		m_opHeader->LoaderFlags,
		m_opHeader->NumberOfRvaAndSizes
		);
	//m_opHeader->DataDirectory 一共有16(IMAGE_NUMBEROF_DIRECTORY_ENTRIES)个。目前再用的有11个，
	//其中包含导入表，导出表等，在其他函数中单独分析；
	m_secHeader = (IMAGE_SECTION_HEADER*)(lpFile+lfanew+sizeof(IMAGE_NT_HEADERS));
	for (int i = 0; i < m_fileHeader->NumberOfSections; i++,m_secHeader += 1)
	{
		//m_secHeader = (IMAGE_SECTION_HEADER*)(lpFile + lfanew + sizeof(IMAGE_NT_HEADERS)+i*sizeof(IMAGE_SECTION_HEADER));
		m_vSectionVirtualAddress.push_back(m_secHeader->VirtualAddress);
		m_vSectionVirtualSize.push_back(m_secHeader->Misc.VirtualSize);//实际的大小
		//如果有空隙，加上空隙
		if (m_vSectionVirtualSize[i] % m_opHeader->SectionAlignment != 0)// 节大小 % 节对齐
		{
			UINT interspace = m_opHeader->SectionAlignment - m_vSectionVirtualSize[i] % m_opHeader->SectionAlignment;//空隙大小
			m_vSectionVirtualSize[i] += interspace;
		}
		m_vSectionRawAddress.push_back(m_secHeader->PointerToRawData);
		m_vSectionRawSize.push_back(m_secHeader->SizeOfRawData);
		DebugPrint("\n——————————IMAGE_SECTION_HEADER Info——————————\n"\
			"IMAGE_SECTION_HEADER Size : 0x%08x\toffset : 0x%08x\n"\
			"typedef struct _IMAGE_SECTION_HEADER {\n"\
			"\tBYTE  Name :  %s\n"\
			"\tDWORD VirtualSize :  0x%08x \t VirtualSizeAlignment : 0x%08x\n"\
			"\tDWORD VirtualAddress :  0x%08x\n"\
			"\tDWORD SizeOfRawData :  0x%08x\n"\
			"\tDWORD PointerToRawData :  0x%08x\n"\
			"\tDWORD PointerToRelocations :  0x%08x\n"\
			"\tDWORD PointerToLinenumbers :  0x%08x\n"\
			"\tWORD  NumberOfRelocations :  0x%08x\n"\
			"\tWORD  NumberOfLinenumbers :  0x%08x\n"\
			"\tDWORD Characteristics :  0x%08x\n"\
			"} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;",
			sizeof(IMAGE_SECTION_HEADER),
			lfanew + sizeof(IMAGE_NT_HEADERS)+i*sizeof(IMAGE_SECTION_HEADER),
			m_secHeader->Name,
			m_secHeader->Misc.VirtualSize,m_vSectionVirtualSize[i],
			m_secHeader->VirtualAddress, 
			m_secHeader->SizeOfRawData,
			m_secHeader->PointerToRawData,
			m_secHeader->PointerToRelocations,
			m_secHeader->PointerToLinenumbers,
			m_secHeader->NumberOfRelocations,
			m_secHeader->NumberOfLinenumbers,
			m_secHeader->Characteristics
			);
	}
}

// 虚拟地址转换为物理地址
// http://blog.csdn.net/sryan/article/details/7950950
UINT CPeParser::VAToRawAddr(UINT virtualAddr)
{
	assert(virtualAddr);
	if (m_fileHeader->NumberOfSections > 0 && virtualAddr < m_vSectionVirtualAddress[0])
	{
		return virtualAddr;
	}
	// 枚举所有的节表	前面解析过，所以就直接用 m_vSectionVirtualAddress[i]
	// if ( m_secHeader->VirtualAddress < 虚拟地址 < m_secHeader->VirtualAddress + m_opHeader->SectionAlignment )
	// virtualAddr - m_secHeader->VirtualAddress + m_secHeader->PointerToRawData;
	for (int i = 0; i < m_fileHeader->NumberOfSections; i++)
	{
		if (virtualAddr >= m_vSectionVirtualAddress[i] && virtualAddr < m_vSectionVirtualAddress[i] + m_vSectionVirtualSize[i])
		{
			return virtualAddr - m_vSectionVirtualAddress[i] + m_vSectionRawAddress[i];
		}
	}
	return -1;
}
//查找是否在m_vExportFunc中
bool CPeParser::findIsFunc(UINT rva, UINT ordinal)
{
	assert(ordinal >= 0);
	assert(rva >= 0);
	for (int i = 0; i < m_vExportFunc.size(); i++)
	{
		if (m_vExportFunc.at(i).ordinal == ordinal)
		{
			m_vExportFunc.at(i).rva = rva;
			return true;
		}
	}
	FUNCEXPINFO funcInfo = { 0 };
	funcInfo.rva = rva;
	funcInfo.ordinal = ordinal;
	m_vExportFunc.push_back(funcInfo);
	return true;
}

//打印输出表信息
void CPeParser::printExportTable(FUNCEXPINFO funcInfo)
{
	DebugPrint("0x%08x\t0x%08x\t%s\n", funcInfo.rva, funcInfo.ordinal, funcInfo.name.c_str());
}

//打印输入表信息
void CPeParser::printImportTable(FUNCIMPINFO funcImpInfo)
{
	DebugPrint("%s\t0x%08x\t%s\n", funcImpInfo.dllName.c_str(), funcImpInfo.ordinal, funcImpInfo.funcName.c_str());
}

//解析输出表
void CPeParser::ParseExportTable()
{
	m_dataDir = &(m_opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	if (m_dataDir->Size != 0)
	{
		UINT exportStartAddr = VAToRawAddr(m_dataDir->VirtualAddress);
		m_exportDir = (IMAGE_EXPORT_DIRECTORY *)(lpFile + exportStartAddr);
		UINT nameStartAddr = VAToRawAddr(m_exportDir->AddressOfNames);
		for (int i = 0; i < m_exportDir->NumberOfNames; i++)
		{
			FUNCEXPINFO funcInfo = { 0 };
			char FuncName[40] = { 0 };
			assert(m_exportDir->AddressOfNames != 0);
			//ENT
			UINT nameRVA = m_exportDir->AddressOfNames + i * sizeof(DWORD);
			UINT nameFileAddr = VAToRawAddr(nameRVA);
			UINT nameRVA2;
			UINT nameFileAddr2;
			//fseek(pFPE, nameFileAddr, 0);
			//fread_s(&nameRVA2, sizeof(nameRVA2), sizeof(UINT), 1, pFPE);
			memcpy(&nameRVA2, lpFile + nameFileAddr, sizeof(UINT));

			nameFileAddr2 = VAToRawAddr(nameRVA2);
			//fseek(pFPE, nameFileAddr2, 0);
			//fread_s(&FuncName, sizeof(FuncName), 40, 1, pFPE);
			memcpy(FuncName, lpFile + nameFileAddr2, sizeof(FuncName));
			FuncName[39] = 0x00;
			funcInfo.name.assign(FuncName);

			//ENT对应的序号表
			UINT ordinalRVA = m_exportDir->AddressOfNameOrdinals + i * sizeof(WORD);
			UINT ordinalFileAddr = VAToRawAddr(ordinalRVA);
			short int ordinal;
			//fseek(pFPE, ordinalFileAddr, 0);
			//fread_s(&ordinal, sizeof(ordinal), sizeof(WORD), 1, pFPE);
			memcpy(&ordinal, lpFile + ordinalFileAddr, sizeof(short int));
			//ordinal = (int)(lpFile + ordinalFileAddr);
			funcInfo.ordinal = ordinal;

			m_vExportFunc.push_back(funcInfo);

		}
		//查找EAT，并找出以序号输出的函数
		for (int i = 0; i < m_exportDir->NumberOfFunctions; i++)
		{
			UINT funcAddr = m_exportDir->AddressOfFunctions + i*sizeof(DWORD);
			UINT funcFileAddr = VAToRawAddr(funcAddr);
			UINT rva;
			UINT ordinal = m_exportDir->Base + i;//当前输出函数的序号
			//fseek(pFPE, funcFileAddr, 0);
			//fread_s(&rva, sizeof(rva), sizeof(DWORD), 1, pFPE);
			memcpy(&rva, lpFile + funcFileAddr, sizeof(UINT));
			//如果不是名称，那么它一定是以序号输出的
			findIsFunc(rva, ordinal);
		}
		//打印输出表信息
		DebugPrint("\n\n\n——————————Export Table——————————\n");
		for_each(m_vExportFunc.begin(), m_vExportFunc.end(), CPeParser::printExportTable);
	}
}

/*	解析输入表
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
union {
DWORD   Characteristics;            // 0 for terminating null import descriptor
DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
} DUMMYUNIONNAME;
DWORD   TimeDateStamp;                  // 0 if not bound,
// -1 if bound, and real date\time stamp
//     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
// O.W. date/time stamp of DLL bound to (Old BIND)
DWORD   ForwarderChain;                 // -1 if no forwarders
DWORD   Name;
DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;
typedef struct _IMAGE_DATA_DIRECTORY {
DWORD VirtualAddress;	//虚拟地址
DWORD Size;				//大小
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
*/
void CPeParser::ParseImportTable()
{
	IMAGE_THUNK_DATA32* thunkData;
	IMAGE_IMPORT_DESCRIPTOR* importTable;
	char dllName[56] = { '0' };
	m_dataDir = &(m_opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]);
	if (m_dataDir->VirtualAddress)
	{
		UINT curFileAddr = VAToRawAddr(m_dataDir->VirtualAddress);
		importTable = (IMAGE_IMPORT_DESCRIPTOR *)(lpFile + curFileAddr);
		m_NumImportDll = 0;
		while (importTable->FirstThunk)
		{
			m_NumImportDll++;
			//获取导入库的名称
			UINT dllNameFileAddr = VAToRawAddr(importTable->Name);
			//fseek(pFPE, dllNameFileAddr, 0);
			//fread_s(&dllName, sizeof(dllName), sizeof(dllName), 1, pFPE);
			memcpy(dllName, lpFile + dllNameFileAddr, sizeof(dllName));

			UINT originalRawAddr = VAToRawAddr(importTable->OriginalFirstThunk);
			thunkData = (IMAGE_THUNK_DATA32 *)(lpFile + originalRawAddr);

			unsigned int k = 0;
			while (thunkData->u1.AddressOfData)
			{
				FUNCIMPINFO funcImpInfo;
				funcImpInfo.dllName.assign(dllName);
				if (thunkData->u1.Ordinal & 0x80000000) //如果最高位为1，那么函数是以序号导入的
				{
					funcImpInfo.ordinal = thunkData->u1.Ordinal & 0x7fffffff;
				}
				else //如果是名字输出，那么该地址是指向IMAGE_IMPORT_BY_NAME的RVA
				{
					IMAGE_IMPORT_BY_NAME importByName;
					char funcName[50] = { '0' };
					UINT nameFuncAddr = VAToRawAddr(thunkData->u1.AddressOfData);
					//fseek(pFPE, nameFuncAddr, 0);
					//fread_s(&importByName, sizeof(importByName), sizeof(IMAGE_IMPORT_BY_NAME), 1, pFPE);
					memcpy(&importByName, lpFile + nameFuncAddr, sizeof(IMAGE_IMPORT_BY_NAME));

					funcImpInfo.ordinal = importByName.Hint;
					//fseek(pFPE, nameFuncAddr + 2, 0);
					//fread_s(funcName, sizeof(funcName), sizeof(funcName), 1, pFPE);
					memcpy(funcName, lpFile + nameFuncAddr + 2, sizeof(funcName));
					funcName[49] = '\0';
					funcImpInfo.funcName.assign(funcName);
				}
				m_vImportFunc.push_back(funcImpInfo);
				//fseek(pFPE, originalRawAddr + (++k) * sizeof(IMAGE_THUNK_DATA), 0);
				//fread_s(&thunkData, sizeof(thunkData), sizeof(IMAGE_THUNK_DATA), 1, pFPE);
				memcpy(thunkData, lpFile + originalRawAddr + (++k) * sizeof(IMAGE_THUNK_DATA), sizeof(IMAGE_THUNK_DATA));
			}
			//fseek(pFPE, curFileAddr + m_NumImportDll * sizeof(IMAGE_IMPORT_DESCRIPTOR), 0);
			//fread_s(&importTable, sizeof(importTable), sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, pFPE);
			importTable = (IMAGE_IMPORT_DESCRIPTOR *)(lpFile + curFileAddr + m_NumImportDll * sizeof(IMAGE_IMPORT_DESCRIPTOR));
		}
		//打印输入表信息
		DebugPrint("\n\n\n——————————Import Table——————————\n");
		for_each(m_vImportFunc.begin(), m_vImportFunc.end(), CPeParser::printImportTable);
	}
}

//解析延迟输入表
void CPeParser::ParseDelayImportTable()
{
	IMAGE_THUNK_DATA32* thunkData;
	IMAGE_DELAY_IMPORT_DESCRIPTOR* importTable;
	m_dataDir = &(m_opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT]);
	char dllName[56] = { '0' };
	if (m_dataDir->VirtualAddress > 0)
	{
		UINT curFileAddr = VAToRawAddr(m_dataDir->VirtualAddress);
		importTable = (IMAGE_DELAY_IMPORT_DESCRIPTOR *)(lpFile + curFileAddr);
		m_NumImportDll = 0;
		while (importTable->rvaIAT)
		{
			m_NumImportDll++;
			//获取导入库的名称
			UINT dllNameFileAddr = VAToRawAddr(importTable->rvaDLLName);
			//fseek(pFPE, dllNameFileAddr, 0);
			//fread_s(&dllName, sizeof(dllName), sizeof(dllName), 1, pFPE);
			memcpy(dllName, lpFile + dllNameFileAddr, sizeof(dllName));

			UINT originalRawAddr = VAToRawAddr(importTable->rvaINT);
			thunkData = (IMAGE_THUNK_DATA32 *)(lpFile + originalRawAddr);

			unsigned int k = 0;
			while (thunkData->u1.AddressOfData)
			{
				FUNCIMPINFO funcImpInfo;
				funcImpInfo.dllName.assign(dllName);
				if (thunkData->u1.Ordinal & 0x80000000) //如果最高位为1，那么函数是以序号导入的
				{
					funcImpInfo.ordinal = thunkData->u1.Ordinal & 0x7fffffff;
				}
				else //如果是名字输出，那么该地址是指向IMAGE_IMPORT_BY_NAME的RVA
				{
					IMAGE_IMPORT_BY_NAME importByName;
					char funcName[50] = { '0' };
					UINT nameFuncAddr = VAToRawAddr(thunkData->u1.AddressOfData);
					//fseek(pFPE, nameFuncAddr, 0);
					//fread_s(&importByName, sizeof(importByName), sizeof(IMAGE_IMPORT_BY_NAME), 1, pFPE);
					memcpy(&importByName, lpFile + nameFuncAddr, sizeof(IMAGE_IMPORT_BY_NAME));

					funcImpInfo.ordinal = importByName.Hint;
					//fseek(pFPE, nameFuncAddr + 2, 0);
					//fread_s(funcName, sizeof(funcName), sizeof(funcName), 1, pFPE);
					memcpy(funcName, lpFile + nameFuncAddr, sizeof(funcName));
					funcImpInfo.funcName.assign(funcName);
				}
				m_vDelayImportFunc.push_back(funcImpInfo);

				//fseek(pFPE, originalRawAddr + (++k) * sizeof(IMAGE_THUNK_DATA), 0);
				//fread_s(&thunkData, sizeof(thunkData), sizeof(IMAGE_THUNK_DATA), 1, pFPE);
				memcpy(thunkData, lpFile + originalRawAddr + (++k) * sizeof(IMAGE_THUNK_DATA), sizeof(IMAGE_THUNK_DATA));
			}

			//fseek(pFPE, curFileAddr + m_NumImportDll * sizeof(IMAGE_DELAY_IMPORT_DESCRIPTOR), 0);
			//fread_s(&importTable, sizeof(importTable), sizeof(IMAGE_DELAY_IMPORT_DESCRIPTOR), 1, pFPE);
			importTable = (IMAGE_DELAY_IMPORT_DESCRIPTOR *)(lpFile + curFileAddr + m_NumImportDll * sizeof(IMAGE_DELAY_IMPORT_DESCRIPTOR));
		}
		//打印输入表信息
		DebugPrint("\n\n\n——————————Delay Import Table——————————\n");
		for_each(m_vDelayImportFunc.begin(), m_vDelayImportFunc.end(), printImportTable);
	}
}//24530-650

//解析绑定输入表
void CPeParser::ParseBoundImportTable()
{
	IMAGE_BOUND_IMPORT_DESCRIPTOR* boundImportTable;
	m_dataDir = &(m_opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT]);
	char dllName[56] = { '0' };
	if (m_dataDir->VirtualAddress)
	{
		DebugPrint("\n\n\n——————————BOUND IMPORT TABLE——————————\n");
		UINT curFileAddr = VAToRawAddr(m_dataDir->VirtualAddress);
		//fseek(pFPE, curFileAddr, 0);
		//fread_s(&boundImportTable, sizeof(boundImportTable), sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 1, pFPE);
		boundImportTable = (IMAGE_BOUND_IMPORT_DESCRIPTOR *)(lpFile + curFileAddr);

		UINT k = 0;
		while (boundImportTable->OffsetModuleName)
		{
			//fseek(pFPE, curFileAddr + boundImportTable->OffsetModuleName, 0);
			//fread_s(&dllName, sizeof(dllName), 56, 1, pFPE);
			memcpy(dllName, lpFile + curFileAddr + boundImportTable->OffsetModuleName, sizeof(dllName));
			DebugPrint("%s\t", dllName);
			for (int i = 0; i < boundImportTable->NumberOfModuleForwarderRefs; i++)
			{
				//fseek(pFPE, curFileAddr + (++k) * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 0);
				//fread_s(&boundImportTable, sizeof(boundImportTable), sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 1, pFPE);
				boundImportTable = (IMAGE_BOUND_IMPORT_DESCRIPTOR *)(lpFile + curFileAddr + (++k) * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
				//fseek(pFPE, curFileAddr + boundImportTable->OffsetModuleName, 0);
				//fread_s(&dllName, sizeof(dllName), 56, 1, pFPE);
				memcpy(dllName, lpFile + curFileAddr + boundImportTable->OffsetModuleName, sizeof(dllName));
				DebugPrint("%s\t", dllName);
			}
			//fseek(pFPE, curFileAddr + (++k) * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 0);
			//fread_s(&boundImportTable, sizeof(boundImportTable), sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 1, pFPE);
			boundImportTable = (IMAGE_BOUND_IMPORT_DESCRIPTOR *)(lpFile + curFileAddr + (++k) * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR));
		}
	}
}

//解析DEBUG目录表
void CPeParser::ParseDebugTable()
{
	IMAGE_DATA_DIRECTORY* debugDir;
	IMAGE_DEBUG_DIRECTORY* debugTable;
	char pdbName[128];
	debugDir = &(m_opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG]);
	if (debugDir->VirtualAddress)
	{
		UINT curFileAddr = VAToRawAddr(debugDir->VirtualAddress);
		//fseek(pFPE, curFileAddr, 0);
		//fread_s(&debugTable, sizeof(debugTable), sizeof(IMAGE_DEBUG_DIRECTORY), 1, pFPE);
		debugTable = (IMAGE_DEBUG_DIRECTORY *)(lpFile + curFileAddr);
		if (IMAGE_DEBUG_TYPE_CODEVIEW == debugTable->Type)
		{
			//fseek(pFPE, debugTable->PointerToRawData + 6, 0);
			//fread_s(&pdbName, sizeof(pdbName), 128, 1, pFPE);
			memcpy(pdbName, lpFile + debugTable->PointerToRawData + 6, sizeof(pdbName));
			DebugPrint("\n\n\n——————————Debug Table——————————\n"\
				"The path of PDB : %s", pdbName);
		}
	}
}

//解析RESOURSE目录表
void CPeParser::ParseResouceTable()
{
	IMAGE_DATA_DIRECTORY* resDir;
	IMAGE_RESOURCE_DIRECTORY* resTable;
	IMAGE_RESOURCE_DIRECTORY_ENTRY* resEntryTable;
	resDir = &(m_opHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE]);
	if (resDir->VirtualAddress)
	{
		DebugPrint("\n\n\n——————————RESOURCE TABLE——————————\n");
		UINT curFileAddr = VAToRawAddr(resDir->VirtualAddress);
		//fseek(pFPE, curFileAddr, 0);
		//fread_s(&resTable, sizeof(resTable), sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pFPE);
		resTable = (IMAGE_RESOURCE_DIRECTORY *)(lpFile + curFileAddr);
		UINT numEntry = resTable->NumberOfIdEntries + resTable->NumberOfNamedEntries;
		DebugPrint("numEntry1:%d\n", numEntry);
		//第一层目录	----->	定义的是资源类型
		for (int i = 0; i < numEntry; i++)
		{
			//fseek(pFPE, curFileAddr + sizeof(IMAGE_RESOURCE_DIRECTORY)+i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 0);
			//fread_s(&resEntryTable, sizeof(resEntryTable), sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pFPE);
			resEntryTable = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)
				(lpFile + curFileAddr
				+ sizeof(IMAGE_RESOURCE_DIRECTORY)
				+i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
			//资源类型的ID
			//01 Cursor				08 Font（字体）         
			//02 Bitmap				09 Accelerators(加速键)  
			//03 Icon					0A Unformatted(未格式资源)      
			//04 Menu					0B MessageTable(消息表)
			//05 Dialog				0C Group Cursor(光标组)
			//06 String					0E Group Icon(图标组)
			//07 Font Directory		10 Versoin Information(版本信息）
			DebugPrint("\nresType%d : 0x%x\n", i, resEntryTable->Id);
			//是否低位数据指向下一层目录块的起始地址
			if (resEntryTable->DataIsDirectory)
			{
				IMAGE_RESOURCE_DIRECTORY* resTable2;
				//fseek(pFPE, curFileAddr + resEntryTable->OffsetToDirectory, 0);
				//fread_s(&resTable2, sizeof(resTable2), sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pFPE);
				resTable2 = (IMAGE_RESOURCE_DIRECTORY *)(lpFile + curFileAddr + resEntryTable->OffsetToDirectory);

				UINT numEntry2 = resTable2->NumberOfIdEntries + resTable2->NumberOfNamedEntries;
				DebugPrint("numEntry2:%d\n", numEntry2);
				//第二层目录	----->	定义的是资源的名称
				for (int j = 0; j < numEntry2; j++)
				{
					IMAGE_RESOURCE_DIRECTORY_ENTRY* resEntryTable2;
					//fseek(pFPE, curFileAddr + resEntryTable->OffsetToDirectory
					//	+ sizeof(IMAGE_RESOURCE_DIRECTORY)+j * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 0);
					//fread_s(&resEntryTable2, sizeof(resEntryTable2), sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pFPE);
					resEntryTable2 = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)
						(lpFile + curFileAddr
						+ resEntryTable->OffsetToDirectory
						+ sizeof(IMAGE_RESOURCE_DIRECTORY)
						+j * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
					//第二层的NAME字段是目录项的名称字符串指针，否则用ID号表示
					if (resEntryTable2->NameIsString)
					{
						IMAGE_RESOURCE_DIR_STRING_U* dirStr;
						//fseek(pFPE, curFileAddr + resEntryTable2->NameOffset, 0);
						//fread_s(&dirStr, sizeof(resDir), sizeof(IMAGE_RESOURCE_DIR_STRING_U), 1, pFPE);
						dirStr = (IMAGE_RESOURCE_DIR_STRING_U *)(lpFile + curFileAddr + resEntryTable2->NameOffset);
						DebugPrint("Name:%s\n", dirStr->NameString);
					}
					else
					{
						DebugPrint("ID:%d\n", resEntryTable2->NameOffset);
					}
					//最高位为1时，指向下一层目录块的起始地址，否则指针指向IMAGE_RESOURCE_DATA_ENTRY
					if (resEntryTable2->DataIsDirectory)
					{
						IMAGE_RESOURCE_DIRECTORY* resTable3;
						//fseek(pFPE, curFileAddr + resEntryTable2->OffsetToDirectory, 0);
						//fread_s(&resTable3, sizeof(resTable3), sizeof(IMAGE_RESOURCE_DIRECTORY), 1, pFPE);
						resTable3 = (IMAGE_RESOURCE_DIRECTORY *)(lpFile + curFileAddr + resEntryTable2->OffsetToDirectory);
						UINT numEntry3 = resTable3->NumberOfIdEntries + resTable3->NumberOfNamedEntries;
						DebugPrint("numEntry3:%d\n", numEntry3);
						//第三层
						//定义的是代码页编号
						for (int k = 0; k < numEntry3; k++)
						{
							IMAGE_RESOURCE_DIRECTORY_ENTRY* resEntryTable3;
							//fseek(pFPE, curFileAddr + resEntryTable2->OffsetToDirectory
							//	+ sizeof(IMAGE_RESOURCE_DIRECTORY)+k * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 0);
							//fread_s(&resEntryTable3, sizeof(resEntryTable3), sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, pFPE);
							resEntryTable3 = (IMAGE_RESOURCE_DIRECTORY_ENTRY *)
								(lpFile + curFileAddr + resEntryTable2->OffsetToDirectory
								+ sizeof(IMAGE_RESOURCE_DIRECTORY)+k * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY));
							if (!resEntryTable3->DataIsDirectory)
							{
								IMAGE_RESOURCE_DATA_ENTRY* resDirEntry;
								//fseek(pFPE, curFileAddr + resEntryTable3->OffsetToDirectory, 0);
								//fread_s(&resDirEntry, sizeof(resDirEntry), sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, pFPE);
								resDirEntry = (IMAGE_RESOURCE_DATA_ENTRY *)(lpFile + curFileAddr + resEntryTable3->OffsetToDirectory);
								//DebugPrint("Rva:0x%x\t", resDirEntry->OffsetToData + m_PeInfo->imageBase);
								//DebugPrint("size:%d\n", resDirEntry->Size);
							}
							else
							{
								_asm int 3
							}
						}
					}
					else
					{
						IMAGE_RESOURCE_DATA_ENTRY* resDirEntry;
						fseek(pFPE, curFileAddr + resEntryTable2->OffsetToDirectory, 0);
						fread_s(&resDirEntry, sizeof(resDirEntry), sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, pFPE);
						resDirEntry = (IMAGE_RESOURCE_DATA_ENTRY *)(lpFile + curFileAddr + resEntryTable2->OffsetToDirectory);
						//DebugPrint("Rva:0x%x\t", resDirEntry->OffsetToData + m_PeInfo->imageBase);
						//DebugPrint("size:%d\n", resDirEntry->Size);
					}
				}
			}
		}
	}
}