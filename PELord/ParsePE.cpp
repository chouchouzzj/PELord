#include "StdAfx.h"
#include "ParsePE.h"
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

CParsePE::CParsePE(const wchar_t *pFileName)
{
	assert(0 != pFileName);
	m_PeInfo.imageBase = 0;
	errno_t err;
	if ((err = _wfopen_s(&fp, pFileName, L"r")) != 0)
	{
		cout << "The file '" << pFileName << "'" << "was not opened!" << endl;
	}
	if (!is_pe_file())
	{
		cout << "is not pe file!" << endl;
	}

}
CParsePE::~CParsePE(void)
{
	if (fp != 0)
	{
		fclose(fp);
	}
}
//判断是否是PE文件格式，两个地方：1.DOS块标识e_magic；2.PE文件头标识signature
bool CParsePE::is_pe_file()
{
  WORD dosMagic; //DOS MZ Header的标识符
  DWORD peMagic; //PE文件头的标识符
  long peStaAddr;
  fseek(fp, 0, 0);
  fread_s(&dosMagic, sizeof(dosMagic), sizeof(WORD), 1, fp);
  fseek(fp, 60, 0); //IMAGE_DOS_HEADER->e_lfanew 新exe头在文件中的地址
  fread_s(&peStaAddr, sizeof(peStaAddr), sizeof(long), 1, fp);
  fseek(fp, peStaAddr, 0);
  fread_s(&peMagic, sizeof(peMagic), sizeof(DWORD), 1, fp);

  if (IMAGE_DOS_SIGNATURE != dosMagic || IMAGE_NT_SIGNATURE != peMagic)	// 'MZ' 'PE'
  {
    return false;
  }
  return true;
}

DWORD CParsePE::ImageFileType(LPVOID lpFile)
{
	/* DOS文件签名先出现。 */
	if (*(USHORT *)lpFile == IMAGE_DOS_SIGNATURE)
	{
		/* 从DOS头开始确定PE文件头的位置。 */
		if (LOWORD(*(DWORD *)NTSIGNATURE(lpFile)) == IMAGE_OS2_SIGNATURE
			|| LOWORD(*(DWORD *)NTSIGNATURE(lpFile)) == IMAGE_OS2_SIGNATURE_LE
			)
			return (DWORD)LOWORD(*(DWORD *)NTSIGNATURE(lpFile));
		else if (*(DWORD *)NTSIGNATURE(lpFile) == IMAGE_NT_SIGNATURE)
			return IMAGE_NT_SIGNATURE;
		else
			return IMAGE_DOS_SIGNATURE;
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
void CParsePE::ParseDosHeader()
{
  LONG lfanew;
  fseek(fp, 0, 0);
  fread_s(&m_dosHeader, sizeof(m_dosHeader), sizeof(IMAGE_DOS_HEADER), 1, fp);
  fseek(fp, 60, 0); //IMAGE_DOS_HEADER->e_lfanew 新exe头在文件中的地址
  fread_s(&lfanew, sizeof(lfanew), sizeof(LONG), 1, fp);// 新exe头在文件中的地址
  m_PeInfo.pNtHeader = m_PeInfo.imageBase + lfanew;
  m_PeInfo.dosRVA = m_PeInfo.imageBase;
  m_PeInfo.dosSize = m_PeInfo.pNtHeader - m_PeInfo.imageBase;
  //打印DOS MZ部首信息
  DebugPrint("\n——————————Dos Header Info——————————\n"\
		"IMAGE_DOS_HEADER Size : 0x%08x\n"\
		"lfanew : 0x%08x\n"\
		"dos RVA : 0x%08x\n"\
		"dos size : 0x%08x\n",
		sizeof(IMAGE_DOS_HEADER),
		lfanew,
		m_PeInfo.dosRVA, 
		m_PeInfo.dosSize);
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
		DWORD PointerToRawData;                         // 20 原始数据指针
		DWORD PointerToRelocations;                     // 24 重定位指针
		DWORD PointerToLinenumbers;                     // 28 行数指针
		WORD  NumberOfRelocations;                      // 32 重定位数目
		WORD  NumberOfLinenumbers;                      //		行数数目
		DWORD Characteristics;                          // 36 特征
	} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

*/
void CParsePE::ParseNtHeader()
{
  fseek(fp, m_PeInfo.pNtHeader, 0);//IMAGE_DOS_HEADER->e_lfanew 新exe头在文件中的地址
  fread_s(&m_ntHeader, sizeof(m_ntHeader), sizeof(IMAGE_NT_HEADERS), 1, fp);
  m_fileHeader = m_ntHeader.FileHeader;
  m_opHeader = m_ntHeader.OptionalHeader;
  //映象文件头
  m_PeInfo.bDLL = m_fileHeader.Characteristics & IMAGE_FILE_DLL != 0 ? true : false;
  m_PeInfo.numSections = m_fileHeader.NumberOfSections;
  //可选映象头
  m_PeInfo.sectionAlign = m_opHeader.SectionAlignment;
  m_PeInfo.fileAlign = m_opHeader.FileAlignment;
  m_PeInfo.entryPoint = m_opHeader.AddressOfEntryPoint;
  m_PeInfo.imageBase = m_opHeader.ImageBase;

  int curSecOffset = m_PeInfo.pNtHeader + sizeof(IMAGE_NT_HEADERS); // e_lfanew + 0x78
  IMAGE_SECTION_HEADER sectionHeader;

  DebugPrint("\n——————————sections Info——————————\n");
  for (int i = 0; i < m_PeInfo.numSections; i++)
  {
    fseek(fp, curSecOffset + i * sizeof(IMAGE_SECTION_HEADER), 0);
    fread_s(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER), 1, fp);
    m_vSectionVirtualAddress.push_back(sectionHeader.VirtualAddress);
    m_vSectionVirtualSize.push_back(sectionHeader.Misc.VirtualSize);//实际的大小

    //如果有空隙，加上空隙
    if (m_vSectionVirtualSize[i]%m_PeInfo.sectionAlign != 0)
    {
      UINT interspace = m_PeInfo.sectionAlign - m_vSectionVirtualSize[i]%m_PeInfo.sectionAlign;
      m_vSectionVirtualSize[i] += interspace;
    }
    m_vSectionRawAddress.push_back(sectionHeader.PointerToRawData);
    m_vSectionRawSize.push_back(sectionHeader.SizeOfRawData);

    DebugPrint("section name : %s\n"\
      "VirtualAddress : 0x%08x\n"\
      "VirtualSize : 0x%08x\n"\
      "RawAddress : 0x%08x\n"\
      "RwaSize : 0x%08x\n",
      sectionHeader.Name, sectionHeader.VirtualAddress, m_vSectionVirtualSize[i], m_vSectionRawAddress[i], m_vSectionRawSize[i]);
  }
  DebugPrint("\n——————————Header Info——————————\n"\
    "imageBase : 0x%08x\n"\
    "entryPoint : 0x%08x\n"\
    "sectionAlignment : 0x%08x\n"\
    "fileAlignment : 0x%08x\n"\
    "numSections : 0x%08x\n",
    m_PeInfo.imageBase, m_PeInfo.entryPoint, m_PeInfo.sectionAlign, m_PeInfo.fileAlign, m_vSectionRawAddress.size());

  ParseExportTable();

}

//虚拟地址转换为物理地址
UINT CParsePE::VAToRawAddr( UINT virtualAddr )
{
  assert(virtualAddr);
  if (m_PeInfo.numSections > 0 && virtualAddr < m_vSectionVirtualAddress[0])
  {
    return virtualAddr;
  }

  for (int i = 0; i < m_PeInfo.numSections; i++)
  {
    if (virtualAddr >= m_vSectionVirtualAddress[i] && virtualAddr < m_vSectionVirtualAddress[i] + m_vSectionVirtualSize[i])
    {
      return virtualAddr - (m_vSectionVirtualAddress[i] - m_vSectionRawAddress[i]);
    }
  }
  return -1;
}
//查找是否在m_vExportFunc中
bool CParsePE::findIsFunc(UINT rva, UINT ordinal)
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
  FUNCEXPINFO funcInfo = {0};
  funcInfo.rva = rva;
  funcInfo.ordinal = ordinal;
  m_vExportFunc.push_back(funcInfo);
  return true;
}

//打印输出表信息
void CParsePE::printExportTable(FUNCEXPINFO funcInfo)
{
  DebugPrint("0x%08x\t0x%08x\t%s\n", funcInfo.rva, funcInfo.ordinal, funcInfo.name.c_str());
}

//打印输入表信息
void CParsePE::printImportTable(FUNCIMPINFO funcImpInfo)
{
  DebugPrint("%s\t0x%08x\t%s\n", funcImpInfo.dllName.c_str(), funcImpInfo.ordinal, funcImpInfo.funcName.c_str());
}

//解析输出表
void CParsePE::ParseExportTable()
{
  IMAGE_DATA_DIRECTORY dataDir;
  dataDir = m_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
  if (dataDir.Size != 0)
  {
    UINT exportStartAddr = VAToRawAddr(dataDir.VirtualAddress);
    fseek(fp, exportStartAddr, 0);
    fread_s(&m_exportDir, sizeof(m_exportDir), sizeof(IMAGE_EXPORT_DIRECTORY), 1, fp);
    UINT nameStartAddr = VAToRawAddr(m_exportDir.AddressOfNames);
    for (int i = 0; i < m_exportDir.NumberOfNames; i++)
    {
      FUNCEXPINFO funcInfo = {0};
      char FuncName[40] = {0};
      assert(m_exportDir.AddressOfNames != 0);
      //ENT
      UINT nameRVA = m_exportDir.AddressOfNames + i * sizeof(DWORD);
      UINT nameFileAddr = VAToRawAddr(nameRVA);
      UINT nameRVA2;
      UINT nameFileAddr2;
      fseek(fp, nameFileAddr, 0);
      fread_s(&nameRVA2, sizeof(nameRVA2), sizeof(UINT), 1, fp);

      nameFileAddr2 = VAToRawAddr(nameRVA2);
      fseek(fp, nameFileAddr2, 0);
      fread_s(&FuncName, sizeof(FuncName), 40, 1, fp);
      funcInfo.name.assign(FuncName);

      //ENT对应的序号表
      UINT ordinalRVA = m_exportDir.AddressOfNameOrdinals + i * sizeof(WORD);
      UINT ordinalFileAddr = VAToRawAddr(ordinalRVA);
      short int ordinal;
      fseek(fp, ordinalFileAddr, 0);
      fread_s(&ordinal, sizeof(ordinal), sizeof(WORD), 1, fp);
      funcInfo.ordinal = ordinal;

      m_vExportFunc.push_back(funcInfo);

    }
    //查找EAT，并找出以序号输出的函数
    for (int i = 0; i < m_exportDir.NumberOfFunctions; i++)
    {
      UINT funcAddr = m_exportDir.AddressOfFunctions + i*sizeof(DWORD);
      UINT funcFileAddr = VAToRawAddr(funcAddr);
      UINT rva;
      UINT ordinal = m_exportDir.Base + i;//当前输出函数的序号
      fseek(fp, funcFileAddr, 0);
      fread_s(&rva, sizeof(rva), sizeof(DWORD), 1, fp);
      //如果不是名称，那么它一定是以序号输出的
      findIsFunc(rva, ordinal);
    }
    //打印输出表信息
    DebugPrint("\n\n\n——————————Export Table——————————\n");
	for_each(m_vExportFunc.begin(), m_vExportFunc.end(), CParsePE::printExportTable);
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
void CParsePE::ParseImportTable()
{
  IMAGE_THUNK_DATA32 thunkData;
  IMAGE_DATA_DIRECTORY dataDir;
  IMAGE_IMPORT_DESCRIPTOR importTable;
  char dllName[56] = {'0'};
  dataDir = m_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
  if (dataDir.VirtualAddress)
  {
    UINT curFileAddr = VAToRawAddr(dataDir.VirtualAddress);
    fseek(fp, curFileAddr, 0);
    fread_s(&importTable, sizeof(importTable), sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, fp);
    m_NumImportDll = 0;
    while(importTable.FirstThunk)
    {
      m_NumImportDll++;
      //获取导入库的名称
      UINT dllNameFileAddr = VAToRawAddr(importTable.Name);
      fseek(fp, dllNameFileAddr, 0);
      fread_s(&dllName, sizeof(dllName), sizeof(dllName), 1, fp);

      UINT originalRawAddr = VAToRawAddr(importTable.OriginalFirstThunk);
      fseek(fp, originalRawAddr, 0);
      fread_s(&thunkData, sizeof(thunkData), sizeof(IMAGE_THUNK_DATA), 1, fp);

      unsigned int k = 0;
      while(thunkData.u1.AddressOfData)
      {
        FUNCIMPINFO funcImpInfo;
        funcImpInfo.dllName.assign(dllName);
        if (thunkData.u1.Ordinal & 0x80000000) //如果最高位为1，那么函数是以序号导入的
        {
          funcImpInfo.ordinal = thunkData.u1.Ordinal & 0x7fffffff;
        }
        else //如果是名字输出，那么该地址是指向IMAGE_IMPORT_BY_NAME的RVA
        {
          IMAGE_IMPORT_BY_NAME importByName;
          char funcName[50] = {'0'};
          UINT nameFuncAddr = VAToRawAddr(thunkData.u1.AddressOfData);
          fseek(fp, nameFuncAddr, 0);
          fread_s(&importByName, sizeof(importByName), sizeof(IMAGE_IMPORT_BY_NAME), 1, fp);
          funcImpInfo.ordinal = importByName.Hint;
          fseek(fp, nameFuncAddr + 2, 0);
          fread_s(funcName, sizeof(funcName), sizeof(funcName), 1, fp);
          funcImpInfo.funcName.assign(funcName);
        }
        m_vImportFunc.push_back(funcImpInfo);

        fseek(fp, originalRawAddr + (++k) * sizeof(IMAGE_THUNK_DATA), 0);
        fread_s(&thunkData, sizeof(thunkData), sizeof(IMAGE_THUNK_DATA), 1, fp);
      }

      fseek(fp, curFileAddr + m_NumImportDll * sizeof(IMAGE_IMPORT_DESCRIPTOR), 0);
      fread_s(&importTable, sizeof(importTable), sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, fp);
    }
    //打印输入表信息
    DebugPrint("\n\n\n——————————Import Table——————————\n");
    for_each(m_vImportFunc.begin(), m_vImportFunc.end(), printImportTable);

  }
}

//解析延迟输入表
void CParsePE::ParseDelayImportTable()
{
  IMAGE_THUNK_DATA32 thunkData;
  IMAGE_DATA_DIRECTORY dataDir;
  IMAGE_DELAY_IMPORT_DESCRIPTOR importTable;
  char dllName[56] = {'0'};
  dataDir = m_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
  if (dataDir.VirtualAddress > 0)
  {
    UINT curFileAddr = VAToRawAddr(dataDir.VirtualAddress);
    fseek(fp, curFileAddr, 0);
    fread_s(&importTable, sizeof(importTable), sizeof(IMAGE_DELAY_IMPORT_DESCRIPTOR), 1, fp);
    m_NumImportDll = 0;
    while(importTable.rvaIAT)
    {
      m_NumImportDll++;
      //获取导入库的名称
      UINT dllNameFileAddr = VAToRawAddr(importTable.rvaDLLName);
      fseek(fp, dllNameFileAddr, 0);
      fread_s(&dllName, sizeof(dllName), sizeof(dllName), 1, fp);

      UINT originalRawAddr = VAToRawAddr(importTable.rvaINT);
      fseek(fp, originalRawAddr, 0);
      fread_s(&thunkData, sizeof(thunkData), sizeof(IMAGE_THUNK_DATA), 1, fp);

      unsigned int k = 0;
      while(thunkData.u1.AddressOfData)
      {
        FUNCIMPINFO funcImpInfo;
        funcImpInfo.dllName.assign(dllName);
        if (thunkData.u1.Ordinal & 0x80000000) //如果最高位为1，那么函数是以序号导入的
        {
          funcImpInfo.ordinal = thunkData.u1.Ordinal & 0x7fffffff;
        }
        else //如果是名字输出，那么该地址是指向IMAGE_IMPORT_BY_NAME的RVA
        {
          IMAGE_IMPORT_BY_NAME importByName;
          char funcName[50] = {'0'};
          UINT nameFuncAddr = VAToRawAddr(thunkData.u1.AddressOfData);
          fseek(fp, nameFuncAddr, 0);
          fread_s(&importByName, sizeof(importByName), sizeof(IMAGE_IMPORT_BY_NAME), 1, fp);
          funcImpInfo.ordinal = importByName.Hint;
          fseek(fp, nameFuncAddr + 2, 0);
          fread_s(funcName, sizeof(funcName), sizeof(funcName), 1, fp);
          funcImpInfo.funcName.assign(funcName);
        }
        m_vDelayImportFunc.push_back(funcImpInfo);

        fseek(fp, originalRawAddr + (++k) * sizeof(IMAGE_THUNK_DATA), 0);
        fread_s(&thunkData, sizeof(thunkData), sizeof(IMAGE_THUNK_DATA), 1, fp);
      }

      fseek(fp, curFileAddr + m_NumImportDll * sizeof(IMAGE_DELAY_IMPORT_DESCRIPTOR), 0);
      fread_s(&importTable, sizeof(importTable), sizeof(IMAGE_DELAY_IMPORT_DESCRIPTOR), 1, fp);
    }
    //打印输入表信息
    DebugPrint("\n\n\n——————————Delay Import Table——————————\n");
    for_each(m_vDelayImportFunc.begin(), m_vDelayImportFunc.end(), printImportTable);
  }
}
//解析绑定输入表
void CParsePE::ParseBoundImportTable()
{
  IMAGE_DATA_DIRECTORY dataDir;
  IMAGE_BOUND_IMPORT_DESCRIPTOR boundImportTable;
  char dllName[56] = {'0'};
  dataDir = m_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
  if (dataDir.VirtualAddress)
  {
    DebugPrint("\n\n\n——————————BOUND IMPORT TABLE——————————\n");
    UINT curFileAddr = VAToRawAddr(dataDir.VirtualAddress);
    fseek(fp, curFileAddr, 0);
    fread_s(&boundImportTable, sizeof(boundImportTable), sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 1, fp);
    UINT k = 0;
    while(boundImportTable.OffsetModuleName)
    {
      fseek(fp, curFileAddr + boundImportTable.OffsetModuleName, 0);
      fread_s(&dllName, sizeof(dllName), 56, 1, fp);
      DebugPrint("%s\t", dllName);
      for (int i = 0; i < boundImportTable.NumberOfModuleForwarderRefs; i++)
      {
        fseek(fp, curFileAddr + (++k) * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 0);
        fread_s(&boundImportTable, sizeof(boundImportTable), sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 1, fp);
        fseek(fp, curFileAddr + boundImportTable.OffsetModuleName, 0);
        fread_s(&dllName, sizeof(dllName), 56, 1, fp);
        DebugPrint("%s\t", dllName);
      }

      fseek(fp, curFileAddr + (++k) * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 0);
      fread_s(&boundImportTable, sizeof(boundImportTable), sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR), 1, fp);
    }
  }
  //boundImportTable.OffsetModuleName


}
//解析DEBUG目录表
void CParsePE::ParseDebugTable()
{
  IMAGE_DATA_DIRECTORY debugDir;
  IMAGE_DEBUG_DIRECTORY debugTable;
  char pdbName[128]; 
  debugDir = m_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
  if (debugDir.VirtualAddress)
  {
    UINT curFileAddr = VAToRawAddr(debugDir.VirtualAddress);
    fseek(fp, curFileAddr, 0);
    fread_s(&debugTable, sizeof(debugTable), sizeof(IMAGE_DEBUG_DIRECTORY), 1, fp);
    if (IMAGE_DEBUG_TYPE_CODEVIEW == debugTable.Type)
    {
      fseek(fp, debugTable.PointerToRawData + 6, 0);
      fread_s(&pdbName, sizeof(pdbName), 128, 1, fp);
      DebugPrint("\n\n\n——————————Debug Table——————————\n"\
        "The path of PDB : %s", pdbName);
    }
  }

}

//解析RESOURSE目录表
void CParsePE::ParseResouceTable()
{
  IMAGE_DATA_DIRECTORY resDir;
  IMAGE_RESOURCE_DIRECTORY resTable;
  IMAGE_RESOURCE_DIRECTORY_ENTRY resEntryTable;
  resDir = m_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  if (resDir.VirtualAddress)
  {
    DebugPrint("\n\n\n——————————RESOURCE TABLE——————————\n");
    UINT curFileAddr = VAToRawAddr(resDir.VirtualAddress);
    fseek(fp, curFileAddr, 0);
    fread_s(&resTable, sizeof(resTable), sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
    UINT numEntry = resTable.NumberOfIdEntries + resTable.NumberOfNamedEntries;
    DebugPrint("numEntry1:%d\n", numEntry);
    //第一层目录
    //定义的是资源类型
    for (int i = 0; i < numEntry; i++)
    {
      fseek(fp, curFileAddr + sizeof(IMAGE_RESOURCE_DIRECTORY) + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 0);
      fread_s(&resEntryTable, sizeof(resEntryTable), sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
      //资源类型的ID
      //01 Cursor          08 Font（字体）         
      //02 Bitmap          09 Accelerators(加速键)  
      //03 Icon          0A Unformatted(未格式资源)      
      //04 Menu          0B MessageTable(消息表)
      //05 Dialog          0C Group Cursor(光标组)
      //06 String          0E Group Icon(图标组)
      //07 Font Directory      10 Versoin Information(版本信息）
      DebugPrint("\nresType%d : 0x%x\n", i, resEntryTable.Id);
      //是否低位数据指向下一层目录块的起始地址
      if (resEntryTable.DataIsDirectory)
      {
        IMAGE_RESOURCE_DIRECTORY resTable2;
        fseek(fp, curFileAddr + resEntryTable.OffsetToDirectory, 0);
        fread_s(&resTable2, sizeof(resTable2), sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
        UINT numEntry2 = resTable2.NumberOfIdEntries + resTable2.NumberOfNamedEntries;
        DebugPrint("numEntry2:%d\n", numEntry2);
        //第二层目录
        //定义的是资源的名称
        for (int j = 0; j < numEntry2; j++)
        {
          IMAGE_RESOURCE_DIRECTORY_ENTRY resEntryTable2;
          fseek(fp, curFileAddr + resEntryTable.OffsetToDirectory
            + sizeof(IMAGE_RESOURCE_DIRECTORY) + j * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 0);
          fread_s(&resEntryTable2, sizeof(resEntryTable2), sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
          //第二层的NAME字段是目录项的名称字符串指针，否则用ID号表示
          if (resEntryTable2.NameIsString)
          {
            IMAGE_RESOURCE_DIR_STRING_U dirStr;
            fseek(fp, curFileAddr + resEntryTable2.NameOffset, 0);
            fread_s(&dirStr, sizeof(resDir), sizeof(IMAGE_RESOURCE_DIR_STRING_U), 1, fp);
            DebugPrint("Name:%s\n", dirStr.NameString);

          }
          else
          {
            DebugPrint("ID:%d\n", resEntryTable2.NameOffset);
          }
          //最高位为1时，指向下一层目录块的起始地址，否则指针指向IMAGE_RESOURCE_DATA_ENTRY
          if (resEntryTable2.DataIsDirectory)
          {
            IMAGE_RESOURCE_DIRECTORY resTable3;
            fseek(fp, curFileAddr + resEntryTable2.OffsetToDirectory, 0);
            fread_s(&resTable3, sizeof(resTable3), sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
            UINT numEntry3 = resTable3.NumberOfIdEntries + resTable3.NumberOfNamedEntries;
            DebugPrint("numEntry3:%d\n", numEntry3);
            //第三层
            //定义的是代码页编号
            for (int k = 0; k < numEntry3; k++)
            {
              IMAGE_RESOURCE_DIRECTORY_ENTRY resEntryTable3;
              fseek(fp, curFileAddr + resEntryTable2.OffsetToDirectory 
                + sizeof(IMAGE_RESOURCE_DIRECTORY) + k * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 0);
              fread_s(&resEntryTable3, sizeof(resEntryTable3), sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
              if (!resEntryTable3.DataIsDirectory)
              {
                IMAGE_RESOURCE_DATA_ENTRY resDirEntry;
                fseek(fp, curFileAddr + resEntryTable3.OffsetToDirectory, 0);
                fread_s(&resDirEntry, sizeof(resDirEntry), sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, fp);
                DebugPrint("Rva:0x%x\t", resDirEntry.OffsetToData + m_PeInfo.imageBase);
                DebugPrint("size:%d\n", resDirEntry.Size);
              }
              else
              {
                _asm int 3
              }
            }

          }
          else
          {
            IMAGE_RESOURCE_DATA_ENTRY resDirEntry;
            fseek(fp, curFileAddr + resEntryTable2.OffsetToDirectory, 0);
            fread_s(&resDirEntry, sizeof(resDirEntry), sizeof(IMAGE_RESOURCE_DATA_ENTRY), 1, fp);
            DebugPrint("Rva:0x%x\t", resDirEntry.OffsetToData + m_PeInfo.imageBase);
            DebugPrint("size:%d\n", resDirEntry.Size);
          }
        }
      }
    }
  }

}
void CParsePE::DisplayPEInfo()
{

} 
