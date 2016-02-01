#include "StdAfx.h"
#include "ParsePE.h"
#include <algorithm>
#include <delayimp.h>

typedef ImgDelayDescr IMAGE_DELAY_IMPORT_DESCRIPTOR;
extern FILE *pFResult;

//����ʱ�Ŵ�ӡ����Ϣ����Ҫ��ʱ��Ҳ���Դ�ӡ���ļ���ȥ
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
//�ж��Ƿ���PE�ļ���ʽ�������ط���1.DOS���ʶe_magic��2.PE�ļ�ͷ��ʶsignature
bool CParsePE::is_pe_file()
{
  WORD dosMagic; //DOS MZ Header�ı�ʶ��
  DWORD peMagic; //PE�ļ�ͷ�ı�ʶ��
  long peStaAddr;
  fseek(fp, 0, 0);
  fread_s(&dosMagic, sizeof(dosMagic), sizeof(WORD), 1, fp);
  fseek(fp, 60, 0); //IMAGE_DOS_HEADER->e_lfanew ��exeͷ���ļ��еĵ�ַ
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
	/* DOS�ļ�ǩ���ȳ��֡� */
	if (*(USHORT *)lpFile == IMAGE_DOS_SIGNATURE)
	{
		/* ��DOSͷ��ʼȷ��PE�ļ�ͷ��λ�á� */
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
		/* δ֪���ļ����͡� */
		return 0;

}

/* ����DOS MZ����
   IMAGE_DOS_HEADER	0x40�ֽ�
   typedef struct _IMAGE_DOS_HEADER {  // DOS�µ�.EXE�ļ�ͷ
   USHORT e_magic;         // ħ��
   USHORT e_cblp;          // �ļ����һҳ���ֽ���
   USHORT e_cp;            // �ļ���ҳ��
   USHORT e_crlc;          // �ض�λ
   USHORT e_cparhdr;       // ����ͷ�Ĵ�С
   USHORT e_minalloc;      // ��Ҫ�����ٶ����
   USHORT e_maxalloc;      // ��Ҫ���������
   USHORT e_ss;            // ��ʼ��(��Ե�)SS�Ĵ���ֵ
   USHORT e_sp;            // ��ʼ��SP�Ĵ���ֵ
   USHORT e_csum;          // У���
   USHORT e_ip;            // ��ʼ��IP�Ĵ���ֵ
   USHORT e_cs;            // ��ʼ��(��Ե�)CS�Ĵ���ֵ
   USHORT e_lfarlc;        // �ض�λ�����ļ��еĵ�ַ
   USHORT e_ovno;          // ������
   USHORT e_res[4];        // ������
   USHORT e_oemid;         // OEMʶ���(����e_oeminfo��Ա)
   USHORT e_oeminfo;       // OEM��Ϣ; e_oemid��ָ����
   USHORT e_res2[10];      // ������
   LONG   e_lfanew;        // ��exeͷ���ļ��еĵ�ַ	��_IMAGE_NT_HEADERS�ṹ�ĵ�ַ
   } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
*/
void CParsePE::ParseDosHeader()
{
  LONG lfanew;
  fseek(fp, 0, 0);
  fread_s(&m_dosHeader, sizeof(m_dosHeader), sizeof(IMAGE_DOS_HEADER), 1, fp);
  fseek(fp, 60, 0); //IMAGE_DOS_HEADER->e_lfanew ��exeͷ���ļ��еĵ�ַ
  fread_s(&lfanew, sizeof(lfanew), sizeof(LONG), 1, fp);// ��exeͷ���ļ��еĵ�ַ
  m_PeInfo.pNtHeader = m_PeInfo.imageBase + lfanew;
  m_PeInfo.dosRVA = m_PeInfo.imageBase;
  m_PeInfo.dosSize = m_PeInfo.pNtHeader - m_PeInfo.imageBase;
  //��ӡDOS MZ������Ϣ
  DebugPrint("\n��������������������Dos Header Info��������������������\n"\
		"IMAGE_DOS_HEADER Size : 0x%08x\n"\
		"lfanew : 0x%08x\n"\
		"dos RVA : 0x%08x\n"\
		"dos size : 0x%08x\n",
		sizeof(IMAGE_DOS_HEADER),
		lfanew,
		m_PeInfo.dosRVA, 
		m_PeInfo.dosSize);
}

/*	����PE�ļ�ͷ
	//��С 4+20+96 = 120 = 0x78
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
	//��С 96
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
	// ��С 40 = 0x28
	typedef struct _IMAGE_SECTION_HEADER {	// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx
		BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];            // 0 ��������
		union {                                         // 8 �������־
		  DWORD PhysicalAddress;						//�����ַ
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

*/
void CParsePE::ParseNtHeader()
{
  fseek(fp, m_PeInfo.pNtHeader, 0);//IMAGE_DOS_HEADER->e_lfanew ��exeͷ���ļ��еĵ�ַ
  fread_s(&m_ntHeader, sizeof(m_ntHeader), sizeof(IMAGE_NT_HEADERS), 1, fp);
  m_fileHeader = m_ntHeader.FileHeader;
  m_opHeader = m_ntHeader.OptionalHeader;
  //ӳ���ļ�ͷ
  m_PeInfo.bDLL = m_fileHeader.Characteristics & IMAGE_FILE_DLL != 0 ? true : false;
  m_PeInfo.numSections = m_fileHeader.NumberOfSections;
  //��ѡӳ��ͷ
  m_PeInfo.sectionAlign = m_opHeader.SectionAlignment;
  m_PeInfo.fileAlign = m_opHeader.FileAlignment;
  m_PeInfo.entryPoint = m_opHeader.AddressOfEntryPoint;
  m_PeInfo.imageBase = m_opHeader.ImageBase;

  int curSecOffset = m_PeInfo.pNtHeader + sizeof(IMAGE_NT_HEADERS); // e_lfanew + 0x78
  IMAGE_SECTION_HEADER sectionHeader;

  DebugPrint("\n��������������������sections Info��������������������\n");
  for (int i = 0; i < m_PeInfo.numSections; i++)
  {
    fseek(fp, curSecOffset + i * sizeof(IMAGE_SECTION_HEADER), 0);
    fread_s(&sectionHeader, sizeof(IMAGE_SECTION_HEADER), sizeof(IMAGE_SECTION_HEADER), 1, fp);
    m_vSectionVirtualAddress.push_back(sectionHeader.VirtualAddress);
    m_vSectionVirtualSize.push_back(sectionHeader.Misc.VirtualSize);//ʵ�ʵĴ�С

    //����п�϶�����Ͽ�϶
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
  DebugPrint("\n��������������������Header Info��������������������\n"\
    "imageBase : 0x%08x\n"\
    "entryPoint : 0x%08x\n"\
    "sectionAlignment : 0x%08x\n"\
    "fileAlignment : 0x%08x\n"\
    "numSections : 0x%08x\n",
    m_PeInfo.imageBase, m_PeInfo.entryPoint, m_PeInfo.sectionAlign, m_PeInfo.fileAlign, m_vSectionRawAddress.size());

  ParseExportTable();

}

//�����ַת��Ϊ�����ַ
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
//�����Ƿ���m_vExportFunc��
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

//��ӡ�������Ϣ
void CParsePE::printExportTable(FUNCEXPINFO funcInfo)
{
  DebugPrint("0x%08x\t0x%08x\t%s\n", funcInfo.rva, funcInfo.ordinal, funcInfo.name.c_str());
}

//��ӡ�������Ϣ
void CParsePE::printImportTable(FUNCIMPINFO funcImpInfo)
{
  DebugPrint("%s\t0x%08x\t%s\n", funcImpInfo.dllName.c_str(), funcImpInfo.ordinal, funcImpInfo.funcName.c_str());
}

//���������
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

      //ENT��Ӧ����ű�
      UINT ordinalRVA = m_exportDir.AddressOfNameOrdinals + i * sizeof(WORD);
      UINT ordinalFileAddr = VAToRawAddr(ordinalRVA);
      short int ordinal;
      fseek(fp, ordinalFileAddr, 0);
      fread_s(&ordinal, sizeof(ordinal), sizeof(WORD), 1, fp);
      funcInfo.ordinal = ordinal;

      m_vExportFunc.push_back(funcInfo);

    }
    //����EAT�����ҳ����������ĺ���
    for (int i = 0; i < m_exportDir.NumberOfFunctions; i++)
    {
      UINT funcAddr = m_exportDir.AddressOfFunctions + i*sizeof(DWORD);
      UINT funcFileAddr = VAToRawAddr(funcAddr);
      UINT rva;
      UINT ordinal = m_exportDir.Base + i;//��ǰ������������
      fseek(fp, funcFileAddr, 0);
      fread_s(&rva, sizeof(rva), sizeof(DWORD), 1, fp);
      //����������ƣ���ô��һ��������������
      findIsFunc(rva, ordinal);
    }
    //��ӡ�������Ϣ
    DebugPrint("\n\n\n��������������������Export Table��������������������\n");
	for_each(m_vExportFunc.begin(), m_vExportFunc.end(), CParsePE::printExportTable);
  }
}

/*	���������
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
		DWORD VirtualAddress;	//�����ַ
		DWORD Size;				//��С
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
      //��ȡ����������
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
        if (thunkData.u1.Ordinal & 0x80000000) //������λΪ1����ô����������ŵ����
        {
          funcImpInfo.ordinal = thunkData.u1.Ordinal & 0x7fffffff;
        }
        else //����������������ô�õ�ַ��ָ��IMAGE_IMPORT_BY_NAME��RVA
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
    //��ӡ�������Ϣ
    DebugPrint("\n\n\n��������������������Import Table��������������������\n");
    for_each(m_vImportFunc.begin(), m_vImportFunc.end(), printImportTable);

  }
}

//�����ӳ������
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
      //��ȡ����������
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
        if (thunkData.u1.Ordinal & 0x80000000) //������λΪ1����ô����������ŵ����
        {
          funcImpInfo.ordinal = thunkData.u1.Ordinal & 0x7fffffff;
        }
        else //����������������ô�õ�ַ��ָ��IMAGE_IMPORT_BY_NAME��RVA
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
    //��ӡ�������Ϣ
    DebugPrint("\n\n\n��������������������Delay Import Table��������������������\n");
    for_each(m_vDelayImportFunc.begin(), m_vDelayImportFunc.end(), printImportTable);
  }
}
//�����������
void CParsePE::ParseBoundImportTable()
{
  IMAGE_DATA_DIRECTORY dataDir;
  IMAGE_BOUND_IMPORT_DESCRIPTOR boundImportTable;
  char dllName[56] = {'0'};
  dataDir = m_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
  if (dataDir.VirtualAddress)
  {
    DebugPrint("\n\n\n��������������������BOUND IMPORT TABLE��������������������\n");
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
//����DEBUGĿ¼��
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
      DebugPrint("\n\n\n��������������������Debug Table��������������������\n"\
        "The path of PDB : %s", pdbName);
    }
  }

}

//����RESOURSEĿ¼��
void CParsePE::ParseResouceTable()
{
  IMAGE_DATA_DIRECTORY resDir;
  IMAGE_RESOURCE_DIRECTORY resTable;
  IMAGE_RESOURCE_DIRECTORY_ENTRY resEntryTable;
  resDir = m_opHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
  if (resDir.VirtualAddress)
  {
    DebugPrint("\n\n\n��������������������RESOURCE TABLE��������������������\n");
    UINT curFileAddr = VAToRawAddr(resDir.VirtualAddress);
    fseek(fp, curFileAddr, 0);
    fread_s(&resTable, sizeof(resTable), sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
    UINT numEntry = resTable.NumberOfIdEntries + resTable.NumberOfNamedEntries;
    DebugPrint("numEntry1:%d\n", numEntry);
    //��һ��Ŀ¼
    //���������Դ����
    for (int i = 0; i < numEntry; i++)
    {
      fseek(fp, curFileAddr + sizeof(IMAGE_RESOURCE_DIRECTORY) + i * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 0);
      fread_s(&resEntryTable, sizeof(resEntryTable), sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
      //��Դ���͵�ID
      //01 Cursor          08 Font�����壩         
      //02 Bitmap          09 Accelerators(���ټ�)  
      //03 Icon          0A Unformatted(δ��ʽ��Դ)      
      //04 Menu          0B MessageTable(��Ϣ��)
      //05 Dialog          0C Group Cursor(�����)
      //06 String          0E Group Icon(ͼ����)
      //07 Font Directory      10 Versoin Information(�汾��Ϣ��
      DebugPrint("\nresType%d : 0x%x\n", i, resEntryTable.Id);
      //�Ƿ��λ����ָ����һ��Ŀ¼�����ʼ��ַ
      if (resEntryTable.DataIsDirectory)
      {
        IMAGE_RESOURCE_DIRECTORY resTable2;
        fseek(fp, curFileAddr + resEntryTable.OffsetToDirectory, 0);
        fread_s(&resTable2, sizeof(resTable2), sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
        UINT numEntry2 = resTable2.NumberOfIdEntries + resTable2.NumberOfNamedEntries;
        DebugPrint("numEntry2:%d\n", numEntry2);
        //�ڶ���Ŀ¼
        //���������Դ������
        for (int j = 0; j < numEntry2; j++)
        {
          IMAGE_RESOURCE_DIRECTORY_ENTRY resEntryTable2;
          fseek(fp, curFileAddr + resEntryTable.OffsetToDirectory
            + sizeof(IMAGE_RESOURCE_DIRECTORY) + j * sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 0);
          fread_s(&resEntryTable2, sizeof(resEntryTable2), sizeof(IMAGE_RESOURCE_DIRECTORY_ENTRY), 1, fp);
          //�ڶ����NAME�ֶ���Ŀ¼��������ַ���ָ�룬������ID�ű�ʾ
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
          //���λΪ1ʱ��ָ����һ��Ŀ¼�����ʼ��ַ������ָ��ָ��IMAGE_RESOURCE_DATA_ENTRY
          if (resEntryTable2.DataIsDirectory)
          {
            IMAGE_RESOURCE_DIRECTORY resTable3;
            fseek(fp, curFileAddr + resEntryTable2.OffsetToDirectory, 0);
            fread_s(&resTable3, sizeof(resTable3), sizeof(IMAGE_RESOURCE_DIRECTORY), 1, fp);
            UINT numEntry3 = resTable3.NumberOfIdEntries + resTable3.NumberOfNamedEntries;
            DebugPrint("numEntry3:%d\n", numEntry3);
            //������
            //������Ǵ���ҳ���
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
