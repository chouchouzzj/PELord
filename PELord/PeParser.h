#pragma once

#include <Windows.h>
#include <stdio.h>
#include <assert.h>
#include <iostream>
#include <vector>
using namespace std;

//导出表函数
typedef struct _FUNCEXPINFO
{
	UINT rva;		//相对虚拟地址
	UINT ordinal;	//序号
	string name;	//名称
}FUNCEXPINFO;

//导入表函数
typedef struct _FUNCIMPINFO
{
	string dllName;		//DLL名称
	UINT ordinal;		//在对应的DLL输出表的序号
	string funcName;	//导入函数名称
}FUNCIMPINFO;

typedef struct _PEINFO
{
	bool bDLL;
	long imageBase;
	long entryPoint;
	long dosRVA;
	long dosSize;
	long m_ntHeader;
	long numSections;
	long sectionAlign;
	long fileAlign;
}PEINFO;

#define NTSIGNATURE(a) ((LPVOID)((BYTE *)a + ((PIMAGE_DOS_HEADER)a)->e_lfanew))	//
class CPeParser
{
public:
	CPeParser();
	CPeParser(const wchar_t *pFileName);
	~CPeParser();
private:
	// 0: 未知的文件类型
	DWORD   ImageFileType();
	static void printExportTable(FUNCEXPINFO funcInfo);
	static void printImportTable(FUNCIMPINFO funcImpInfo);
private:
	LONG lfanew;
	FILE *pFPE;
	char* lpFile;
	IMAGE_DOS_HEADER* m_dosHeader;
	IMAGE_NT_HEADERS* m_ntHeader;
	IMAGE_FILE_HEADER* m_fileHeader;
	IMAGE_OPTIONAL_HEADER* m_opHeader;
	IMAGE_SECTION_HEADER* m_secHeader;
	IMAGE_DATA_DIRECTORY* m_dataDir;
	IMAGE_IMPORT_DESCRIPTOR* m_importDir;
	IMAGE_EXPORT_DIRECTORY* m_exportDir;
	IMAGE_RESOURCE_DIRECTORY* m_resourceDir;
	IMAGE_TLS_DIRECTORY* m_tlsDir;
	vector<UINT> m_vSectionVirtualAddress;	//块的起始地址VA
	vector<UINT> m_vSectionVirtualSize;		//块的大小（包含块的间隙）
	vector<UINT> m_vSectionRawAddress;		//块的起始地址（在物理文件中)
	vector<UINT> m_vSectionRawSize;			//块的大小（物理文件中）
	vector<FUNCEXPINFO> m_vExportFunc;
	vector<FUNCIMPINFO> m_vImportFunc;
	vector<FUNCIMPINFO> m_vDelayImportFunc;
	int m_NumImportDll;
public:
	void ParseDosHeader();
	bool is_pe_file();
	bool findIsFunc(UINT rva, UINT ordinal);
	void ParseSections();
	void ParseNtHeader();
	void ParseExportTable();
	void ParseImportTable();
	void ParseBoundImportTable();
	void ParseDelayImportTable();
	void ParseDebugTable();
	void ParseResouceTable();
	UINT VAToRawAddr(UINT virtualAddr);
};

