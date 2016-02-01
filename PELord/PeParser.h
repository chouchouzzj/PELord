#pragma once

#include <Windows.h>
#include <stdio.h>
#include <assert.h>
#include <iostream>
#include <vector>
using namespace std;

//��������
typedef struct _FUNCEXPINFO
{
	UINT rva;		//��������ַ
	UINT ordinal;	//���
	string name;	//����
}FUNCEXPINFO;

//�������
typedef struct _FUNCIMPINFO
{
	string dllName;		//DLL����
	UINT ordinal;		//�ڶ�Ӧ��DLL���������
	string funcName;	//���뺯������
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
	// 0: δ֪���ļ�����
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
	vector<UINT> m_vSectionVirtualAddress;	//�����ʼ��ַVA
	vector<UINT> m_vSectionVirtualSize;		//��Ĵ�С��������ļ�϶��
	vector<UINT> m_vSectionRawAddress;		//�����ʼ��ַ���������ļ���)
	vector<UINT> m_vSectionRawSize;			//��Ĵ�С�������ļ��У�
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

